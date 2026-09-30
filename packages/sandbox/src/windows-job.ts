// Windows PowerShell host for a governed child. The host puts itself in a
// kill-on-close Job Object before it starts the command; children inherit the
// job. Its exit therefore terminates descendants even if their leader exited.
const SOURCE = String.raw`
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
public static class PiShipJob {
  [StructLayout(LayoutKind.Sequential)] struct Basic {
    public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass, SchedulingClass;
  }
  [StructLayout(LayoutKind.Sequential)] struct Counters {
    public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
    public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
  }
  [StructLayout(LayoutKind.Sequential)] struct Extended {
    public Basic BasicLimitInformation;
    public Counters IoInfo;
    public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
  }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int kind, ref Extended info, uint length);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  public static string Arguments(string[] args) {
    var result = new StringBuilder();
    foreach (string arg in args) {
      if (result.Length != 0) result.Append(' ');
      result.Append('"');
      int slashes = 0;
      foreach (char ch in arg) {
        if (ch == '\\') { slashes++; continue; }
        if (ch == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); }
        else { result.Append('\\', slashes); result.Append(ch); }
        slashes = 0;
      }
      result.Append('\\', slashes * 2);
      result.Append('"');
    }
    return result.ToString();
  }
  public static int Run(ProcessStartInfo start) {
    IntPtr job = CreateJobObject(IntPtr.Zero, null);
    if (job == IntPtr.Zero) throw new Exception("CreateJobObject failed");
    try {
      var limits = new Extended();
      limits.BasicLimitInformation.LimitFlags = 0x2000; // KILL_ON_JOB_CLOSE
      if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Extended))))
        throw new Exception("SetInformationJobObject failed");
      if (!AssignProcessToJobObject(job, Process.GetCurrentProcess().Handle))
        throw new Exception("AssignProcessToJobObject failed");
      using (var child = new Process()) {
        child.StartInfo = start;
        if (!child.Start()) throw new Exception("child start failed");
        bool assigned;
        if (!IsProcessInJob(child.Handle, job, out assigned) || !assigned) {
          child.Kill();
          throw new Exception("the governed child did not inherit the Job Object");
        }
        var output = Task.Run(() => child.StandardOutput.BaseStream.CopyTo(Console.OpenStandardOutput()));
        var error = Task.Run(() => child.StandardError.BaseStream.CopyTo(Console.OpenStandardError()));
        Task.Run(() => { try { Console.OpenStandardInput().CopyTo(child.StandardInput.BaseStream); child.StandardInput.Close(); } catch {} });
        child.WaitForExit();
        int code = child.ExitCode;
        // Terminate any descendants now; otherwise inherited pipes might
        // prevent output and error copy tasks from ever reaching EOF.
        CloseHandle(job); job = IntPtr.Zero;
        Task.WaitAll(new Task[] { output, error });
        return code;
      }
    } finally { if (job != IntPtr.Zero) CloseHandle(job); }
  }
}`;

const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
try {
  Add-Type -TypeDefinition @'
${SOURCE}
'@
  $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PISHIP_JOB_REQUEST)) | ConvertFrom-Json
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = [string]$request.file
  $start.Arguments = [PiShipJob]::Arguments([string[]]$request.args)
  $start.WorkingDirectory = [string]$request.cwd
  $start.UseShellExecute = $false
  $start.RedirectStandardInput = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $start.CreateNoWindow = $true
  $start.EnvironmentVariables.Clear()
  foreach ($entry in $request.env.PSObject.Properties) { $start.EnvironmentVariables[$entry.Name] = [string]$entry.Value }
  exit ([PiShipJob]::Run($start))
} catch {
  [Console]::Error.WriteLine('PISHIP_WINDOWS_JOB_ERROR')
  exit 127
}`;

export function windowsJobCommand(target: {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
}): { file: string; args: string[]; env: NodeJS.ProcessEnv } {
  const request = Buffer.from(JSON.stringify(target)).toString("base64");
  return {
    file: "powershell.exe",
    args: [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(SCRIPT, "utf16le").toString("base64"),
    ],
    env: { ...process.env, PISHIP_JOB_REQUEST: request },
  };
}
