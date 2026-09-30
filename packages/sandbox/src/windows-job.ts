// The PowerShell supervisor stays outside the kill-on-close Job Object.
// CreateProcess starts the child suspended; only after job assignment may it run.
const SOURCE = String.raw`
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
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
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
    public int length;
    public IntPtr descriptor;
    [MarshalAs(UnmanagedType.Bool)] public bool inherit;
  }
  [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
    public int cb;
    public IntPtr reserved, desktop, title;
    public int x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
    public short showWindow, reserved2;
    public IntPtr reservedBytes, stdInput, stdOutput, stdError;
  }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {
    public IntPtr process, thread;
    public int processId, threadId;
  }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int kind, ref Extended info, uint length);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, int size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, int mask, int flags);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
    bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation process);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  static void Close(ref IntPtr handle) { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
  static Exception Failure(string operation) { return new Exception(operation + " failed: " + Marshal.GetLastWin32Error()); }
  static void Pipe(ref SecurityAttributes attributes, out IntPtr read, out IntPtr write) {
    if (!CreatePipe(out read, out write, ref attributes, 0)) throw Failure("CreatePipe");
  }
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
  public static int Run(ProcessStartInfo start, string[] args) {
    IntPtr job = IntPtr.Zero, inputRead = IntPtr.Zero, inputWrite = IntPtr.Zero;
    IntPtr outputRead = IntPtr.Zero, outputWrite = IntPtr.Zero;
    IntPtr errorRead = IntPtr.Zero, errorWrite = IntPtr.Zero;
    IntPtr environment = IntPtr.Zero;
    var process = new ProcessInformation();
    try {
      job = CreateJobObject(IntPtr.Zero, null);
      if (job == IntPtr.Zero) throw Failure("CreateJobObject");
      var limits = new Extended();
      limits.BasicLimitInformation.LimitFlags = 0x2000;
      if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Extended))))
        throw Failure("SetInformationJobObject");
      var attributes = new SecurityAttributes { length = Marshal.SizeOf(typeof(SecurityAttributes)), inherit = true };
      Pipe(ref attributes, out inputRead, out inputWrite);
      Pipe(ref attributes, out outputRead, out outputWrite);
      Pipe(ref attributes, out errorRead, out errorWrite);
      if (!SetHandleInformation(inputWrite, 1, 0) || !SetHandleInformation(outputRead, 1, 0) ||
          !SetHandleInformation(errorRead, 1, 0)) throw Failure("SetHandleInformation");
      var startup = new StartupInfo {
        cb = Marshal.SizeOf(typeof(StartupInfo)), flags = 0x100,
        stdInput = inputRead, stdOutput = outputWrite, stdError = errorWrite
      };
      var names = new System.Collections.Generic.List<string>();
      foreach (string name in start.EnvironmentVariables.Keys) names.Add(name);
      names.Sort(StringComparer.OrdinalIgnoreCase);
      var block = new StringBuilder();
      foreach (string name in names) block.Append(name).Append('=').Append(start.EnvironmentVariables[name]).Append('\0');
      block.Append('\0');
      environment = Marshal.StringToHGlobalUni(block.ToString());
      var command = new StringBuilder(Arguments(new string[] { start.FileName }) + " " + Arguments(args));
      // CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT.
      if (!CreateProcessW(null, command, IntPtr.Zero, IntPtr.Zero, true, 0x4 | 0x08000000 | 0x400,
        environment, start.WorkingDirectory, ref startup, out process)) throw Failure("CreateProcess");
      Close(ref inputRead); Close(ref outputWrite); Close(ref errorWrite);
      if (!AssignProcessToJobObject(job, process.process)) throw Failure("AssignProcessToJobObject");
      if (ResumeThread(process.thread) == 0xffffffff) throw Failure("ResumeThread");
      using (var output = new FileStream(new SafeFileHandle(outputRead, true), FileAccess.Read)) {
        outputRead = IntPtr.Zero;
        using (var error = new FileStream(new SafeFileHandle(errorRead, true), FileAccess.Read)) {
          errorRead = IntPtr.Zero;
          using (var input = new FileStream(new SafeFileHandle(inputWrite, true), FileAccess.Write)) {
            inputWrite = IntPtr.Zero;
            var outputTask = Task.Run(() => output.CopyTo(Console.OpenStandardOutput()));
            var errorTask = Task.Run(() => error.CopyTo(Console.OpenStandardError()));
            Task.Run(() => { try { Console.OpenStandardInput().CopyTo(input); input.Close(); } catch {} });
            if (WaitForSingleObject(process.process, 0xffffffff) != 0) throw Failure("WaitForSingleObject");
            uint code;
            if (!GetExitCodeProcess(process.process, out code)) throw Failure("GetExitCodeProcess");
            Close(ref job);
            Task.WaitAll(outputTask, errorTask);
            return unchecked((int)code);
          }
        }
      }
    } finally {
      if (process.process != IntPtr.Zero && job != IntPtr.Zero) TerminateProcess(process.process, 1);
      Close(ref process.thread); Close(ref process.process); Close(ref job);
      Close(ref inputRead); Close(ref inputWrite); Close(ref outputRead); Close(ref outputWrite);
      Close(ref errorRead); Close(ref errorWrite);
      if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
    }
  }
}`;

const SCRIPT = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  Add-Type -TypeDefinition @'
${SOURCE}
'@
  $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PISHIP_JOB_REQUEST)) | ConvertFrom-Json
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = [string]$request.file
  $start.WorkingDirectory = [string]$request.cwd
  $start.UseShellExecute = $false
  $start.EnvironmentVariables.Clear()
  foreach ($entry in $request.env.PSObject.Properties) { $start.EnvironmentVariables[$entry.Name] = [string]$entry.Value }
  exit ([PiShipJob]::Run($start, [string[]]$request.args))
} catch {
  [Console]::Error.WriteLine('PISHIP_WINDOWS_JOB_ERROR: ' + $_.Exception.Message)
  exit 127
}`;

export function windowsJobCommand(target: {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
}): { file: string; args: string[]; env: NodeJS.ProcessEnv } {
  // Windows needs SystemRoot to resolve side-by-side runtime assemblies when
  // CreateProcess receives an explicit environment block. Keep the rest of
  // the child's environment restricted to the caller-approved values.
  const childEnv = { ...target.env };
  for (const name of ["SystemRoot", "WINDIR"] as const)
    if (!(name in childEnv) && process.env[name])
      childEnv[name] = process.env[name];
  const request = Buffer.from(
    JSON.stringify({ ...target, env: childEnv }),
  ).toString("base64");
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
