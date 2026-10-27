import { windowsJobHelper } from "./windows-job-helper.js";
import { JOB_SOURCE } from "./windows-job-source.js";

const SCRIPT = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
try {
  Import-Module ($PSHOME + '\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1')
  Add-Type -TypeDefinition @'
${JOB_SOURCE}
'@
  $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PISHIP_JOB_REQUEST)) | ConvertFrom-Json
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = [string]$request.file
  $start.WorkingDirectory = [string]$request.cwd
  $start.UseShellExecute = $false
  $start.EnvironmentVariables.Clear()
  foreach ($entry in $request.env.PSObject.Properties) { $start.EnvironmentVariables[$entry.Name] = [string]$entry.Value }
  exit ([PiShipJob]::Run($start, [string[]]$request.args, [int]$env:PISHIP_JOB_PARENT_PID))
} catch {
  [Console]::Error.WriteLine('PISHIP_WINDOWS_JOB_ERROR: ' + $_.Exception.Message)
  exit 127
}`;

/**
 * The host variables the supervisor keeps (no credentials): TEMP and TMP,
 * where Add-Type writes its compile.
 */
const SUPERVISOR_SYSTEM_VARIABLES = ["TEMP", "TMP"] as const;

/**
 * The Windows directory from `SystemRoot` (or `WINDIR`), only when it is an
 * absolute drive path. Anything else fails closed: a bare `powershell.exe`
 * would be looked up in the workspace before `PATH`.
 */
export function systemRoot(host: NodeJS.ProcessEnv): string {
  const value = host.SystemRoot || host.WINDIR;
  if (!value || !/^[A-Za-z]:[\\/]/.test(value) || value.includes(".."))
    throw new Error(
      "Windows Job Object supervisor needs an absolute SystemRoot or WINDIR",
    );
  return value.replace(/[\\/]+$/, "");
}

type JobTarget = {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
};

/** The base64 request both supervisors read, and the child's approved PATH. */
function jobRequest(
  target: JobTarget,
  host: NodeJS.ProcessEnv,
): { request: string; path: string | undefined } {
  // Windows needs SystemRoot to resolve side-by-side runtime assemblies when
  // CreateProcess receives an explicit environment block. Keep the rest of
  // the child's environment restricted to the caller-approved values.
  // Windows environment names are case-insensitive. Pi can supply PATH
  // alongside Path; PowerShell's ConvertFrom-Json refuses those duplicates.
  // Match Node's sorted, first-key-wins handling of Windows environment keys.
  const childEnv: Record<string, string> = {};
  const names = new Set<string>();
  for (const name of Object.keys(target.env).sort()) {
    const folded = name.toUpperCase();
    if (names.has(folded)) continue;
    names.add(folded);
    childEnv[name] = target.env[name] as string;
  }
  for (const name of ["SystemRoot", "WINDIR"] as const)
    if (!names.has(name.toUpperCase()) && host[name]) {
      childEnv[name] = host[name];
      names.add(name.toUpperCase());
    }
  const request = Buffer.from(
    JSON.stringify({ ...target, env: childEnv }),
  ).toString("base64");
  const path = Object.keys(childEnv).find(
    (name) => name.toUpperCase() === "PATH",
  );
  return { request, path: path === undefined ? undefined : childEnv[path] };
}

export function windowsJobCommand(
  target: JobTarget,
  host: NodeJS.ProcessEnv = process.env,
): { file: string; args: string[]; env: NodeJS.ProcessEnv } {
  const root = systemRoot(host);
  const { request, path } = jobRequest(target, host);
  // The supervisor runs outside the Job Object, so it gets the variables
  // Windows itself sets for a user session, which PowerShell 5.1 and the
  // Add-Type compile need to start, and never the rest of the launcher's
  // environment. Its PATH is the child's approved one: CreateProcess
  // resolves a bare child file name through the supervisor's PATH.
  const env: NodeJS.ProcessEnv = {
    SystemRoot: root,
    WINDIR: root,
    PISHIP_JOB_REQUEST: request,
    PISHIP_JOB_PARENT_PID: String(process.pid),
  };
  for (const name of SUPERVISOR_SYSTEM_VARIABLES) {
    const key = Object.keys(host).find(
      (candidate) => candidate.toUpperCase() === name.toUpperCase(),
    );
    const value = key === undefined ? undefined : host[key];
    if (value) env[name] = value;
  }
  if (path !== undefined) env.PATH = path;
  return {
    file: `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
    args: [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(SCRIPT, "utf16le").toString("base64"),
    ],
    env,
  };
}

/**
 * The supervisor to start a governed child with: the compiled helper when this
 * machine has a verified one, otherwise the PowerShell supervisor above. The
 * helper runs the same Job Object code without PowerShell's start or an
 * Add-Type compile, which cost about 900 ms per child.
 */
export function windowsJobSupervisor(
  target: JobTarget,
  host: NodeJS.ProcessEnv = process.env,
): { file: string; args: string[]; env: NodeJS.ProcessEnv } {
  // Fail closed first: an unresolved SystemRoot never reaches either path.
  const root = systemRoot(host);
  const helper = windowsJobHelper({ host, systemRoot: root });
  if (helper === undefined) return windowsJobCommand(target, host);
  const { request, path } = jobRequest(target, host);
  const env: NodeJS.ProcessEnv = {
    SystemRoot: root,
    WINDIR: root,
    PISHIP_JOB_REQUEST: request,
    PISHIP_JOB_PARENT_PID: String(process.pid),
  };
  if (path !== undefined) env.PATH = path;
  return { file: helper, args: [], env };
}
