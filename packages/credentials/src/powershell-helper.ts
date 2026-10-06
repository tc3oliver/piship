// One PowerShell process that serves the Windows Credential Manager requests
// of a launch.
//
// Each request used to start powershell.exe, which then compiled a C#
// P/Invoke class with Add-Type (csc.exe), seconds on a Windows machine, and a
// signed-in launch makes one to three reads. The helper starts PowerShell
// once, defines the three Win32 calls in memory with System.Reflection.Emit
// (no compiler), and answers one request per line until its input closes.
// The credentials stay where they were: the same Credential Manager targets
// (`piship:<ref>`, parts `piship:<ref>+<n>`), the same generic credentials
// with the same blobs, so what an earlier PiShip stored still reads and what
// this stores still reads for it.
//
// Constructs the script relies on, all present in Windows PowerShell 5.1
// (.NET Framework 4.5 and later): AssemblyBuilder.DefineDynamicAssembly (the
// static overload), ModuleBuilder.DefineType / DefineField / DefineMethod,
// DllImportAttribute through CustomAttributeBuilder, Marshal.StructureToPtr /
// PtrToStructure / GetLastWin32Error, and [Console]::In.ReadLine. Nothing
// needs administrator rights, and nothing newer than 5.1 is used.
// Reflection.Emit and Add-Type both need FullLanguage mode, so a machine
// that constrains PowerShell (AppLocker, WDAC) is reported by the script
// itself and the store keeps its per-request implementation, which fails
// there as it always did.
import { type spawn as nodeSpawn, spawn } from "node:child_process";

/** What a request came back with, as `CommandResult` carries it. */
export interface HelperReply {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** A process that serves credential requests, in order. */
export interface CredentialHelper {
  request(
    op: "get" | "put" | "delete",
    target: string,
    value?: string,
  ): Promise<HelperReply>;
}

/**
 * The helper could not be started, or runs on a machine it does not support
 * (a constrained PowerShell). Nothing was sent: the caller may use another
 * way. Any other failure of a request leaves its outcome unknown.
 */
export class HelperUnavailable extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "HelperUnavailable";
  }
}

/** Ends every helper process this process started, once, when it exits. */
const running = new Set<() => void>();
process.once("exit", () => {
  for (const stop of running) stop();
});

const READY = "PISHIP-CRED READY";
const UNSUPPORTED = "PISHIP-CRED UNSUPPORTED";
/** One chunk of a value: Windows generic credentials hold 2,560 bytes. */
const MAX_CHUNK = 2048;

/**
 * The part of the script that talks to Windows: three P/Invoke methods and
 * the CREDENTIAL structure, emitted in memory, and `CredRead`, `CredWrite`
 * and `CredDelete` on top of them. Each returns what the service part
 * expects: `CredRead` the text or `$null` for no such credential (error
 * 1168) and throws on any other error; `CredWrite` and `CredDelete` a Win32
 * error code, 0 for success (and, for a delete, for no such credential).
 */
export const WINDOWS_NATIVE = `
$asmName = New-Object System.Reflection.AssemblyName('PiShipCredentialNative')
$asm = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($asmName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$mod = $asm.DefineDynamicModule('PiShipCredentialNative')
$structBuilder = $mod.DefineType('PiShipCredential', [System.Reflection.TypeAttributes]'Public, Sealed, SequentialLayout, UnicodeClass', [System.ValueType])
$fields = @(
  @('Flags', [int]), @('Type', [int]), @('TargetName', [string]), @('Comment', [string]),
  @('LastWrittenLow', [uint32]), @('LastWrittenHigh', [uint32]),
  @('CredentialBlobSize', [int]), @('CredentialBlob', [System.IntPtr]),
  @('Persist', [int]), @('AttributeCount', [int]), @('Attributes', [System.IntPtr]),
  @('TargetAlias', [string]), @('UserName', [string])
)
foreach ($field in $fields) { [void]$structBuilder.DefineField($field[0], $field[1], [System.Reflection.FieldAttributes]::Public) }
$credType = $structBuilder.CreateType()
$nativeBuilder = $mod.DefineType('PiShipCredentialCalls', [System.Reflection.TypeAttributes]'Public, Sealed, Abstract')
function Import-Call($name, $returnType, $parameterTypes) {
  $method = $nativeBuilder.DefineMethod($name, [System.Reflection.MethodAttributes]'Public, Static, PinvokeImpl', $returnType, $parameterTypes)
  $dllImport = [System.Runtime.InteropServices.DllImportAttribute]
  $constructor = $dllImport.GetConstructor([System.Type[]]@([string]))
  $named = [System.Reflection.FieldInfo[]]@($dllImport.GetField('EntryPoint'), $dllImport.GetField('SetLastError'), $dllImport.GetField('CharSet'))
  $values = [object[]]@($name, $true, [System.Runtime.InteropServices.CharSet]::Unicode)
  $attribute = New-Object System.Reflection.Emit.CustomAttributeBuilder($constructor, [object[]]@('advapi32.dll'), $named, $values)
  $method.SetCustomAttribute($attribute)
}
Import-Call 'CredWriteW' ([bool]) ([System.Type[]]@([System.IntPtr], [uint32]))
Import-Call 'CredReadW' ([bool]) ([System.Type[]]@([string], [uint32], [uint32], [System.IntPtr].MakeByRefType()))
Import-Call 'CredDeleteW' ([bool]) ([System.Type[]]@([string], [uint32], [uint32]))
Import-Call 'CredFree' ([void]) ([System.Type[]]@([System.IntPtr]))
$native = $nativeBuilder.CreateType()
$marshal = [System.Runtime.InteropServices.Marshal]
# The overloads that take a Type are asked for by signature: called as
# $marshal::SizeOf($credType), PowerShell picks the one that takes an object.
$sizeOf = $marshal.GetMethod('SizeOf', [System.Type[]]@([System.Type]))
$toStructure = $marshal.GetMethod('PtrToStructure', [System.Type[]]@([System.IntPtr], [System.Type]))
$destroy = $marshal.GetMethod('DestroyStructure', [System.Type[]]@([System.IntPtr], [System.Type]))
function CredWrite($target, $text) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  $blob = $marshal::AllocHGlobal([Math]::Max($bytes.Length, 1))
  $buffer = $marshal::AllocHGlobal($sizeOf.Invoke($null, @($credType)))
  $built = $false
  try {
    $marshal::Copy($bytes, 0, $blob, $bytes.Length)
    $c = [System.Activator]::CreateInstance($credType)
    $c.Type = 1
    $c.TargetName = $target
    $c.UserName = 'piship'
    $c.Persist = 2
    $c.CredentialBlobSize = $bytes.Length
    $c.CredentialBlob = $blob
    $marshal::StructureToPtr($c, $buffer, $false)
    $built = $true
    if ($native::CredWriteW($buffer, 0)) { return 0 }
    return $marshal::GetLastWin32Error()
  } finally {
    if ($built) { [void]$destroy.Invoke($null, @($buffer, $credType)) }
    $marshal::FreeHGlobal($buffer)
    $marshal::FreeHGlobal($blob)
  }
}
function CredRead($target) {
  $pointer = [System.IntPtr]::Zero
  if (-not $native::CredReadW($target, 1, 0, [ref]$pointer)) {
    $code = $marshal::GetLastWin32Error()
    if ($code -eq 1168) { return $null }
    throw ('CredRead ' + $code)
  }
  try {
    $c = $toStructure.Invoke($null, @($pointer, $credType))
    $bytes = [byte[]]::new($c.CredentialBlobSize)
    if ($bytes.Length -gt 0) { $marshal::Copy($c.CredentialBlob, $bytes, 0, $bytes.Length) }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
  } finally {
    $native::CredFree($pointer)
  }
}
function CredDelete($target) {
  if ($native::CredDeleteW($target, 1, 0)) { return 0 }
  $code = $marshal::GetLastWin32Error()
  if ($code -eq 1168) { return 0 }
  return $code
}
`;

/**
 * The part that serves requests, on top of `CredRead`, `CredWrite` and
 * `CredDelete`. A request is one line, `<id> <op> <target> <value>`, with
 * the value base64url text or `-` for none; the answer is one line,
 * `<id> <status> <stdout> <stderr>`, with each text base64 or `-` when
 * empty. Status 0 is success, 44 is no such credential, anything else a
 * failure with its message on stderr. The chunking is what the per-request
 * script did: a value over 2048 characters is split across `<target>+<n>`
 * items and the primary holds `chunks:<count>`.
 */
export const SERVICE_LOOP = `
$Max = ${MAX_CHUNK}
$MaxParts = 1024
function Say($text) { [Console]::Out.WriteLine($text) }
function Encode($text) {
  if ([string]::IsNullOrEmpty($text)) { return '-' }
  return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))
}
function Parts($text) {
  if ($null -ne $text -and $text.StartsWith('chunks:')) {
    $n = 0
    $digits = [System.Globalization.NumberStyles]::None
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if (-not [int]::TryParse($text.Substring(7), $digits, $invariant, [ref]$n) -or $n -gt $MaxParts) { throw 'stored credential has an invalid part count' }
    return $n
  }
  return 0
}
function Save($target, $text) {
  $code = CredWrite $target $text
  if ($code -ne 0) { throw ('CredWrite ' + $code) }
}
function Discard($target) {
  $code = CredDelete $target
  if ($code -ne 0) { throw ('CredDelete ' + $code) }
}
function Serve($op, $target, $text) {
  if ($op -eq 'put') {
    $old = Parts (CredRead $target)
    $n = 0
    if ($text.Length -le $Max) { Save $target $text }
    else {
      $n = [int][Math]::Ceiling($text.Length / $Max)
      for ($i = 0; $i -lt $n; $i++) {
        $chunk = $text.Substring($i * $Max, [Math]::Min($Max, $text.Length - $i * $Max))
        Save ($target + '+' + $i) $chunk
      }
      Save $target ('chunks:' + $n)
    }
    for ($i = $n; $i -lt $old; $i++) { Discard ($target + '+' + $i) }
    return @{ Status = 0; Out = '' }
  }
  if ($op -eq 'get') {
    $v = CredRead $target
    if ($null -eq $v) { return @{ Status = 44; Out = '' } }
    $n = Parts $v
    if ($n -gt 0) {
      $joined = New-Object System.Text.StringBuilder
      for ($i = 0; $i -lt $n; $i++) {
        $part = CredRead ($target + '+' + $i)
        if ($null -eq $part) { throw ('CredRead missing part ' + $i) }
        [void]$joined.Append($part)
      }
      $v = $joined.ToString()
    }
    return @{ Status = 0; Out = $v }
  }
  if ($op -eq 'delete') {
    $n = Parts (CredRead $target)
    for ($i = 0; $i -lt $n; $i++) { Discard ($target + '+' + $i) }
    Discard $target
    return @{ Status = 0; Out = '' }
  }
  throw 'unknown request'
}
Say '${READY}'
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  $f = $line.Split(' ')
  $text = $f[3]
  if ($text -eq '-') { $text = '' }
  try {
    $r = Serve $f[1] $f[2] $text
    Say ($f[0] + ' ' + $r.Status + ' ' + (Encode $r.Out) + ' -')
  } catch {
    Say ($f[0] + ' 1 - ' + (Encode $_.Exception.Message))
  }
}
`;

/**
 * The whole script: the language mode check, the native part (any failure to
 * set it up is reported and ends the script), and the service loop.
 */
export function helperScript(native: string = WINDOWS_NATIVE): string {
  // Write-Output, not [Console]: a constrained PowerShell refuses method
  // calls on most .NET types, and still has to be able to say so.
  return `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
  Write-Output '${UNSUPPORTED} language-mode'
  exit 3
}
try {
${native}
} catch {
  Write-Output ('${UNSUPPORTED} ' + $_.Exception.GetType().Name)
  exit 3
}
${SERVICE_LOOP}`;
}

export interface PowerShellHelperOptions {
  /** The program to run; `powershell.exe`, Windows PowerShell 5.1. */
  readonly command?: string;
  /** Its arguments; by default the script, encoded, with no profile. */
  readonly args?: readonly string[];
  readonly script?: string;
  readonly spawn?: typeof nodeSpawn;
  /** How long PowerShell may take to start and report ready. */
  readonly startTimeoutMs?: number;
  /** How long one request may take. */
  readonly requestTimeoutMs?: number;
  /** How long an idle helper lives; the next request starts another. */
  readonly idleMs?: number;
}

interface Session {
  readonly child: ReturnType<typeof nodeSpawn>;
  /** Lines waiting for a reader; the first is the ready line. */
  readonly waiting: ((line: string | null) => void)[];
  readonly lines: string[];
  readonly stop: () => void;
  closed: boolean;
}

/**
 * A helper that starts its PowerShell on the first request, serves every
 * request through it in order, and lets it end after `idleMs` without one.
 * It never keeps the process alive by itself.
 */
export function createPowerShellHelper(
  options: PowerShellHelperOptions = {},
): CredentialHelper {
  const run = options.spawn ?? spawn;
  const command = options.command ?? "powershell.exe";
  const script = options.script ?? helperScript();
  const args = options.args ?? [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    Buffer.from(script, "utf16le").toString("base64"),
  ];
  const startTimeoutMs = options.startTimeoutMs ?? 60_000;
  const requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
  const idleMs = options.idleMs ?? 15_000;
  let session: Session | undefined;
  let starting: Promise<Session> | undefined;
  /** Once PowerShell cannot serve here, it is not asked again by this process. */
  let refused: HelperUnavailable | undefined;
  let idle: NodeJS.Timeout | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  let nextId = 1;

  const end = (target: Session, kill: boolean) => {
    if (target.closed) return;
    target.closed = true;
    running.delete(target.stop);
    if (session === target) session = undefined;
    for (const waiter of target.waiting.splice(0)) waiter(null);
    try {
      target.child.stdin?.end();
    } catch {
      // Already closed.
    }
    if (kill) target.child.kill();
  };

  const readLine = (target: Session, ms: number): Promise<string | null> =>
    new Promise((resolve, reject) => {
      const buffered = target.lines.shift();
      if (buffered !== undefined) return resolve(buffered);
      if (target.closed) return resolve(null);
      const timer = setTimeout(() => {
        const at = target.waiting.indexOf(waiter);
        if (at >= 0) target.waiting.splice(at, 1);
        end(target, true);
        reject(new Error("the PowerShell credential helper did not answer"));
      }, ms);
      const waiter = (line: string | null) => {
        clearTimeout(timer);
        resolve(line);
      };
      target.waiting.push(waiter);
    });

  const start = (): Promise<Session> => {
    starting ??= new Promise<Session>((resolve, reject) => {
      const child = run(command, [...args], {
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
        env: process.env,
      });
      const target: Session = {
        child,
        waiting: [],
        lines: [],
        stop: () => end(target, true),
        closed: false,
      };
      let text = "";
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        text += chunk;
        for (let at = text.indexOf("\n"); at >= 0; at = text.indexOf("\n")) {
          const line = text.slice(0, at).replace(/\r$/, "");
          text = text.slice(at + 1);
          const waiter = target.waiting.shift();
          if (waiter) waiter(line);
          else target.lines.push(line);
        }
      });
      // Diagnostics only; a secret never reaches the error stream.
      child.stderr?.on("data", () => {});
      child.stdin?.on("error", () => {});
      child.on("error", (error: NodeJS.ErrnoException) => {
        end(target, false);
        reject(
          new HelperUnavailable(
            error.code === "ENOENT"
              ? `${command} was not found`
              : `${command} could not be started (${error.code ?? error.message})`,
          ),
        );
      });
      child.on("exit", () => end(target, false));
      // An idle helper must not keep the process alive; a pending request
      // does, through its timer.
      child.unref();
      (child.stdin as unknown as { unref?: () => void } | null)?.unref?.();
      (child.stdout as unknown as { unref?: () => void } | null)?.unref?.();
      (child.stderr as unknown as { unref?: () => void } | null)?.unref?.();
      running.add(target.stop);
      void readLine(target, startTimeoutMs).then(
        (line) => {
          if (line === READY) {
            session = target;
            resolve(target);
          } else {
            end(target, true);
            reject(
              new HelperUnavailable(
                line?.startsWith(UNSUPPORTED)
                  ? `PowerShell cannot define the credential calls here (${line.slice(UNSUPPORTED.length).trim() || "unsupported"})`
                  : "PowerShell ended before the credential helper was ready",
              ),
            );
          }
        },
        (error: Error) => reject(new HelperUnavailable(error.message)),
      );
    }).finally(() => {
      starting = undefined;
    });
    return starting;
  };

  const send = async (
    op: string,
    target: string,
    value: string | undefined,
  ): Promise<HelperReply> => {
    // A request is one line split at spaces: a target that holds one, or a
    // line break or another control character, would be read as other fields
    // or another request.
    if (
      [...target].some(
        (character) =>
          /\s/u.test(character) ||
          character.charCodeAt(0) < 0x20 ||
          character.charCodeAt(0) === 0x7f,
      )
    )
      throw new Error(
        "the credential target holds a space or control character the PowerShell helper cannot carry",
      );
    clearTimeout(idle);
    if (refused) throw refused;
    let live: Session;
    try {
      live = session && !session.closed ? session : await start();
    } catch (error) {
      if (error instanceof HelperUnavailable) refused = error;
      throw error;
    }
    const id = nextId++;
    const line = `${id} ${op} ${target} ${value === undefined || value === "" ? "-" : value}\n`;
    try {
      live.child.stdin?.write(line);
      const answer = await readLine(live, requestTimeoutMs);
      if (answer === null)
        throw new Error("the PowerShell credential helper ended mid-request");
      const [reply, status, out, err] = answer.split(" ");
      if (reply !== String(id) || status === undefined)
        throw new Error(
          "the PowerShell credential helper answered out of turn",
        );
      const decode = (text: string | undefined) =>
        text === undefined || text === "-"
          ? ""
          : Buffer.from(text, "base64").toString("utf8");
      return {
        status: Number(status),
        stdout: decode(out),
        stderr: decode(err),
      };
    } catch (error) {
      end(live, true);
      throw error;
    } finally {
      if (!live.closed) {
        idle = setTimeout(() => end(live, false), idleMs);
        idle.unref?.();
      }
    }
  };

  return {
    request(op, target, value) {
      const result = queue.then(() => send(op, target, value));
      queue = result.catch(() => undefined);
      return result;
    },
  };
}

/** The helper every Windows store of this process shares: one PowerShell per launch. */
let shared: CredentialHelper | undefined;
export function sharedPowerShellHelper(): CredentialHelper {
  shared ??= createPowerShellHelper();
  return shared;
}
