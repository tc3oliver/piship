import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { PiShipError, type SecretStore, SecretValue } from "@piship/contracts";

export interface CommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}
/** Runs a command with secret material only on stdin, never in argv. */
export type CommandRunner = (
  command: string,
  args: readonly string[],
  stdin?: string,
) => CommandResult;

export const runCommand: CommandRunner = (command, args, stdin) => {
  const result = spawnSync(command, [...args], {
    input: stdin ?? "",
    encoding: "utf8",
    timeout: 30_000,
    windowsHide: true,
    env: process.env,
  });
  return {
    status: result.error ? null : result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
};

const SERVICE = "piship";
function checkRef(ref: string): void {
  if (!/^[A-Za-z0-9:._#-]{1,200}$/.test(ref))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Invalid secret reference ${JSON.stringify(ref)}`,
      {
        component: "secret-store",
      },
    );
}
function unavailable(kind: string, detail: string): PiShipError {
  return new PiShipError(
    "SECRET_STORE_UNAVAILABLE",
    `${kind} secret store failed: ${detail.trim().split("\n")[0] || "unknown error"}`,
    {
      component: "secret-store",
      userAction:
        "Unlock or install the platform secret store, or explicitly opt in to the restricted file fallback",
    },
  );
}
// Secrets are stored base64url-encoded so every backend handles them as
// printable text without shell or quoting concerns.
const encode = (value: SecretValue) =>
  Buffer.from(value.reveal(), "utf8").toString("base64url");
const decode = (value: string) =>
  new SecretValue(Buffer.from(value.trim(), "base64url").toString("utf8"));

/** In-memory store: process lifetime only (tests and non-persistent sessions). */
export class MemorySecretStore implements SecretStore {
  readonly kind = "memory";
  readonly description = "process memory (not persisted)";
  readonly #values = new Map<string, SecretValue>();
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    this.#values.set(ref, value);
  }
  async get(ref: string): Promise<SecretValue | null> {
    return this.#values.get(ref) ?? null;
  }
  async delete(ref: string): Promise<void> {
    this.#values.delete(ref);
  }
  refs(): string[] {
    return [...this.#values.keys()].sort();
  }
}

// Platform stores cap one item's size (Windows generic credentials at 2,560
// bytes; macOS `security -i` reads one bounded command line). Larger values,
// such as OIDC token bundles, are split across part items named
// `<ref>+<index>` and the primary item holds `chunks:<count>`. Neither can be
// confused with a stored value: base64url has no ":", references have no "+".
const CHUNK_MARKER = "chunks:";
const MAC_CHUNK = 1024;
const partRef = (ref: string, index: number) => `${ref}+${index}`;
function chunkCount(raw: string | null): number {
  if (!raw?.startsWith(CHUNK_MARKER)) return 0;
  const count = Number(raw.slice(CHUNK_MARKER.length));
  return Number.isInteger(count) && count > 0 && count <= 1000 ? count : 0;
}
function splitChunks(value: string, size: number): string[] {
  const parts: string[] = [];
  for (let index = 0; index < value.length; index += size)
    parts.push(value.slice(index, index + size));
  return parts;
}

/** macOS login Keychain through /usr/bin/security in interactive (stdin) mode. */
export class MacKeychainSecretStore implements SecretStore {
  readonly kind = "macos-keychain";
  readonly description = "macOS Keychain";
  constructor(private readonly run: CommandRunner = runCommand) {}
  #read(account: string): string | null {
    const result = this.run("/usr/bin/security", [
      "find-generic-password",
      "-a",
      account,
      "-s",
      SERVICE,
      "-w",
    ]);
    if (result.status === 44) return null;
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
    return result.stdout.trim();
  }
  #remove(account: string): void {
    const result = this.run("/usr/bin/security", [
      "delete-generic-password",
      "-a",
      account,
      "-s",
      SERVICE,
    ]);
    if (result.status !== 0 && result.status !== 44)
      throw unavailable(this.description, result.stderr);
  }
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const encoded = encode(value);
    const previous = chunkCount(this.#read(ref));
    const parts =
      encoded.length > MAC_CHUNK ? splitChunks(encoded, MAC_CHUNK) : [];
    const add = (account: string, text: string) =>
      `add-generic-password -U -a ${account} -s ${SERVICE} -X ${Buffer.from(text, "utf8").toString("hex")}`;
    const lines = [
      ...parts.map((part, index) => add(partRef(ref, index), part)),
      add(ref, parts.length ? `${CHUNK_MARKER}${parts.length}` : encoded),
    ];
    for (let index = parts.length; index < previous; index += 1)
      lines.push(
        `delete-generic-password -a ${partRef(ref, index)} -s ${SERVICE}`,
      );
    const result = this.run(
      "/usr/bin/security",
      ["-i"],
      `${lines.join("\n")}\n`,
    );
    if (result.status !== 0 || /error/i.test(result.stderr))
      throw unavailable(this.description, result.stderr);
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const raw = this.#read(ref);
    if (raw === null) return null;
    const count = chunkCount(raw);
    if (!count) return decode(raw);
    let joined = "";
    for (let index = 0; index < count; index += 1) {
      const part = this.#read(partRef(ref, index));
      if (part === null)
        throw unavailable(this.description, "a stored secret part is missing");
      joined += part;
    }
    return decode(joined);
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    const count = chunkCount(this.#read(ref));
    for (let index = 0; index < count; index += 1)
      this.#remove(partRef(ref, index));
    this.#remove(ref);
  }
}

/** Linux Secret Service (GNOME Keyring, KWallet) through libsecret's secret-tool. */
export class SecretServiceSecretStore implements SecretStore {
  readonly kind = "secret-service";
  readonly description = "Linux Secret Service";
  constructor(private readonly run: CommandRunner = runCommand) {}
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const result = this.run(
      "secret-tool",
      ["store", `--label=PiShip ${ref}`, "service", SERVICE, "account", ref],
      encode(value),
    );
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const result = this.run("secret-tool", [
      "lookup",
      "service",
      SERVICE,
      "account",
      ref,
    ]);
    if (result.status === 1 && !result.stderr.trim()) return null;
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
    return result.stdout.trim() ? decode(result.stdout) : null;
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    const result = this.run("secret-tool", [
      "clear",
      "service",
      SERVICE,
      "account",
      ref,
    ]);
    if (result.status !== 0 && result.stderr.trim())
      throw unavailable(this.description, result.stderr);
  }
}

const WINDOWS_CREDMAN = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class PiShipCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWriteW(ref CREDENTIAL c, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredReadW(string target, int type, int flags, out IntPtr c);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr c);
  public static int Write(string target, string value) {
    byte[] blob = Encoding.UTF8.GetBytes(value);
    CREDENTIAL c = new CREDENTIAL();
    c.Type = 1; c.TargetName = target; c.UserName = "piship"; c.Persist = 2;
    c.CredentialBlobSize = blob.Length; c.CredentialBlob = Marshal.AllocHGlobal(blob.Length);
    try { Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length); return CredWriteW(ref c, 0) ? 0 : Marshal.GetLastWin32Error(); }
    finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
  public static string Read(string target) {
    IntPtr p;
    if (!CredReadW(target, 1, 0, out p)) { int e = Marshal.GetLastWin32Error(); if (e == 1168) return null; throw new Exception("CredRead " + e); }
    try { CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL)); byte[] b = new byte[c.CredentialBlobSize]; Marshal.Copy(c.CredentialBlob, b, 0, b.Length); return Encoding.UTF8.GetString(b); }
    finally { CredFree(p); }
  }
  public static int Delete(string target) { if (CredDeleteW(target, 1, 0)) return 0; int e = Marshal.GetLastWin32Error(); return e == 1168 ? 0 : e; }
}
'@
$Max = 2048
function Save($t, $v) { $r = [PiShipCred]::Write($t, $v); if ($r -ne 0) { [Console]::Error.WriteLine("CredWrite $r"); exit 1 } }
function Remove($t) { $r = [PiShipCred]::Delete($t); if ($r -ne 0) { [Console]::Error.WriteLine("CredDelete $r"); exit 1 } }
function Parts($v) { if ($null -ne $v -and $v.StartsWith('chunks:')) { return [int]$v.Substring(7) } return 0 }
$op = [Console]::In.ReadLine(); $target = [Console]::In.ReadLine()
if ($op -eq 'put') {
  $value = [Console]::In.ReadLine(); $old = Parts ([PiShipCred]::Read($target)); $n = 0
  if ($value.Length -le $Max) { Save $target $value }
  else {
    $n = [int][Math]::Ceiling($value.Length / $Max)
    for ($i = 0; $i -lt $n; $i++) { $chunk = $value.Substring($i * $Max, [Math]::Min($Max, $value.Length - $i * $Max)); Save "$target+$i" $chunk }
    Save $target "chunks:$n"
  }
  for ($i = $n; $i -lt $old; $i++) { Remove "$target+$i" }
}
elseif ($op -eq 'get') {
  $v = [PiShipCred]::Read($target); if ($null -eq $v) { exit 44 }
  $n = Parts $v
  if ($n -gt 0) {
    $b = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $n; $i++) { $p = [PiShipCred]::Read("$target+$i"); if ($null -eq $p) { [Console]::Error.WriteLine("CredRead missing part $i"); exit 1 }; [void]$b.Append($p) }
    $v = $b.ToString()
  }
  [Console]::Out.Write($v)
}
elseif ($op -eq 'delete') { $n = Parts ([PiShipCred]::Read($target)); for ($i = 0; $i -lt $n; $i++) { Remove "$target+$i" }; Remove $target }
else { exit 2 }
`;

/** Windows Credential Manager (DPAPI-protected, per user) via PowerShell; secrets travel on stdin. */
export class WindowsCredentialSecretStore implements SecretStore {
  readonly kind = "windows-credential-manager";
  readonly description = "Windows Credential Manager";
  constructor(private readonly run: CommandRunner = runCommand) {}
  #invoke(lines: readonly string[]): CommandResult {
    const encoded = Buffer.from(WINDOWS_CREDMAN, "utf16le").toString("base64");
    return this.run(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
      ],
      `${lines.join("\n")}\n`,
    );
  }
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const result = this.#invoke(["put", `${SERVICE}:${ref}`, encode(value)]);
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const result = this.#invoke(["get", `${SERVICE}:${ref}`]);
    if (result.status === 44) return null;
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
    return decode(result.stdout);
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    const result = this.#invoke(["delete", `${SERVICE}:${ref}`]);
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
  }
}

/**
 * Opt-in plaintext fallback: one file per reference under a 0700 directory,
 * written 0600 through a temporary file and atomic rename. It is not
 * equivalent to platform secure storage and is always reported as such.
 */
export interface RestrictedFileStoreOptions {
  readonly platform?: NodeJS.Platform;
  /** Runs `icacls` on Windows; the directory path travels as one argument. */
  readonly run?: CommandRunner;
  /** Windows account granted access; defaults to USERDOMAIN\USERNAME. */
  readonly account?: string;
}

/** The current Windows account as `DOMAIN\user`, or `user` without a domain. */
function windowsAccount(env: NodeJS.ProcessEnv = process.env): string | null {
  const user = env.USERNAME?.trim();
  if (!user) return null;
  const domain = env.USERDOMAIN?.trim();
  return domain ? `${domain}\\${user}` : user;
}

export class RestrictedFileSecretStore implements SecretStore {
  readonly kind = "file";
  readonly description = "restricted plaintext file (explicit opt-in fallback)";
  readonly #platform: NodeJS.Platform;
  readonly #run: CommandRunner;
  readonly #account: string | null;
  #secured = false;
  constructor(
    readonly directory: string,
    options: RestrictedFileStoreOptions = {},
  ) {
    this.#platform = options.platform ?? process.platform;
    this.#run = options.run ?? runCommand;
    this.#account = options.account ?? windowsAccount();
  }
  #path(ref: string): string {
    checkRef(ref);
    return join(
      this.directory,
      `${createHash("sha256").update(ref).digest("hex")}.secret`,
    );
  }
  /**
   * Windows ignores POSIX modes, so the directory gets an owner-only ACL:
   * inherited entries are removed and only the current account keeps full
   * control, inherited by every secret file. Failing to apply it is fatal.
   */
  #secureWindows(): void {
    if (this.#secured) return;
    if (!this.#account)
      throw unavailable(
        this.description,
        "cannot restrict the secret directory: the current Windows account is unknown (USERNAME is not set)",
      );
    const result = this.#run("icacls", [
      this.directory,
      "/inheritance:r",
      "/grant:r",
      `${this.#account}:(OI)(CI)F`,
    ]);
    if (result.status !== 0)
      throw unavailable(
        this.description,
        `cannot restrict the secret directory to the current user with icacls: ${result.stderr.trim() || result.stdout.trim() || `exit ${result.status ?? "unknown"}`}`,
      );
    this.#secured = true;
  }
  #prepare(): void {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    if (this.#platform === "win32") this.#secureWindows();
    else {
      chmodSync(this.directory, 0o700);
      const mode = statSync(this.directory).mode & 0o077;
      if (mode)
        throw unavailable(
          this.description,
          "directory permissions are not owner-only",
        );
    }
  }
  async put(ref: string, value: SecretValue): Promise<void> {
    this.#prepare();
    const path = this.#path(ref);
    const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      writeFileSync(temporary, JSON.stringify({ ref, value: encode(value) }), {
        mode: 0o600,
        flag: "wx",
      });
      renameSync(temporary, path);
    } catch (error) {
      rmSync(temporary, { force: true });
      throw unavailable(this.description, (error as Error).message);
    }
  }
  async get(ref: string): Promise<SecretValue | null> {
    const path = this.#path(ref);
    if (!existsSync(path)) return null;
    if (this.#platform === "win32") this.#secureWindows();
    else if (statSync(path).mode & 0o077)
      throw unavailable(
        this.description,
        "secret file permissions are not owner-only",
      );
    const record = JSON.parse(readFileSync(path, "utf8")) as {
      ref?: string;
      value?: string;
    };
    if (record.ref !== ref || typeof record.value !== "string")
      throw unavailable(
        this.description,
        "secret file does not match its reference",
      );
    return decode(record.value);
  }
  async delete(ref: string): Promise<void> {
    rmSync(this.#path(ref), { force: true });
  }
}

export interface SecretStoreSelection {
  readonly provider: "system" | "file";
  readonly fileDirectory: string;
  readonly platform?: NodeJS.Platform;
  readonly run?: CommandRunner;
}

/**
 * Select the configured store. "system" never silently degrades to a file:
 * an unavailable platform store surfaces SECRET_STORE_UNAVAILABLE on use.
 */
export function createSecretStore(
  selection: SecretStoreSelection,
): SecretStore {
  if (selection.provider === "file")
    return new RestrictedFileSecretStore(selection.fileDirectory, {
      ...(selection.platform ? { platform: selection.platform } : {}),
      ...(selection.run ? { run: selection.run } : {}),
    });
  const platform = selection.platform ?? process.platform;
  const run = selection.run ?? runCommand;
  if (platform === "darwin") return new MacKeychainSecretStore(run);
  if (platform === "win32") return new WindowsCredentialSecretStore(run);
  return new SecretServiceSecretStore(run);
}
