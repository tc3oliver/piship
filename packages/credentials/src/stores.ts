import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { PiShipError, type SecretStore, SecretValue } from "@piship/contracts";
import { writeFileAtomic } from "./atomic.js";
import { touchHeldLocks } from "./lock-heartbeat.js";
import {
  type CredentialHelper,
  HelperUnavailable,
  sharedPowerShellHelper,
} from "./powershell-helper.js";

export interface CommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** The command could not be started: it is not installed or not on PATH. */
  readonly missing?: boolean;
}
/** Runs a command with secret material only on stdin, never in argv. */
export type CommandRunner = (
  command: string,
  args: readonly string[],
  stdin?: string,
) => CommandResult;

export const runCommand: CommandRunner = (command, args, stdin) => {
  // This blocks the event loop for up to 30 s; keep held locks fresh first.
  touchHeldLocks();
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
    ...((result.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT"
      ? { missing: true }
      : {}),
  };
};

const SERVICE = "piship";
function checkRef(ref: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9:._#-]{0,199}$/.test(ref))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Invalid secret reference ${JSON.stringify(ref)}`,
      {
        component: "secret-store",
      },
    );
}
function unavailable(
  kind: string,
  detail: string,
  userAction = "Unlock or install the platform secret store, or explicitly opt in to the restricted file fallback",
  unreachable = false,
): PiShipError {
  return new PiShipError(
    "SECRET_STORE_UNAVAILABLE",
    `${kind} secret store ${unreachable ? "is unavailable" : "failed"}: ${detail.trim().split("\n")[0] || "unknown error"}`,
    {
      component: "secret-store",
      userAction,
      ...(unreachable ? { sanitizedDetail: { reachable: false } } : {}),
    },
  );
}

/**
 * Whether `error` says the secret store could not be reached at all: the
 * command that serves it is not installed, so nothing was read, written, or
 * deleted. Any other failure leaves the outcome of a write unknown.
 */
export function secretStoreUnreachable(error: unknown): boolean {
  return (
    error instanceof PiShipError &&
    error.code === "SECRET_STORE_UNAVAILABLE" &&
    error.sanitizedDetail?.reachable === false
  );
}

/** Run a store command; a command that is not installed is an unreachable store. */
function invoke(
  run: CommandRunner,
  description: string,
  userAction: string | undefined,
  command: string,
  args: readonly string[],
  stdin?: string,
): CommandResult {
  const result = run(command, args, stdin);
  if (result.missing)
    throw unavailable(
      description,
      `${command} was not found (${result.stderr.trim() || "ENOENT"})`,
      userAction,
      true,
    );
  return result;
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
const MAX_CHUNKS = 1000;
// `secret-tool clear` removes every match in one call.
const MAX_CLEAR_ATTEMPTS = 3;
const MAC_CHUNK = 1024;
const partRef = (ref: string, index: number) => `${ref}+${index}`;
function chunkCount(raw: string | null): number {
  if (!raw?.startsWith(CHUNK_MARKER)) return 0;
  const count = Number(raw.slice(CHUNK_MARKER.length));
  return Number.isInteger(count) && count > 0 && count <= MAX_CHUNKS
    ? count
    : 0;
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

// `secret-tool store` reads at most 8191 bytes from stdin: beyond that it warns
// "password is too long", keeps the first 8192 bytes, and still exits 0 (seen
// with libsecret 0.21.4). Larger values are split into parts below that limit;
// anything that already fit stays one item, so stored values keep their form.
const SECRET_SERVICE_CHUNK = 8000;
const SECRET_SERVICE_ACTION =
  "Install and unlock a Secret Service keyring (such as GNOME Keyring) and libsecret's secret-tool (on Debian and Ubuntu, the gnome-keyring and libsecret-tools packages), or set credential.storage.provider to file in piship.yaml, then lock and build the distribution again";

/** Linux Secret Service (GNOME Keyring, KWallet) through libsecret's secret-tool. */
export class SecretServiceSecretStore implements SecretStore {
  readonly kind = "secret-service";
  readonly description = "Linux Secret Service";
  constructor(private readonly run: CommandRunner = runCommand) {}
  #run(args: readonly string[], stdin?: string): CommandResult {
    return invoke(
      this.run,
      this.description,
      SECRET_SERVICE_ACTION,
      "secret-tool",
      args,
      stdin,
    );
  }
  #unavailable(detail: string): PiShipError {
    return unavailable(this.description, detail, SECRET_SERVICE_ACTION);
  }
  /**
   * A lookup that finds nothing exits 1 with no message, and so does one on a
   * locked keyring (libsecret 0.21.4): a locked keyring would read as an
   * absent secret. `secret-tool search` lists the attributes of an existing
   * item even when the keyring is locked, so a miss is confirmed with it.
   */
  #confirmAbsent(attributes: readonly string[]): void {
    const result = this.#run(["search", "service", SERVICE, ...attributes]);
    if (result.status !== 0 && result.stderr.trim())
      throw this.#unavailable(result.stderr);
    if (result.stdout.trim())
      throw this.#unavailable("the keyring is locked; unlock it and try again");
  }
  #read(account: string, extra: readonly string[] = []): string | null {
    const attributes = ["account", account, ...extra];
    const result = this.#run(["lookup", "service", SERVICE, ...attributes]);
    if (result.status === 1 && !result.stderr.trim()) {
      this.#confirmAbsent(attributes);
      return null;
    }
    if (result.status !== 0) throw this.#unavailable(result.stderr);
    return result.stdout.trim() || null;
  }
  #write(account: string, text: string, extra: readonly string[] = []): void {
    const result = this.#run(
      [
        "store",
        `--label=PiShip ${account}`,
        "service",
        SERVICE,
        "account",
        account,
        ...extra,
      ],
      text,
    );
    // A truncated store still exits 0, so the warning is the only signal.
    if (result.status !== 0 || /too long/i.test(result.stderr))
      throw this.#unavailable(result.stderr);
  }
  #remove(account: string): void {
    const result = this.#run(["clear", "service", SERVICE, "account", account]);
    if (result.status !== 0 && result.stderr.trim())
      throw this.#unavailable(result.stderr);
  }
  // Every part carries its primary's reference as a `parent` attribute and a
  // random `write` id, which the primary also records. Parts are found and
  // cleared by `parent` without knowing how many a failed or older write left
  // behind, and `get` reads only the parts of the write its primary names, so
  // two writers of one reference can never leave a value made of both. The
  // primary has neither attribute.
  #hasParts(parent: string): boolean {
    const attributes = ["parent", parent];
    const result = this.#run(["lookup", "service", SERVICE, ...attributes]);
    if (result.status === 1 && !result.stderr.trim()) {
      this.#confirmAbsent(attributes);
      return false;
    }
    if (result.status !== 0) throw this.#unavailable(result.stderr);
    return true;
  }
  #clearParts(parent: string): void {
    // One `clear` removes every match (checked on libsecret 0.21.4 with five
    // parts of one parent, and with parts of two writes). The repeat is only a
    // guard: a store that keeps answering with parts is broken, not slow.
    for (let attempt = 0; attempt < MAX_CLEAR_ATTEMPTS; attempt += 1) {
      const result = this.#run(["clear", "service", SERVICE, "parent", parent]);
      if (result.status !== 0 && result.stderr.trim())
        throw this.#unavailable(result.stderr);
      if (!this.#hasParts(parent)) return;
    }
    throw this.#unavailable("the stored secret parts remain");
  }
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const encoded = encode(value);
    const parts =
      encoded.length > SECRET_SERVICE_CHUNK
        ? splitChunks(encoded, SECRET_SERVICE_CHUNK)
        : [];
    const write = randomBytes(8).toString("hex");
    try {
      // Parts of an earlier write go first, so none can pair with the new
      // primary, and the primary is written last.
      this.#clearParts(ref);
      for (const [index, part] of parts.entries())
        this.#write(partRef(ref, index), part, ["parent", ref, "write", write]);
      this.#write(
        ref,
        parts.length ? `${CHUNK_MARKER}${parts.length}:${write}` : encoded,
      );
    } catch (error) {
      // A failed write leaves no part behind. An earlier chunked primary
      // would now point at cleared parts, so it goes too; an earlier plain
      // value is untouched and stays valid.
      try {
        this.#clearParts(ref);
        if (this.#read(ref)?.startsWith(CHUNK_MARKER)) this.#remove(ref);
      } catch {
        // The store is down; the write error is the one to report, and
        // delete() clears every part by attribute later.
      }
      throw error;
    }
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const raw = this.#read(ref);
    if (raw === null) return null;
    if (!raw.startsWith(CHUNK_MARKER)) return decode(raw);
    const marker = /^chunks:([1-9]\d{0,3}):([0-9a-f]{16})$/.exec(raw);
    const count = Number(marker?.[1]);
    const write = marker?.[2];
    if (!write || count > MAX_CHUNKS)
      throw this.#unavailable("a stored secret part is missing");
    const scope = ["parent", ref, "write", write];
    let joined = "";
    for (let index = 0; index < count; index += 1) {
      const part = this.#read(partRef(ref, index), scope);
      if (part === null)
        throw this.#unavailable("a stored secret part is missing");
      joined += part;
    }
    if (this.#read(partRef(ref, count), scope) !== null)
      throw this.#unavailable("a stored secret has an extra part");
    return decode(joined);
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    this.#clearParts(ref);
    this.#remove(ref);
    if (this.#read(ref) !== null || this.#hasParts(ref))
      throw this.#unavailable("the stored secret could not be deleted");
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

export interface WindowsStoreOptions {
  /**
   * Serves requests through one PowerShell that defines the Win32 calls in
   * memory, instead of starting a PowerShell that compiles them for each
   * request. Started on the first request. When it cannot serve (PowerShell
   * is constrained, or cannot be started) the store runs each request
   * through its runner, as it did before the helper.
   */
  readonly helper?: () => CredentialHelper;
}

/** Windows Credential Manager (DPAPI-protected, per user) via PowerShell; secrets travel on stdin. */
export class WindowsCredentialSecretStore implements SecretStore {
  readonly kind = "windows-credential-manager";
  readonly description = "Windows Credential Manager";
  constructor(
    private readonly run: CommandRunner = runCommand,
    private readonly options: WindowsStoreOptions = {},
  ) {}
  /** One PowerShell per request, compiling its P/Invoke class: seconds each. */
  #invoke(lines: readonly string[]): CommandResult {
    const encoded = Buffer.from(WINDOWS_CREDMAN, "utf16le").toString("base64");
    return invoke(
      this.run,
      this.description,
      undefined,
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
  async #call(
    op: "get" | "put" | "delete",
    ref: string,
    value?: string,
  ): Promise<CommandResult> {
    const target = `${SERVICE}:${ref}`;
    if (this.options.helper)
      try {
        return await this.options.helper().request(op, target, value);
      } catch (error) {
        if (!(error instanceof HelperUnavailable))
          throw unavailable(
            this.description,
            error instanceof Error ? error.message : String(error),
          );
      }
    return this.#invoke([op, target, ...(value === undefined ? [] : [value])]);
  }
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const result = await this.#call("put", ref, encode(value));
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const result = await this.#call("get", ref);
    if (result.status === 44) return null;
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
    return decode(result.stdout);
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    const result = await this.#call("delete", ref);
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
    try {
      writeFileAtomic(path, JSON.stringify({ ref, value: encode(value) }));
    } catch (error) {
      throw unavailable(this.description, (error as Error).message);
    }
  }
  async get(ref: string): Promise<SecretValue | null> {
    const path = this.#path(ref);
    // Only a missing entry is absent. An entry or directory that exists but
    // cannot be read is an unavailable store, never "not signed in".
    const unreadable = (detail: string) =>
      unavailable(
        this.description,
        `cannot read ${path}: ${detail}`,
        `Give your user owner-only access to ${this.directory} and its files (chmod 700 on the directory, 600 on the files), or remove an entry that is not a valid secret file and sign in again`,
      );
    const code = (error: unknown) =>
      (error as NodeJS.ErrnoException).code ?? (error as Error).message;
    let mode: number;
    try {
      mode = statSync(path).mode;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw unreadable(code(error));
    }
    if (this.#platform === "win32") this.#secureWindows();
    else if (mode & 0o077)
      throw unreadable("secret file permissions are not owner-only");
    let record: { ref?: string; value?: string };
    try {
      record = JSON.parse(readFileSync(path, "utf8"));
    } catch (error) {
      throw unreadable(code(error));
    }
    if (record?.ref !== ref || typeof record.value !== "string")
      throw unreadable("secret file does not match its reference");
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
  // Without an injected runner, every request of the launch goes through one
  // PowerShell (powershell-helper.ts); an injected runner serves each request.
  if (platform === "win32")
    return new WindowsCredentialSecretStore(
      run,
      selection.run ? {} : { helper: sharedPowerShellHelper },
    );
  return new SecretServiceSecretStore(run);
}
