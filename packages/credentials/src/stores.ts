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

/** macOS login Keychain through /usr/bin/security in interactive (stdin) mode. */
export class MacKeychainSecretStore implements SecretStore {
  readonly kind = "macos-keychain";
  readonly description = "macOS Keychain";
  constructor(private readonly run: CommandRunner = runCommand) {}
  async put(ref: string, value: SecretValue): Promise<void> {
    checkRef(ref);
    const hex = Buffer.from(encode(value), "utf8").toString("hex");
    const result = this.run(
      "/usr/bin/security",
      ["-i"],
      `add-generic-password -U -a ${ref} -s ${SERVICE} -X ${hex}\n`,
    );
    if (result.status !== 0 || /error/i.test(result.stderr))
      throw unavailable(this.description, result.stderr);
  }
  async get(ref: string): Promise<SecretValue | null> {
    checkRef(ref);
    const result = this.run("/usr/bin/security", [
      "find-generic-password",
      "-a",
      ref,
      "-s",
      SERVICE,
      "-w",
    ]);
    if (result.status === 44) return null;
    if (result.status !== 0) throw unavailable(this.description, result.stderr);
    return decode(result.stdout);
  }
  async delete(ref: string): Promise<void> {
    checkRef(ref);
    const result = this.run("/usr/bin/security", [
      "delete-generic-password",
      "-a",
      ref,
      "-s",
      SERVICE,
    ]);
    if (result.status !== 0 && result.status !== 44)
      throw unavailable(this.description, result.stderr);
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
$op = [Console]::In.ReadLine(); $target = [Console]::In.ReadLine()
if ($op -eq 'put') { $value = [Console]::In.ReadLine(); $r = [PiShipCred]::Write($target, $value); if ($r -ne 0) { [Console]::Error.WriteLine("CredWrite $r"); exit 1 } }
elseif ($op -eq 'get') { $v = [PiShipCred]::Read($target); if ($null -eq $v) { exit 44 } [Console]::Out.Write($v) }
elseif ($op -eq 'delete') { $r = [PiShipCred]::Delete($target); if ($r -ne 0) { [Console]::Error.WriteLine("CredDelete $r"); exit 1 } }
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
export class RestrictedFileSecretStore implements SecretStore {
  readonly kind = "file";
  readonly description = "restricted plaintext file (explicit opt-in fallback)";
  constructor(readonly directory: string) {}
  #path(ref: string): string {
    checkRef(ref);
    return join(
      this.directory,
      `${createHash("sha256").update(ref).digest("hex")}.secret`,
    );
  }
  #prepare(): void {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
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
    if (process.platform !== "win32" && statSync(path).mode & 0o077)
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
    return new RestrictedFileSecretStore(selection.fileDirectory);
  const platform = selection.platform ?? process.platform;
  const run = selection.run ?? runCommand;
  if (platform === "darwin") return new MacKeychainSecretStore(run);
  if (platform === "win32") return new WindowsCredentialSecretStore(run);
  return new SecretServiceSecretStore(run);
}
