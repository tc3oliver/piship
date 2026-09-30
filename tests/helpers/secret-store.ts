import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";

// The platform secret store as the E2E scenarios see it. A scenario stores
// secrets in the restricted `file` fallback (every run) or in the `system`
// store: macOS Keychain, Windows Credential Manager, or the Linux Secret
// Service. The system store belongs to the user, not to the test, so it is
// used only when PISHIP_LIVE_SECRET_STORE=1 asks for it; the Portable E2E
// workflow sets that with a throwaway keychain or keyring on every target.

export type Storage = "file" | "system";

export const LIVE_SECRET_STORE = process.env.PISHIP_LIVE_SECRET_STORE === "1";

/** Why a `system` scenario does not run here, or null when it does. */
export const liveStoreSkipReason: string | null = LIVE_SECRET_STORE
  ? null
  : "the platform secret store is live only with PISHIP_LIVE_SECRET_STORE=1 (it writes to the user's store; the Portable E2E workflow uses a throwaway one)";

/**
 * Why a lifecycle scenario with `storage` does not run here, or null when it
 * does. A scenario that runs once per storage has a test file per storage.
 */
export function storageSkipReason(storage: Storage): string | null {
  return storage === "system" ? liveStoreSkipReason : null;
}

/**
 * The storage of a scenario that runs once instead of once per storage: the
 * platform store where it is live (CI), the file fallback everywhere else.
 */
export const PRIMARY_STORAGE: Storage = LIVE_SECRET_STORE ? "system" : "file";

/** The `kind` PiShip reports for the platform store of this OS. */
export const PLATFORM_STORE_KIND =
  process.platform === "darwin"
    ? "macos-keychain"
    : process.platform === "win32"
      ? "windows-credential-manager"
      : "secret-service";

const SERVICE = "piship";

function run(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  input = "",
): { status: number | null; stdout: string; stderr: string } {
  const done = spawnSync(command, [...args], {
    input,
    env,
    encoding: "utf8",
    timeout: 60_000,
    windowsHide: true,
  });
  if (done.error) throw done.error;
  return { status: done.status, stdout: done.stdout, stderr: done.stderr };
}

function succeed(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  input?: string,
): string {
  const done = run(command, args, env, input);
  // Only the command and its error are reported: listings can carry secrets.
  if (done.status !== 0)
    throw new Error(
      `${command} ${args[0]} exited ${done.status}: ${done.stderr.trim().split("\n")[0]}`,
    );
  return done.stdout;
}

/** Quoted keychain paths as `security list-keychains` prints them. */
const keychainPaths = (text: string): string[] =>
  [...text.matchAll(/"([^"]+)"/g)].map((match) => match[1] as string);

/**
 * The Keychain search list and default keychain live in the preferences of
 * `$HOME`, so a scenario's own home starts with neither and every Keychain
 * call would fail. Give that home the user's search list and default
 * keychain (in CI: only the job's temporary keychain). This writes the
 * preferences under `home` only.
 */
export function shareKeychainSearchList(home: string): void {
  if (process.platform !== "darwin") return;
  const security = "/usr/bin/security";
  const list = keychainPaths(
    succeed(security, ["list-keychains", "-d", "user"], process.env),
  );
  const [fallback] = keychainPaths(
    succeed(security, ["default-keychain", "-d", "user"], process.env),
  );
  if (!list.length || !fallback)
    throw new Error("The user has no keychain search list to share");
  mkdirSync(join(home, "Library", "Preferences"), { recursive: true });
  const env = { ...process.env, HOME: home };
  succeed(security, ["list-keychains", "-d", "user", "-s", ...list], env);
  succeed(security, ["default-keychain", "-d", "user", "-s", fallback], env);
  const shared = keychainPaths(
    succeed(security, ["list-keychains", "-d", "user"], env),
  );
  if (JSON.stringify(shared) !== JSON.stringify(list))
    throw new Error(
      `The scenario home did not take the keychain search list: ${JSON.stringify(shared)}`,
    );
}

// Lists (or deletes) the Credential Manager targets under a prefix. The
// struct and call conventions follow the store in packages/credentials.
const WINDOWS_LIST = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PiShipCredList {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr c);
  public static string[] List(string filter) {
    int count; IntPtr p;
    if (!CredEnumerateW(filter, 0, out count, out p)) { int e = Marshal.GetLastWin32Error(); if (e == 1168) return new string[0]; throw new Exception("CredEnumerate " + e); }
    try {
      string[] names = new string[count];
      for (int i = 0; i < count; i++) {
        CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(Marshal.ReadIntPtr(p, i * IntPtr.Size), typeof(CREDENTIAL));
        names[i] = c.TargetName;
      }
      return names;
    }
    finally { CredFree(p); }
  }
  public static int Delete(string target) { if (CredDeleteW(target, 1, 0)) return 0; int e = Marshal.GetLastWin32Error(); return e == 1168 ? 0 : e; }
}
'@
$op = [Console]::In.ReadLine(); $prefix = [Console]::In.ReadLine()
$names = [PiShipCredList]::List("$prefix*")
foreach ($name in $names) {
  if ($op -eq 'delete') { $r = [PiShipCredList]::Delete($name); if ($r -ne 0) { [Console]::Error.WriteLine("CredDelete $r"); exit 1 } }
  else { [Console]::Out.WriteLine($name) }
}
`;

function windows(
  op: "list" | "delete",
  prefix: string,
  env: NodeJS.ProcessEnv,
) {
  return succeed(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      Buffer.from(WINDOWS_LIST, "utf16le").toString("base64"),
    ],
    env,
    `${op}\n${SERVICE}:${prefix}\n`,
  );
}

/** `security dump-keychain` items of the PiShip service: their accounts. */
function keychainAccounts(env: NodeJS.ProcessEnv): string[] {
  const [keychain] = keychainPaths(
    succeed("/usr/bin/security", ["default-keychain", "-d", "user"], env),
  );
  if (!keychain) throw new Error("No default keychain");
  // Without -d the dump holds attributes only, never a secret.
  const dump = succeed("/usr/bin/security", ["dump-keychain", keychain], env);
  const accounts: string[] = [];
  for (const item of dump.split(/^keychain: /m)) {
    if (!item.includes(`"svce"<blob>="${SERVICE}"`)) continue;
    const account = /"acct"<blob>="([^"]*)"/.exec(item)?.[1];
    if (account) accounts.push(account);
  }
  return accounts;
}

/** Secret Service items of the PiShip service: their `account` attributes. */
function secretServiceAccounts(env: NodeJS.ProcessEnv): string[] {
  // `search` prints each item's secret too; only attribute lines are read.
  const done = run("secret-tool", ["search", "--all", "service", SERVICE], env);
  if (done.status !== 0 && done.stderr.trim())
    throw new Error(
      `secret-tool search failed: ${done.stderr.trim().split("\n")[0]}`,
    );
  return [
    ...`${done.stdout}\n${done.stderr}`.matchAll(
      /^attribute\.account = (.*)$/gm,
    ),
  ].map((match) => (match[1] as string).trim());
}

/**
 * Every platform store entry of the PiShip service whose reference starts
 * with `prefix`, including the `<ref>+<n>` parts of a split value. Only
 * names are read, never a secret.
 */
export function platformStoreRefs(
  prefix: string,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const refs =
    process.platform === "win32"
      ? windows("list", prefix, env)
          .split(/\r?\n/)
          .filter(Boolean)
          .map((target) => target.slice(`${SERVICE}:`.length))
      : process.platform === "darwin"
        ? keychainAccounts(env)
        : secretServiceAccounts(env);
  return refs.filter((ref) => ref.startsWith(prefix)).sort();
}

/** Delete every platform store entry under `prefix` (test teardown). */
export function clearPlatformStore(
  prefix: string,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (process.platform === "win32") {
    windows("delete", prefix, env);
    return;
  }
  for (const ref of platformStoreRefs(prefix, env))
    if (process.platform === "darwin")
      run(
        "/usr/bin/security",
        ["delete-generic-password", "-a", ref, "-s", SERVICE],
        env,
      );
    else run("secret-tool", ["clear", "service", SERVICE, "account", ref], env);
  const left = platformStoreRefs(prefix, env);
  if (left.length)
    throw new Error(`Platform store entries remain: ${left.join(", ")}`);
}

/** Primary references without the parts a split value is stored in. */
export const primaryRefs = (refs: readonly string[]): string[] =>
  refs.filter((ref) => !ref.includes("+"));

/** The parts `<ref>+<n>` of one reference in a listing. */
export const partsOf = (refs: readonly string[], ref: string): string[] =>
  refs.filter((item) => item.startsWith(`${ref}+`));

/**
 * The platform store part names of each primary must be exactly
 * `<ref>+0` to `<ref>+<n-1>`, and a primary seen at the previous check must
 * still have the same number of parts: a reference is written once per
 * generation, so a changed count means a stray or a lost part.
 */
export function expectOwnParts(
  listed: readonly string[],
  primaries: readonly string[],
  counts: Map<string, number>,
): void {
  for (const ref of primaries) {
    const parts = partsOf(listed, ref).sort(
      (a, b) =>
        Number(a.slice(ref.length + 1)) - Number(b.slice(ref.length + 1)),
    );
    expect(parts, `the parts of ${ref}`).toEqual(
      parts.map((_, index) => `${ref}+${index}`),
    );
    const before = counts.get(ref);
    if (before !== undefined)
      expect(parts.length, `the part count of ${ref}`).toBe(before);
  }
  counts.clear();
  for (const ref of primaries) counts.set(ref, partsOf(listed, ref).length);
}
