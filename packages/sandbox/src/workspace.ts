// Workspace verification: whether a remote sandbox really sees the files
// PiShip's file tools edit. A backend declares `shared` or `synchronized`;
// PiShip refutes the claim if it can with a two-way sentinel in a
// PiShip-owned directory, and proves from outside, without changing
// anything, that the host's git control files cannot be changed from the
// sandbox. The check can refute a claim but never proves a mount: an
// immediate result also fits a very fast sync.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  rmdirSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join, relative, sep } from "node:path";
import {
  DEFAULT_PROPAGATION_MS,
  type SandboxWorkspaceDeclaration,
  type WorkspaceMode,
} from "./backend.js";
import { isWithin, type ProtectedPaths } from "./profile.js";

export type WorkspaceVerification =
  /** A local backend, or a declared snapshot: there is nothing to verify. */
  | "not-required"
  /** Shared or synchronized, and no sandboxed command has run yet. */
  | "pending"
  | "verified"
  /** No PiShip-owned location to verify it in; the effective mode is snapshot. */
  | "unverifiable"
  /** A direction did not propagate; the effective mode is lowered. */
  | "failed";

export type Propagation = "immediate" | "delayed" | "missing";

/**
 * `verified`: the live probe proved it (local backends). `attested-renames`:
 * writing a protected file and creating a file in a protected directory
 * failed from inside the sandbox; renaming them is not tried (it would be
 * destructive) and stays attested by the backend. `pending`: checked before
 * the first sandboxed command. `not-verified`: the local live probe could
 * not prove it (reported, not yet required). `not-applicable`: the sandbox
 * cannot reach this host's files.
 */
export type GitControlProtectionState =
  | "verified"
  | "attested-renames"
  | "pending"
  | "not-verified"
  | "not-applicable";

export interface WorkspaceReport {
  readonly declared: WorkspaceMode;
  /**
   * What the evidence supports; never stronger than declared. `snapshot`
   * until a shared or synchronized workspace has been verified.
   */
  readonly effective: WorkspaceMode;
  readonly verification: WorkspaceVerification;
  readonly hostToSandbox?: Propagation;
  readonly sandboxToHost?: Propagation;
  /** The window a delayed direction had to propagate in, in milliseconds. */
  readonly windowMs?: number;
  readonly gitControlProtection: GitControlProtectionState;
  /** RFC 3339 time of the last verification. */
  readonly verifiedAt?: string;
  /** Why the effective mode is lower than declared. Never a path, token, or origin. */
  readonly reason?: string;
  /**
   * A complete coding-agent workspace: the effective mode is shared or
   * synchronized and it was verified (or needs none: a local backend). A
   * snapshot never is.
   */
  readonly complete: boolean;
}

export interface SentinelContext {
  /** The workspace root (a real path). */
  readonly workspace: string;
  /** Decides whether a working-tree `sentinelDir` may be used. */
  readonly origin: "company" | "external" | "unknown";
  /** A shared or synchronized declaration. */
  readonly declaration: SandboxWorkspaceDeclaration;
  /** The profile's `writeProtect`. */
  readonly protectedPaths: ProtectedPaths;
  /** Wall clock for `verifiedAt` and the stale sweep. */
  readonly now?: () => number;
}

/** How long a verification result counts before the next command checks again. */
export const WORKSPACE_VALIDITY_MS = 30 * 60_000;
/** The window a declared `shared` workspace gets before it counts as missing. */
export const SHARED_WINDOW_MS = 10_000;
/** Printed by the workspace check command; every line is a token, never content. */
export const WORKSPACE_MARKER = "piship-ws";

const POLL_MS = 200;
const STALE_MS = 24 * 3600_000;
const NONCE = /^[0-9a-f]{32}$/;
const LOCATION = "piship-workspace";
/** The only names a run puts in its nonce directory. */
const SENTINEL_NAMES = ["h2s", "s2h", "s2h.tmp"] as const;
const OUTPUT_LIMIT = 4096;

/** The window a declaration gives each direction. */
export function workspaceWindowMs(
  declaration: SandboxWorkspaceDeclaration,
): number {
  return declaration.mode === "synchronized"
    ? (declaration.propagationMs ?? DEFAULT_PROPAGATION_MS)
    : SHARED_WINDOW_MS;
}

/** A local backend: commands run against this host's files. */
export function localWorkspaceReport(
  gitControlProven: boolean,
): WorkspaceReport {
  return {
    declared: "shared",
    effective: "shared",
    verification: "not-required",
    gitControlProtection: gitControlProven ? "verified" : "not-verified",
    complete: true,
  };
}

/** A remote backend at activation: snapshot needs nothing, the others are pending. */
export function initialWorkspaceReport(
  declaration: SandboxWorkspaceDeclaration,
): WorkspaceReport {
  if (declaration.mode === "snapshot")
    return {
      declared: "snapshot",
      effective: "snapshot",
      verification: "not-required",
      gitControlProtection: "not-applicable",
      complete: false,
    };
  return {
    declared: declaration.mode,
    effective: "snapshot",
    verification: "pending",
    gitControlProtection: "pending",
    complete: false,
  };
}

const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

function lstatOrUndefined(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

class LocationError extends Error {}

/**
 * The directory `root/segments...`, each component a plain directory (never
 * a symbolic link) and the result inside `root`. With `create`, missing
 * components are made one level at a time with mode 0700.
 */
function plainDirectory(
  root: string,
  segments: readonly string[],
  create: boolean,
): string {
  let current = root;
  for (const segment of segments) {
    current = join(current, segment);
    let stat = lstatOrUndefined(current);
    if (!stat && create) {
      try {
        mkdirSync(current, { mode: 0o700 });
      } catch (error) {
        if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error;
      }
      stat = lstatOrUndefined(current);
    }
    if (!stat)
      throw new LocationError("a directory of the location is missing");
    if (stat.isSymbolicLink() || !stat.isDirectory())
      throw new LocationError(
        "a component of the location is a symbolic link or not a directory",
      );
  }
  if (!isWithin(realpathSync.native(current), realpathSync.native(root)))
    throw new LocationError("the location resolves outside the workspace");
  return current;
}

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

function writeNew(path: string, content: string): void {
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW,
    0o600,
  );
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
}

/** A short regular file's content, never through a symbolic link. */
function readToken(path: string): string | undefined {
  try {
    if (!lstatSync(path).isFile()) return undefined;
    const fd = openSync(path, constants.O_RDONLY | NOFOLLOW);
    try {
      const buffer = Buffer.alloc(128);
      const length = readSync(fd, buffer, 0, buffer.length, 0);
      return buffer.subarray(0, length).toString("utf8");
    } finally {
      closeSync(fd);
    }
  } catch {
    return undefined;
  }
}

/** Where the sentinel lives, as workspace-relative segments, or why there is no such place. */
export function sentinelLocation(
  ctx: Pick<SentinelContext, "workspace" | "origin" | "declaration">,
): { readonly segments: readonly string[] } | { readonly reason: string } {
  const dotGit = lstatOrUndefined(join(ctx.workspace, ".git"));
  const gitDirectory =
    !!dotGit && !dotGit.isSymbolicLink() && dotGit.isDirectory();
  const declared = ctx.declaration.sentinelDir;
  if (declared !== undefined) {
    const segments = declared
      .split("/")
      .filter((segment) => segment !== "" && segment !== ".");
    const inGitDirectory = gitDirectory && segments[0] === ".git";
    if (!inGitDirectory && ctx.origin !== "company")
      return {
        reason:
          "the backend's sentinel directory is in the working tree, which PiShip writes to only in company-origin projects",
      };
    return { segments: [...segments, LOCATION] };
  }
  if (!dotGit) return { reason: "the workspace has no .git directory" };
  if (!gitDirectory)
    return {
      reason: dotGit.isSymbolicLink()
        ? "the workspace's .git is a symbolic link"
        : "the workspace's .git is a file (a linked worktree), so its git directory is not in the workspace",
    };
  return { segments: [".git", LOCATION] };
}

/**
 * Remove a nonce directory, never recursively. The sandbox can write here,
 * so a recursive delete would follow whatever it swaps in for a component
 * (a link from the location to a host directory holding a directory of the
 * same name) and delete host files. A run makes only the names in
 * `SENTINEL_NAMES`: each that is a regular file is unlinked, then the
 * directory is removed if that left it empty. `plainDirectory` runs again
 * before every step. With `onlyOwn`, a directory that holds any other name
 * is left untouched. Returns whether the directory is gone.
 */
export function removeSentinelDirectory(
  workspace: string,
  base: readonly string[],
  nonce: string,
  options: { readonly onlyOwn?: boolean } = {},
): boolean {
  const segments = [...base, nonce];
  const directory = () => plainDirectory(workspace, segments, false);
  try {
    if (options.onlyOwn)
      for (const name of readdirSync(directory()))
        if (!(SENTINEL_NAMES as readonly string[]).includes(name)) return false;
    for (const name of SENTINEL_NAMES)
      if (lstatOrUndefined(join(directory(), name))?.isFile())
        unlinkSync(join(directory(), name));
    rmdirSync(directory());
    return true;
  } catch {
    // gone already, not empty, or no longer safe to follow
    return false;
  }
}

/** Remove nonce directories an earlier run left behind for more than a day. */
function sweepStale(
  workspace: string,
  base: readonly string[],
  now: number,
): void {
  let names: string[];
  try {
    names = readdirSync(plainDirectory(workspace, base, false));
  } catch {
    return;
  }
  for (const name of names) {
    if (!NONCE.test(name)) continue;
    try {
      const stat = lstatSync(
        join(plainDirectory(workspace, base, false), name),
      );
      if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
      if (now - stat.mtimeMs <= STALE_MS) continue;
    } catch {
      continue;
    }
    removeSentinelDirectory(workspace, base, name, { onlyOwn: true });
  }
}

// Sentinel directories of runs in progress, removed if the process exits
// before the run's own cleanup.
const liveSentinels = new Map<
  string,
  {
    readonly workspace: string;
    readonly base: readonly string[];
    readonly nonce: string;
  }
>();
let exitHookInstalled = false;

function trackSentinel(
  workspace: string,
  base: readonly string[],
  nonce: string,
): void {
  liveSentinels.set(join(workspace, ...base, nonce), {
    workspace,
    base,
    nonce,
  });
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const live of liveSentinels.values())
      removeSentinelDirectory(live.workspace, live.base, live.nonce);
  });
}

interface ProtectedTarget {
  /** Workspace-relative POSIX path. */
  readonly relative: string;
  /** Workspace-relative segments. */
  readonly segments: readonly string[];
}

interface ProtectedFile extends ProtectedTarget {
  /**
   * Absent on the host when the check started. Git reads such a file if it
   * appears (`.git/commondir` redirects the git directory), so the check
   * tries to create it instead of appending to it.
   */
  readonly missing: boolean;
}

function insideWorkspace(
  workspace: string,
  paths: readonly string[],
): ProtectedTarget[] {
  const targets: ProtectedTarget[] = [];
  for (const path of paths) {
    if (path === workspace || !isWithin(path, workspace)) continue;
    const rel = relative(workspace, path);
    targets.push({ relative: toPosix(rel), segments: rel.split(sep) });
  }
  return targets;
}

interface ScriptInput {
  readonly sentinel?: {
    readonly dir: string;
    readonly hostToken: string;
    readonly sandboxToken: string;
    readonly polls: number;
  };
  readonly files: readonly ProtectedFile[];
  readonly directories: readonly ProtectedTarget[];
  readonly nonce: string;
}

/** POSIX sh; every path is workspace-relative and quoted; output is tokens only. */
function checkScript(input: ScriptInput): string {
  const lines: string[] = [];
  const sentinel = input.sentinel;
  if (sentinel) {
    const h2s = `"$d/h2s"`;
    const token = quote(sentinel.hostToken);
    lines.push(
      `d=${quote(sentinel.dir)}; n=${sentinel.polls}; i=0`,
      `while [ "$(cat ${h2s} 2>/dev/null)" != ${token} ] && [ "$i" -lt "$n" ]; do if sleep 0.2 2>/dev/null; then i=$((i+1)); else sleep 1; i=$((i+5)); fi; done`,
      `if [ "$(cat ${h2s} 2>/dev/null)" = ${token} ]; then echo "${WORKSPACE_MARKER} h2s $i"; else echo "${WORKSPACE_MARKER} h2s missing"; fi`,
      // The directory exists here only if the host's write arrived; create
      // it so the other direction is tested on its own.
      `if mkdir -p "$d" 2>/dev/null && printf '%s' ${quote(sentinel.sandboxToken)} > "$d/s2h.tmp" 2>/dev/null && mv -f "$d/s2h.tmp" "$d/s2h" 2>/dev/null; then echo "${WORKSPACE_MARKER} s2h written"; else echo "${WORKSPACE_MARKER} s2h failed"; fi`,
    );
  }
  input.files.forEach((file, index) => {
    // An existing file is opened for append and nothing is written; a missing
    // one must not be creatable (no-clobber, so nothing existing is touched).
    lines.push(
      file.missing
        ? `if ( set -C; : > ${quote(file.relative)} ) 2>/dev/null; then echo "${WORKSPACE_MARKER} creatable file ${index}"; fi`
        : `if ( : >> ${quote(file.relative)} ) 2>/dev/null; then echo "${WORKSPACE_MARKER} writable file ${index}"; fi`,
    );
  });
  input.directories.forEach((dir, index) => {
    const probe = `${dir.relative}/.piship-probe-${input.nonce}`;
    lines.push(
      `if ( mkdir -p ${quote(dir.relative)} && : > ${quote(probe)} ) 2>/dev/null; then echo "${WORKSPACE_MARKER} writable dir ${index}"; fi`,
    );
  });
  lines.push(`echo ${WORKSPACE_MARKER} done`);
  return lines.join("\n");
}

/** Missing components of each protected directory, recorded before the check runs. */
function missingChains(
  workspace: string,
  directories: readonly ProtectedTarget[],
): string[][] {
  return directories.map((dir) => {
    const missing: string[] = [];
    for (let depth = 1; depth <= dir.segments.length; depth++) {
      const path = join(workspace, ...dir.segments.slice(0, depth));
      if (!lstatOrUndefined(path)) missing.push(path);
    }
    return missing;
  });
}

/** Remove what the git-control probe may have left: probe files and directories it created. */
function cleanProtected(
  workspace: string,
  directories: readonly ProtectedTarget[],
  missing: readonly string[][],
  nonce: string,
): void {
  directories.forEach((dir, index) => {
    try {
      const path = plainDirectory(workspace, dir.segments, false);
      const probe = join(path, `.piship-probe-${nonce}`);
      if (lstatOrUndefined(probe)) unlinkSync(probe);
    } catch {
      // not there, or not a plain directory: nothing PiShip may remove
    }
    for (const created of [...(missing[index] ?? [])].reverse()) {
      const stat = lstatOrUndefined(created);
      if (!stat || stat.isSymbolicLink() || !stat.isDirectory()) continue;
      try {
        rmdirSync(created);
      } catch {
        // not empty: something else put content there; leave it
      }
    }
  });
}

/**
 * Remove the protected files the check created because the sandbox could:
 * only those that were missing before it ran and are empty regular files
 * now, reached through plain directories.
 */
function cleanCreatedFiles(
  workspace: string,
  files: readonly ProtectedFile[],
): void {
  for (const file of files) {
    if (!file.missing) continue;
    try {
      const parent = plainDirectory(
        workspace,
        file.segments.slice(0, -1),
        false,
      );
      const path = join(parent, file.segments[file.segments.length - 1] ?? "");
      const stat = lstatOrUndefined(path);
      if (stat?.isFile() && stat.size === 0) unlinkSync(path);
    } catch {
      // not there, or not a plain directory: nothing PiShip may remove
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function rfc3339(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function hostToSandbox(lines: readonly string[]): Propagation {
  const line = lines.find((item) =>
    item.startsWith(`${WORKSPACE_MARKER} h2s `),
  );
  const value = line?.slice(`${WORKSPACE_MARKER} h2s `.length);
  if (value === undefined || value === "missing" || !/^\d+$/.test(value))
    return "missing";
  return value === "0" ? "immediate" : "delayed";
}

function lowered(h2s: Propagation, s2h: Propagation): string {
  if (h2s === "missing" && s2h === "missing")
    return "neither side saw the other's changes";
  return h2s === "missing"
    ? "the sandbox did not see host changes"
    : "the host did not see sandbox changes";
}

/**
 * Run the two-way sentinel and the git-control probe through one command.
 * `run` executes a POSIX shell command in the sandbox at the workspace root
 * and resolves with its exit code; it rejects when the command could not run
 * or timed out. `unsafe` is set when the host's git control files could be
 * changed from the sandbox, or the check could not show that they cannot:
 * the caller retires the instance and fails the pending command.
 */
export async function verifyWorkspace(
  run: (command: string, onData: (chunk: Buffer) => void) => Promise<number>,
  ctx: SentinelContext,
): Promise<{ readonly report: WorkspaceReport; readonly unsafe?: string }> {
  const now = ctx.now ?? Date.now;
  const declared = ctx.declaration.mode;
  const windowMs = workspaceWindowMs(ctx.declaration);
  const nonce = randomBytes(16).toString("hex");
  const workspace = ctx.workspace;
  // A protected file that exists as a regular file is appended to; one that
  // does not exist yet is tried for creation. Anything else that exists (a
  // directory, a link) is not a file to probe.
  const files = insideWorkspace(workspace, ctx.protectedPaths.files).flatMap(
    (file): ProtectedFile[] => {
      const stat = lstatOrUndefined(join(workspace, ...file.segments));
      if (!stat) return [{ ...file, missing: true }];
      return stat.isFile() ? [{ ...file, missing: false }] : [];
    },
  );
  const directories = insideWorkspace(
    workspace,
    ctx.protectedPaths.directories,
  );
  let location = sentinelLocation(ctx);
  let sentinelDir: string | undefined;
  let locationSegments: readonly string[] = [];
  let segments: readonly string[] = [];
  const hostToken = randomBytes(16).toString("hex");
  const sandboxToken = randomBytes(16).toString("hex");
  const missing = missingChains(workspace, directories);
  try {
    if ("segments" in location) {
      try {
        plainDirectory(workspace, location.segments, true);
        locationSegments = location.segments;
        sweepStale(workspace, locationSegments, now());
        segments = [...locationSegments, nonce];
        sentinelDir = plainDirectory(workspace, segments, true);
        trackSentinel(workspace, locationSegments, nonce);
        writeNew(join(sentinelDir, "h2s"), hostToken);
      } catch (error) {
        if (sentinelDir) {
          liveSentinels.delete(sentinelDir);
          // Best effort; the stale sweep removes what is left later.
          removeSentinelDirectory(workspace, locationSegments, nonce);
          sentinelDir = undefined;
        }
        location = {
          reason:
            error instanceof LocationError
              ? error.message
              : "PiShip could not create its sentinel directory",
        };
      }
    }
    let output = "";
    let exitCode: number | undefined;
    let runError: string | undefined;
    try {
      exitCode = await run(
        checkScript({
          ...(sentinelDir
            ? {
                sentinel: {
                  dir: segments.join("/"),
                  hostToken,
                  sandboxToken,
                  polls: Math.ceil(windowMs / POLL_MS),
                },
              }
            : {}),
          files,
          directories,
          nonce,
        }),
        (chunk) => {
          if (output.length < OUTPUT_LIMIT) output += chunk.toString("utf8");
        },
      );
    } catch (error) {
      runError = String((error as Error)?.message ?? error);
    }
    const lines = output.split(/\r?\n/).map((line) => line.trim());
    let unsafe: string | undefined;
    if (runError !== undefined)
      unsafe = "the workspace check command did not complete";
    else if (exitCode !== 0 || !lines.includes(`${WORKSPACE_MARKER} done`))
      unsafe = `the workspace check command did not report back (exit ${exitCode})`;
    else if (
      lines.some((line) =>
        line.startsWith(`${WORKSPACE_MARKER} writable file `),
      )
    )
      unsafe = "a protected git control file was writable from the sandbox";
    else if (
      lines.some((line) =>
        line.startsWith(`${WORKSPACE_MARKER} creatable file `),
      )
    )
      unsafe =
        "a protected git control file that does not exist yet could be created from the sandbox";
    else if (
      lines.some((line) => line.startsWith(`${WORKSPACE_MARKER} writable dir `))
    )
      unsafe =
        "a file could be created in a protected git directory from the sandbox";
    let h2s: Propagation = "missing";
    let s2h: Propagation = "missing";
    if (sentinelDir && !unsafe) {
      h2s = hostToSandbox(lines);
      if (lines.includes(`${WORKSPACE_MARKER} s2h written`)) {
        const target = join(sentinelDir, "s2h");
        if (readToken(target) === sandboxToken) s2h = "immediate";
        else {
          const deadline = Date.now() + windowMs;
          while (Date.now() < deadline) {
            await sleep(Math.min(POLL_MS, Math.max(1, deadline - Date.now())));
            if (readToken(target) === sandboxToken) {
              s2h = "delayed";
              break;
            }
          }
        }
      }
    }
    const verifiedAt = rfc3339(now());
    const base = { declared, windowMs, verifiedAt, complete: false } as const;
    if (unsafe)
      return {
        report: {
          ...base,
          effective: "snapshot",
          verification: "failed",
          gitControlProtection: "not-verified",
          reason: unsafe,
        },
        unsafe,
      };
    if (!sentinelDir)
      return {
        report: {
          ...base,
          effective: "snapshot",
          verification: "unverifiable",
          gitControlProtection: "attested-renames",
          reason: "reason" in location ? location.reason : "no location",
        },
      };
    if (h2s === "missing" || s2h === "missing")
      return {
        report: {
          ...base,
          effective: "snapshot",
          verification: "failed",
          hostToSandbox: h2s,
          sandboxToHost: s2h,
          gitControlProtection: "attested-renames",
          reason: lowered(h2s, s2h),
        },
      };
    const effective: WorkspaceMode =
      declared === "shared" && h2s === "immediate" && s2h === "immediate"
        ? "shared"
        : "synchronized";
    return {
      report: {
        ...base,
        effective,
        verification: "verified",
        hostToSandbox: h2s,
        sandboxToHost: s2h,
        gitControlProtection: "attested-renames",
        complete: true,
        ...(effective !== declared
          ? { reason: "a direction was delayed, which a mount would not be" }
          : {}),
      },
    };
  } finally {
    if (sentinelDir) {
      liveSentinels.delete(sentinelDir);
      // The sandbox may have replaced a component with a link while the
      // check ran: nothing is followed, and nothing is deleted recursively.
      removeSentinelDirectory(workspace, locationSegments, nonce);
    }
    cleanProtected(workspace, directories, missing, nonce);
    cleanCreatedFiles(workspace, files);
  }
}

/** The workspace sentence of the containment line, for enforced remote backends. */
export function describeWorkspace(report: WorkspaceReport): string {
  const declared = report.declared;
  switch (report.verification) {
    case "not-required":
      return declared === "snapshot"
        ? "Workspace: snapshot. Remote commands see a copy, not the files the agent edits; this is not a complete coding-agent workspace."
        : "Workspace: shared (commands run on this host's files).";
    case "pending":
      return `Workspace: ${declared} declared, verified before the first sandboxed command.`;
    case "verified": {
      const at = report.verifiedAt ?? "an unknown time";
      if (report.effective === "shared")
        return `Workspace: shared (verified ${at}, both directions immediate).`;
      const was = declared !== "synchronized" ? `declared ${declared}; ` : "";
      return `Workspace: synchronized (${was}verified ${at}, within ${report.windowMs ?? DEFAULT_PROPAGATION_MS} ms).`;
    }
    case "unverifiable":
      return `Workspace: snapshot (declared ${declared}; no PiShip-owned location to verify it: ${report.reason ?? "unknown reason"}).`;
    default:
      return `Workspace: snapshot (declared ${declared}; ${report.reason ?? "the check failed"}). Not a complete coding-agent workspace.`;
  }
}
