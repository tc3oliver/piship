// What a Pi package needs around it at launch, declared in the manifest:
// the environment it reads and the JSON configuration it keeps in Pi's agent
// directory (`resources.packages[].environment` and `.agentFiles`). Both are
// non-secret values from the lock; PiShip sets them before Pi loads the
// package, so a user's shell or an old copy of a file cannot change what the
// distribution declared, except where a file is a `seed` the user has edited.
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { PiShipError, processHostToken } from "@piship/contracts";
import { writeFileAtomic } from "@piship/credentials";
import type {
  AgentFileMode,
  PackageAgentFile,
  PackageEnvironmentValue,
} from "@piship/schema";
import { agentFilesLockHooks } from "./agent-files-hooks.js";
import type { DistributionLock, LockedAgentFile } from "./lock-schema.js";
import {
  recordedIdentity,
  recordedProcessGone,
  recordedStart,
} from "./process-identity.js";

/** The bytes written for a declared file: its JSON in declared key order. */
export function agentFileContent(json: unknown): string {
  return `${JSON.stringify(json, null, 2)}\n`;
}

export function agentFileDigest(content: string): string {
  return `sha256-${createHash("sha256").update(content).digest("hex")}`;
}

/** The lock's record of the declared files. */
export function lockedAgentFiles(
  files: readonly PackageAgentFile[],
): LockedAgentFile[] {
  return files.map((file) => ({
    path: file.path,
    mode: file.mode,
    sha256: agentFileDigest(agentFileContent(file.json)),
  }));
}

// ------------------------------------------------------------ environment

export interface PackageEnvironmentEntry {
  readonly package: string;
  readonly name: string;
  /** What the process gets: the literal, or the resolved state path. */
  readonly value: string;
  /** The declared value, for reports: a state path stays relative. */
  readonly declared: PackageEnvironmentValue;
}

/** Resolve a declared value on this machine. */
function resolveEnvironmentValue(
  value: PackageEnvironmentValue,
  stateDir: string,
): string {
  return typeof value === "string"
    ? value
    : join(stateDir, ...value.statePath.split("/"));
}

/** Every environment variable the lock declares, resolved against `stateDir`. */
export function packageEnvironment(
  lock: Pick<DistributionLock, "packages">,
  stateDir: string,
): PackageEnvironmentEntry[] {
  return (lock.packages ?? []).flatMap((item) =>
    Object.entries(item.environment ?? {}).map(([name, declared]) => ({
      package: item.id,
      name,
      value: resolveEnvironmentValue(declared, stateDir),
      declared,
    })),
  );
}

/**
 * Set the declared variables on `env`. A declared value replaces the one the
 * user's shell had, in every mode: a distribution that declares
 * `PI_BG_FEATURES` declares it for the reason a user cannot undo by exporting
 * another. Called again after a managed launch removed the ambient `PI_*`
 * variables, so a managed value is never one the shell chose.
 */
export function applyPackageEnvironment(
  lock: Pick<DistributionLock, "packages">,
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
): PackageEnvironmentEntry[] {
  const entries = packageEnvironment(lock, stateDir);
  for (const entry of entries) env[entry.name] = entry.value;
  return entries;
}

// ------------------------------------------------------------ agent files

export type AgentFileOutcome =
  /** Written for the first time. */
  | "seeded"
  /** A seed replaced by a newer default, because the user had not edited it. */
  | "updated"
  /** An enforced file rewritten to the declared content. */
  | "enforced"
  /** Already what the lock declares. */
  | "unchanged"
  /** A seed the user edited: kept as it is. */
  | "kept";

export interface AgentFileReport {
  readonly package: string;
  readonly path: string;
  readonly mode: AgentFileMode;
  readonly outcome: AgentFileOutcome;
}

interface SeedState {
  readonly schema: "piship-agent-files/v1";
  /** Digest of what PiShip last wrote, per path. */
  readonly files: Record<string, string>;
  /** A session override that has not been taken back (a crashed launch). */
  readonly override?: SessionOverride;
}

interface SessionOverride {
  readonly owner?: string;
  readonly pid?: number;
  readonly path: string;
  readonly key: string;
  readonly hadKey: boolean;
  readonly original?: unknown;
}

const SEED_STATE = ".piship-agent-files.json";
const SEED_SCHEMA = "piship-agent-files/v1";

function readSeedState(agentDir: string): SeedState {
  try {
    const parsed = JSON.parse(
      readFileSync(join(agentDir, SEED_STATE), "utf8"),
    ) as Partial<SeedState> | null;
    if (
      parsed?.schema === SEED_SCHEMA &&
      parsed.files &&
      typeof parsed.files === "object"
    )
      return {
        schema: SEED_SCHEMA,
        files: { ...parsed.files },
        ...(parsed.override ? { override: parsed.override } : {}),
      };
  } catch {
    // Missing or unreadable: every existing file then counts as the user's.
  }
  return { schema: SEED_SCHEMA, files: {} };
}

function writeSeedState(agentDir: string, state: SeedState): void {
  writeFileAtomic(
    join(agentDir, SEED_STATE),
    `${JSON.stringify(state, null, 2)}\n`,
    { directoryMode: 0o700 },
  );
}

/** A declared file's absolute path, refusing a link anywhere below `agentDir`. */
function filePath(agentDir: string, path: string): string {
  if (
    !path ||
    path.split("/").some((part) => part === ".." || part === "." || !part) ||
    path.startsWith("/") ||
    path.includes("\\")
  )
    throw new PiShipError(
      "CONFIG_INVALID",
      "Invalid package configuration path",
    );
  let current = agentDir;
  for (const segment of path.split("/")) {
    current = join(current, segment);
    if (lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink())
      throw new PiShipError(
        "CONFIG_INVALID",
        `${current} is a link; PiShip does not write package configuration through one`,
        {
          userAction: `Remove the link, or move it aside, and start the distribution again`,
        },
      );
  }
  return current;
}

interface DeclaredFile {
  readonly package: string;
  readonly file: LockedAgentFile;
  readonly content: string;
}

/**
 * The declared files with their content, from the lock: the lock's record of
 * each file is checked against the content in its manifest, so a lock whose
 * parts disagree fails before anything is written.
 */
function declaredFiles(lock: DistributionLock): DeclaredFile[] {
  const declared = lock.governance?.manifest.resources?.packages ?? [];
  const output: DeclaredFile[] = [];
  for (const item of lock.packages ?? []) {
    for (const file of item.agentFiles ?? []) {
      const source = declared
        .find((entry) => entry.id === item.id)
        ?.agentFiles?.find((entry) => entry.path === file.path);
      const content = source ? agentFileContent(source.json) : undefined;
      if (content === undefined || agentFileDigest(content) !== file.sha256)
        throw new PiShipError(
          "LOCK_INVALID",
          `The lock's record of ${file.path} for package ${item.id} does not match the manifest it holds`,
          { userAction: "Run piship lock again and rebuild the distribution" },
        );
      output.push({ package: item.id, file, content });
    }
  }
  return output;
}

/**
 * The key a session-wide auto-approval is switched on with, when the
 * distribution's permission provider declares one: the settings
 * `autoApproveFile` (one of its agent files) and `autoApproveKey` (a top-level
 * boolean of that JSON file) of the `permissions` capability.
 */
export function sessionAutoApproveTarget(
  lock: Pick<DistributionLock, "governance">,
): { readonly path: string; readonly key: string } | undefined {
  const settings = lock.governance?.manifest.capabilities?.find(
    (item) => item.name === "permissions" && item.enabled,
  )?.settings;
  const path = settings?.autoApproveFile;
  const key = settings?.autoApproveKey;
  return path && key ? { path, key } : undefined;
}

function readJsonObject(path: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Put a session override's key back to what the file had before it. */
function takeBack(agentDir: string, override: SessionOverride): void {
  const target = filePath(agentDir, override.path);
  const current = readJsonObject(target);
  if (!current) return;
  // Only the one key: what else the session changed (an extension's own
  // command saving a log setting) stays.
  if (override.hadKey) current[override.key] = override.original;
  else delete current[override.key];
  writeFileAtomic(target, agentFileContent(current), { directoryMode: 0o700 });
}

export interface AgentFilesResult {
  readonly reports: readonly AgentFileReport[];
  /** Undo the session override; idempotent, and a no-op without one. */
  readonly restore: () => void;
  /**
   * End the session's own auto-approval (`/auto off`). Returns a notice when
   * the provider's approvals cannot be switched off yet because another
   * `--yolo` session shares them.
   */
  readonly endAutoApprove?: () => string | undefined;
}

/**
 * Write the lock's agent files into `agentDir`. A `seed` is written when it is
 * absent, and replaced on a later release only while it is still what PiShip
 * last wrote; one the user edited is kept. An `enforce` file is rewritten
 * whenever it differs. `sessionAutoApprove` switches the declared
 * auto-approval key on for this launch only: it is taken back by `restore`,
 * and by the next launch if this one never got to run it.
 */
function applyAgentFilesLocked(
  lock: DistributionLock,
  agentDir: string,
  options: {
    readonly sessionAutoApprove?: boolean;
    readonly session?: boolean;
    readonly owner?: string;
    /**
     * Another live `--yolo` session already switched the provider's key on:
     * this one shares it, takes no override of its own, and leaves the
     * hand-over to the session that owns it.
     */
    readonly share?: boolean;
  } = {},
): AgentFilesResult {
  const files = declaredFiles(lock);
  const target = sessionAutoApproveTarget(lock);
  if (!files.length && !target) return { reports: [], restore: () => {} };
  let state = readSeedState(agentDir);
  if (state.override) {
    // A launch that never reached its end left the override on.
    const live = state.override.pid && liveProcess(state.override.pid);
    if (live && !options.share)
      throw new PiShipError(
        "CONFIG_INVALID",
        "Another live session owns the permission provider auto-approval",
        { userAction: SHARED_PROVIDER_ACTION },
      );
    if (!live) {
      if (
        target &&
        state.override.path === target.path &&
        state.override.key === target.key
      )
        takeBack(agentDir, state.override);
      state = { schema: SEED_SCHEMA, files: state.files };
      writeSeedState(agentDir, state);
    }
  }
  const reports: AgentFileReport[] = [];
  const recorded = { ...state.files };
  for (const { package: owner, file, content } of files) {
    const path = filePath(agentDir, file.path);
    const wanted = file.sha256;
    const exists = existsSync(path);
    const found = exists
      ? agentFileDigest(readFileSync(path, "utf8"))
      : undefined;
    let outcome: AgentFileOutcome;
    if (found === wanted) outcome = "unchanged";
    else if (file.mode === "enforce")
      outcome = found === undefined ? "seeded" : "enforced";
    else if (found === undefined) outcome = "seeded";
    else if (found === state.files[file.path]) outcome = "updated";
    else outcome = "kept";
    if (outcome !== "unchanged" && outcome !== "kept") {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      writeFileAtomic(path, content, { directoryMode: 0o700 });
    }
    // What PiShip last wrote is what a later release may replace unasked.
    if (outcome !== "kept") recorded[file.path] = wanted;
    reports.push({ package: owner, path: file.path, mode: file.mode, outcome });
  }
  let override: SessionOverride | undefined;
  if (options.sessionAutoApprove && options.share && state.override) {
    // The owner's override stays as it is. A file this launch just rewrote
    // (an enforced one) loses the switched-on key, so it is put back.
    if (!target)
      throw new PiShipError(
        "CONFIG_INVALID",
        "This distribution's permission provider declares no session auto-approval (the permissions capability needs the settings autoApproveFile and autoApproveKey)",
        { userAction: "Start the distribution without the option" },
      );
    const path = filePath(agentDir, target.path);
    const current = readJsonObject(path);
    if (current && current[target.key] !== true)
      writeFileAtomic(
        path,
        agentFileContent({ ...current, [target.key]: true }),
        { directoryMode: 0o700 },
      );
    writeSeedState(agentDir, {
      schema: SEED_SCHEMA,
      files: recorded,
      override: state.override,
    });
  } else if (options.sessionAutoApprove) {
    if (!target)
      throw new PiShipError(
        "CONFIG_INVALID",
        "This distribution's permission provider declares no session auto-approval (the permissions capability needs the settings autoApproveFile and autoApproveKey)",
        { userAction: "Start the distribution without the option" },
      );
    const path = filePath(agentDir, target.path);
    const current = readJsonObject(path);
    if (!current)
      throw new PiShipError(
        "CONFIG_INVALID",
        `${target.path} is not a JSON object, so the session auto-approval cannot be switched on`,
        { userAction: "Fix or remove the file and start again" },
      );
    override = {
      ...(options.owner ? { owner: options.owner } : {}),
      pid: process.pid,
      path: target.path,
      key: target.key,
      hadKey: target.key in current,
      ...(target.key in current ? { original: current[target.key] } : {}),
    };
    writeSeedState(agentDir, {
      schema: SEED_SCHEMA,
      files: recorded,
      override,
    });
    writeFileAtomic(
      path,
      agentFileContent({ ...current, [target.key]: true }),
      { directoryMode: 0o700 },
    );
  } else if (files.length)
    writeSeedState(agentDir, { schema: SEED_SCHEMA, files: recorded });
  let restored = false;
  return {
    reports,
    restore: () => {
      if (restored || !override) return;
      const currentState = readSeedState(agentDir);
      if (currentState.override?.owner !== override.owner) return;
      takeBack(agentDir, override);
      writeSeedState(agentDir, {
        schema: SEED_SCHEMA,
        files: currentState.files,
      });
      restored = true;
    },
  };
}

/** What to do about a session that cannot share the permission provider. */
const SHARED_PROVIDER_ACTION =
  "Close the other session, or start this one the same way (both with --yolo, or neither): the permission provider reads one settings file";

/**
 * The live `--yolo` sessions other than `except` that still want the
 * provider's auto-approval: not one that already ran `/auto off`.
 */
function liveYoloSessions(
  agentDir: string,
  except: string,
): { owner: string; pid: number }[] {
  const dir = filePath(agentDir, ".piship-provider-sessions");
  if (!existsSync(dir)) return [];
  const sessions: { owner: string; pid: number }[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === except) continue;
    const lease = readJsonObject(
      filePath(agentDir, `.piship-provider-sessions/${entry}`),
    );
    if (
      lease &&
      typeof lease.pid === "number" &&
      lease.yolo === true &&
      lease.ended !== true &&
      liveProcess(lease.pid)
    )
      sessions.push({ owner: entry, pid: lease.pid });
  }
  return sessions;
}

function liveProcess(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

// Serialize the registration and configuration change, so two launches cannot
// both decide the shared provider file is free. Sessions keep separate leases.
const BUSY_MESSAGE =
  "Package configuration is being changed by another launch; retry when it finishes";
/**
 * Another launch holds the transaction. A class of its own, so the wait
 * below recognizes the condition by what it is and not by its message; it
 * reports as `CONFIG_INVALID` with the same message as it always did.
 */
class AgentFilesBusyError extends PiShipError {
  constructor() {
    super("CONFIG_INVALID", BUSY_MESSAGE);
  }
}
/** How long a session launch waits for another launch's transaction. */
export const AGENT_FILES_LOCK_WAIT_MS = 3000;
/**
 * A lock directory with no readable owner this old was left by a launch that
 * died between creating it and recording itself (a write takes milliseconds).
 */
export const AGENT_FILES_OWNERLESS_STALE_MS = 10_000;

// ponytail: a synchronous wait, since the launch path is synchronous; the
// holder only keeps the lock for one small file edit.
function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Parallel session launches (a subagent's children) meet here at once: they
// wait out a busy lock for `waitMs`, then report the same error as before.
// The wait backs off with jitter so that they do not retry in step, and it
// never runs past the budget; with none (a launch that is not a session) the
// first busy answer is the error.
function agentFilesTransaction<T>(
  agentDir: string,
  operation: () => T,
  waitMs: number,
): T {
  const deadline = Date.now() + waitMs;
  for (let attempt = 0; ; attempt += 1) {
    try {
      return agentFilesTransactionOnce(agentDir, operation);
    } catch (error) {
      const left = deadline - Date.now();
      if (!(error instanceof AgentFilesBusyError) || left <= 0) throw error;
      const ceiling = Math.min(20 * 2 ** attempt, 400);
      pause(Math.min(left, ceiling / 2 + Math.random() * (ceiling / 2)));
    }
  }
}

/** Whether `path` was last changed more than `ms` ago; false if it is gone. */
function olderThan(path: string, ms: number): boolean {
  try {
    return Date.now() - statSync(path).mtimeMs > ms;
  } catch {
    return false;
  }
}

/** What a lock's `owner.json` says about the launch that holds it. */
interface LockOwner {
  readonly pid: number;
  /** Random per claim: tells this holder's lock from a later holder's at the same path. */
  readonly token: string | null;
  /** The holder's start identity and time, and host (absent in an older release's record). */
  readonly identity: string | null;
  readonly started: number | null;
  readonly host: string | null;
}

const rename = (from: string, to: string) =>
  (agentFilesLockHooks.rename ?? renameSync)(from, to);
const removeTree = (path: string) =>
  (
    agentFilesLockHooks.rm ??
    ((target) => rmSync(target, { recursive: true, force: true }))
  )(path);

/**
 * Takes the lock with its owner record already inside: the record is written
 * in a directory of its own, which one rename puts at the lock's path, so no
 * other launch can see a lock that its holder is still filling. Returns the
 * record, or false when the lock is held (the rename cannot replace a
 * directory that has an owner record in it).
 */
function claim(guard: string): LockOwner | false {
  for (let attempt = 0; ; attempt += 1) {
    // POSIX renames over an empty directory; one without an owner record (an
    // older release's, still being filled) is not ours to replace.
    if (existsSync(guard)) return false;
    const held: LockOwner = {
      pid: process.pid,
      token: randomUUID(),
      identity: recordedIdentity(),
      started: recordedStart(),
      host: processHostToken(),
    };
    const staging = `${guard}.${randomUUID()}.new`;
    mkdirSync(staging, { mode: 0o700 });
    try {
      writeFileSync(join(staging, "owner.json"), JSON.stringify(held), {
        mode: 0o600,
        flag: "wx",
      });
      rename(staging, guard);
      return held;
    } catch (error) {
      rmSync(staging, { recursive: true, force: true });
      // Held by another launch (a holder that let go in the meantime is found
      // on the next attempt).
      const code = (error as NodeJS.ErrnoException).code;
      if (
        existsSync(guard) ||
        code === "ENOTEMPTY" ||
        code === "EEXIST" ||
        // Windows: a directory cannot be renamed onto an existing one, or
        // while another process (or a scanner) has a handle inside it.
        code === "EPERM" ||
        code === "EACCES" ||
        code === "EBUSY"
      )
        return false;
      // The staging directory was swept (it looked abandoned): once more,
      // then the lock is simply busy.
      if (code === "ENOENT") {
        if (attempt === 0) continue;
        throw new AgentFilesBusyError();
      }
      throw error;
    }
  }
}

/**
 * The owner record of a lock; "missing" when there is none (or it is not
 * readable as one); "unknown" when reading it failed for any reason but
 * absence, so the holder cannot be told dead.
 */
function readOwner(path: string): LockOwner | "missing" | "unknown" {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? "missing"
      : "unknown";
  }
  try {
    const value = JSON.parse(text) as Record<string, unknown> | null;
    if (typeof value?.pid !== "number") return "missing";
    const text_ = (field: string) =>
      typeof value[field] === "string" ? (value[field] as string) : null;
    return {
      pid: value.pid,
      token: text_("token"),
      identity: text_("identity"),
      started: typeof value.started === "number" ? value.started : null,
      host: text_("host"),
    };
  } catch {
    return "missing";
  }
}

/**
 * Whether the process a record names still runs and is the one that wrote
 * it: a process ID that exists may belong to an unrelated process that was
 * given it after the holder died, which the start identity (or time) tells.
 * An older record without them is as live as its process ID.
 */
function holderRuns(owner: LockOwner): boolean {
  if (!liveProcess(owner.pid)) return false;
  // A waiter asks again at every retry. Where the answer costs a process
  // (Windows starts PowerShell for a start time), asking again and again for
  // the same holder would starve the holder it waits for; a holder found
  // running is taken to run for HOLDER_CHECK_REUSE_MS.
  const now = Date.now();
  const key = owner.token === null ? null : `${owner.pid}:${owner.token}`;
  const seen = key === null ? undefined : holdersSeenRunning.get(key);
  if (seen !== undefined && now - seen < HOLDER_CHECK_REUSE_MS) return true;
  const runs =
    recordedProcessGone({
      pid: owner.pid,
      identity: owner.identity,
      host: owner.host,
      started: owner.started,
    }) !== true;
  if (runs && key !== null) {
    if (holdersSeenRunning.size > 64) holdersSeenRunning.clear();
    holdersSeenRunning.set(key, now);
  }
  return runs;
}

/** How long a holder found running is not looked up again (ms). */
const HOLDER_CHECK_REUSE_MS = 1000;
const holdersSeenRunning = new Map<string, number>();

const sameOwner = (
  found: LockOwner | "missing" | "unknown",
  expected: LockOwner | "missing",
) =>
  expected === "missing"
    ? found === "missing"
    : typeof found === "object" &&
      found.pid === expected.pid &&
      found.token === expected.token;

/**
 * Takes a lock down: the owner is read in place first and the lock is only
 * moved if it is the one expected, then it is renamed away (so that only one
 * process does it) and the owner is read once more from the renamed
 * directory; a lock that is not the expected owner's is never removed, and is
 * put back if it was moved. "gone" when nothing was there; "changed" when it
 * was another owner's; "unknown" when the owner could not be read (a scanner
 * holding the file on Windows), which says nothing about whose it is. A
 * rename that fails for another reason throws.
 */
function takeDown(
  path: string,
  expected: LockOwner | "missing",
): "removed" | "changed" | "gone" | "unknown" {
  if (!existsSync(path)) return "gone";
  const before = readOwner(join(path, "owner.json"));
  if (before === "unknown") return "unknown";
  if (!sameOwner(before, expected)) return "changed";
  const away = `${path}.${randomUUID()}.stale`;
  try {
    rename(path, away);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "gone";
    throw error;
  }
  const found = readOwner(join(away, "owner.json"));
  if (!sameOwner(found, expected)) {
    try {
      // Only where nothing took the path since (a rename over an empty
      // directory would replace it).
      if (!existsSync(path)) rename(away, path);
    } catch {
      // The displaced holder lost its lock to a newer one; its release finds
      // the lock is no longer its own and leaves it alone.
    }
    return found === "unknown" ? "unknown" : "changed";
  }
  try {
    removeTree(away);
  } catch {
    // Moved out of the way; a later takeover sweeps what is left.
  }
  return "removed";
}

/**
 * Removes a recovery directory a launch that died left: renamed away so that
 * one process does it, and put back when it turns out not to be old (unless
 * a fresh one has been made since, which is then the other launch's).
 */
function discardRecovery(path: string): void {
  const away = `${path}.${randomUUID()}.stale`;
  try {
    rename(path, away);
  } catch {
    return;
  }
  if (!olderThan(away, AGENT_FILES_OWNERLESS_STALE_MS))
    try {
      if (!existsSync(path)) {
        rename(away, path);
        return;
      }
    } catch {
      // Something else is there now: this one is removed below.
    }
  try {
    removeTree(away);
  } catch {
    // swept later
  }
}

/** Marks the recovery directory as in use, so that a slow recoverer does not look dead. */
function touch(path: string): void {
  try {
    const now = new Date();
    utimesSync(path, now, now);
  } catch {
    // gone: the next check finds out
  }
}

/**
 * Lets go of the lock this launch holds. The rename is retried (on Windows
 * a scanner holding the directory fails it for a moment, or hides the owner
 * record), then the lock is removed in place; only if both fail is the error
 * surfaced, since a lock left behind with a live holder blocks every later
 * launch.
 */
function release(guard: string, held: LockOwner): void {
  agentFilesLockHooks.beforeRelease?.();
  const ownerFile = join(guard, "owner.json");
  let failure: unknown;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      // Gone or another owner's: nothing of ours to remove.
      if (takeDown(guard, held) !== "unknown") return;
    } catch (error) {
      failure = error;
    }
    pause(20 * 2 ** attempt);
  }
  try {
    const found = readOwner(ownerFile);
    if (found === "unknown") throw new Error("the owner record is unreadable");
    if (sameOwner(found, held)) removeTree(guard);
    return;
  } catch (error) {
    throw new PiShipError(
      "CONFIG_INVALID",
      "The package configuration lock could not be released",
      {
        userAction: `Close any program that holds ${guard} open, then delete that directory`,
        cause: failure ?? error,
      },
    );
  }
}

/** Staging and discarded directories a process that died left beside the lock. */
function sweepStaging(agentDir: string): void {
  for (const entry of readdirSync(agentDir)) {
    if (
      !/^\.piship-agent-files-(?:lock|recovery)\..*\.(?:new|stale)$/.test(entry)
    )
      continue;
    const path = join(agentDir, entry);
    if (olderThan(path, AGENT_FILES_OWNERLESS_STALE_MS))
      rmSync(path, { recursive: true, force: true });
  }
}

function agentFilesTransactionOnce<T>(agentDir: string, operation: () => T): T {
  mkdirSync(agentDir, { recursive: true, mode: 0o700 });
  const guard = filePath(agentDir, ".piship-agent-files-lock");
  const recovery = filePath(agentDir, ".piship-agent-files-recovery");
  const busy = () => new AgentFilesBusyError();
  if (existsSync(recovery)) {
    // A recovery that never finished (its process died) must not block for good.
    if (!olderThan(recovery, AGENT_FILES_OWNERLESS_STALE_MS)) throw busy();
    // Only one process wins the rename; the age is looked at again after it.
    discardRecovery(recovery);
  }
  let held = claim(guard);
  if (!held) {
    try {
      mkdirSync(recovery, { mode: 0o700 });
    } catch {
      throw busy();
    }
    try {
      const holder = readOwner(join(guard, "owner.json"));
      agentFilesLockHooks.afterOwnerRead?.();
      if (holder === "unknown") {
        // Unreadable for a reason other than absence (a scanner holding it
        // open on Windows): its holder may be alive. Not ours to take.
        throw busy();
      }
      if (typeof holder === "object") {
        if (holderRuns(holder)) throw busy();
      } else if (!olderThan(guard, AGENT_FILES_OWNERLESS_STALE_MS)) {
        // No owner record: one an older release was still writing, or gone.
        throw busy();
      }
      // The check above can be slow (a process lookup that starts a process);
      // the recovery directory is marked as in use again before the lock is
      // touched, so that it does not look abandoned to a launch that waited.
      touch(recovery);
      agentFilesLockHooks.afterHolderCheck?.();
      // Every acquirer checks recovery after recording its live owner, so no
      // newcomer can mutate the config while this dead directory is removed.
      // The lock that is taken down is the one that was read: if a stalled
      // recovery lets another holder in meanwhile, that one is put back.
      let outcome: ReturnType<typeof takeDown>;
      try {
        outcome = takeDown(guard, holder);
      } catch {
        throw busy();
      }
      if (outcome === "changed" || outcome === "unknown") throw busy();
      sweepStaging(agentDir);
    } finally {
      rmSync(recovery, { recursive: true, force: true });
    }
    held = claim(guard);
    if (!held) throw busy();
  }
  try {
    if (existsSync(recovery)) throw busy();
    try {
      return operation();
    } catch (error) {
      if (error instanceof PiShipError) throw error;
      throw new PiShipError(
        "CONFIG_INVALID",
        "The distribution package configuration could not be updated",
        {
          userAction:
            "Check permissions and file types in the distribution agent directory",
        },
      );
    }
  } finally {
    // Renamed away whole, never emptied in place: a directory with its owner
    // record taken out would be one a rename can replace.
    release(guard, held);
  }
}

export function applyAgentFiles(
  lock: DistributionLock,
  agentDir: string,
  options: {
    readonly sessionAutoApprove?: boolean;
    readonly session?: boolean;
    /** Test hook: how long a session launch waits for a busy lock. */
    readonly lockWaitMs?: number;
  } = {},
): AgentFilesResult {
  if (
    !(lock.packages ?? []).some((item) => item.agentFiles?.length) &&
    !sessionAutoApproveTarget(lock)
  )
    return { reports: [], restore: () => {} };
  const owner = randomUUID();
  const leases = filePath(agentDir, ".piship-provider-sessions");
  let registered = false;
  const waitMs = options.session
    ? (options.lockWaitMs ?? AGENT_FILES_LOCK_WAIT_MS)
    : 0;
  const result = agentFilesTransaction(
    agentDir,
    () => {
      const target = sessionAutoApproveTarget(lock);
      let share = false;
      if (target && (options.session || options.sessionAutoApprove)) {
        mkdirSync(leases, { recursive: true, mode: 0o700 });
        for (const entry of readdirSync(leases)) {
          const path = filePath(agentDir, `.piship-provider-sessions/${entry}`);
          const lease = readJsonObject(path);
          if (!lease || typeof lease.pid !== "number")
            throw new PiShipError(
              "CONFIG_INVALID",
              "Invalid permission provider session ownership record",
              { userAction: SHARED_PROVIDER_ACTION },
            );
          if (!liveProcess(lease.pid)) {
            rmSync(path);
            continue;
          }
          // The provider reads one file, so a `--yolo` session and an ordinary
          // one cannot both have what they asked for. Two `--yolo` sessions
          // want the same thing and share the key.
          const wants = options.sessionAutoApprove === true;
          if (wants && lease.yolo === true) share = true;
          if (wants === (lease.yolo === true)) continue;
          throw new PiShipError(
            "CONFIG_INVALID",
            options.sessionAutoApprove
              ? "Another session is using the permission provider, whose own approvals --yolo switches on for every session"
              : "A --yolo session is using the permission provider, whose own approvals it switched on for every session",
            { userAction: SHARED_PROVIDER_ACTION },
          );
        }
      }
      const applied = applyAgentFilesLocked(lock, agentDir, {
        ...options,
        owner,
        share,
      });
      if (target && (options.session || options.sessionAutoApprove)) {
        writeFileSync(
          join(leases, owner),
          JSON.stringify({
            pid: process.pid,
            yolo: options.sessionAutoApprove === true,
          }),
          { mode: 0o600, flag: "wx" },
        );
        registered = true;
      }
      return applied;
    },
    waitMs,
  );
  let ended = false;
  const leasePath = () =>
    filePath(agentDir, `.piship-provider-sessions/${owner}`);
  /**
   * Give the key to the next live `--yolo` session that still wants it, and
   * report whether there was one; without one, the key is put back.
   */
  const handOverOrTakeBack = (): boolean => {
    const state = readSeedState(agentDir);
    const target = sessionAutoApproveTarget(lock);
    if (
      state.override?.owner !== owner ||
      !target ||
      state.override.path !== target.path ||
      state.override.key !== target.key
    )
      return false;
    const heir = liveYoloSessions(agentDir, owner)[0];
    if (heir) {
      writeSeedState(agentDir, {
        ...state,
        override: { ...state.override, owner: heir.owner, pid: heir.pid },
      });
      return true;
    }
    takeBack(agentDir, state.override);
    return false;
  };
  return {
    reports: result.reports,
    endAutoApprove: () => {
      if (ended) return undefined;
      return agentFilesTransaction(
        agentDir,
        () => {
          const handedOver = handOverOrTakeBack();
          // The lease stays, so a provider's stale save is still restored at
          // exit; it stops counting as a session that wants the key.
          if (registered)
            writeFileSync(
              leasePath(),
              JSON.stringify({ pid: process.pid, yolo: true, ended: true }),
              { mode: 0o600 },
            );
          // A session that shares the key, or hands it on, cannot switch the
          // provider's approvals off for itself without ending the other's.
          return handedOver || liveYoloSessions(agentDir, owner).length > 0
            ? "The permission provider's own approvals stay on until the other --yolo session ends."
            : undefined;
        },
        waitMs,
      );
    },
    restore: () => {
      if (ended) return;
      agentFilesTransaction(
        agentDir,
        () => {
          handOverOrTakeBack();
          result.restore();
          if (registered)
            rmSync(filePath(agentDir, `.piship-provider-sessions/${owner}`), {
              force: true,
            });
          ended = true;
        },
        waitMs,
      );
    },
  };
}

export type AgentFileState =
  /** The file is what the lock declares. */
  | "current"
  /** A seed the user edited; kept at launch. */
  | "edited"
  /** Missing, or an enforced file that differs: a launch rewrites it. */
  | "pending";

export interface AgentFileStatus {
  readonly package: string;
  readonly path: string;
  readonly mode: AgentFileMode;
  readonly state: AgentFileState;
}

/** Read-only form of `applyAgentFiles`, for `doctor`. */
export function inspectAgentFiles(
  lock: DistributionLock,
  agentDir: string,
): AgentFileStatus[] {
  const seeds = readSeedState(agentDir);
  return declaredFiles(lock).map(({ package: owner, file }) => {
    const path = join(agentDir, ...file.path.split("/"));
    const found = existsSync(path)
      ? agentFileDigest(readFileSync(path, "utf8"))
      : undefined;
    const state: AgentFileState =
      found === file.sha256
        ? "current"
        : found !== undefined &&
            file.mode === "seed" &&
            found !== seeds.files[file.path]
          ? "edited"
          : "pending";
    return { package: owner, path: file.path, mode: file.mode, state };
  });
}
