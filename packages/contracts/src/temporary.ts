// PiShip-owned temporary directories and their recovery after a hard
// termination. Every directory a PiShip workflow makes for temporary work (a
// verified release's extraction, throwaway launch-check state, a session's
// sandbox temp, build and release staging, install and update staging) is
// created here, with an ownership marker written before anything else. A
// `finally`, `dispose()`, or `exit` hook removes it in the normal case; none
// of them runs after SIGKILL, a machine reset, or power loss, so a later
// PiShip process removes what a dead owner left.
//
// The marker (`.piship-owner`, 0600, in the directory, which is 0700) is one
// JSON record: the owner's process ID, a random instance ID, a host token,
// the directory's name and kind, and the creation time. It is the only proof
// of ownership. What is reclaimed, and when:
//
// - Only a directory that has the exact name shape of its kind (the kind's
//   prefix and mkdtemp's six characters), is a real directory (never a link),
//   belongs to the current user, is on the same filesystem as the directory
//   that holds it, and carries a valid marker naming that same directory and
//   kind. Anything else sharing a prefix is never touched.
// - The owner is gone when its process no longer exists on this host: the
//   directory is removed at once. Where the host cannot be told (another
//   machine or container sharing the directory) or the process ID exists, the
//   directory stays while the marker is fresh. A live owner refreshes the
//   marker's modification time (`TEMPORARY_HEARTBEAT_MS`), so it is never
//   older than the lease for a process that is running; a marker not
//   refreshed for `TEMPORARY_LEASE_MS` belongs to a process whose ID another,
//   unrelated process took after a crash (or to a machine that is not this
//   one), and is reclaimed. Same trade as the lifecycle lock: a machine that
//   sleeps for more than the lease while its owner cannot refresh, or a clock
//   that jumps forward by more, displaces a live owner's directory.
// - A directory this process itself holds is never reclaimed, whatever the
//   marker says.
//
// Trust. The marker is not authenticated: a process that can write a
// directory can write a marker into it, for a dead owner or an old date,
// including a sandboxed command in any directory the sandbox lets it write.
// So a marker only selects a directory of PiShip's own name shape for
// removal, and two things keep that from reaching anything outside it:
// callers sweep only roots such a command cannot write (the OS temp
// directory, the install home, `apps/<id>`; build and release output roots,
// which lie in the workspace, are swept only when the user asks), and the
// removal verifies identity, not names (`removeAbandoned`): the directory
// is moved to a fresh name, found to be the same real directory (device and
// inode) it was judged to be, and removed by `rm` (or, where there is none,
// by a walk that never reads a path it has not just examined), never by a
// path that can be swapped for a link after it was checked.
//
// Directories made before markers existed have none and are never removed,
// however old: nothing tells them from a live older PiShip's session (a
// sandbox session can run for days) or from a user's directory that happens
// to have the same six-character shape, and deleting either cannot be undone.
// They can be deleted by hand.
//
// A process killed in the instant between creating a directory and writing
// its marker leaves an empty directory, which is not reclaimed for the same
// reason. A marker that cannot be read, parsed, or that names another
// directory keeps the directory too.
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  readSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
  writeSync,
  type Stats,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

export const TEMPORARY_OWNER_FILE = ".piship-owner";
export const TEMPORARY_OWNER_SCHEMA = "piship-temporary-owner/v1";
/**
 * A marker not refreshed for this long is abandoned even when a process with
 * its owner's ID exists: 24 hours. It only has to recover a crashed owner
 * whose ID an unrelated process took, so it is far above any step that
 * blocks the refresh (a launch check runs for up to five minutes) and above
 * the clock corrections and sleeps a running owner sees.
 */
export const TEMPORARY_LEASE_MS = 24 * 60 * 60_000;
/** A held directory's marker is refreshed this often (an unref'd timer). */
export const TEMPORARY_HEARTBEAT_MS = 15 * 60_000;
/** Retries of a removal that fails for a moment (EBUSY, EPERM, ENOTEMPTY), with a growing wait. */
const REMOVE_RETRIES = 5;
const REMOVE_RETRY_MS = 50;
/** A marker is a few hundred bytes; a larger file is not one. */
const MARKER_LIMIT = 4096;

/**
 * What a directory is for; the name shape and the root it lives in follow.
 *
 * - `sandbox`, `probe`, `verify`, `launch-check`, `release-test`: under the
 *   OS temp directory (a probe also beside the workspace-outside locations
 *   the sandbox probe checks).
 * - `build`, `release`: staging beside the output of `piship build` and
 *   `piship release`.
 * - `staging`: `.staging-*` under the install home and under `apps/<id>`.
 */
export type TemporaryKind =
  | "sandbox"
  | "probe"
  | "verify"
  | "launch-check"
  | "release-test"
  | "build"
  | "release"
  | "staging";

interface Shape {
  /** The name up to mkdtemp's random suffix. */
  readonly prefix: (label: string | undefined) => string;
  /** Every name the prefix can produce. */
  readonly name: RegExp;
  /** What the label of a kind whose name carries one may be. */
  readonly label?: RegExp;
}

const RANDOM = "[A-Za-z0-9]{6}";
const SHAPES: Record<TemporaryKind, Shape> = {
  sandbox: {
    prefix: () => "piship-sandbox-",
    name: new RegExp(`^piship-sandbox-${RANDOM}$`),
  },
  probe: {
    prefix: () => ".piship-probe-",
    name: new RegExp(`^\\.piship-probe-${RANDOM}$`),
  },
  verify: {
    prefix: () => "piship-verify-",
    name: new RegExp(`^piship-verify-${RANDOM}$`),
  },
  "launch-check": {
    prefix: () => "piship-launch-check-",
    name: new RegExp(`^piship-launch-check-${RANDOM}$`),
  },
  "release-test": {
    prefix: () => "piship-release-test-",
    name: new RegExp(`^piship-release-test-${RANDOM}$`),
  },
  // `.piship-<distribution id>-XXXXXX`
  build: {
    prefix: (label) => `.piship-${label}-`,
    name: new RegExp(`^\\.piship-[a-z][a-z0-9-]*-${RANDOM}$`),
    label: /^[a-z][a-z0-9-]*$/,
  },
  // `.piship-release-<distribution id>-XXXXXX`; the label stays open to the
  // longer names an earlier layout used, which it still recognises.
  release: {
    prefix: (label) => `.piship-release-${label}-`,
    name: new RegExp(
      `^\\.piship-release-[A-Za-z0-9][A-Za-z0-9._+-]*-${RANDOM}$`,
    ),
    label: /^[A-Za-z0-9][A-Za-z0-9._+-]*$/,
  },
  staging: {
    prefix: () => ".staging-",
    name: new RegExp(`^\\.staging-${RANDOM}$`),
  },
};

function isKind(value: unknown): value is TemporaryKind {
  return typeof value === "string" && Object.hasOwn(SHAPES, value);
}

/** The record in a directory's marker. */
export interface TemporaryOwner {
  readonly schema: typeof TEMPORARY_OWNER_SCHEMA;
  readonly kind: TemporaryKind;
  /** The directory's own name: a marker copied elsewhere owns nothing. */
  readonly name: string;
  readonly pid: number;
  /** Random per directory; what tells this owner from a later one of the same ID. */
  readonly instance: string;
  /** Names the machine and PID namespace: a process ID means something only there. */
  readonly host: string;
  readonly created: string;
}

/** Whether a process with this ID exists (EPERM: it exists, not ours). */
export function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

let cachedHost: string | undefined;
/**
 * A token for this machine's process IDs: the host name (the convention the
 * audit rotation lock uses) and, on Linux, the PID namespace, since a
 * container sharing a bind mount and a host name still has other IDs.
 */
function hostToken(): string {
  if (cachedHost === undefined) {
    let namespace = "";
    try {
      namespace = readlinkSync("/proc/self/ns/pid");
    } catch {
      // Not Linux, or no /proc.
    }
    cachedHost = createHash("sha256")
      .update(`${hostname()}\0${namespace}`)
      .digest("hex")
      .slice(0, 12);
  }
  return cachedHost;
}

function ownedByCurrentUser(stat: Stats): boolean {
  return process.getuid === undefined || stat.uid === process.getuid();
}

/** What every directory this process holds shares, across module copies. */
interface Registry {
  /** Instance ID to the marker's path. */
  readonly held: Map<string, string>;
  timer: NodeJS.Timeout | undefined;
}
const REGISTRY = Symbol.for("piship.temporary-directories");
function registry(): Registry {
  const shared = globalThis as { [REGISTRY]?: Registry };
  shared[REGISTRY] ??= { held: new Map(), timer: undefined };
  return shared[REGISTRY];
}

/** Set the modification time of the marker at `marker` if it is still ours. */
function refresh(instance: string, marker: string): void {
  try {
    if (readMarker(marker)?.owner.instance !== instance) return;
    const now = new Date();
    utimesSync(marker, now, now);
  } catch {
    // Retried on the next beat.
  }
}

function hold(instance: string, marker: string): void {
  const state = registry();
  state.held.set(instance, marker);
  if (state.timer) return;
  state.timer = setInterval(() => {
    for (const [held, path] of state.held) refresh(held, path);
  }, TEMPORARY_HEARTBEAT_MS);
  state.timer.unref?.();
}

function release(instance: string): void {
  const state = registry();
  state.held.delete(instance);
  if (state.held.size === 0 && state.timer) {
    clearInterval(state.timer);
    state.timer = undefined;
  }
}

/** A temporary directory this process created and still owns. */
export interface TemporaryDirectory {
  readonly path: string;
  /** The instance ID its marker records. */
  readonly instance: string;
  /**
   * Remove the directory and stop refreshing its marker. Idempotent and best
   * effort: it retries what a scanner or another process's open handle makes
   * fail for a moment (on Windows an open handle blocks the removal of a
   * directory), and when the directory still cannot be removed it returns
   * false rather than throwing, because the operation it belonged to is done
   * and a scratch directory must not fail it. What is left is reclaimed by a
   * later process once this one is gone.
   */
  remove(): boolean;
}

/**
 * Create a private (0700) temporary directory of `kind` in `parent`, with its
 * marker (0600) written before anything else. `label` completes the name of
 * the kinds that carry one (`build`: the distribution ID; `release`: the
 * distribution ID). A failure to write the marker removes the directory and
 * throws: an unmarked directory would never be recovered.
 */
export function createTemporaryDirectory(
  parent: string,
  kind: TemporaryKind,
  label?: string,
): TemporaryDirectory {
  const shape = SHAPES[kind];
  if (shape.label && !(label !== undefined && shape.label.test(label)))
    throw new Error(`Invalid label for a ${kind} temporary directory`);
  const path = mkdtempSync(join(parent, shape.prefix(label)));
  const instance = randomBytes(8).toString("hex");
  const marker = join(path, TEMPORARY_OWNER_FILE);
  try {
    const record: TemporaryOwner = {
      schema: TEMPORARY_OWNER_SCHEMA,
      kind,
      name: basename(path),
      pid: process.pid,
      instance,
      host: hostToken(),
      created: new Date().toISOString(),
    };
    // `wx` never follows or replaces an existing entry; the record is one
    // small write.
    const fd = openSync(marker, "wx", 0o600);
    try {
      writeSync(fd, `${JSON.stringify(record)}\n`);
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    rmSync(path, { recursive: true, force: true });
    throw error;
  }
  hold(instance, marker);
  let removed = false;
  return {
    path,
    instance,
    remove() {
      if (removed) return true;
      release(instance);
      try {
        rmSync(path, {
          recursive: true,
          force: true,
          maxRetries: REMOVE_RETRIES,
          retryDelay: REMOVE_RETRY_MS,
        });
      } catch {
        return false;
      }
      removed = true;
      return true;
    },
  };
}

function parseOwner(text: string): TemporaryOwner | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (
    record.schema !== TEMPORARY_OWNER_SCHEMA ||
    !isKind(record.kind) ||
    typeof record.name !== "string" ||
    !Number.isSafeInteger(record.pid) ||
    (record.pid as number) <= 0 ||
    typeof record.instance !== "string" ||
    !/^[0-9a-f]{16}$/.test(record.instance) ||
    typeof record.host !== "string" ||
    !/^[0-9a-f]{12}$/.test(record.host) ||
    typeof record.created !== "string" ||
    Number.isNaN(Date.parse(record.created))
  )
    return undefined;
  return record as unknown as TemporaryOwner;
}

/**
 * The marker at `path` and its modification time, or undefined unless it is
 * a small regular file of the current user with a valid record. Never
 * follows a link.
 */
function readMarker(
  path: string,
): { owner: TemporaryOwner; mtimeMs: number; text: string } | undefined {
  let fd: number | undefined;
  try {
    const entry = lstatSync(path);
    if (!entry.isFile() || !ownedByCurrentUser(entry)) return undefined;
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.size > MARKER_LIMIT ||
      !ownedByCurrentUser(stat) ||
      (process.platform !== "win32" &&
        (stat.ino !== entry.ino || stat.dev !== entry.dev))
    )
      return undefined;
    const buffer = Buffer.alloc(stat.size);
    let read = 0;
    while (read < buffer.length) {
      const count = readSync(fd, buffer, read, buffer.length - read, read);
      if (count === 0) break;
      read += count;
    }
    const text = buffer.subarray(0, read).toString("utf8");
    const owner = parseOwner(text);
    return owner ? { owner, mtimeMs: stat.mtimeMs, text } : undefined;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined)
      try {
        closeSync(fd);
      } catch {
        // Nothing more to release.
      }
  }
}

/** The owner a directory's marker records and when it was last refreshed. */
export function readTemporaryOwner(
  directory: string,
): { owner: TemporaryOwner; mtimeMs: number } | undefined {
  const marker = readMarker(join(directory, TEMPORARY_OWNER_FILE));
  return marker && { owner: marker.owner, mtimeMs: marker.mtimeMs };
}

/** Whether the owner of a directory last refreshed at `mtimeMs` is gone. */
function abandoned(owner: TemporaryOwner, mtimeMs: number, now: number) {
  if (registry().held.has(owner.instance)) return false;
  if (owner.host === hostToken() && !processAlive(owner.pid)) return true;
  return now - mtimeMs > TEMPORARY_LEASE_MS;
}

/** What a directory keeps when its name is swapped for another entry. */
export interface DirectoryIdentity {
  readonly dev: number;
  readonly ino: number;
}

/**
 * A directory judged abandoned, with the identity it had then. Removal acts
 * only on an entry that still has it.
 */
export interface AbandonedDirectory extends DirectoryIdentity {
  readonly path: string;
  /** Undefined for a directory a removal that was killed left half done. */
  readonly kind: TemporaryKind | undefined;
  /** The marker as read, written back when a removal stops half way; empty when there is none. */
  readonly marker: string;
}

/** The steps of a removal a test can act between (see `ReclaimOptions`). */
export type ReclaimStep = "found" | "renamed" | "walk";

export interface ReclaimOptions {
  /** The clock, for tests. */
  readonly now?: number;
  /**
   * Test seam: called before each step of a removal that acts on the file
   * system, with the path it is about to act on (`found`: the judged
   * directory; `renamed`: where it was moved to; `walk`: a directory the
   * portable walk is about to list), so a test can swap an entry for a link
   * at exactly that moment.
   */
  readonly onStep?: (step: ReclaimStep, path: string) => void;
  /** Test seam: `portable` uses the portable walk where `rm` would be used. */
  readonly remover?: "portable";
}

/** A name nothing else looks for, in the directory that held the original. */
const QUARANTINE = ".piship-reclaim-";
const QUARANTINE_NAME = /^\.piship-reclaim-[0-9a-f]{16}$/;
/**
 * A quarantined directory not changed for this long belongs to a removal that
 * was killed after it moved the directory and before it finished: its marker
 * may be gone (`rm` removes in any order), so it is recognised by the name
 * PiShip gave it, its owner, and its age, and removed the same way. One a
 * running removal is working on changes (its entries are being deleted) and
 * is left until it stops.
 */
const QUARANTINE_IDLE_MS = 10 * 60_000;

/**
 * The directories in `root` that are PiShip-owned, of one of `kinds`, and
 * abandoned (see the rules above), without touching them, and the
 * quarantined leftovers of removals that were killed. Never throws.
 */
export function findAbandonedTemporaryDirectories(
  root: string,
  kinds: readonly TemporaryKind[],
  options: ReclaimOptions = {},
): AbandonedDirectory[] {
  let names: string[];
  let rootDevice: number;
  try {
    names = readdirSync(root);
    rootDevice = statSync(root).dev;
  } catch {
    return [];
  }
  const now = options.now ?? Date.now();
  const found: AbandonedDirectory[] = [];
  for (const name of names) {
    const quarantined = QUARANTINE_NAME.test(name);
    if (!quarantined && !kinds.some((kind) => SHAPES[kind].name.test(name)))
      continue;
    const path = join(root, name);
    try {
      const entry = lstatSync(path);
      // A link, a file, another user's directory, or a mount point is not ours.
      if (
        !entry.isDirectory() ||
        !ownedByCurrentUser(entry) ||
        entry.dev !== rootDevice
      )
        continue;
      if (quarantined) {
        if (now - Math.max(entry.mtimeMs, entry.ctimeMs) > QUARANTINE_IDLE_MS)
          found.push({
            path,
            kind: undefined,
            dev: entry.dev,
            ino: entry.ino,
            marker: "",
          });
        continue;
      }
      const marker = readMarker(join(path, TEMPORARY_OWNER_FILE));
      if (
        !marker ||
        marker.owner.name !== name ||
        !kinds.includes(marker.owner.kind) ||
        !SHAPES[marker.owner.kind].name.test(name)
      )
        continue;
      if (abandoned(marker.owner, marker.mtimeMs, now))
        found.push({
          path,
          kind: marker.owner.kind,
          dev: entry.dev,
          ino: entry.ino,
          marker: marker.text,
        });
    } catch {
      // Gone already, or unreadable: not this sweep's.
    }
  }
  return found;
}

function missing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

function changed(): Error {
  return new Error(
    "an entry is not the directory that was judged abandoned: it was replaced",
  );
}

/** Whether `path` is, right now, a real directory with this identity. */
function isDirectoryWith(path: string, identity: DirectoryIdentity): boolean {
  const stat = lstatSync(path);
  return (
    stat.isDirectory() && stat.dev === identity.dev && stat.ino === identity.ino
  );
}

/** How the system removes a tree without following links, if it can. */
export interface Remover {
  readonly file: string;
  readonly args: readonly string[];
}
/** Where an `rm` is looked for: absolute paths only, never `PATH`. */
const REMOVER_FILES = [
  "/bin/rm",
  "/usr/bin/rm",
  // NixOS keeps coreutils under the current system profile.
  "/run/current-system/sw/bin/rm",
] as const;
const REMOVER_FLAGS: readonly (readonly string[])[] = [
  // GNU coreutils: fts with descriptor-relative removal, `--one-file-system`.
  ["-rf", "--one-file-system", "--"],
  // macOS and the BSDs: fts, `-x` does not cross mount points.
  ["-rfx", "--"],
];
/**
 * The candidates in the order they are tried: each path with the GNU flags,
 * then the BSD flags, before the next path.
 */
export const REMOVER_CANDIDATES: readonly Remover[] = REMOVER_FILES.flatMap(
  (file) => REMOVER_FLAGS.map((args) => ({ file, args })),
);
let remover: Remover | null | undefined;

/**
 * The first of `candidates` that removes a whole tree safely, or null. `rm`
 * walks with descriptor-relative calls (fts), so a directory swapped for a
 * link while it runs is never followed, and it cannot be given a path that is
 * resolved after a check, which a walk in this process cannot avoid. A
 * candidate is used only after it proved on a throwaway tree that it removes a
 * tree, leaves what a link inside it and a link operand point to, and accepts
 * the flags that keep it on one filesystem (BusyBox `rm` does not). One that
 * is missing, fails, or proves nothing is skipped for the next.
 */
export function findRemover(candidates: readonly Remover[]): Remover | null {
  for (const candidate of candidates) {
    let scratch: string | undefined;
    try {
      scratch = mkdtempSync(join(tmpdir(), "piship-rm-probe-"));
      mkdirSync(join(scratch, "victim"));
      writeFileSync(join(scratch, "victim", "kept"), "kept");
      mkdirSync(join(scratch, "tree", "deep"), { recursive: true });
      symlinkSync(join(scratch, "victim"), join(scratch, "tree", "link"));
      symlinkSync(join(scratch, "victim"), join(scratch, "link"));
      const run = (target: string) =>
        spawnSync(candidate.file, [...candidate.args, target], {
          stdio: "ignore",
          env: {},
          timeout: 30_000,
        });
      if (
        run(join(scratch, "tree")).status === 0 &&
        !existsSync(join(scratch, "tree")) &&
        // A link given as the operand is removed, not followed.
        run(join(scratch, "link")).status === 0 &&
        !existsSync(join(scratch, "link")) &&
        readFileSync(join(scratch, "victim", "kept"), "utf8") === "kept"
      ) {
        return candidate;
      }
    } catch {
      // Not usable here; the next candidate, or the portable walk.
    } finally {
      if (scratch)
        try {
          rmSync(scratch, { recursive: true, force: true });
        } catch {
          // A throwaway directory in the OS temp directory.
        }
    }
  }
  return null;
}

/**
 * The system `rm` removal uses, found once per process; null where there is
 * none (Windows has no such `rm`, and Alpine's BusyBox `rm` fails the probe),
 * and the portable walk is used instead.
 */
function systemRemover(): Remover | null {
  if (remover === undefined)
    remover =
      process.platform === "win32" ? null : findRemover(REMOVER_CANDIDATES);
  return remover;
}

/** Whether removal uses the system's `rm` here (it does not on Windows). */
export function usesSystemRemover(): boolean {
  return systemRemover() !== null;
}

/**
 * Remove `path` and everything under it with the portable walk, which has
 * Node's path-based calls only. It never reads a path it has not just
 * `lstat`ed as a real directory, checks that directory is still the one it
 * listed (same device and inode) before it acts on the names it listed, and
 * never leaves the device `device`. A directory swapped for a link between
 * its `lstat` and its listing is caught by that second look, before anything
 * is removed. What remains is the gap between that look and the removal of
 * each entry, which no path-based call can close: it is the fallback for
 * Windows, where no sandbox backend runs local processes, and for systems
 * without a usable `rm` (Alpine), where the roots a sweep is allowed to look
 * at carry the safety (see temporary-directories.ts in core).
 */
function removeContents(
  path: string,
  entry: Stats,
  device: number,
  options: ReclaimOptions,
  keep?: string,
): void {
  options.onStep?.("walk", path);
  const names = readdirSync(path);
  const after = lstatSync(path);
  if (
    !after.isDirectory() ||
    after.dev !== entry.dev ||
    after.ino !== entry.ino
  )
    throw changed();
  for (const name of names) {
    if (name === keep) continue;
    const child = join(path, name);
    let stat: Stats;
    try {
      stat = lstatSync(child);
    } catch (error) {
      if (missing(error)) continue;
      throw error;
    }
    if (stat.dev !== device)
      throw new Error("a mount point inside a temporary directory");
    try {
      if (stat.isDirectory()) {
        removeContents(child, stat, device, options);
        rmdirSync(child);
      } else unlinkSync(child);
    } catch (error) {
      if (!missing(error)) throw error;
    }
  }
}

/** Contents first, the marker last: a stop half way stays recognised. */
function removePortable(
  path: string,
  identity: DirectoryIdentity,
  options: ReclaimOptions,
): void {
  const top = lstatSync(path);
  if (!isDirectoryWith(path, identity)) throw changed();
  removeContents(path, top, top.dev, options, TEMPORARY_OWNER_FILE);
  if (!isDirectoryWith(path, identity)) throw changed();
  rmSync(join(path, TEMPORARY_OWNER_FILE), { force: true });
  rmdirSync(path);
}

/** One `rm` of the moved directory itself, as the only operand. */
function removeWithSystem(tool: Remover, path: string): void {
  const result = spawnSync(tool.file, [...tool.args, path], {
    stdio: "ignore",
    env: {},
    timeout: 10 * 60_000,
  });
  if (result.error || result.status !== 0)
    throw new Error("the system remover could not remove the directory");
  if (existsSync(path)) throw new Error("the directory is still there");
}

/**
 * Put a directory that could not be removed back under its own name and
 * marker, so the next sweep finds and retries it and a diagnostic can count
 * it. Best effort: a directory that cannot be put back keeps its quarantine
 * name and is left for the user.
 */
function restore(
  quarantine: string,
  path: string,
  found: AbandonedDirectory,
  ours: boolean,
): void {
  try {
    if (ours && found.marker) {
      const marker = join(quarantine, TEMPORARY_OWNER_FILE);
      if (!existsSync(marker)) {
        const fd = openSync(marker, "wx", 0o600);
        try {
          writeSync(fd, found.marker);
        } finally {
          closeSync(fd);
        }
      }
    }
    renameSync(quarantine, path);
  } catch {
    // Left under its quarantine name.
  }
}

/**
 * Remove one abandoned directory without trusting its name, which a
 * process that can write its parent can swap for a link at any moment:
 * 1. it is still the real directory with the identity it was judged with;
 * 2. for a sandbox session, its `tmp` (where contained commands write) is
 *    renamed first, cutting every path a surviving command has into it;
 * 3. the directory is renamed to a fresh name nothing is looking for, which
 *    is no longer reachable by the paths a survivor knows, and the entry
 *    under that name must be the same real directory (same device and
 *    inode), else the removal stops and nothing is removed;
 * 4. the moved directory, as the single operand, is removed by `rm` (which
 *    never follows a link, not even as its operand), or, where there is no
 *    usable `rm`, by the portable walk.
 * A removal that fails puts the directory back under its name and marker.
 */
function removeAbandoned(
  found: AbandonedDirectory,
  options: ReclaimOptions,
): "removed" | "gone" {
  const { path } = found;
  options.onStep?.("found", path);
  try {
    if (!isDirectoryWith(path, found)) throw changed();
  } catch (error) {
    if (missing(error)) return "gone";
    throw error;
  }
  if (found.kind === "sandbox")
    try {
      if (lstatSync(join(path, "tmp")).isDirectory())
        renameSync(
          join(path, "tmp"),
          join(path, `tmp-${randomBytes(8).toString("hex")}`),
        );
    } catch (error) {
      if (!missing(error)) throw error;
    }
  const quarantine = join(
    dirname(path),
    `${QUARANTINE}${randomBytes(8).toString("hex")}`,
  );
  try {
    renameSync(path, quarantine);
  } catch (error) {
    if (missing(error)) return "gone";
    throw error;
  }
  options.onStep?.("renamed", quarantine);
  let verified = false;
  try {
    verified = isDirectoryWith(quarantine, found);
  } catch {
    // Not there, or not a directory: not verified.
  }
  if (!verified) {
    restore(quarantine, path, found, false);
    throw changed();
  }
  try {
    const tool = options.remover === "portable" ? null : systemRemover();
    if (tool) removeWithSystem(tool, quarantine);
    else removePortable(quarantine, found, options);
  } catch (error) {
    let ours = false;
    try {
      ours = isDirectoryWith(quarantine, found);
    } catch {
      // Gone or replaced: nothing to put back.
    }
    if (ours) restore(quarantine, path, found, true);
    throw error;
  }
  return "removed";
}

export interface ReclaimResult {
  readonly removed: readonly string[];
  /** Abandoned directories that could not be removed. */
  readonly failed: readonly string[];
}

/**
 * Remove the abandoned PiShip temporary directories of `kinds` in `root`.
 * Best effort, never throws; what cannot be removed is reported in `failed`
 * and tried again by the next call. Call it only for a root no sandboxed
 * command can write (docs/architecture.md, "Temporary directories"):
 * the removal does not follow a link a swapped directory leaves, but a root
 * that a contained process writes is a root where it can plant directories
 * with forged markers for PiShip to remove.
 */
export function reclaimTemporaryDirectories(
  root: string,
  kinds: readonly TemporaryKind[],
  options: ReclaimOptions = {},
): ReclaimResult {
  const removed: string[] = [];
  const failed: string[] = [];
  for (const found of findAbandonedTemporaryDirectories(root, kinds, options))
    try {
      if (removeAbandoned(found, options) === "removed")
        removed.push(found.path);
    } catch {
      failed.push(found.path);
    }
  return { removed, failed };
}
