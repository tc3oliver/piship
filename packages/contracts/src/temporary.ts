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
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readlinkSync,
  readSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeSync,
  type Stats,
} from "node:fs";
import { hostname } from "node:os";
import { basename, join } from "node:path";

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
  // `.piship-release-<release name>-XXXXXX`
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
   * Remove the directory and stop refreshing its marker. Idempotent, and
   * throws what `rmSync` throws when the directory cannot be removed (the
   * marker then stays, so a later process reclaims it once this one is gone).
   */
  remove(): void;
}

/**
 * Create a private (0700) temporary directory of `kind` in `parent`, with its
 * marker (0600) written before anything else. `label` completes the name of
 * the kinds that carry one (`build`: the distribution ID; `release`: the
 * release name). A failure to write the marker removes the directory and
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
      if (removed) return;
      release(instance);
      rmSync(path, { recursive: true, force: true });
      removed = true;
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
): { owner: TemporaryOwner; mtimeMs: number } | undefined {
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
    const owner = parseOwner(buffer.subarray(0, read).toString("utf8"));
    return owner ? { owner, mtimeMs: stat.mtimeMs } : undefined;
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
  return readMarker(join(directory, TEMPORARY_OWNER_FILE));
}

/** Whether the owner of a directory last refreshed at `mtimeMs` is gone. */
function abandoned(owner: TemporaryOwner, mtimeMs: number, now: number) {
  if (registry().held.has(owner.instance)) return false;
  if (owner.host === hostToken() && !processAlive(owner.pid)) return true;
  return now - mtimeMs > TEMPORARY_LEASE_MS;
}

export interface ReclaimOptions {
  /** The clock, for tests. */
  readonly now?: number;
}

/**
 * The directories in `root` that are PiShip-owned, of one of `kinds`, and
 * abandoned (see the rules above), without touching them. Never throws.
 */
export function findAbandonedTemporaryDirectories(
  root: string,
  kinds: readonly TemporaryKind[],
  options: ReclaimOptions = {},
): string[] {
  let names: string[];
  let rootDevice: number;
  try {
    names = readdirSync(root);
    rootDevice = statSync(root).dev;
  } catch {
    return [];
  }
  const now = options.now ?? Date.now();
  const found: string[] = [];
  for (const name of names) {
    if (!kinds.some((kind) => SHAPES[kind].name.test(name))) continue;
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
      const marker = readTemporaryOwner(path);
      if (
        !marker ||
        marker.owner.name !== name ||
        !kinds.includes(marker.owner.kind) ||
        !SHAPES[marker.owner.kind].name.test(name)
      )
        continue;
      if (abandoned(marker.owner, marker.mtimeMs, now)) found.push(path);
    } catch {
      // Gone already, or unreadable: not this sweep's.
    }
  }
  return found;
}

/** The same directory as `before`: neither swapped for a link nor replaced. */
function unchanged(path: string, before: Stats): boolean {
  const now = lstatSync(path);
  return now.isDirectory() && now.dev === before.dev && now.ino === before.ino;
}

/**
 * Remove `path` and everything under it without following a link and without
 * leaving the filesystem `device`: a link is unlinked, a directory on another
 * device (a mount) fails the removal. Descriptor-relative removal is not
 * available in Node, so this walk is path based; the owner of what it removes
 * is gone, and it checks a directory is still the one it listed before it
 * removes what it listed.
 */
function removeTree(path: string, device: number): void {
  let entry: Stats;
  try {
    entry = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (entry.dev !== device)
    throw new Error("a mount point inside a temporary directory");
  if (!entry.isDirectory()) {
    try {
      unlinkSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    return;
  }
  const names = readdirSync(path);
  if (!unchanged(path, entry))
    throw new Error("a directory changed while it was removed");
  for (const name of names) removeTree(join(path, name), device);
  rmdirSync(path);
}

/**
 * Remove one abandoned directory. The marker goes last, so a removal that
 * stops half way (a mount point, a file that cannot be deleted) leaves a
 * directory that is still recognised and retried.
 */
function removeAbandoned(path: string): void {
  const entry = lstatSync(path);
  for (const name of readdirSync(path))
    if (name !== TEMPORARY_OWNER_FILE) removeTree(join(path, name), entry.dev);
  if (!unchanged(path, entry))
    throw new Error("a directory changed while it was removed");
  rmSync(join(path, TEMPORARY_OWNER_FILE), { force: true });
  rmdirSync(path);
}

export interface ReclaimResult {
  readonly removed: readonly string[];
  /** Abandoned directories that could not be removed. */
  readonly failed: readonly string[];
}

/**
 * Remove the abandoned PiShip temporary directories of `kinds` in `root`.
 * Best effort, never throws; what cannot be removed is reported in `failed`
 * and tried again by the next call.
 */
export function reclaimTemporaryDirectories(
  root: string,
  kinds: readonly TemporaryKind[],
  options: ReclaimOptions = {},
): ReclaimResult {
  const removed: string[] = [];
  const failed: string[] = [];
  for (const path of findAbandonedTemporaryDirectories(root, kinds, options))
    try {
      removeAbandoned(path);
      removed.push(path);
    } catch {
      failed.push(path);
    }
  return { removed, failed };
}
