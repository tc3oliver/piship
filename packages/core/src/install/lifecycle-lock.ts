// The lifecycle lock: one update, rollback, or uninstall per distribution at
// a time. A lock names its holder's process ID and a random instance ID, and
// the holder refreshes the lock's mtime while it runs (a lease).
//
// Who is judged how: a lock whose holder process is gone is stale at once. A
// lock whose process exists is stale only when the lease ran out, which means
// the ID belongs to a later, unrelated process that reused it after the
// holder crashed. Every lifecycle command is one attempt in a fresh process,
// so unlike the credential lock's waiters it has no earlier observation of
// the lock to compare with, and the lock's mtime against the wall clock is
// all it has. That reading is wrong when the clock jumps forward (NTP, a
// resumed VM) or the machine slept while the holder was alive, and a holder
// blocked in a synchronous step (a launch check, up to 300 s) cannot
// refresh. So the bound is far above any step or ordinary correction
// (LIFECYCLE_LOCK_REUSE_MS), and a holder that loses its lock anyway finds
// out before it commits (`stillHeld`).
import { randomBytes } from "node:crypto";
import {
  closeSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  utimesSync,
  writeSync,
} from "node:fs";
import { abandoned } from "./temporaries.js";

export const LIFECYCLE_LOCK_SCHEMA = "piship-lifecycle-lock/v1";
/** A held lock is refreshed this often. */
const LOCK_HEARTBEAT_MS = 15_000;
/**
 * A lock not refreshed for this long by the wall clock is stale even when a
 * process with its ID exists: 24 hours. It only has to recover a crashed
 * holder's ID that an unrelated process took, so it can be far above the
 * longest step that blocks the refresh (a launch check runs for up to five
 * minutes) and above the clock corrections and sleeps a running holder can
 * see. The price is that a crashed holder's lock whose ID is now in use
 * blocks the next operation for up to this long; the error names the file so
 * it can be removed by hand.
 */
export const LIFECYCLE_LOCK_REUSE_MS = 24 * 60 * 60_000;

interface Holder {
  /** Null when the record names no process (unreadable or foreign). */
  readonly pid: number | null;
  /** Null for a record without one (written before instance IDs). */
  readonly instance: string | null;
  readonly mtimeMs: number;
  /** Null when the lock exists but its content cannot be read. */
  readonly raw: string | null;
  /** False for a directory or symlink at the lock's path. */
  readonly regular: boolean;
}

function readHolder(path: string): Holder | undefined {
  let raw: string;
  let mtimeMs: number;
  let regular: boolean;
  try {
    const stat = lstatSync(path);
    mtimeMs = stat.mtimeMs;
    regular = stat.isFile();
  } catch {
    return undefined;
  }
  try {
    raw = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    return { pid: null, instance: null, mtimeMs, raw: null, regular };
  }
  const pid = (value: unknown) =>
    Number.isSafeInteger(value) && (value as number) > 0
      ? (value as number)
      : null;
  if (/^\d+$/.test(raw.trim()))
    return {
      pid: pid(Number(raw.trim())),
      instance: null,
      mtimeMs,
      raw,
      regular,
    };
  try {
    const record = JSON.parse(raw) as {
      schema?: unknown;
      pid?: unknown;
      instance?: unknown;
    };
    if (
      record.schema === LIFECYCLE_LOCK_SCHEMA &&
      typeof record.instance === "string"
    )
      return {
        pid: pid(record.pid),
        instance: record.instance,
        mtimeMs,
        raw,
        regular,
      };
  } catch {
    // Not a lock record.
  }
  return { pid: null, instance: null, mtimeMs, raw, regular };
}

/**
 * Whether nobody holds the lock any more. An empty lock is being created
 * right now, unless it has been empty for longer than any creation takes.
 */
function stale(holder: Holder, now = Date.now()): boolean {
  // Not a file this module made: never moved aside or deleted.
  if (!holder.regular) return false;
  // Content that cannot be read (a root-owned lock a crashed `sudo` command
  // left) names no process; only the lease can tell.
  if (holder.raw === null)
    return now - holder.mtimeMs > LIFECYCLE_LOCK_REUSE_MS;
  if (holder.raw === "") return now - holder.mtimeMs > 5_000;
  if (holder.pid === null) return true;
  return abandoned(holder.pid, holder.mtimeMs, now, LIFECYCLE_LOCK_REUSE_MS);
}

/** Create the lock with its whole record, failing with EEXIST if held. */
function create(path: string, record: string): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, record);
  } finally {
    closeSync(fd);
  }
}

/**
 * Remove a stale lock without racing another process doing the same: move
 * it aside under a unique name (only one rename succeeds), check that what
 * was moved is the stale lock that was read, and only then delete it. A lock
 * that turned out to be another one is put back unless a new lock already
 * took its place.
 *
 * Limit: if a third process creates the lock between the rename and the
 * put-back, the link fails and the aside copy is deleted, so a live holder
 * that was moved aside resumes without its lock. The window is microseconds
 * and only opens for a holder whose lock looked stale; that holder finds out
 * through `stillHeld` before it commits its receipt.
 */
function breakStale(path: string, observed: Holder): void {
  const aside = `${path}.p${process.pid}-${randomBytes(6).toString("hex")}.stale`;
  try {
    renameSync(path, aside);
  } catch {
    return;
  }
  const moved = readHolder(aside);
  if (moved && (moved.raw !== observed.raw || !stale(moved)))
    try {
      linkSync(aside, path);
    } catch {
      // A new holder already created the lock.
    }
  try {
    rmSync(aside, { force: true });
  } catch {
    // Left behind; the next operation's recovery removes it.
  }
}

/** A held lifecycle lock. */
export interface LifecycleHold {
  /**
   * Remove this holder's lock, and only this holder's; never throws, because
   * it runs after an activation has committed.
   */
  release(): void;
  /**
   * Whether the lock file still names this holder. False once another
   * process took the lock over (it looked stale to it) or it was removed.
   * A holder checks it right before it commits, and does not commit when it
   * is false: the operation that holds the lock now owns the installation.
   */
  stillHeld(): boolean;
}

/**
 * Take the lock at `path`, or throw `busy(pid)` while a live holder has it.
 */
export function acquireLifecycleLock(
  path: string,
  busy: (pid: number | null) => Error,
  unavailable: () => Error,
): LifecycleHold {
  const instance = randomBytes(8).toString("hex");
  const record = `${JSON.stringify({
    schema: LIFECYCLE_LOCK_SCHEMA,
    pid: process.pid,
    instance,
    acquiredAt: new Date().toISOString(),
  })}\n`;
  for (let attempt = 0; attempt < 3; attempt += 1)
    try {
      create(path, record);
      return hold(path, instance);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const holder = readHolder(path);
      if (!holder) continue;
      if (!stale(holder)) throw busy(holder.pid);
      breakStale(path, holder);
    }
  throw unavailable();
}

function hold(path: string, instance: string): LifecycleHold {
  const ours = () => readHolder(path)?.instance === instance;
  const heartbeat = setInterval(() => {
    try {
      if (!ours()) {
        // Released, or removed with the installation (uninstall).
        clearInterval(heartbeat);
        return;
      }
      const now = new Date();
      utimesSync(path, now, now);
    } catch {
      // Retried on the next beat.
    }
  }, LOCK_HEARTBEAT_MS);
  heartbeat.unref?.();
  return {
    release() {
      clearInterval(heartbeat);
      try {
        if (ours()) rmSync(path, { force: true });
      } catch {
        // A lock left behind is stale once this process exits.
      }
    },
    stillHeld: ours,
  };
}
