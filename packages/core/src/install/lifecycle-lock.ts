// The lifecycle lock: one update, rollback, or uninstall per distribution at
// a time. A lock names its holder's process ID and a random instance ID, and
// the holder refreshes the lock's mtime while it runs (a lease). A lock is
// stale when its holder process is gone, or when the lease ran out: then the
// process ID it names belongs to a later, unrelated process that reused it.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  linkSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeSync,
} from "node:fs";
import { abandoned } from "./temporaries.js";

export const LIFECYCLE_LOCK_SCHEMA = "piship-lifecycle-lock/v1";
/** A held lock is refreshed this often. */
const LOCK_HEARTBEAT_MS = 15_000;
/**
 * A lock not refreshed for this long is stale even when a process with its ID
 * exists. Longer than the longest step that blocks the refresh (a candidate's
 * launch check may run for 300 s), with margin.
 */
export const LIFECYCLE_LOCK_STALE_MS = 10 * 60_000;

interface Holder {
  /** Null when the record names no process (unreadable or foreign). */
  readonly pid: number | null;
  /** Null for a record without one (written before instance IDs). */
  readonly instance: string | null;
  readonly mtimeMs: number;
  readonly raw: string;
}

function readHolder(path: string): Holder | undefined {
  let raw: string;
  let mtimeMs: number;
  try {
    mtimeMs = statSync(path).mtimeMs;
    raw = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  const pid = (value: unknown) =>
    Number.isSafeInteger(value) && (value as number) > 0
      ? (value as number)
      : null;
  if (/^\d+$/.test(raw.trim()))
    return { pid: pid(Number(raw.trim())), instance: null, mtimeMs, raw };
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
      return { pid: pid(record.pid), instance: record.instance, mtimeMs, raw };
  } catch {
    // Not a lock record.
  }
  return { pid: null, instance: null, mtimeMs, raw };
}

/**
 * Whether nobody holds the lock any more. An empty lock is being created
 * right now, unless it has been empty for longer than any creation takes.
 */
function stale(holder: Holder, now = Date.now()): boolean {
  if (holder.raw === "") return now - holder.mtimeMs > 5_000;
  if (holder.pid === null) return true;
  return abandoned(holder.pid, holder.mtimeMs, now, LIFECYCLE_LOCK_STALE_MS);
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
  rmSync(aside, { force: true });
}

/**
 * Take the lock at `path`, or throw `busy(pid)` while a live holder has it.
 * Returns the release, which removes only this holder's lock and never
 * throws: it runs after an activation has committed.
 */
export function acquireLifecycleLock(
  path: string,
  busy: (pid: number | null) => Error,
  unavailable: () => Error,
): () => void {
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

function hold(path: string, instance: string): () => void {
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
  return () => {
    clearInterval(heartbeat);
    try {
      if (ours()) rmSync(path, { force: true });
    } catch {
      // A lock left behind is stale once this process exits.
    }
  };
}
