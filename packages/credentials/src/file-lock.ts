import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";
import { basename, dirname } from "node:path";
import { PiShipError } from "@piship/contracts";
import { heldLocks, touchLock } from "./lock-heartbeat.js";

/** A held lock is refreshed this often, so only an abandoned one goes stale. */
const LOCK_HEARTBEAT_MS = 5_000;
/**
 * Longer than the worst gap between refreshes: one blocking secret-store
 * command (30 s timeout; locks are touched before each one) plus a missed
 * heartbeat, with margin. Still below the wait, so an abandoned lock is
 * broken before a waiter gives up.
 */
const LOCK_STALE_MS = 75_000;
const LOCK_WAIT_MS = 90_000;
/** How long a waiter waits in silence before it says what it waits for. */
const LOCK_NOTICE_MS = 2_000;
const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
/**
 * Elapsed time for lock decisions. It never jumps with the wall clock (NTP
 * corrections, manual changes, a resumed VM), which must not change who
 * holds a lock or how long a caller waits.
 */
const monotonic = (): number => performance.now();

/**
 * The lock files the current asynchronous call chain holds. A task that
 * already holds a lock and asks for it again (a login that clears and
 * acquires the credential under one lock) runs at once instead of waiting
 * for itself. Other call chains, in this process or another, still wait.
 * Work a task starts belongs to its chain, so a task must not start work
 * that outlives it (it would still count as holding the lock).
 */
const heldByChain = new AsyncLocalStorage<ReadonlySet<string>>();

const LOCK_TIMEOUT = "lock-timeout";

/** Whether `error` is a wait for a cross-process lock that ran out. */
export function isLockTimeout(error: unknown): boolean {
  return (
    error instanceof PiShipError &&
    error.sanitizedDetail?.reason === LOCK_TIMEOUT
  );
}

/** Whether the current call chain holds the lock beside `path`. */
export function holdsFileLock(path: string): boolean {
  return heldByChain.getStore()?.has(`${path}.lock`) ?? false;
}

export interface FileLockTiming {
  readonly heartbeatMs?: number;
  readonly staleMs?: number;
  readonly waitMs?: number;
  readonly noticeMs?: number;
  /** Where the one wait notice goes; standard error by default. */
  readonly notify?: (message: string) => void;
}

/**
 * The holder a lock token names. A token is `<pid>-<random>@<hostname>`; one
 * written before the hostname was recorded is `<pid>-<random>`, and its host
 * is unknown. Anything else (an unusual hostname included) names no holder,
 * so it is shown as "another process" and judged by the stale interval.
 */
function lockHolder(
  token: string,
): { pid: number; host: string | undefined } | undefined {
  const match = /^(\d+)-[0-9a-f]+(?:@([\w.-]{1,255}))?$/.exec(token);
  if (!match) return undefined;
  return { pid: Number(match[1]), host: match[2] };
}

/** The holder named in an observed lock state, or undefined when unreadable. */
function observedHolder(state: string) {
  const token = state.slice(0, state.lastIndexOf("\n"));
  return token === "?" ? undefined : lockHolder(token);
}

function describeHolder(state: string | undefined): string {
  if (state === undefined) return "another process";
  const holder = observedHolder(state);
  if (!holder) return "another process";
  return holder.host === undefined
    ? `process ${holder.pid}`
    : `process ${holder.pid} on ${holder.host}`;
}

/**
 * Whether the lock's holder is provably gone: it recorded this host and its
 * PID no longer exists here. Only "no such process" counts; any other answer
 * (EPERM: alive under another user) leaves the holder alive. A reused PID can
 * only make a dead holder look alive, which falls back to the stale interval,
 * never a live holder look dead. A lock from another host, or from a token
 * without a host, is judged by the stale interval alone. Limit: two machines
 * or containers that share the lock directory, report the same hostname and
 * see different process tables could break each other's live locks.
 */
function holderIsDead(state: string): boolean {
  const holder = observedHolder(state);
  if (!holder || holder.host !== hostname() || holder.pid <= 0) return false;
  try {
    process.kill(holder.pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

/**
 * What a waiter observes of a lock: its holder's token and the heartbeat
 * (the mtime the holder keeps changing). Only equality is ever compared,
 * never the mtime against the clock. A lock that exists but cannot be read (a
 * root-owned file a crashed `sudo` command left, a directory) is observed by
 * its mtime alone: a holder that heartbeats still changes it, and one that
 * does not is taken over like any other. Undefined when the lock is gone or
 * cannot be statted (a dangling symlink), so a waiter never mistakes what it
 * cannot see for progress.
 */
function observe(lock: string): string | undefined {
  let mtimeMs: number;
  try {
    mtimeMs = statSync(lock).mtimeMs;
  } catch {
    return undefined;
  }
  try {
    return `${readFileSync(lock, "utf8")}\n${mtimeMs}`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    return `?\n${mtimeMs}`;
  }
}

/**
 * Break a lock whose holder made no progress, without racing another waiter:
 * move it aside under a unique name (atomic), check that what was moved is
 * still the lock observed without progress, and only then delete it. A lock
 * that changed meanwhile (a heartbeat, or a new holder) is put back unless a
 * new lock already took its place.
 *
 * Limit: a holder that heartbeats just after the waiter last looked is moved
 * aside and put back; if a third process creates the lock in between, the put
 * back fails, the aside copy is deleted, and that holder resumes without its
 * lock and is not told. Two holders then run until the first releases (each
 * removes only a lock carrying its own token). The window is microseconds and
 * only opens for a holder that made no progress for the whole stale interval;
 * a lock file has no compare-and-delete to close it.
 */
function breakStaleLock(lock: string, observed: string): void {
  // Only a regular file is a lock: never move or delete a directory or a
  // symlink someone put at the lock's path.
  try {
    if (!lstatSync(lock).isFile()) return;
  } catch {
    return;
  }
  const aside = `${lock}.${process.pid}-${randomBytes(6).toString("hex")}.stale`;
  try {
    renameSync(lock, aside);
  } catch {
    return;
  }
  if (observe(aside) !== observed)
    try {
      linkSync(aside, lock);
    } catch {
      // A new holder already created the lock.
    }
  try {
    rmSync(aside, { force: true });
  } catch {
    // Left behind; the lock's own path is free either way.
  }
}

/**
 * Cross-process lock beside the metadata file. The holder writes a unique
 * token into the lock and refreshes the lock's mtime while its task runs (on
 * an interval, and before each blocking secret-store command). A waiter
 * breaks the lock only when it has watched the same token with the same
 * mtime for the stale interval, measured on the monotonic clock: its holder
 * made no progress, such as a crashed process. A lock whose holder recorded
 * this host and no longer exists here is broken at once (see `holderIsDead`). How old the mtime looks
 * against the wall clock never matters, so a clock that jumps forward never
 * lets a live holder lose the lock, and one that jumps backward never keeps
 * an abandoned lock forever. The caller's wait is monotonic as well; after
 * it, the caller fails with a retryable error. The lock is reentrant within
 * one call chain (see `holdsFileLock`). A waiter that is still waiting after
 * the notice interval says once which lock it waits for and who holds it.
 *
 * A lease has a limit: a holder that makes no progress for the whole stale
 * interval (a stopped process, a suspended VM, a very long blocking call)
 * loses its lock to a waiter and is not told; its task runs on beside the
 * new holder's.
 */
export async function withFileLock<T>(
  path: string,
  task: () => Promise<T>,
  timing: FileLockTiming = {},
): Promise<T> {
  const heartbeatMs = timing.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const staleMs = timing.staleMs ?? LOCK_STALE_MS;
  const waitMs = timing.waitMs ?? LOCK_WAIT_MS;
  const noticeMs = timing.noticeMs ?? LOCK_NOTICE_MS;
  const notify =
    timing.notify ?? ((message) => process.stderr.write(`${message}\n`));
  const lock = `${path}.lock`;
  const held = heldByChain.getStore();
  if (held?.has(lock)) return task();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const token = `${process.pid}-${randomBytes(8).toString("hex")}@${hostname()}`;
  const started = monotonic();
  const deadline = started + waitMs;
  let noticed = false;
  // The holder state last seen, and since when (monotonic) it is unchanged.
  let seen: { state: string; since: number } | undefined;
  for (;;) {
    try {
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeSync(fd, token);
      } finally {
        closeSync(fd);
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const state = observe(lock);
      const now = monotonic();
      // A lock that cannot be observed (released just now, or a dangling
      // symlink) waits like any other: the deadline and the pause apply on
      // every pass, so no state of the lock path can make a waiter spin.
      if (state === undefined) seen = undefined;
      else if (holderIsDead(state)) {
        // Retried after the pause below, so a lock that cannot be moved
        // aside never makes the waiter spin.
        breakStaleLock(lock, state);
        seen = undefined;
      } else if (seen?.state !== state) seen = { state, since: now };
      else if (now - seen.since > staleMs) {
        breakStaleLock(lock, state);
        seen = undefined;
        continue;
      }
      if (!noticed && now - started >= noticeMs) {
        noticed = true;
        notify(
          `Waiting for ${lock}, held by ${describeHolder(state)} (up to ${Math.round(waitMs / 1000)} s)`,
        );
      }
      if (now > deadline)
        throw new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          `Another process is still updating ${basename(path)} (held by ${describeHolder(state)}); gave up after ${Math.round(waitMs / 1000)} s`,
          {
            component: "credential",
            retryable: true,
            userAction:
              "Try again when the other session finishes signing in or refreshing",
            sanitizedDetail: { reason: LOCK_TIMEOUT },
          },
        );
      await sleep(50);
    }
  }
  heldLocks.add(lock);
  const heartbeat = setInterval(() => touchLock(lock), heartbeatMs);
  heartbeat.unref?.();
  try {
    return await heldByChain.run(new Set([...(held ?? []), lock]), task);
  } finally {
    clearInterval(heartbeat);
    heldLocks.delete(lock);
    // Release only this holder's lock, never one another process took over.
    let owner: string | undefined;
    try {
      owner = readFileSync(lock, "utf8");
    } catch {
      owner = undefined;
    }
    if (owner === token) rmSync(lock, { force: true });
  }
}
