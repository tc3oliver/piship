import { utimesSync } from "node:fs";

/** Cross-process lock files this process currently holds. */
export const heldLocks = new Set<string>();

/** The mtime each held lock was last given, so every heartbeat changes it. */
const lastBeat = new Map<string, number>();

/**
 * One heartbeat: give the lock a new mtime. Waiters only compare it with
 * what they saw before, never with their clock, so the value only has to
 * differ from the previous one, including when the wall clock stood still or
 * went back to it.
 */
export function touchLock(lock: string): void {
  let next = Date.now();
  if (next === lastBeat.get(lock)) next += 1;
  try {
    utimesSync(lock, new Date(next), new Date(next));
    lastBeat.set(lock, next);
  } catch {
    // The lock is gone; its holder notices on release.
  }
}

/**
 * Refresh every held lock's mtime. The interval heartbeat cannot run while a
 * synchronous secret-store command blocks the event loop, so callers touch
 * the locks right before each such command.
 */
export function touchHeldLocks(): void {
  for (const lock of heldLocks) touchLock(lock);
}
