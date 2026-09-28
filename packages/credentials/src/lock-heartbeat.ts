import { utimesSync } from "node:fs";

/** Cross-process lock files this process currently holds. */
export const heldLocks = new Set<string>();

/**
 * Refresh every held lock's mtime. The interval heartbeat cannot run while a
 * synchronous secret-store command blocks the event loop, so callers touch
 * the locks right before each such command.
 */
export function touchHeldLocks(): void {
  const now = new Date();
  for (const lock of heldLocks)
    try {
      utimesSync(lock, now, now);
    } catch {
      // The lock is gone; its holder notices on release.
    }
}
