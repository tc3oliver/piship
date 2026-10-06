// File system steps of install and update that Windows makes flaky: directory
// renames that a scanner or indexer briefly blocks.
import { PiShipError } from "@piship/contracts";
import { renameWithRetry as retryRename } from "../rename-retry.js";

/** Waits between attempts, about 1.6 s in all. */
const RENAME_DELAYS_MS = [25, 50, 100, 200, 400, 800];

export interface RenameOptions {
  /** Test seams. */
  readonly rename?: (from: string, to: string) => void;
  readonly sleep?: (ms: number) => void;
  readonly platform?: NodeJS.Platform;
}

/**
 * Rename `from` to `to`. On Windows a rename that fails with EPERM, EBUSY, or
 * EACCES is retried with a growing wait (a scanner or indexer holds a handle
 * for a moment) and then fails with an error that says so. Elsewhere those
 * codes are real failures, reported at once.
 */
export function renameWithRetry(
  from: string,
  to: string,
  options: RenameOptions = {},
): void {
  retryRename(from, to, {
    ...options,
    delays: RENAME_DELAYS_MS,
    giveUp: ({ code, cause }) =>
      new PiShipError(
        "UPDATE_FAILED",
        `Could not move ${from} to ${to} (${code}): another program, often an antivirus scanner or an indexer, still has a file in it open`,
        {
          retryable: true,
          userAction:
            "Wait a moment and run the command again; nothing was changed",
          component: "install",
          cause,
        },
      ),
  });
}
