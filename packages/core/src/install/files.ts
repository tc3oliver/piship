// File system steps of install and update that Windows makes flaky: directory
// renames that a scanner or indexer briefly blocks.
import { renameSync } from "node:fs";
import { PiShipError } from "@piship/contracts";

/** Codes Windows reports while another program holds a handle inside a directory. */
const BLOCKED = new Set(["EPERM", "EBUSY", "EACCES"]);
/** Waits between attempts, about 1.6 s in all. */
const RENAME_DELAYS_MS = [25, 50, 100, 200, 400, 800];

export interface RenameOptions {
  /** Test seams. */
  readonly rename?: (from: string, to: string) => void;
  readonly sleep?: (ms: number) => void;
  readonly platform?: NodeJS.Platform;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
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
  const rename = options.rename ?? renameSync;
  const sleep = options.sleep ?? sleepSync;
  const windows = (options.platform ?? process.platform) === "win32";
  for (let attempt = 0; ; attempt++) {
    try {
      rename(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "";
      if (!windows || !BLOCKED.has(code)) throw error;
      const delay = RENAME_DELAYS_MS[attempt];
      if (delay === undefined)
        throw new PiShipError(
          "UPDATE_FAILED",
          `Could not move ${from} to ${to} (${code}): another program, often an antivirus scanner or an indexer, still has a file in it open`,
          {
            retryable: true,
            userAction:
              "Wait a moment and run the command again; nothing was changed",
            component: "install",
            cause: error,
          },
        );
      sleep(delay);
    }
  }
}
