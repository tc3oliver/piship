// The one place that renames a directory the way Windows needs: a scanner or
// indexer holds a handle on a file just written and the rename fails with
// EPERM, EBUSY, or EACCES until the handle closes.
import { renameSync } from "node:fs";

/** Codes Windows reports while another program holds a handle inside a directory. */
const BLOCKED = new Set(["EPERM", "EBUSY", "EACCES"]);

/** Ten attempts with a growing pause: about four and a half seconds in all. */
export const RENAME_DELAYS_MS: readonly number[] = [
  100, 200, 300, 400, 500, 600, 700, 800, 900,
];
/** The same budget for `rmSync`, which retries by itself. */
export const TRANSIENT_ATTEMPTS = RENAME_DELAYS_MS.length + 1;
export const TRANSIENT_RETRY_MS = 100;

export interface RenameRetryOptions {
  /** Pauses between attempts, in milliseconds; there is one more attempt than pauses. */
  readonly delays?: readonly number[];
  /**
   * What to throw once every attempt failed with a blocked code. The error
   * the last attempt gave by default.
   */
  readonly giveUp?: (failure: {
    readonly from: string;
    readonly to: string;
    readonly code: string;
    readonly cause: unknown;
  }) => unknown;
  /** Test seams. */
  readonly rename?: (from: string, to: string) => void;
  readonly sleep?: (ms: number) => void;
  readonly platform?: NodeJS.Platform;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Rename `from` to `to`. On Windows a rename that fails with a blocked code is
 * retried after each pause in `delays`; every other error, EXDEV included, and
 * every error off Windows is reported at once, as it is a real failure.
 */
export function renameWithRetry(
  from: string,
  to: string,
  options: RenameRetryOptions = {},
): void {
  const rename = options.rename ?? renameSync;
  const sleep = options.sleep ?? sleepSync;
  const delays = options.delays ?? RENAME_DELAYS_MS;
  const windows = (options.platform ?? process.platform) === "win32";
  for (let attempt = 0; ; attempt++) {
    try {
      rename(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "";
      if (!windows || !BLOCKED.has(code)) throw error;
      const delay = delays[attempt];
      if (delay === undefined)
        throw options.giveUp?.({ from, to, code, cause: error }) ?? error;
      sleep(delay);
    }
  }
}
