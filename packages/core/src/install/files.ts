// File system steps of install and update that Windows makes slow or flaky:
// directory renames that a scanner or indexer briefly blocks, and copying
// thousands of small files one at a time.
import { constants, renameSync } from "node:fs";
import { copyFile, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { JobPool } from "../job-pool.js";

/** Codes Windows reports while another program holds a handle inside a directory. */
const BLOCKED = new Set(["EPERM", "EBUSY", "EACCES"]);
/** Waits between attempts, about 1.6 s in all. */
const RENAME_DELAYS_MS = [25, 50, 100, 200, 400, 800];
const COPY_CONCURRENCY = 8;

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

/**
 * Copy the directory tree `source` to `destination`, which must not hold the
 * same files yet. Directories are made level by level and files are copied by
 * several writers at once; a symbolic link or special file is refused, as a
 * payload has none.
 */
export async function copyTree(
  source: string,
  destination: string,
): Promise<void> {
  await mkdir(destination, { recursive: true });
  const files: string[] = [];
  let level = [""];
  while (level.length > 0) {
    const next: string[] = [];
    const settled = await Promise.allSettled(
      level.map(async (directory) => {
        const entries = await readdir(join(source, directory), {
          withFileTypes: true,
        });
        await Promise.all(
          entries.map(async (entry) => {
            const child = join(directory, entry.name);
            if (entry.isDirectory()) {
              await mkdir(join(destination, child));
              next.push(child);
            } else if (entry.isFile()) files.push(child);
            else throw new Error(`Unsupported payload entry: ${child}`);
          }),
        );
      }),
    );
    for (const result of settled)
      if (result.status === "rejected") throw result.reason;
    level = next;
  }
  const writers = new JobPool(COPY_CONCURRENCY);
  try {
    for (const file of files)
      await writers.run(() =>
        copyFile(
          join(source, file),
          join(destination, file),
          constants.COPYFILE_EXCL,
        ),
      );
  } catch (error) {
    // Writers still running must not outlive the failure that stops the copy.
    await writers.drain();
    throw error;
  }
  await writers.finish();
}
