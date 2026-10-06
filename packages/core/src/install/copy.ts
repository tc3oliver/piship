// Copying a payload directory for an install: thousands of small files, written
// by several writers at once, each hashed from the bytes that are read.
import { createHash } from "node:crypto";
import { link, mkdir, open, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { JobPool } from "../job-pool.js";

const COPY_CONCURRENCY = 8;
/** Files up to this size are read whole; larger ones go through a buffer of this size. */
const CHUNK = 1 << 20;
const WINDOWS = process.platform === "win32";

/** SHA-256 of a file's content: read whole when small, in chunks otherwise. */
async function hashFile(path: string): Promise<string> {
  const input = await open(path, "r");
  try {
    const hash = createHash("sha256");
    if ((await input.stat()).size <= CHUNK) {
      hash.update(await input.readFile());
      return hash.digest("hex");
    }
    const buffer = Buffer.allocUnsafe(CHUNK);
    for (;;) {
      const { bytesRead } = await input.read(buffer, 0, CHUNK, null);
      if (bytesRead === 0) return hash.digest("hex");
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    await input.close();
  }
}

async function copyHashed(from: string, to: string): Promise<string> {
  const input = await open(from, "r");
  try {
    const { size, mode } = await input.stat();
    const bits = WINDOWS ? 0o666 : mode & 0o777;
    const output = await open(to, "wx", bits);
    try {
      const hash = createHash("sha256");
      if (size <= CHUNK) {
        const data = await input.readFile();
        hash.update(data);
        if (data.length > 0) await output.writeFile(data);
      } else {
        const buffer = Buffer.allocUnsafe(CHUNK);
        for (;;) {
          const { bytesRead } = await input.read(buffer, 0, CHUNK, null);
          if (bytesRead === 0) break;
          hash.update(buffer.subarray(0, bytesRead));
          let written = 0;
          while (written < bytesRead)
            written += (
              await output.write(buffer, written, bytesRead - written)
            ).bytesWritten;
        }
      }
      // The creation mode is cut by the umask; the copy keeps the source's.
      if (!WINDOWS) await output.chmod(bits);
      return hash.digest("hex");
    } finally {
      await output.close();
    }
  } finally {
    await input.close();
  }
}

export interface CopyOptions {
  /**
   * Hard-link each file after hashing it instead of writing a second copy.
   * Creating a file costs a scanner's pass over it on Windows; a link costs a
   * directory entry. The installed file is then the source's file, so use it
   * only for a source nothing rewrites in place (an extracted release), on one
   * volume: a file that cannot be linked (another volume, a file system
   * without links) is copied, and so is every file after the first such
   * failure.
   */
  readonly link?: boolean;
  /** Test seam. */
  readonly linkFile?: (from: string, to: string) => Promise<void>;
}

/**
 * Copy the directory tree `source` to `destination`, which must not hold the
 * same files yet, and return the SHA-256 of every file by its `/`-separated
 * path, computed from the bytes that were read. Directories are made level by
 * level and files are copied (or linked) by several writers at once; a
 * symbolic link or special file is refused, as a payload has none.
 */
export async function copyTree(
  source: string,
  destination: string,
  options: CopyOptions = {},
): Promise<ReadonlyMap<string, string>> {
  const linkFile = options.linkFile ?? link;
  let linking = options.link === true;
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
  const digests = new Map<string, string>();
  const writers = new JobPool(COPY_CONCURRENCY);
  try {
    for (const file of files)
      await writers.run(async () => {
        const from = join(source, file);
        const to = join(destination, file);
        let digest: string | undefined;
        if (linking) {
          const hashed = await hashFile(from);
          try {
            await linkFile(from, to);
            digest = hashed;
          } catch (error) {
            // Not an existing file: only a link that cannot be made here
            // (another volume, no links, a refused one) falls back to copying.
            if ((error as NodeJS.ErrnoException).code === "EEXIST") throw error;
            linking = false;
          }
        }
        digests.set(
          file.split(sep).join("/"),
          digest ?? (await copyHashed(from, to)),
        );
      });
  } catch (error) {
    // Writers still running must not outlive the failure that stops the copy.
    await writers.drain();
    throw error;
  }
  await writers.finish();
  return digests;
}
