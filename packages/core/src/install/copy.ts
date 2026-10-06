// Copying a payload directory for an install: thousands of small files, written
// by several writers at once, each hashed from the bytes that are read.
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, link, mkdir, open, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { pipeline } from "node:stream/promises";
import { JobPool } from "../job-pool.js";

const COPY_CONCURRENCY = 8;
/** Files up to this size are read whole; larger ones go through a buffer of this size. */
const CHUNK = 1 << 20;
const WINDOWS = process.platform === "win32";

/** SHA-256 of a file's content: read whole when small, streamed otherwise. */
async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  const input = await open(path, "r");
  try {
    if ((await input.stat()).size <= CHUNK) {
      hash.update(await input.readFile());
      return hash.digest("hex");
    }
  } finally {
    await input.close();
  }
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function copyHashed(from: string, to: string): Promise<string> {
  const hash = createHash("sha256");
  const input = await open(from, "r");
  let size: number;
  let mode: number;
  let data: Buffer | undefined;
  try {
    ({ size, mode } = await input.stat());
    if (size <= CHUNK) data = await input.readFile();
  } finally {
    await input.close();
  }
  const bits = WINDOWS ? 0o666 : mode & 0o777;
  if (data) {
    hash.update(data);
    const output = await open(to, "wx", bits);
    try {
      if (data.length > 0) await output.writeFile(data);
      // The creation mode is cut by the umask; the copy keeps the source's.
      if (!WINDOWS) await output.chmod(bits);
    } finally {
      await output.close();
    }
    return hash.digest("hex");
  }
  // A large file goes through streams, which handle partial reads and writes.
  await pipeline(
    createReadStream(from),
    async function* (source: AsyncIterable<Buffer>) {
      for await (const chunk of source) {
        hash.update(chunk);
        yield chunk;
      }
    },
    createWriteStream(to, { flags: "wx", mode: bits }),
  );
  if (!WINDOWS) await chmod(to, bits);
  return hash.digest("hex");
}

export interface CopyOptions {
  /**
   * Hard-link each file after hashing it instead of writing a second copy.
   * Creating a file costs a scanner's pass over it on Windows; a link costs a
   * directory entry. The installed file is then the source's file: a later
   * write through the source path changes what is installed. Opt-in, only for
   * a throwaway source, on one volume: a file that cannot be linked (another volume, a file system
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
