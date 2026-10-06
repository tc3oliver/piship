// Copying a payload directory for an install: thousands of small files, written
// by several writers at once, each hashed from the bytes that are written.
import { createHash } from "node:crypto";
import { mkdir, open, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { JobPool } from "../job-pool.js";

const COPY_CONCURRENCY = 8;
/** Files up to this size are read whole; larger ones go through a buffer of this size. */
const CHUNK = 1 << 20;
const WINDOWS = process.platform === "win32";

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

/**
 * Copy the directory tree `source` to `destination`, which must not hold the
 * same files yet, and return the SHA-256 of every file by its `/`-separated
 * path, computed from the bytes that were copied. Directories are made level
 * by level and files are copied by several writers at once; a symbolic link or
 * special file is refused, as a payload has none.
 */
export async function copyTree(
  source: string,
  destination: string,
): Promise<ReadonlyMap<string, string>> {
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
        digests.set(
          file.split(sep).join("/"),
          await copyHashed(join(source, file), join(destination, file)),
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
