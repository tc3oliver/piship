// Crash-safe replacement of a small state file (the install receipt, the
// state marker, identity and credential metadata, preferences, and the file
// secret store's entries): write a sibling temporary completely, flush it,
// and rename it over the target, so a reader sees the previous file or the
// new one, never a truncated one.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

/**
 * The temporary an atomic write of `path` uses: `<path>.p<pid>-<random>.tmp`.
 * The writer's process ID lets a later sweep tell an abandoned temporary
 * (its writer is gone) from one a live writer is still filling.
 */
export function temporarySibling(path: string): string {
  return `${path}.p${process.pid}-${randomBytes(6).toString("hex")}.tmp`;
}

/** Flush a directory entry; best effort where the filesystem refuses it. */
export function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  try {
    const fd = openSync(path, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Some filesystems refuse fsync on directories.
  }
}

/**
 * Write every byte of `bytes`. A write may take fewer bytes than asked (disk
 * or quota pressure); the rest is written again, and a write that makes no
 * progress fails instead of leaving a short file.
 */
function writeFully(fd: number, bytes: Buffer, path: string): void {
  let offset = 0;
  let stalled = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (written > 0) {
      offset += written;
      stalled = 0;
    } else if (++stalled >= 3)
      throw Object.assign(
        new Error(
          `EIO: the write of ${path} made no progress after ${offset} of ${bytes.length} bytes`,
        ),
        { code: "EIO" },
      );
  }
}

export interface AtomicWriteOptions {
  /** Mode of a directory this write creates; the process umask otherwise. */
  readonly directoryMode?: number;
}

/**
 * Replace `path` with `content` through a temporary sibling: write it fully,
 * fsync it, then rename it over `path` and flush the directory (best effort;
 * Windows cannot flush a directory). Until the rename, `path` keeps its
 * previous content. Any failure before the rename removes the temporary; a
 * process killed before the rename leaves it for the sweep the distribution
 * runs when it next starts. The file is owner-only (0600).
 */
export function writeFileAtomic(
  path: string,
  content: string,
  options: AtomicWriteOptions = {},
): void {
  const directory = dirname(path);
  mkdirSync(directory, {
    recursive: true,
    ...(options.directoryMode === undefined
      ? {}
      : { mode: options.directoryMode }),
  });
  const temporary = temporarySibling(path);
  let renamed = false;
  try {
    const fd = openSync(temporary, "wx", 0o600);
    try {
      writeFully(fd, Buffer.from(content, "utf8"), path);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, path);
    renamed = true;
  } finally {
    if (!renamed)
      try {
        rmSync(temporary, { force: true });
      } catch {
        // Left for the stale-temporary sweep.
      }
  }
  syncDirectory(directory);
}
