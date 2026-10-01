// Session-owned persistence of full shell output. Pi 0.87.1's shell tool keeps
// a bounded display tail and writes the complete output to `pi-bash-*.log`
// in the OS temp directory: a file no option names, nothing removes, and
// whose write stream has no error handler, so a full temp disk crashes the
// process. PiShip's governed bash tool keeps the same tail and footer but
// persists through this store instead: one private directory per governance
// session, a byte budget per file, an error handler before the first write,
// and removal when the session closes.
import { randomBytes } from "node:crypto";
import {
  createWriteStream,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statfsSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import type { Writable } from "node:stream";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  type TruncationResult,
  truncateTail,
} from "@earendil-works/pi-coding-agent";

/** Directory name prefix of a session output store under the OS temp dir. */
export const OUTPUT_DIR_PREFIX = "piship-out-";
/** Bytes of one command's full output kept on disk. */
export const PERSIST_LIMIT_BYTES = 64 * 1024 * 1024 + 4096;
/** Free temp-disk space never used for shell output. */
export const TEMP_DISK_RESERVE_BYTES = 256 * 1024 * 1024;
/**
 * Below this many bytes of output Pi's `!` path writes no file (it starts one
 * past DEFAULT_MAX_BYTES); a nearly full temp disk still runs small commands.
 */
const MIN_USER_BASH_BUDGET = 32 * 1024;
const OWNER_FILE = "owner";
const PI_BASH_LOG = /^pi-bash-[0-9a-f]{16}\.log$/;

/** Free bytes on the filesystem holding `path`, or undefined when unknown. */
export function freeBytes(path: string): number | undefined {
  try {
    const stats = statfsSync(path);
    return Number(stats.bavail) * Number(stats.bsize);
  } catch {
    return undefined;
  }
}

/**
 * The output budget for a `!` command: the shell output limit, lowered to the
 * free temp space minus the reserve, but never below what writes no file.
 */
export function userBashBudget(limit: number, free: number | undefined) {
  if (free === undefined) return limit;
  return Math.min(
    limit,
    Math.max(free - TEMP_DISK_RESERVE_BYTES, MIN_USER_BASH_BUDGET),
  );
}

const uid = () => process.getuid?.();

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

export interface SessionOutputStoreOptions {
  /** Parent of the store directory; the OS temp directory by default. */
  readonly root?: string;
  /** Opens a file's write stream; tests inject failing sinks. */
  readonly openSink?: (path: string) => Writable;
  /** Free space kept on the temp disk; TEMP_DISK_RESERVE_BYTES by default. */
  readonly reserveBytes?: number;
}

/** One command's persisted full output. */
export class OutputFile {
  #stream: Writable | undefined;
  #written = 0;
  #failure: string | undefined;
  #capped = false;

  constructor(
    readonly path: string,
    stream: Writable | undefined,
    readonly limit: number,
    failure?: string,
  ) {
    this.#failure = failure;
    if (!stream) return;
    // Installed before the first write: an asynchronous ENOSPC or EIO stops
    // persistence and is reported in the result, never thrown at the process.
    stream.on("error", (error: NodeJS.ErrnoException) => {
      this.#failure ??= error.code ?? "write failed";
      this.#stream = undefined;
      stream.destroy();
      // Free what was written; the session directory goes at close anyway.
      try {
        rmSync(this.path, { force: true });
      } catch {
        // Removed at session close.
      }
    });
    this.#stream = stream;
  }

  /** Why the full output is not saved, or undefined when it is. */
  get failure(): string | undefined {
    return this.#failure;
  }

  /** The path to report: undefined when the output could not be saved. */
  get savedPath(): string | undefined {
    return this.#failure ? undefined : this.path;
  }

  /** True when output past the limit was dropped. */
  get capped(): boolean {
    return this.#capped;
  }

  write(data: Buffer): void {
    const stream = this.#stream;
    if (!stream || this.#failure || data.length === 0) return;
    const room = this.limit - this.#written;
    if (data.length > room) this.#capped = true;
    if (room <= 0) return;
    const part = data.length > room ? data.subarray(0, room) : data;
    this.#written += part.length;
    stream.write(part);
  }

  /** Flush and close; resolves after a write error too. */
  close(): Promise<void> {
    const stream = this.#stream;
    this.#stream = undefined;
    if (!stream || stream.destroyed) return Promise.resolve();
    return new Promise((resolve) => {
      stream.once("close", () => resolve());
      stream.end();
    });
  }
}

/**
 * Full shell output owned by one governance session: a private directory
 * created on first use, removed with everything in it at dispose(). It also
 * removes the `pi-bash-*.log` files Pi wrote for this session's `!` commands.
 */
export class SessionOutputStore {
  readonly openedAt = Date.now();
  #dir: string | undefined;
  #root: string | undefined;
  #userBashLogs = new Set<string>();
  #disposed = false;

  constructor(private readonly options: SessionOutputStoreOptions = {}) {}

  /** The store directory, once created. */
  get dir(): string | undefined {
    return this.#dir;
  }

  #ensureDir(): string {
    if (this.#dir) return this.#dir;
    const root = this.options.root ?? tmpdir();
    const dir = mkdtempSync(join(root, OUTPUT_DIR_PREFIX));
    // mkdtemp creates 0700. The owner record lets a later session remove the
    // directory of a process that died before it could.
    try {
      writeFileSync(
        join(dir, OWNER_FILE),
        JSON.stringify({ pid: process.pid, host: hostname() }),
        { mode: 0o600 },
      );
    } catch (error) {
      rmSync(dir, { recursive: true, force: true });
      throw error;
    }
    this.#root = root;
    this.#dir = dir;
    return dir;
  }

  /** A new output file; a setup failure is recorded on it, never thrown. */
  createFile(): OutputFile {
    const name = `bash-${randomBytes(8).toString("hex")}.log`;
    if (this.#disposed) return new OutputFile(name, undefined, 0, "closed");
    let dir: string;
    try {
      dir = this.#ensureDir();
    } catch (error) {
      return new OutputFile(
        name,
        undefined,
        0,
        (error as NodeJS.ErrnoException).code ?? "unavailable",
      );
    }
    const path = join(dir, name);
    const free = freeBytes(dir);
    const reserve = this.options.reserveBytes ?? TEMP_DISK_RESERVE_BYTES;
    const limit =
      free === undefined
        ? PERSIST_LIMIT_BYTES
        : Math.min(PERSIST_LIMIT_BYTES, free - reserve);
    if (limit <= 0)
      return new OutputFile(path, undefined, 0, "temporary disk nearly full");
    const open =
      this.options.openSink ??
      ((file: string) => createWriteStream(file, { flags: "wx", mode: 0o600 }));
    try {
      return new OutputFile(path, open(path), limit);
    } catch (error) {
      return new OutputFile(
        path,
        undefined,
        0,
        (error as NodeJS.ErrnoException).code ?? "unavailable",
      );
    }
  }

  /**
   * Record the full-output files Pi wrote for this session's `!` commands,
   * read from the session entries; removed at dispose().
   */
  adoptUserBashOutput(entries: readonly unknown[]): void {
    for (const entry of entries) {
      const message = (entry as { type?: string; message?: unknown }).message as
        | { role?: string; fullOutputPath?: unknown; timestamp?: unknown }
        | undefined;
      if ((entry as { type?: string }).type !== "message" || !message) continue;
      if (message.role !== "bashExecution") continue;
      const path = message.fullOutputPath;
      if (typeof path !== "string" || !isAbsolute(path)) continue;
      if (typeof message.timestamp !== "number") continue;
      if (message.timestamp < this.openedAt) continue;
      this.#userBashLogs.add(path);
    }
  }

  /** Remove this session's output. Never throws. */
  async dispose(): Promise<void> {
    this.#disposed = true;
    for (const path of this.#userBashLogs) removeUserBashLog(path);
    this.#userBashLogs.clear();
    const dir = this.#dir;
    const root = this.#root;
    this.#dir = undefined;
    if (!dir || !root) return;
    try {
      // Only the directory this store created: under its root, by name.
      const real = realpathSync(dir);
      if (
        dirname(real) === realpathSync(root) &&
        basename(real).startsWith(OUTPUT_DIR_PREFIX)
      )
        rmSync(real, { recursive: true, force: true });
    } catch {
      // Already gone, or left for the next session's sweep.
    }
  }

  /**
   * Remove the store directories of dead PiShip processes: owned by this
   * user, mode 0700, and recording a process on this host that no longer
   * runs. Anything else is left alone. Never throws; POSIX only.
   */
  static sweep(root: string = tmpdir()): void {
    const me = uid();
    if (me === undefined) return;
    let names: string[];
    try {
      names = readdirSync(root);
    } catch {
      return;
    }
    for (const name of names) {
      if (!name.startsWith(OUTPUT_DIR_PREFIX)) continue;
      const dir = join(root, name);
      try {
        const stats = lstatSync(dir);
        if (!stats.isDirectory() || stats.uid !== me) continue;
        if ((stats.mode & 0o777) !== 0o700) continue;
        const owner = JSON.parse(
          readFileSync(join(dir, OWNER_FILE), "utf8"),
        ) as { pid?: unknown; host?: unknown };
        if (typeof owner.pid !== "number" || owner.host !== hostname())
          continue;
        if (owner.pid === process.pid || alive(owner.pid)) continue;
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Unreadable or concurrently removed: not provably abandoned.
      }
    }
  }
}

/**
 * Remove a Pi `!` output file: a regular file named as Pi names it, directly
 * in the OS temp directory, owned by this user. Anything else is kept.
 */
function removeUserBashLog(path: string): void {
  try {
    if (!PI_BASH_LOG.test(basename(path))) return;
    const stats = lstatSync(path);
    if (!stats.isFile()) return;
    const me = uid();
    if (me !== undefined && stats.uid !== me) return;
    if (dirname(realpathSync(path)) !== realpathSync(tmpdir())) return;
    unlinkSync(path);
  } catch {
    // Already gone.
  }
}

/** The rolling display tail of one command, persisting through the store. */
export class ShellOutput {
  readonly #maxRollingBytes = Math.max(DEFAULT_MAX_BYTES * 2, 1);
  #decoder = new TextDecoder();
  #rawChunks: Buffer[] = [];
  #tailText = "";
  #tailBytes = 0;
  #tailStartsAtLineBoundary = true;
  #totalRawBytes = 0;
  #totalDecodedBytes = 0;
  #completedLines = 0;
  #totalLines = 0;
  #currentLineBytes = 0;
  #hasOpenLine = false;
  #finished = false;
  #file: OutputFile | undefined;

  constructor(private readonly store: SessionOutputStore) {}

  get file(): OutputFile | undefined {
    return this.#file;
  }

  get lastLineBytes(): number {
    return this.#currentLineBytes;
  }

  append(data: Buffer): void {
    if (this.#finished) return;
    this.#totalRawBytes += data.length;
    this.#appendText(this.#decoder.decode(data, { stream: true }));
    if (this.#file || this.#shouldPersist()) {
      this.#ensureFile().write(data);
    } else if (data.length > 0) {
      this.#rawChunks.push(data);
    }
  }

  finish(): void {
    if (this.#finished) return;
    this.#finished = true;
    this.#appendText(this.#decoder.decode());
    if (this.#shouldPersist()) this.#ensureFile();
  }

  snapshot(): {
    content: string;
    truncation: TruncationResult;
    fullOutputPath: string | undefined;
  } {
    const tail = truncateTail(this.#snapshotText(), {
      maxLines: DEFAULT_MAX_LINES,
      maxBytes: DEFAULT_MAX_BYTES,
    });
    const truncated =
      this.#totalLines > DEFAULT_MAX_LINES ||
      this.#totalDecodedBytes > DEFAULT_MAX_BYTES;
    const truncatedBy = truncated
      ? (tail.truncatedBy ??
        (this.#totalDecodedBytes > DEFAULT_MAX_BYTES ? "bytes" : "lines"))
      : null;
    const truncation: TruncationResult = {
      ...tail,
      truncated,
      truncatedBy,
      totalLines: this.#totalLines,
      totalBytes: this.#totalDecodedBytes,
      maxLines: DEFAULT_MAX_LINES,
      maxBytes: DEFAULT_MAX_BYTES,
    };
    if (truncated) this.#ensureFile();
    return {
      content: truncation.content,
      truncation,
      fullOutputPath: this.#file?.savedPath,
    };
  }

  close(): Promise<void> {
    return this.#file?.close() ?? Promise.resolve();
  }

  #ensureFile(): OutputFile {
    if (this.#file) return this.#file;
    const file = this.store.createFile();
    this.#file = file;
    for (const chunk of this.#rawChunks) file.write(chunk);
    this.#rawChunks = [];
    return file;
  }

  #shouldPersist(): boolean {
    return (
      this.#totalRawBytes > DEFAULT_MAX_BYTES ||
      this.#totalDecodedBytes > DEFAULT_MAX_BYTES ||
      this.#totalLines > DEFAULT_MAX_LINES
    );
  }

  #appendText(text: string): void {
    if (text.length === 0) return;
    const bytes = Buffer.byteLength(text, "utf-8");
    this.#totalDecodedBytes += bytes;
    this.#tailText += text;
    this.#tailBytes += bytes;
    if (this.#tailBytes > this.#maxRollingBytes * 2) this.#trimTail();
    let newlines = 0;
    let lastNewline = -1;
    for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) {
      newlines++;
      lastNewline = i;
    }
    if (newlines === 0) {
      this.#currentLineBytes += bytes;
      this.#hasOpenLine = true;
    } else {
      this.#completedLines += newlines;
      const rest = text.slice(lastNewline + 1);
      this.#currentLineBytes = Buffer.byteLength(rest, "utf-8");
      this.#hasOpenLine = rest.length > 0;
    }
    this.#totalLines = this.#completedLines + (this.#hasOpenLine ? 1 : 0);
  }

  #trimTail(): void {
    const buffer = Buffer.from(this.#tailText, "utf-8");
    if (buffer.length <= this.#maxRollingBytes) {
      this.#tailBytes = buffer.length;
      return;
    }
    let start = buffer.length - this.#maxRollingBytes;
    while (start < buffer.length && ((buffer[start] ?? 0) & 0xc0) === 0x80)
      start++;
    this.#tailStartsAtLineBoundary =
      start === 0 ? this.#tailStartsAtLineBoundary : buffer[start - 1] === 0x0a;
    this.#tailText = buffer.subarray(start).toString("utf-8");
    this.#tailBytes = Buffer.byteLength(this.#tailText, "utf-8");
  }

  #snapshotText(): string {
    if (this.#tailStartsAtLineBoundary) return this.#tailText;
    const firstNewline = this.#tailText.indexOf("\n");
    return firstNewline === -1
      ? this.#tailText
      : this.#tailText.slice(firstNewline + 1);
  }
}
