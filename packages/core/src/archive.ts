// Deterministic ustar + gzip release archives, and a strict extractor for
// them. Dependency-free and streaming so large payloads never sit in memory.
import { createHash } from "node:crypto";
import {
  createReadStream,
  createWriteStream,
  readdirSync,
  rmSync,
} from "node:fs";
import {
  type FileHandle,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip, createGzip } from "node:zlib";

export interface ArchiveResult {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly entries: number;
}

export interface ExtractResult {
  readonly root: string;
  readonly entries: number;
  readonly bytes: number;
}

const BLOCK = 512;
const CHUNK = 1 << 20;
/** Largest size or mtime a 12-byte ustar octal field can hold. */
const OCTAL_12_MAX = 8 ** 11 - 1;
const MAX_PAX_BYTES = 1 << 20;
const DEFAULT_MAX_BYTES = 2 * 1024 ** 3;
const DEFAULT_MAX_ENTRIES = 200_000;
const WINDOWS = process.platform === "win32";
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$/i;
const utf8 = new TextDecoder("utf-8", { fatal: true });

interface SourceEntry {
  /** Tar name: `<root>/...`, with a trailing `/` for directories. */
  readonly name: string;
  readonly key: Buffer;
  readonly absolute?: string;
  readonly size: number;
  readonly mode: number;
}

function compareBytes(a: SourceEntry, b: SourceEntry): number {
  return Buffer.compare(a.key, b.key);
}

/** True for a path segment that is unsafe on any supported platform. */
function unsafeSegment(segment: string): boolean {
  if (
    segment === "" ||
    segment === "." ||
    segment === ".." ||
    segment.includes("/") ||
    segment.includes("\\") ||
    /^[A-Za-z]:/.test(segment)
  )
    return true;
  for (let i = 0; i < segment.length; i++) {
    const code = segment.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function checkSegment(segment: string, path: string): void {
  if (unsafeSegment(segment))
    throw new Error(`Unsupported path in archive source: ${path}`);
}

function resolveMtime(mtime: number | undefined): number {
  if (mtime !== undefined) {
    if (!Number.isInteger(mtime) || mtime < 0 || mtime > OCTAL_12_MAX)
      throw new Error(`Invalid archive mtime: ${mtime}`);
    return mtime;
  }
  const raw = process.env.SOURCE_DATE_EPOCH;
  if (raw !== undefined && /^[0-9]+$/.test(raw)) {
    const epoch = Number(raw);
    if (Number.isSafeInteger(epoch) && epoch <= OCTAL_12_MAX) return epoch;
  }
  return 0;
}

async function collect(
  sourceDir: string,
  rootName: string,
  executable: ((relativePath: string) => boolean) | undefined,
): Promise<SourceEntry[]> {
  const rootEntry = `${rootName}/`;
  const entries: SourceEntry[] = [
    { name: rootEntry, key: Buffer.from(rootEntry), size: 0, mode: 0o755 },
  ];
  const pending: string[] = [""];
  for (let rel = pending.pop(); rel !== undefined; rel = pending.pop()) {
    const dir = rel === "" ? sourceDir : join(sourceDir, ...rel.split("/"));
    const names = await readdir(dir);
    const stats = await Promise.all(
      names.map(async (name) => {
        const childRel = rel === "" ? name : `${rel}/${name}`;
        checkSegment(name, join(dir, name));
        const absolute = join(dir, name);
        return { childRel, absolute, stats: await lstat(absolute) };
      }),
    );
    for (const { childRel, absolute, stats: info } of stats) {
      if (info.isDirectory()) {
        const name = `${rootName}/${childRel}/`;
        entries.push({ name, key: Buffer.from(name), size: 0, mode: 0o755 });
        pending.push(childRel);
      } else if (info.isFile()) {
        const name = `${rootName}/${childRel}`;
        const exec =
          executable?.(childRel) === true ||
          (!WINDOWS && (info.mode & 0o111) !== 0);
        entries.push({
          name,
          key: Buffer.from(name),
          absolute,
          size: info.size,
          mode: exec ? 0o755 : 0o644,
        });
      } else {
        const kind = info.isSymbolicLink() ? "symbolic link" : "special file";
        throw new Error(`Cannot archive ${kind}: ${absolute}`);
      }
    }
  }
  return entries.sort(compareBytes);
}

function writeOctal(
  block: Buffer,
  offset: number,
  width: number,
  value: number,
): void {
  const digits = value.toString(8).padStart(width - 1, "0");
  if (digits.length > width - 1)
    throw new Error(`Value ${value} does not fit a tar header field`);
  block.write(`${digits}\0`, offset, "latin1");
}

function header(
  name: string,
  prefix: string,
  type: string,
  mode: number,
  size: number,
  mtime: number,
): Buffer {
  const block = Buffer.alloc(BLOCK);
  block.write(name, 0, 100, "latin1");
  writeOctal(block, 100, 8, mode);
  writeOctal(block, 108, 8, 0);
  writeOctal(block, 116, 8, 0);
  writeOctal(block, 124, 12, size);
  writeOctal(block, 136, 12, mtime);
  block.fill(0x20, 148, 156);
  block.write(type, 156, 1, "latin1");
  block.write("ustar\0", 257, "latin1");
  block.write("00", 263, "latin1");
  writeOctal(block, 329, 8, 0);
  writeOctal(block, 337, 8, 0);
  block.write(prefix, 345, 155, "latin1");
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return block;
}

/** Split into ustar name/prefix fields, or undefined when PAX is needed. */
function ustarFields(path: string): [string, string] | undefined {
  if (!/^[\x20-\x7e]*$/.test(path)) return undefined;
  if (path.length <= 100) return [path, ""];
  for (let i = path.indexOf("/"); i !== -1; i = path.indexOf("/", i + 1)) {
    if (i > 155) break;
    const name = path.slice(i + 1);
    if (i > 0 && name.length > 0 && name.length <= 100)
      return [name, path.slice(0, i)];
  }
  return undefined;
}

function paxRecord(key: string, value: string): string {
  const body = ` ${key}=${value}\n`;
  const length = Buffer.byteLength(body);
  let digits = 1;
  while (String(length + digits).length > digits) digits++;
  return `${length + digits}${body}`;
}

function padding(size: number): number {
  return (BLOCK - (size % BLOCK)) % BLOCK;
}

function entryHeaders(
  entry: SourceEntry,
  index: number,
  mtime: number,
): Buffer[] {
  const type = entry.name.endsWith("/") ? "5" : "0";
  const fields = ustarFields(entry.name);
  const records: string[] = [];
  if (fields === undefined) records.push(paxRecord("path", entry.name));
  if (entry.size > OCTAL_12_MAX)
    records.push(paxRecord("size", String(entry.size)));
  const [name, prefix] = fields ?? [
    entry.name.replace(/[^\x20-\x7e]/g, "_").slice(-100),
    "",
  ];
  const size = entry.size > OCTAL_12_MAX ? 0 : entry.size;
  const main = header(name, prefix, type, entry.mode, size, mtime);
  if (records.length === 0) return [main];
  const data = Buffer.from(records.join(""));
  return [
    header(`PaxHeader/${index}`, "", "x", 0o644, data.length, mtime),
    data,
    Buffer.alloc(padding(data.length)),
    main,
  ];
}

async function* tarStream(
  entries: readonly SourceEntry[],
  mtime: number,
): AsyncGenerator<Buffer> {
  let parts: Buffer[] = [];
  let pending = 0;
  const take = (): Buffer => {
    const out = Buffer.concat(parts, pending);
    parts = [];
    pending = 0;
    return out;
  };
  const add = (buffer: Buffer): void => {
    parts.push(buffer);
    pending += buffer.length;
  };
  for (const [index, entry] of entries.entries()) {
    for (const part of entryHeaders(entry, index, mtime)) add(part);
    if (pending >= CHUNK) yield take();
    if (entry.absolute === undefined) continue;
    const handle = await open(entry.absolute, "r");
    try {
      let remaining = entry.size;
      while (remaining > 0) {
        const buffer = Buffer.allocUnsafe(Math.min(remaining, CHUNK));
        let filled = 0;
        while (filled < buffer.length) {
          const { bytesRead } = await handle.read(
            buffer,
            filled,
            buffer.length - filled,
            null,
          );
          if (bytesRead === 0)
            throw new Error(`File changed while archiving: ${entry.absolute}`);
          filled += bytesRead;
        }
        remaining -= buffer.length;
        if (buffer.length >= CHUNK) {
          if (pending > 0) yield take();
          yield buffer;
        } else {
          add(buffer);
          if (pending >= CHUNK) yield take();
        }
      }
      if ((await handle.stat()).size !== entry.size)
        throw new Error(`File changed while archiving: ${entry.absolute}`);
    } finally {
      await handle.close();
    }
    add(Buffer.alloc(padding(entry.size)));
    if (pending >= CHUNK) yield take();
  }
  add(Buffer.alloc(BLOCK * 2));
  yield take();
}

/** Lowercase hex SHA-256 of a file's contents. */
export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/**
 * Write `sourceDir` as `<rootName>/...` into a deterministic .tar.gz.
 * `executable` receives `/`-separated paths relative to `sourceDir`.
 */
export async function createArchive(
  sourceDir: string,
  rootName: string,
  outFile: string,
  options: {
    readonly mtime?: number;
    readonly executable?: (relativePath: string) => boolean;
  } = {},
): Promise<ArchiveResult> {
  checkSegment(rootName, rootName);
  const source = resolve(sourceDir);
  const out = resolve(outFile);
  if (!(await stat(source)).isDirectory())
    throw new Error(`Archive source is not a directory: ${source}`);
  const inside = relative(source, out);
  if (!inside.startsWith("..") && !isAbsolute(inside))
    throw new Error(`Archive output must be outside the source: ${out}`);
  const mtime = resolveMtime(options.mtime);
  const entries = await collect(source, rootName, options.executable);
  const partial = `${out}.partial`;
  try {
    await pipeline(
      Readable.from(tarStream(entries, mtime)),
      // Level 9 compressed about 2.7x slower than 6 for an archive under
      // 0.5% smaller.
      createGzip({ level: 6 }),
      createWriteStream(partial),
    );
    // zlib records the build platform in the OS byte; normalize it.
    const handle = await open(partial, "r+");
    try {
      const head = Buffer.alloc(10);
      await handle.read(head, 0, 10, 0);
      if (head[0] !== 0x1f || head[1] !== 0x8b)
        throw new Error(`Unexpected gzip header in ${partial}`);
      head.fill(0, 4, 8);
      head[9] = 0xff;
      await handle.write(head, 0, 10, 0);
    } finally {
      await handle.close();
    }
    const sha256 = await sha256File(partial);
    const { size } = await stat(partial);
    await rename(partial, out);
    return { path: out, sha256, bytes: size, entries: entries.length };
  } catch (error) {
    await rm(partial, { force: true });
    throw error;
  }
}

function octalField(block: Buffer, offset: number, width: number): number {
  const text = block
    .toString("latin1", offset, offset + width)
    .replace(/[\0 ]+$/, "")
    .replace(/^ +/, "");
  if (!/^[0-7]*$/.test(text))
    throw new Error("Corrupt archive: invalid numeric header field");
  return text === "" ? 0 : Number.parseInt(text, 8);
}

function stringField(block: Buffer, offset: number, width: number): string {
  const field = block.subarray(offset, offset + width);
  const end = field.indexOf(0);
  try {
    return utf8.decode(end === -1 ? field : field.subarray(0, end));
  } catch {
    throw new Error("Corrupt archive: header name is not valid UTF-8");
  }
}

function parsePax(data: Buffer): Map<string, string> {
  const records = new Map<string, string>();
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const lengthText =
      space === -1 ? "" : data.toString("latin1", offset, space);
    if (!/^[1-9][0-9]{0,7}$/.test(lengthText))
      throw new Error("Corrupt archive: malformed PAX record");
    const end = offset + Number(lengthText);
    if (end > data.length || data[end - 1] !== 0x0a)
      throw new Error("Corrupt archive: malformed PAX record");
    let record: string;
    try {
      record = utf8.decode(data.subarray(space + 1, end - 1));
    } catch {
      throw new Error("Corrupt archive: PAX record is not valid UTF-8");
    }
    const equals = record.indexOf("=");
    if (equals <= 0) throw new Error("Corrupt archive: malformed PAX record");
    records.set(record.slice(0, equals), record.slice(equals + 1));
    offset = end;
  }
  return records;
}

/**
 * Validated `/` segments of an entry path; throws on anything unsafe. The
 * search tool reader applies the same rules to upstream archives.
 */
export function entrySegments(path: string, directory: boolean): string[] {
  const unsafe = () =>
    new Error(`Unsafe archive entry path: ${JSON.stringify(path)}`);
  const trimmed = directory && path.endsWith("/") ? path.slice(0, -1) : path;
  if (trimmed === "" || path.startsWith("/")) throw unsafe();
  const segments = trimmed.split("/");
  for (const segment of segments) {
    if (unsafeSegment(segment)) throw unsafe();
    if (
      WINDOWS &&
      (segment.includes(":") ||
        /[<>"|?*]/.test(segment) ||
        /[. ]$/.test(segment) ||
        WINDOWS_DEVICE.test(segment))
    )
      throw unsafe();
  }
  return segments;
}

type ParserState =
  | { readonly kind: "header" }
  | { readonly kind: "file"; remaining: number; readonly pad: number }
  | {
      readonly kind: "pax";
      readonly data: Buffer;
      filled: number;
      readonly pad: number;
      readonly global: boolean;
    }
  | { readonly kind: "skip"; remaining: number }
  | { readonly kind: "end" };

/** Extract a .tar.gz produced by createArchive into `destination` (must not exist or be empty). */
export async function extractArchive(
  archive: string,
  destination: string,
  options: {
    readonly expectedRoot?: string;
    readonly maxBytes?: number;
    readonly maxEntries?: number;
  } = {},
): Promise<ExtractResult> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxHeaders = maxEntries * 3 + 16;
  const target = resolve(destination);
  let created = false;
  try {
    const info = await stat(target);
    if (!info.isDirectory())
      throw new Error(`Extraction destination is not a directory: ${target}`);
    if (readdirSync(target).length > 0)
      throw new Error(`Extraction destination is not empty: ${target}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await mkdir(target, { recursive: true });
    created = true;
  }

  let root = options.expectedRoot;
  let entries = 0;
  let headers = 0;
  let bytes = 0;
  let zeroBlocks = 0;
  let pax: Map<string, string> | undefined;
  let state: ParserState = { kind: "header" };
  let handle: FileHandle | undefined;
  const block = Buffer.alloc(BLOCK);
  let blockFilled = 0;
  const seen = new Set<string>();
  const directories = new Set<string>([target]);

  const ensureDirectory = async (dir: string): Promise<void> => {
    if (directories.has(dir)) return;
    await mkdir(dir, { recursive: true, mode: 0o755 });
    directories.add(dir);
  };

  const finishFile = async (pad: number): Promise<void> => {
    await handle?.close();
    handle = undefined;
    state = pad > 0 ? { kind: "skip", remaining: pad } : { kind: "header" };
  };

  const onHeader = async (): Promise<void> => {
    if (block.every((byte) => byte === 0)) {
      if (pax !== undefined)
        throw new Error("Corrupt archive: PAX header without an entry");
      zeroBlocks++;
      if (zeroBlocks === 2) state = { kind: "end" };
      return;
    }
    if (zeroBlocks > 0)
      throw new Error("Corrupt archive: data after end marker");
    if (++headers > maxHeaders)
      throw new Error(`Archive has more than ${maxEntries} entries`);
    let sum = 0;
    for (let i = 0; i < BLOCK; i++)
      sum += i >= 148 && i < 156 ? 0x20 : (block[i] as number);
    if (octalField(block, 148, 8) !== sum)
      throw new Error("Corrupt archive: header checksum mismatch");
    if (block.toString("latin1", 257, 262) !== "ustar")
      throw new Error("Corrupt archive: not a ustar header");
    const type = String.fromCharCode(block[156] as number);
    const paxSize = pax?.get("size");
    if (paxSize !== undefined && !/^[0-9]{1,16}$/.test(paxSize))
      throw new Error("Corrupt archive: invalid PAX size");
    const size =
      paxSize !== undefined ? Number(paxSize) : octalField(block, 124, 12);
    if (!Number.isSafeInteger(size))
      throw new Error("Corrupt archive: invalid entry size");

    if (type === "x" || type === "g") {
      if (pax !== undefined)
        throw new Error("Corrupt archive: consecutive PAX headers");
      if (size > MAX_PAX_BYTES)
        throw new Error("Corrupt archive: PAX header too large");
      state = {
        kind: "pax",
        data: Buffer.alloc(size),
        filled: 0,
        pad: padding(size),
        global: type === "g",
      };
      if (size === 0) await endPax();
      return;
    }

    const prefix = stringField(block, 345, 155);
    const name = stringField(block, 0, 100);
    const path =
      pax?.get("path") ?? (prefix === "" ? name : `${prefix}/${name}`);
    pax = undefined;
    if (type !== "0" && type !== "\0" && type !== "5")
      throw new Error(
        `Unsupported archive entry type ${JSON.stringify(type)}: ${path}`,
      );
    const directory = type === "5";
    const segments = entrySegments(path, directory);
    if (++entries > maxEntries)
      throw new Error(`Archive has more than ${maxEntries} entries`);
    root ??= segments[0];
    if (segments[0] !== root)
      throw new Error(
        `Archive entry outside root ${JSON.stringify(root)}: ${path}`,
      );
    if (segments.length === 1 && !directory)
      throw new Error(`Archive root is not a directory: ${path}`);
    const key = segments.join("/");
    if (seen.has(key)) throw new Error(`Duplicate archive entry: ${path}`);
    seen.add(key);
    const output = resolve(target, ...segments);
    const inside = relative(target, output);
    if (inside === "" || inside.startsWith("..") || isAbsolute(inside))
      throw new Error(`Unsafe archive entry path: ${JSON.stringify(path)}`);

    if (directory) {
      if (size !== 0)
        throw new Error(`Corrupt archive: directory with data: ${path}`);
      await ensureDirectory(output);
      return;
    }
    bytes += size;
    if (bytes > maxBytes)
      throw new Error(`Archive content exceeds ${maxBytes} bytes`);
    const mode = (octalField(block, 100, 8) & 0o111) !== 0 ? 0o755 : 0o644;
    await ensureDirectory(dirname(output));
    handle = await open(output, "wx", mode);
    if (!WINDOWS) await handle.chmod(mode);
    state = { kind: "file", remaining: size, pad: padding(size) };
    if (size === 0) await finishFile(padding(size));
  };

  const endPax = async (): Promise<void> => {
    if (state.kind !== "pax") return;
    const { data, pad, global } = state;
    if (!global) pax = parsePax(data);
    state = pad > 0 ? { kind: "skip", remaining: pad } : { kind: "header" };
  };

  const consume = async (chunk: Buffer): Promise<void> => {
    let offset = 0;
    while (offset < chunk.length) {
      const available = chunk.length - offset;
      switch (state.kind) {
        case "end": {
          for (let i = offset; i < chunk.length; i++)
            if (chunk[i] !== 0)
              throw new Error("Corrupt archive: data after end marker");
          return;
        }
        case "header": {
          const count = Math.min(BLOCK - blockFilled, available);
          chunk.copy(block, blockFilled, offset, offset + count);
          blockFilled += count;
          offset += count;
          if (blockFilled === BLOCK) {
            blockFilled = 0;
            await onHeader();
          }
          break;
        }
        case "file": {
          const count = Math.min(state.remaining, available);
          let written = 0;
          while (written < count) {
            const result = await (handle as FileHandle).write(
              chunk,
              offset + written,
              count - written,
            );
            written += result.bytesWritten;
          }
          offset += count;
          state.remaining -= count;
          if (state.remaining === 0) await finishFile(state.pad);
          break;
        }
        case "pax": {
          const count = Math.min(state.data.length - state.filled, available);
          chunk.copy(state.data, state.filled, offset, offset + count);
          state.filled += count;
          offset += count;
          if (state.filled === state.data.length) await endPax();
          break;
        }
        case "skip": {
          const count = Math.min(state.remaining, available);
          offset += count;
          state.remaining -= count;
          if (state.remaining === 0) state = { kind: "header" };
          break;
        }
      }
    }
  };

  try {
    // Surface the parser's own error rather than the stream abort it causes.
    let failure: unknown;
    await pipeline(
      createReadStream(archive),
      createGunzip(),
      async (source: AsyncIterable<Buffer>) => {
        try {
          for await (const chunk of source) await consume(chunk);
        } catch (error) {
          failure = error;
          throw error;
        }
      },
    ).catch((error: unknown) => {
      throw failure ?? error;
    });
    if ((state as ParserState).kind !== "end")
      throw new Error("Corrupt archive: unexpected end of archive");
    if (root === undefined || entries === 0)
      throw new Error("Archive has no entries");
    return { root, entries, bytes };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (created) rmSync(target, { recursive: true, force: true });
    else
      for (const child of readdirSync(target))
        rmSync(join(target, child), { recursive: true, force: true });
    throw error;
  }
}
