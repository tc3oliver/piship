// A strict in-memory reader for the upstream search tool archives (.tar.gz
// and .zip). Nothing is written while reading: the caller gets the bytes of
// the executable and its license files. Every entry is checked against the
// release extractor's path rules, and links, devices, and any other
// non-regular entry fail the whole archive, so an archive that would be
// unsafe to unpack is refused even though only a few files are taken.
import { crc32, gunzipSync, inflateRawSync } from "node:zlib";
import { entrySegments } from "../archive.js";

/** Upstream archives are a few MB; this bounds decompression. */
const MAX_UNPACKED_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const LICENSE_FILE =
  /^(LICENSE|LICENCE|COPYING|UNLICENSE|NOTICE)([-._][A-Za-z0-9.-]*)?$/i;

export interface SearchToolFiles {
  /** The executable's path inside the archive. */
  readonly entry: string;
  readonly binary: Buffer;
  /** License files beside the executable, by file name. */
  readonly licenses: ReadonlyMap<string, Buffer>;
}

interface Entry {
  readonly path: string;
  readonly directory: boolean;
  readonly read: () => Buffer;
}

function corrupt(message: string): Error {
  return new Error(`Corrupt search tool archive: ${message}`);
}

/** Every entry of a gzip-compressed ustar or GNU tar archive. */
function tarEntries(archive: Buffer): Entry[] {
  let data: Buffer;
  try {
    data = gunzipSync(archive, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch (error) {
    throw corrupt((error as Error).message);
  }
  const entries: Entry[] = [];
  let pax: Map<string, string> | undefined;
  let offset = 0;
  while (offset + 512 <= data.length) {
    const block = data.subarray(offset, offset + 512);
    if (block.every((byte) => byte === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++)
      sum += i >= 148 && i < 156 ? 0x20 : (block[i] as number);
    const field = (start: number, width: number) =>
      block
        .toString("latin1", start, start + width)
        .replace(/\0.*$/s, "")
        .trim();
    const octal = (start: number, width: number) => {
      const text = field(start, width);
      if (!/^[0-7]*$/.test(text)) throw corrupt("invalid numeric field");
      return text === "" ? 0 : Number.parseInt(text, 8);
    };
    if (octal(148, 8) !== sum) throw corrupt("header checksum mismatch");
    if (block.toString("latin1", 257, 262) !== "ustar")
      throw corrupt("not a ustar header");
    const type = String.fromCharCode(block[156] as number);
    const size = pax?.has("size") ? Number(pax.get("size")) : octal(124, 12);
    if (!Number.isSafeInteger(size) || size < 0)
      throw corrupt("invalid entry size");
    const start = offset + 512;
    const end = start + size;
    if (end > data.length) throw corrupt("unexpected end of archive");
    offset = start + Math.ceil(size / 512) * 512;
    if (type === "x" || type === "g") {
      // A global header sets defaults this reader does not use; a per-entry
      // header can rename the next entry, so it is honored.
      if (type === "x") pax = parsePax(data.subarray(start, end));
      continue;
    }
    const prefix = field(345, 155);
    const name = field(0, 100);
    const path =
      pax?.get("path") ?? (prefix === "" ? name : `${prefix}/${name}`);
    pax = undefined;
    if (type !== "0" && type !== "\0" && type !== "5")
      throw new Error(
        `Search tool archive entry ${JSON.stringify(path)} is not a regular file or directory (type ${JSON.stringify(type)}); links and special files are refused`,
      );
    entries.push({
      path,
      directory: type === "5",
      read: () => Buffer.from(data.subarray(start, end)),
    });
    if (entries.length > MAX_ENTRIES) throw corrupt("too many entries");
  }
  return entries;
}

function parsePax(data: Buffer): Map<string, string> {
  const records = new Map<string, string>();
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const length = Number(data.toString("latin1", offset, space));
    if (space === -1 || !Number.isSafeInteger(length) || length <= 0)
      throw corrupt("malformed PAX record");
    const record = data.toString("utf8", space + 1, offset + length - 1);
    const equals = record.indexOf("=");
    if (equals <= 0) throw corrupt("malformed PAX record");
    records.set(record.slice(0, equals), record.slice(equals + 1));
    offset += length;
  }
  return records;
}

/** Every entry of a zip archive, from its central directory. */
function zipEntries(archive: Buffer): Entry[] {
  const minimum = Math.max(0, archive.length - 65_557);
  let eocd = -1;
  for (let i = archive.length - 22; i >= minimum; i--)
    if (archive.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  if (eocd === -1) throw corrupt("no zip end of central directory");
  const count = archive.readUInt16LE(eocd + 10);
  let offset = archive.readUInt32LE(eocd + 16);
  if (count > MAX_ENTRIES) throw corrupt("too many entries");
  const entries: Entry[] = [];
  let unpacked = 0;
  for (let index = 0; index < count; index++) {
    if (
      offset + 46 > archive.length ||
      archive.readUInt32LE(offset) !== 0x02014b50
    )
      throw corrupt("bad central directory entry");
    const madeBy = archive.readUInt16LE(offset + 4) >> 8;
    const flags = archive.readUInt16LE(offset + 8);
    const method = archive.readUInt16LE(offset + 10);
    const crc = archive.readUInt32LE(offset + 16);
    const compressed = archive.readUInt32LE(offset + 20);
    const size = archive.readUInt32LE(offset + 24);
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const external = archive.readUInt32LE(offset + 38);
    const local = archive.readUInt32LE(offset + 42);
    const path = archive.toString(
      "utf8",
      offset + 46,
      offset + 46 + nameLength,
    );
    offset += 46 + nameLength + extraLength + commentLength;
    if (flags & 0x1) throw corrupt(`${path} is encrypted`);
    if (
      compressed === 0xffffffff ||
      size === 0xffffffff ||
      local === 0xffffffff
    )
      throw corrupt("zip64 archives are not supported");
    // Unix hosts (3) keep the file type in the high external attribute bits.
    const unixType = madeBy === 3 ? (external >>> 16) & 0o170000 : 0;
    const directory = path.endsWith("/");
    if (unixType !== 0 && unixType !== (directory ? 0o040000 : 0o100000))
      throw new Error(
        `Search tool archive entry ${JSON.stringify(path)} is not a regular file or directory; links and special files are refused`,
      );
    if (method !== 0 && method !== 8)
      throw corrupt(`${path} uses unsupported compression ${method}`);
    unpacked += size;
    if (unpacked > MAX_UNPACKED_BYTES) throw corrupt("content too large");
    entries.push({
      path,
      directory,
      read: () => {
        if (
          local + 30 > archive.length ||
          archive.readUInt32LE(local) !== 0x04034b50
        )
          throw corrupt(`bad local header for ${path}`);
        const start =
          local +
          30 +
          archive.readUInt16LE(local + 26) +
          archive.readUInt16LE(local + 28);
        const raw = archive.subarray(start, start + compressed);
        if (raw.length !== compressed)
          throw corrupt(`unexpected end of data for ${path}`);
        let content: Buffer;
        try {
          content =
            method === 0
              ? Buffer.from(raw)
              : inflateRawSync(raw, { maxOutputLength: size || 1 });
        } catch (error) {
          throw corrupt(`${path}: ${(error as Error).message}`);
        }
        if (content.length !== size || crc32(content) !== crc)
          throw corrupt(`${path} does not match its recorded size and CRC`);
        return content;
      },
    });
  }
  return entries;
}

/**
 * The executable `fileName` and the license files beside it. The archive
 * holds exactly one executable of that name, at its root or in its single
 * top-level directory.
 */
export function readSearchToolArchive(
  archive: Buffer,
  format: "tar.gz" | "zip",
  fileName: string,
): SearchToolFiles {
  const entries = format === "zip" ? zipEntries(archive) : tarEntries(archive);
  const seen = new Set<string>();
  const files = new Map<string, Entry>();
  for (const entry of entries) {
    const segments = entrySegments(entry.path, entry.directory);
    const key = segments.join("/");
    if (seen.has(key))
      throw corrupt(`duplicate entry ${JSON.stringify(entry.path)}`);
    seen.add(key);
    if (!entry.directory) files.set(key, entry);
  }
  const binaries = [...files.keys()].filter((path) => {
    const segments = path.split("/");
    return segments.length <= 2 && segments.at(-1) === fileName;
  });
  if (binaries.length !== 1)
    throw new Error(
      `Search tool archive has ${binaries.length ? "more than one" : "no"} ${fileName} at its root`,
    );
  const entry = binaries[0] as string;
  const directory = entry.includes("/")
    ? entry.slice(0, entry.lastIndexOf("/") + 1)
    : "";
  const licenses = new Map<string, Buffer>();
  for (const [path, file] of [...files].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (!path.startsWith(directory)) continue;
    const name = path.slice(directory.length);
    if (!name.includes("/") && LICENSE_FILE.test(name))
      licenses.set(name, file.read());
  }
  return { entry, binary: (files.get(entry) as Entry).read(), licenses };
}
