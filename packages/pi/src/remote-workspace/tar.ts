// A minimal ustar writer: regular files only, no dependency. Names over 100
// bytes use the ustar prefix field; one that does not fit gets a GNU
// `././@LongLink` entry, which GNU tar, busybox tar and bsdtar all extract.
const BLOCK = 512;

export interface TarEntry {
  /** Workspace-relative, `/` separators. */
  readonly path: string;
  /** Permission bits, such as 0o644 or 0o755. */
  readonly mode: number;
  readonly data: Buffer;
}

function octal(value: number, width: number): Buffer {
  return Buffer.from(`${value.toString(8).padStart(width - 1, "0")}\0`);
}

function splitName(path: string): {
  name: Buffer;
  prefix: Buffer;
  long?: true;
} {
  const whole = Buffer.from(path, "utf8");
  if (whole.length <= 100) return { name: whole, prefix: Buffer.alloc(0) };
  for (let at = path.indexOf("/"); at !== -1; at = path.indexOf("/", at + 1)) {
    const prefix = Buffer.from(path.slice(0, at), "utf8");
    const name = Buffer.from(path.slice(at + 1), "utf8");
    if (prefix.length <= 155 && name.length <= 100 && name.length > 0)
      return { name, prefix };
  }
  return { name: whole.subarray(0, 100), prefix: Buffer.alloc(0), long: true };
}

function header(
  entry: TarEntry,
  override?: { name: Buffer; type: string; size: number },
): Buffer {
  const { name, prefix } = override
    ? { name: override.name, prefix: Buffer.alloc(0) }
    : splitName(entry.path);
  const block = Buffer.alloc(BLOCK);
  name.copy(block, 0);
  octal(entry.mode & 0o777, 8).copy(block, 100);
  octal(0, 8).copy(block, 108);
  octal(0, 8).copy(block, 116);
  octal(override?.size ?? entry.data.length, 12).copy(block, 124);
  octal(0, 12).copy(block, 136);
  block.fill(0x20, 148, 156); // the checksum counts itself as spaces
  block.write(override?.type ?? "0", 156);
  block.write("ustar\0", 257);
  block.write("00", 263);
  prefix.copy(block, 345);
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
  return block;
}

export function packTar(entries: readonly TarEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    if (Buffer.from(entry.path, "utf8").includes(0))
      throw new Error("a path contains a NUL byte");
    if (splitName(entry.path).long) {
      const name = Buffer.concat([
        Buffer.from(entry.path, "utf8"),
        Buffer.alloc(1),
      ]);
      parts.push(
        header(entry, {
          name: Buffer.from("././@LongLink"),
          type: "L",
          size: name.length,
        }),
        name,
        Buffer.alloc((BLOCK - (name.length % BLOCK)) % BLOCK),
      );
    }
    parts.push(header(entry), entry.data);
    const pad = (BLOCK - (entry.data.length % BLOCK)) % BLOCK;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(BLOCK * 2));
  return Buffer.concat(parts);
}
