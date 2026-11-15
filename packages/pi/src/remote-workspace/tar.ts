// A minimal ustar writer: regular files only, no dependency. Names over 100
// bytes use the ustar prefix field; a name that does not fit is refused.
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

function splitName(path: string): { name: Buffer; prefix: Buffer } {
  const whole = Buffer.from(path, "utf8");
  if (whole.length <= 100) return { name: whole, prefix: Buffer.alloc(0) };
  for (let at = path.indexOf("/"); at !== -1; at = path.indexOf("/", at + 1)) {
    const prefix = Buffer.from(path.slice(0, at), "utf8");
    const name = Buffer.from(path.slice(at + 1), "utf8");
    if (prefix.length <= 155 && name.length <= 100 && name.length > 0)
      return { name, prefix };
  }
  throw new Error(`the path is too long for the seed archive: ${path}`);
}

function header(entry: TarEntry): Buffer {
  const { name, prefix } = splitName(entry.path);
  const block = Buffer.alloc(BLOCK);
  name.copy(block, 0);
  octal(entry.mode & 0o777, 8).copy(block, 100);
  octal(0, 8).copy(block, 108);
  octal(0, 8).copy(block, 116);
  octal(entry.data.length, 12).copy(block, 124);
  octal(0, 12).copy(block, 136);
  block.fill(0x20, 148, 156); // the checksum counts itself as spaces
  block.write("0", 156);
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
    parts.push(header(entry), entry.data);
    const pad = (BLOCK - (entry.data.length % BLOCK)) % BLOCK;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(BLOCK * 2));
  return Buffer.concat(parts);
}
