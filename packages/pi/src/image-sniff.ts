// The byte checks of Pi's `detectSupportedImageMimeTypeFromFile`, on bytes
// already read through the governed open. Pi's public detector takes a path,
// and opening a host path again would skip that open (a FIFO would block).
// Keep in step with Pi's own rules; image-sniff.test.ts compares them.
const SNIFF_BYTES = 4100;
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

const u8 = (b: Uint8Array, at: number) => b[at] ?? 0;
const u16le = (b: Uint8Array, at: number) => u8(b, at) + (u8(b, at + 1) << 8);
const u32be = (b: Uint8Array, at: number) =>
  u8(b, at) * 0x1000000 +
  (u8(b, at + 1) << 16) +
  (u8(b, at + 2) << 8) +
  u8(b, at + 3);
const u32le = (b: Uint8Array, at: number) =>
  u8(b, at) +
  (u8(b, at + 1) << 8) +
  (u8(b, at + 2) << 16) +
  u8(b, at + 3) * 0x1000000;
const startsWith = (b: Uint8Array, bytes: readonly number[]) =>
  b.length >= bytes.length && bytes.every((byte, i) => b[i] === byte);
const ascii = (b: Uint8Array, at: number, text: string) =>
  b.length >= at + text.length &&
  [...text].every((c, i) => b[at + i] === c.charCodeAt(0));

function isPng(b: Uint8Array): boolean {
  return b.length >= 16 && u32be(b, 8) === 13 && ascii(b, 12, "IHDR");
}

function isAnimatedPng(b: Uint8Array): boolean {
  let offset = PNG_SIGNATURE.length;
  while (offset + 8 <= b.length) {
    const length = u32be(b, offset);
    if (ascii(b, offset + 4, "acTL")) return true;
    if (ascii(b, offset + 4, "IDAT")) return false;
    const next = offset + 8 + length + 4;
    if (next <= offset || next > b.length) return false;
    offset = next;
  }
  return false;
}

function isBmp(b: Uint8Array): boolean {
  if (b.length < 26) return false;
  const fileSize = u32le(b, 2);
  const pixelOffset = u32le(b, 10);
  const dib = u32le(b, 14);
  if (fileSize !== 0 && fileSize < 26) return false;
  if (pixelOffset < 14 + dib) return false;
  if (fileSize !== 0 && pixelOffset >= fileSize) return false;
  let planes: number;
  let bits: number;
  if (dib === 12) {
    planes = u16le(b, 22);
    bits = u16le(b, 24);
  } else if (dib >= 40 && dib <= 124) {
    if (b.length < 30) return false;
    planes = u16le(b, 26);
    bits = u16le(b, 28);
  } else return false;
  return planes === 1 && [1, 4, 8, 16, 24, 32].includes(bits);
}

/** The image type Pi's read tool would return as an image, from the first bytes. */
export function sniffImage(data: Uint8Array): string | undefined {
  const b = data.subarray(0, SNIFF_BYTES);
  if (startsWith(b, [0xff, 0xd8, 0xff]))
    return b[3] === 0xf7 ? undefined : "image/jpeg";
  if (startsWith(b, PNG_SIGNATURE))
    return isPng(b) && !isAnimatedPng(b) ? "image/png" : undefined;
  if (ascii(b, 0, "GIF87a") || ascii(b, 0, "GIF89a")) return "image/gif";
  if (ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP")) return "image/webp";
  if (ascii(b, 0, "BM") && isBmp(b)) return "image/bmp";
  return undefined;
}
