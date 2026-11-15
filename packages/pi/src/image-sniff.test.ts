import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectSupportedImageMimeTypeFromFile } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { sniffImage } from "./image-sniff.js";

const png = (...chunks: [string, Buffer][]) =>
  Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from([0, 0, 0, 13]),
    Buffer.from("IHDR"),
    Buffer.alloc(17),
    ...chunks.map(([type, body]) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(body.length);
      return Buffer.concat([length, Buffer.from(type), body, Buffer.alloc(4)]);
    }),
  ]);
const bmp = (bits = 24) => {
  const b = Buffer.alloc(64);
  b.write("BM", 0);
  b.writeUInt32LE(64, 2);
  b.writeUInt32LE(54, 10);
  b.writeUInt32LE(40, 14);
  b.writeUInt16LE(1, 26);
  b.writeUInt16LE(bits, 28);
  return b;
};

const samples: Record<string, Buffer> = {
  png: png(["IDAT", Buffer.alloc(4)]),
  apng: png(["acTL", Buffer.alloc(8)], ["IDAT", Buffer.alloc(4)]),
  "bare png signature": Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  ]),
  jpeg: Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0]),
  "jpeg-ls": Buffer.from([0xff, 0xd8, 0xff, 0xf7, 0, 0]),
  gif: Buffer.from("GIF89a\0\0"),
  webp: Buffer.from("RIFF\0\0\0\0WEBPVP8 "),
  "riff wave": Buffer.from("RIFF\0\0\0\0WAVEfmt "),
  bmp: bmp(),
  "bmp with bad depth": bmp(7),
  "truncated bmp": bmp().subarray(0, 20),
  "truncated gif": Buffer.from("GIF8"),
  "truncated jpeg": Buffer.from([0xff, 0xd8]),
  text: Buffer.from("hello world\n"),
  empty: Buffer.alloc(0),
};

describe("sniffImage", () => {
  it("answers as Pi's public detector does, for every sample", async () => {
    const dir = await mkdtemp(join(tmpdir(), "piship-sniff-"));
    try {
      for (const [name, data] of Object.entries(samples)) {
        const file = join(dir, "sample");
        await writeFile(file, data);
        const pi = await detectSupportedImageMimeTypeFromFile(file);
        expect(sniffImage(data) ?? null, name).toBe(pi);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
