import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { createArchive, extractArchive, sha256File } from "./archive.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-archive-"));
  roots.push(dir);
  return dir;
}

const POSIX = process.platform !== "win32";
const LONG_DIR = `${"d".repeat(60)}/${"e".repeat(60)}`;
const LONGER = `${"x".repeat(90)}/${"y".repeat(90)}/${"z".repeat(90)}`;

function populate(dir: string): void {
  mkdirSync(join(dir, "bin"), { recursive: true });
  writeFileSync(join(dir, "bin", "run"), "#!/bin/sh\necho hi\n");
  if (POSIX) chmodSync(join(dir, "bin", "run"), 0o755);
  mkdirSync(join(dir, "lib", "nested", "deep"), { recursive: true });
  writeFileSync(join(dir, "lib", "nested", "deep", "a.js"), "a".repeat(1000));
  writeFileSync(join(dir, "lib", "empty.txt"), "");
  mkdirSync(join(dir, "empty-dir"));
  mkdirSync(join(dir, ...LONG_DIR.split("/")), { recursive: true });
  writeFileSync(join(dir, ...LONG_DIR.split("/"), "long-file.txt"), "long");
  mkdirSync(join(dir, ...LONGER.split("/")), { recursive: true });
  writeFileSync(join(dir, ...LONGER.split("/"), "longer.txt"), "longer");
  writeFileSync(join(dir, "héllo-日本.txt"), "unicode");
  writeFileSync(join(dir, "big.bin"), Buffer.alloc(3 * 1024 * 1024 + 7, 1));
}

interface RawEntry {
  readonly name: string;
  readonly type?: string;
  readonly data?: Buffer | string;
  readonly mode?: number;
  readonly prefix?: string;
  readonly badChecksum?: boolean;
}

function rawHeader(entry: RawEntry, size: number): Buffer {
  const block = Buffer.alloc(512);
  const octal = (offset: number, width: number, value: number) =>
    block.write(
      `${value.toString(8).padStart(width - 1, "0")}\0`,
      offset,
      "latin1",
    );
  block.write(entry.name, 0, 100, "utf8");
  octal(100, 8, entry.mode ?? 0o644);
  octal(108, 8, 0);
  octal(116, 8, 0);
  octal(124, 12, size);
  octal(136, 12, 0);
  block.fill(0x20, 148, 156);
  block.write(entry.type ?? "0", 156, 1, "latin1");
  block.write("ustar\0", 257, "latin1");
  block.write("00", 263, "latin1");
  block.write(entry.prefix ?? "", 345, 155, "utf8");
  let sum = 0;
  for (const byte of block) sum += byte;
  if (entry.badChecksum) sum += 1;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return block;
}

/** Hand-built tar.gz for hostile-input tests. */
function rawArchive(
  dir: string,
  entries: readonly RawEntry[],
  options: { end?: boolean; truncate?: number } = {},
): string {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? "");
    parts.push(rawHeader(entry, data.length), data);
    parts.push(Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  if (options.end !== false) parts.push(Buffer.alloc(1024));
  let tar = Buffer.concat(parts);
  if (options.truncate !== undefined) tar = tar.subarray(0, options.truncate);
  const file = join(dir, `raw-${readdirSync(dir).length}.tar.gz`);
  writeFileSync(file, gzipSync(tar));
  return file;
}

function listTree(dir: string, prefix = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const rel = prefix === "" ? name : `${prefix}/${name}`;
    if (statSync(join(dir, name)).isDirectory())
      out.push(`${rel}/`, ...listTree(join(dir, name), rel));
    else out.push(rel);
  }
  return out;
}

describe("createArchive / extractArchive", () => {
  it("round-trips nested, long, unicode, empty, and executable entries", async () => {
    const work = tempDir();
    const source = join(work, "src");
    populate(source);
    const archive = join(work, "out.tar.gz");
    const result = await createArchive(source, "mypi-1.0.0", archive);
    expect(result.path).toBe(archive);
    expect(existsSync(`${archive}.partial`)).toBe(false);
    expect(result.bytes).toBe(statSync(archive).size);
    expect(result.sha256).toBe(await sha256File(archive));
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);

    const dest = join(work, "dest");
    const extracted = await extractArchive(archive, dest, {
      expectedRoot: "mypi-1.0.0",
    });
    expect(extracted.root).toBe("mypi-1.0.0");
    expect(extracted.entries).toBe(result.entries);
    const root = join(dest, "mypi-1.0.0");
    expect(listTree(root)).toEqual(listTree(source));
    for (const file of listTree(source).filter((p) => !p.endsWith("/")))
      expect(
        readFileSync(join(root, file)).equals(readFileSync(join(source, file))),
      ).toBe(true);
    expect(extracted.bytes).toBe(
      listTree(source)
        .filter((p) => !p.endsWith("/"))
        .reduce((sum, p) => sum + statSync(join(source, p)).size, 0),
    );
    expect(existsSync(join(root, "empty-dir"))).toBe(true);
    expect(statSync(join(root, "lib", "empty.txt")).size).toBe(0);
    if (POSIX) {
      expect(statSync(join(root, "bin", "run")).mode & 0o777).toBe(0o755);
      expect(statSync(join(root, "lib", "empty.txt")).mode & 0o777).toBe(0o644);
    }
  });

  it("marks files executable through the option", async () => {
    const work = tempDir();
    const source = join(work, "src");
    mkdirSync(join(source, "bin"), { recursive: true });
    writeFileSync(join(source, "bin", "tool"), "x");
    if (POSIX) chmodSync(join(source, "bin", "tool"), 0o644);
    const archive = join(work, "out.tar.gz");
    await createArchive(source, "root", archive, {
      executable: (path) => path === "bin/tool",
    });
    const dest = join(work, "dest");
    await extractArchive(archive, dest);
    if (POSIX)
      expect(statSync(join(dest, "root", "bin", "tool")).mode & 0o777).toBe(
        0o755,
      );
  });

  it("is deterministic across runs and source mtimes", async () => {
    const work = tempDir();
    const source = join(work, "src");
    populate(source);
    const first = await createArchive(source, "r", join(work, "a.tar.gz"));
    utimesSync(join(source, "big.bin"), 1_000_000, 1_000_000);
    utimesSync(join(source, "lib"), 2_000_000, 2_000_000);
    const second = await createArchive(source, "r", join(work, "b.tar.gz"));
    expect(second.sha256).toBe(first.sha256);
    expect(readFileSync(second.path).equals(readFileSync(first.path))).toBe(
      true,
    );
    const third = await createArchive(source, "r", join(work, "c.tar.gz"), {
      mtime: 1_700_000_000,
    });
    expect(third.sha256).not.toBe(first.sha256);
  });

  it("normalizes the gzip header", async () => {
    const work = tempDir();
    const source = join(work, "src");
    populate(source);
    const { path } = await createArchive(source, "r", join(work, "a.tar.gz"));
    const head = readFileSync(path).subarray(0, 10);
    expect(head[0]).toBe(0x1f);
    expect(head[1]).toBe(0x8b);
    expect([...head.subarray(4, 8)]).toEqual([0, 0, 0, 0]);
    expect(head[9]).toBe(0xff);
  });

  it("rejects a symlink in the source", async () => {
    const work = tempDir();
    const source = join(work, "src");
    mkdirSync(source);
    writeFileSync(join(source, "target"), "x");
    try {
      symlinkSync(join(source, "target"), join(source, "link"));
    } catch (error) {
      if (!POSIX) return;
      throw error;
    }
    await expect(
      createArchive(source, "r", join(work, "a.tar.gz")),
    ).rejects.toThrow(/symbolic link.*link/);
    expect(existsSync(join(work, "a.tar.gz"))).toBe(false);
    expect(existsSync(join(work, "a.tar.gz.partial"))).toBe(false);
  });

  it("refuses a non-empty destination", async () => {
    const work = tempDir();
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "r/a", data: "a" },
    ]);
    const dest = join(work, "dest");
    mkdirSync(dest);
    writeFileSync(join(dest, "keep"), "keep");
    await expect(extractArchive(archive, dest)).rejects.toThrow(/not empty/);
    expect(readdirSync(dest)).toEqual(["keep"]);
  });

  const hostile: [string, RawEntry[], RegExp][] = [
    ["parent traversal", [{ name: "../evil", data: "x" }], /Unsafe/],
    [
      "nested traversal",
      [
        { name: "r/", type: "5" },
        { name: "r/../../evil", data: "x" },
      ],
      /Unsafe/,
    ],
    ["absolute path", [{ name: "/etc/x", data: "x" }], /Unsafe/],
    [
      "backslash path",
      [
        { name: "r/", type: "5" },
        { name: "r\\..\\evil", data: "x" },
      ],
      /Unsafe/,
    ],
    ["drive letter", [{ name: "C:/evil", data: "x" }], /Unsafe/],
    ["dot segment", [{ name: "r/./a", data: "x" }], /Unsafe/],
    ["empty segment", [{ name: "r//a", data: "x" }], /Unsafe/],
    [
      "symlink entry",
      [
        { name: "r/", type: "5" },
        { name: "r/link", type: "2" },
      ],
      /Unsupported archive entry type/,
    ],
    [
      "hardlink entry",
      [
        { name: "r/", type: "5" },
        { name: "r/link", type: "1" },
      ],
      /Unsupported archive entry type/,
    ],
    [
      "GNU long name",
      [{ name: "././@LongLink", type: "L", data: "r/x" }],
      /Unsupported archive entry type/,
    ],
    [
      "two roots",
      [
        { name: "r/", type: "5" },
        { name: "r/a", data: "a" },
        { name: "s/b", data: "b" },
      ],
      /outside root/,
    ],
    ["top-level file", [{ name: "r", data: "x" }], /not a directory/],
    [
      "duplicate entry",
      [
        { name: "r/", type: "5" },
        { name: "r/a", data: "a" },
        { name: "r/a", data: "b" },
      ],
      /Duplicate/,
    ],
    [
      "bad checksum",
      [
        { name: "r/", type: "5" },
        { name: "r/a", data: "a", badChecksum: true },
      ],
      /checksum/,
    ],
  ];

  for (const [label, entries, error] of hostile)
    it(`rejects ${label}`, async () => {
      const work = tempDir();
      const archive = rawArchive(work, entries);
      const dest = join(work, "dest");
      await expect(extractArchive(archive, dest)).rejects.toThrow(error);
      expect(existsSync(dest)).toBe(false);
      expect(existsSync(join(work, "evil"))).toBe(false);
    });

  it("reads PAX paths from hand-built archives", async () => {
    const work = tempDir();
    const path = `r/${"p".repeat(200)}/é.txt`;
    const record = ` path=${path}\n`;
    const length = Buffer.byteLength(record) + 3;
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "PaxHeader/1", type: "x", data: `${length}${record}` },
      { name: "placeholder", data: "pax" },
    ]);
    const dest = join(work, "dest");
    const result = await extractArchive(archive, dest);
    expect(result.entries).toBe(2);
    expect(readFileSync(join(dest, ...path.split("/")), "utf8")).toBe("pax");
  });

  it("rejects an unexpected root", async () => {
    const work = tempDir();
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "r/a", data: "a" },
    ]);
    await expect(
      extractArchive(archive, join(work, "dest"), { expectedRoot: "other" }),
    ).rejects.toThrow(/outside root/);
  });

  it("rejects truncated archives and cleans up", async () => {
    const work = tempDir();
    const entries: RawEntry[] = [
      { name: "r/", type: "5" },
      { name: "r/a", data: "a".repeat(600) },
      { name: "r/b", data: "b".repeat(2000) },
    ];
    const truncated = rawArchive(work, entries, { truncate: 512 * 4 + 100 });
    const dest = join(work, "dest");
    await expect(extractArchive(truncated, dest)).rejects.toThrow(
      /unexpected end/,
    );
    expect(existsSync(dest)).toBe(false);

    const noEnd = rawArchive(work, entries, { end: false });
    await expect(extractArchive(noEnd, dest)).rejects.toThrow(/unexpected end/);

    const good = rawArchive(work, entries);
    const gz = readFileSync(good);
    const cut = join(work, "cut.tar.gz");
    writeFileSync(cut, gz.subarray(0, gz.length - 12));
    mkdirSync(dest);
    await expect(extractArchive(cut, dest)).rejects.toThrow();
    expect(readdirSync(dest)).toEqual([]);
  });

  it("enforces maxBytes and maxEntries", async () => {
    const work = tempDir();
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "r/a", data: "a".repeat(100) },
      { name: "r/b", data: "b".repeat(100) },
    ]);
    const dest = join(work, "dest");
    await expect(
      extractArchive(archive, dest, { maxBytes: 150 }),
    ).rejects.toThrow(/exceeds 150 bytes/);
    expect(existsSync(dest)).toBe(false);
    await expect(
      extractArchive(archive, dest, { maxEntries: 2 }),
    ).rejects.toThrow(/more than 2 entries/);
    expect(existsSync(dest)).toBe(false);
    const ok = await extractArchive(archive, dest, {
      maxBytes: 200,
      maxEntries: 3,
    });
    expect(ok).toEqual({
      root: "r",
      entries: 3,
      bytes: 200,
      sha256: await sha256File(archive),
    });
  });

  it("hashes the archive during the extraction that reads it", async () => {
    const work = tempDir();
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "r/a", data: "a".repeat(100) },
    ]);
    const hashed = await extractArchive(archive, join(work, "one"));
    expect(hashed.sha256).toBe(await sha256File(archive));
    const unhashed = await extractArchive(archive, join(work, "two"), {
      hash: false,
    });
    expect(unhashed.sha256).toBeUndefined();
  });

  it.each([1, 8])(
    "writes many small, empty, and large files with %i writers",
    async (concurrency) => {
      const work = tempDir();
      const entries: RawEntry[] = [{ name: "r/", type: "5" }];
      const expected = new Map<string, string>();
      for (let d = 0; d < 12; d++) {
        entries.push({ name: `r/d${d}/`, type: "5" });
        for (let f = 0; f < 40; f++) {
          const data = f % 10 === 0 ? "" : `${d}:${f}:`.repeat(f);
          entries.push({ name: `r/d${d}/f${f}.txt`, data });
          expected.set(`d${d}/f${f}.txt`, data);
        }
      }
      // An entry with no directory entry of its own, and one past the
      // buffered size, which streams in order.
      entries.push({ name: "r/implicit/deep/x.txt", data: "implicit" });
      expected.set("implicit/deep/x.txt", "implicit");
      const large = "L".repeat(1024 * 1024 + 5);
      entries.push({ name: "r/large.bin", data: large });
      expected.set("large.bin", large);
      const archive = rawArchive(work, entries);
      const dest = join(work, "dest");
      const result = await extractArchive(archive, dest, { concurrency });
      expect(result.entries).toBe(entries.length);
      for (const [path, data] of expected)
        expect(readFileSync(join(dest, "r", path), "utf8")).toBe(data);
    },
  );

  it("stops at a failing writer and leaves nothing behind", async () => {
    const work = tempDir();
    // `r/a` is a file, so `r/a/b` cannot be created beneath it.
    const entries: RawEntry[] = [
      { name: "r/", type: "5" },
      { name: "r/a", data: "file" },
      { name: "r/a/b", data: "beneath a file" },
    ];
    for (let i = 0; i < 50; i++)
      entries.push({ name: `r/z${i}`, data: "later" });
    const archive = rawArchive(work, entries);
    const dest = join(work, "dest");
    await expect(extractArchive(archive, dest)).rejects.toThrow();
    // A writer that outlived the failure would recreate files after the cleanup.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(existsSync(dest)).toBe(false);
  });

  it("leaves no files behind after a late failure", async () => {
    const work = tempDir();
    const archive = rawArchive(work, [
      { name: "r/", type: "5" },
      { name: "r/dir/", type: "5" },
      { name: "r/dir/a", data: "a" },
      { name: "r/b", data: "b" },
      { name: "r/evil", type: "2" },
    ]);
    const dest = join(work, "dest");
    mkdirSync(dest);
    await expect(extractArchive(archive, dest)).rejects.toThrow(/Unsupported/);
    expect(readdirSync(dest)).toEqual([]);
  });
});

describe("direct payload extraction", () => {
  it("writes payload files into the final directory and skips release evidence", async () => {
    const root = tempDir();
    const archive = rawArchive(root, [
      { name: "release/", type: "5" },
      { name: "release/payload/", type: "5" },
      { name: "release/payload/bin/run", data: "boot" },
      { name: "release/sbom.spdx.json", data: "release evidence" },
    ]);
    const destination = join(root, "1.0.0");
    await extractArchive(archive, destination, {
      expectedRoot: "release",
      mapEntry: (name) =>
        name.startsWith("release/payload/")
          ? name.slice("release/payload/".length)
          : undefined,
    });
    expect(readFileSync(join(destination, "bin", "run"), "utf8")).toBe("boot");
    expect(readdirSync(destination)).toEqual(["bin"]);
  });

  it("still validates paths and limits of skipped entries", async () => {
    const root = tempDir();
    const archive = rawArchive(root, [
      { name: "release/../outside", data: "bad" },
    ]);
    await expect(
      extractArchive(archive, join(root, "out"), {
        mapEntry: () => undefined,
      }),
    ).rejects.toThrow(/Unsafe archive entry/);
    const oversized = rawArchive(root, [
      { name: "release/large", data: "large" },
    ]);
    await expect(
      extractArchive(oversized, join(root, "out"), {
        maxBytes: 1,
        mapEntry: () => undefined,
      }),
    ).rejects.toThrow(/exceeds 1 bytes/);
  });
});
