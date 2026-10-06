import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { copyTree } from "./copy.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-copy-"));
  roots.push(dir);
  return dir;
}

function tree(root: string, prefix = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    const relative = prefix === "" ? name : `${prefix}/${name}`;
    if (statSync(path).isDirectory())
      out.push(`${relative}/`, ...tree(path, relative));
    else out.push(`${relative}=${readFileSync(path, "utf8")}`);
  }
  return out;
}

const sha256 = (data: string | Buffer) =>
  createHash("sha256").update(data).digest("hex");

describe("copyTree", () => {
  it("copies nested directories, empty directories, and empty files", async () => {
    const dir = temp();
    const source = join(dir, "source");
    for (let d = 0; d < 20; d++) {
      mkdirSync(join(source, `d${d}`, "deep"), { recursive: true });
      for (let f = 0; f < 15; f++)
        writeFileSync(
          join(source, `d${d}`, `f${f}`),
          f === 0 ? "" : `${d}.${f}`,
        );
      writeFileSync(join(source, `d${d}`, "deep", "x"), "x".repeat(d));
    }
    mkdirSync(join(source, "empty"));
    const destination = join(dir, "destination", "payload");
    await copyTree(source, destination);
    expect(tree(destination)).toEqual(tree(source));
  });

  it.runIf(process.platform !== "win32")(
    "keeps the executable bit of a file",
    async () => {
      const dir = temp();
      const source = join(dir, "source");
      mkdirSync(join(source, "bin"), { recursive: true });
      writeFileSync(join(source, "bin", "run"), "#!/bin/sh\n");
      chmodSync(join(source, "bin", "run"), 0o755);
      await copyTree(source, join(dir, "copy"));
      expect(statSync(join(dir, "copy", "bin", "run")).mode & 0o111).not.toBe(
        0,
      );
    },
  );

  it("returns the SHA-256 of each file, computed from the bytes it copied", async () => {
    const dir = temp();
    const source = join(dir, "source");
    mkdirSync(join(source, "a", "b"), { recursive: true });
    writeFileSync(join(source, "empty"), "");
    writeFileSync(join(source, "a", "small"), "small");
    const large = Buffer.alloc(2 * 1024 * 1024 + 3, 7);
    writeFileSync(join(source, "a", "b", "large"), large);
    const digests = await copyTree(source, join(dir, "copy"));
    expect(Object.fromEntries(digests)).toEqual({
      empty: sha256(""),
      "a/small": sha256("small"),
      "a/b/large": sha256(large),
    });
    expect(readFileSync(join(dir, "copy", "a", "b", "large"))).toEqual(large);
  });

  it("refuses to overwrite a file already at the destination", async () => {
    const dir = temp();
    const source = join(dir, "source");
    mkdirSync(source);
    writeFileSync(join(source, "file"), "new");
    const destination = join(dir, "destination");
    mkdirSync(destination);
    writeFileSync(join(destination, "file"), "old");
    await expect(copyTree(source, destination)).rejects.toThrow();
    expect(readFileSync(join(destination, "file"), "utf8")).toBe("old");
  });

  it.runIf(process.platform !== "win32")(
    "refuses a symbolic link, as a payload has none",
    async () => {
      const dir = temp();
      const source = join(dir, "source");
      mkdirSync(source);
      writeFileSync(join(dir, "outside"), "secret");
      symlinkSync(join(dir, "outside"), join(source, "link"));
      await expect(copyTree(source, join(dir, "copy"))).rejects.toThrow(
        /Unsupported payload entry: link/,
      );
      expect(existsSync(join(dir, "copy", "link"))).toBe(false);
    },
  );
});
