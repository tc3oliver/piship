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
    // Buffer.equals: toEqual walks a 2 MiB buffer element by element, which
    // took about 20 s on a loaded Windows runner.
    expect(
      readFileSync(join(dir, "copy", "a", "b", "large")).equals(large),
    ).toBe(true);
  });

  it.runIf(process.platform !== "win32")(
    "links each file after hashing it when asked, creating no second copy",
    async () => {
      const dir = temp();
      const source = join(dir, "source");
      mkdirSync(join(source, "a"), { recursive: true });
      writeFileSync(join(source, "one"), "one");
      writeFileSync(join(source, "a", "two"), "two");
      const digests = await copyTree(source, join(dir, "linked"), {
        link: true,
      });
      expect(Object.fromEntries(digests)).toEqual({
        one: sha256("one"),
        "a/two": sha256("two"),
      });
      for (const file of ["one", join("a", "two")]) {
        const from = statSync(join(source, file));
        const to = statSync(join(dir, "linked", file));
        expect(to.ino).toBe(from.ino);
        expect(from.nlink).toBe(2);
      }
      // Without the option a file is written again.
      await copyTree(source, join(dir, "copied"));
      expect(statSync(join(dir, "copied", "one")).ino).not.toBe(
        statSync(join(source, "one")).ino,
      );
    },
  );

  it("copies when a file cannot be linked, and stops trying after the first refusal", async () => {
    const dir = temp();
    const source = join(dir, "source");
    mkdirSync(source);
    for (let file = 0; file < 20; file++)
      writeFileSync(join(source, `f${file}`), `content ${file}`);
    let attempts = 0;
    const digests = await copyTree(source, join(dir, "copy"), {
      link: true,
      linkFile: async () => {
        attempts++;
        throw Object.assign(
          new Error("EXDEV: cross-device link not permitted"),
          {
            code: "EXDEV",
          },
        );
      },
    });
    expect(digests.size).toBe(20);
    for (let file = 0; file < 20; file++)
      expect(readFileSync(join(dir, "copy", `f${file}`), "utf8")).toBe(
        `content ${file}`,
      );
    // Concurrent writers may already be past the check; it is not 20 attempts.
    expect(attempts).toBeLessThanOrEqual(8);
    expect(digests.get("f3")).toBe(sha256("content 3"));
  });

  it("does not hide a file already at the destination behind the copy fallback", async () => {
    const dir = temp();
    const source = join(dir, "source");
    mkdirSync(source);
    writeFileSync(join(source, "file"), "new");
    const destination = join(dir, "destination");
    mkdirSync(destination);
    writeFileSync(join(destination, "file"), "old");
    await expect(
      copyTree(source, destination, { link: true }),
    ).rejects.toThrow();
    expect(readFileSync(join(destination, "file"), "utf8")).toBe("old");
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
