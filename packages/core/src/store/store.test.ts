import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
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
import { ContentStore, type Primitive, storeLayout } from "./store.js";

const roots: string[] = [];
const temp = (): string => {
  const directory = mkdtempSync(join(tmpdir(), "piship-store-test-"));
  roots.push(directory);
  return directory;
};
afterEach(() => {
  for (const root of roots.splice(0)) {
    // Objects are read-only; a recursive removal must still succeed.
    rmSync(root, { recursive: true, force: true });
  }
});

const digest = (data: Buffer) =>
  createHash("sha256").update(data).digest("hex");
const posix = process.platform !== "win32";
const unprivileged = posix && process.getuid?.() !== 0;

function open(root: string, primitive: Primitive = "copy"): ContentStore {
  const store = ContentStore.open(root, { primitive });
  if (!store) throw new Error("the store did not open");
  return store;
}

function place(
  store: ContentStore,
  output: string,
  text: string,
  options: { path?: string; exec?: boolean } = {},
): Promise<boolean> {
  const data = Buffer.from(text);
  mkdirSync(join(output, ".."), { recursive: true });
  return store.place({
    path: options.path ?? "node_modules/pkg/index.js",
    data,
    digest: digest(data),
    output,
    exec: options.exec ?? false,
  });
}

const objectOf = (store: ContentStore, text: string, exec = false) =>
  store.objectPath(digest(Buffer.from(text)), exec);

describe("the file store", () => {
  it.each(["copy", "clone", "hardlink"] as const)(
    "places a file from a new object and then from the stored one by %s",
    async (primitive) => {
      const home = temp();
      const first = join(home, "a", "index.js");
      const second = join(home, "b", "index.js");
      const store = open(join(home, "store"), primitive);
      expect(await place(store, first, "export const a = 1;\n")).toBe(true);
      expect(await place(store, second, "export const a = 1;\n")).toBe(true);
      expect(readFileSync(first, "utf8")).toBe("export const a = 1;\n");
      expect(readFileSync(second, "utf8")).toBe("export const a = 1;\n");
      expect(store.counts.created).toBe(1);
      expect(store.counts.reused).toBe(0);
      // The second placement of the same object in one operation is not read again.
      expect(
        store.counts.linked + store.counts.cloned + store.counts.copied,
      ).toBe(2);
      store.end();
      const fresh = open(join(home, "store"), primitive);
      expect(
        await place(
          fresh,
          join(home, "c", "index.js"),
          "export const a = 1;\n",
        ),
      ).toBe(true);
      expect(fresh.counts).toMatchObject({ created: 0, reused: 1 });
    },
  );

  it("shares the inode only when asked to hard-link, and then keeps the object read-only", async () => {
    const home = temp();
    const output = join(home, "tree", "index.js");
    const store = open(join(home, "store"), "hardlink");
    await place(store, output, "shared");
    const object = objectOf(store, "shared");
    expect(store.counts.linked).toBe(1);
    expect(lstatSync(output).ino).toBe(lstatSync(object).ino);
    expect(lstatSync(object).nlink).toBe(2);
    if (posix) expect(statSync(object).mode & 0o222).toBe(0);
    if (unprivileged)
      expect(() => writeFileSync(output, "changed")).toThrow(/EACCES|EPERM/);
    expect(readFileSync(object, "utf8")).toBe("shared");
  });

  it.each(["copy", "clone"] as const)(
    "never lets a write to a file placed by %s reach the object or another file",
    async (primitive) => {
      const home = temp();
      const a = join(home, "a", "index.js");
      const b = join(home, "b", "index.js");
      const store = open(join(home, "store"), primitive);
      await place(store, a, "original");
      await place(store, b, "original");
      writeFileSync(a, "changed by a program in the first installation");
      expect(readFileSync(b, "utf8")).toBe("original");
      expect(readFileSync(objectOf(store, "original"), "utf8")).toBe(
        "original",
      );
      // The placed file belongs to its installation: it is not read-only.
      expect(statSync(a).mode & 0o200).not.toBe(0);
      expect(lstatSync(a).ino).not.toBe(
        lstatSync(objectOf(store, "original")).ino,
      );
    },
  );

  it("keeps an object read-only and its executable variant apart", async () => {
    const home = temp();
    const store = open(join(home, "store"));
    await place(store, join(home, "x", "tool"), "#!/bin/sh\n", { exec: true });
    await place(store, join(home, "y", "tool"), "#!/bin/sh\n", { exec: false });
    if (posix) {
      expect(statSync(join(home, "x", "tool")).mode & 0o777).toBe(0o755);
      expect(statSync(join(home, "y", "tool")).mode & 0o777).toBe(0o644);
      expect(statSync(objectOf(store, "#!/bin/sh\n", true)).mode & 0o777).toBe(
        0o555,
      );
      expect(statSync(objectOf(store, "#!/bin/sh\n", false)).mode & 0o777).toBe(
        0o444,
      );
      expect(store.counts.created).toBe(2);
    }
  });

  it("leaves what a distribution owns, and empty files, to the caller", async () => {
    const home = temp();
    const store = open(join(home, "store"));
    for (const path of [
      "resources/AGENTS.md",
      "piship.lock",
      "metadata/inventory.json",
      "bin/tool",
    ])
      expect(
        await place(store, join(home, "out", path), "private", { path }),
      ).toBe(false);
    expect(await place(store, join(home, "empty"), "")).toBe(false);
    expect(existsSync(join(home, "out", "piship.lock"))).toBe(false);
    expect(readdirSync(storeLayout(store.root).objects)).toEqual([]);
  });

  it("detects a changed, truncated, or replaced object, replaces it, and installs the right bytes", async () => {
    const home = temp();
    const root = join(home, "store");
    const first = open(root, "copy");
    await place(first, join(home, "a", "f"), "the true bytes");
    first.end();
    const object = objectOf(first, "the true bytes");
    const damage: [string, () => void][] = [
      [
        "same-size content",
        () => {
          chmodSync(object, 0o644);
          writeFileSync(object, "the evil bytes");
        },
      ],
      [
        "truncation",
        () => {
          chmodSync(object, 0o644);
          writeFileSync(object, "the true");
        },
      ],
      [
        "a symbolic link",
        () => {
          rmSync(object);
          writeFileSync(join(home, "elsewhere"), "the true bytes");
          symlinkSync(join(home, "elsewhere"), object);
        },
      ],
    ];
    for (const [index, [, harm]] of damage.entries()) {
      // A link needs privileges on Windows; the rest hold everywhere.
      try {
        harm();
      } catch {
        if (process.platform === "win32") continue;
        throw new Error("could not damage the object");
      }
      const store = open(root, "copy");
      const output = join(home, `out${index}`, "f");
      expect(await place(store, output, "the true bytes")).toBe(true);
      expect(readFileSync(output, "utf8")).toBe("the true bytes");
      expect(store.counts).toMatchObject({
        repaired: 1,
        created: 1,
        reused: 0,
      });
      expect(readFileSync(object, "utf8")).toBe("the true bytes");
      expect(lstatSync(object).isFile()).toBe(true);
    }
  });

  it("trusts the size alone only when it is told to measure", async () => {
    const home = temp();
    const root = join(home, "store");
    const writer = open(root);
    await place(writer, join(home, "a"), "the true bytes");
    const object = objectOf(writer, "the true bytes");
    chmodSync(object, 0o644);
    writeFileSync(object, "the evil bytes");
    const careful = open(root);
    await place(careful, join(home, "b"), "the true bytes");
    expect(readFileSync(join(home, "b"), "utf8")).toBe("the true bytes");
    const hasty = ContentStore.open(root, {
      primitive: "copy",
      verify: "size",
    });
    chmodSync(object, 0o644);
    writeFileSync(object, "the evil bytes");
    await place(hasty as ContentStore, join(home, "c"), "the true bytes");
    expect(readFileSync(join(home, "c"), "utf8")).toBe("the evil bytes");
  });

  it("materializes one object correctly from many writers at once", async () => {
    const home = temp();
    const root = join(home, "store");
    const stores = [open(root), open(root), open(root, "hardlink")];
    const outputs: string[] = [];
    const jobs: Promise<boolean>[] = [];
    for (let index = 0; index < 60; index += 1) {
      const output = join(home, `tree${index % 3}`, `f${index}`, "index.js");
      outputs.push(output);
      jobs.push(
        place(stores[index % 3] as ContentStore, output, `file ${index % 7}`),
      );
    }
    expect(await Promise.all(jobs)).toEqual(jobs.map(() => true));
    outputs.forEach((output, index) =>
      expect(readFileSync(output, "utf8")).toBe(`file ${index % 7}`),
    );
    for (let value = 0; value < 7; value += 1) {
      const text = `file ${value}`;
      expect(
        readFileSync(objectOf(stores[0] as ContentStore, text), "utf8"),
      ).toBe(text);
    }
    // No temporary file is left where objects are written.
    expect(readdirSync(storeLayout(root).temporary)).toEqual([]);
  });

  it("declines, leaving nothing behind, when the store cannot be written", async () => {
    const home = temp();
    const root = join(home, "store");
    const store = open(root);
    rmSync(storeLayout(root).objects, { recursive: true });
    writeFileSync(storeLayout(root).objects, "not a directory");
    const output = join(home, "tree", "index.js");
    expect(await place(store, output, "bytes")).toBe(false);
    expect(existsSync(output)).toBe(false);
    // The rest of the operation does not try the store again.
    expect(await place(store, join(home, "tree", "two.js"), "other")).toBe(
      false,
    );
    expect(store.counts.declined).toBe(2);
  });

  it("falls back to copying when the volume refuses links, and never overwrites a file", async () => {
    const home = temp();
    const store = open(join(home, "store"), "hardlink");
    const output = join(home, "tree", "index.js");
    await place(store, output, "bytes");
    // A file already there is the caller's mistake, not something to replace.
    await expect(place(store, output, "bytes")).rejects.toMatchObject({
      code: "EEXIST",
    });
    expect(readFileSync(output, "utf8")).toBe("bytes");
  });

  it("refuses a store of another layout", () => {
    const root = temp();
    writeFileSync(join(root, "store.json"), '{"schema":"piship-store/v9"}');
    expect(ContentStore.open(root, { primitive: "copy" })).toBeUndefined();
    const unwritable = join(temp(), "file");
    writeFileSync(unwritable, "");
    expect(
      ContentStore.open(join(unwritable, "store"), { primitive: "copy" }),
    ).toBeUndefined();
  });

  it("records the objects a release placed, whole, and refuses a name that is not an id", async () => {
    const home = temp();
    const root = join(home, "store");
    const store = open(root);
    await place(store, join(home, "a"), "one");
    await place(store, join(home, "b"), "two");
    expect(store.record("acme-pi", "1.0.0", "/home")).toBe(true);
    const reference = JSON.parse(
      readFileSync(
        join(storeLayout(root).refs, "acme-pi", "1.0.0.json"),
        "utf8",
      ),
    ) as { objects: string[]; home: string };
    expect(reference.objects).toEqual(
      [digest(Buffer.from("one")), digest(Buffer.from("two"))].sort(),
    );
    expect(reference.home).toBe("/home");
    expect(store.record("../escape", "1.0.0", "/home")).toBe(false);
    expect(store.record("acme-pi", "../1.0.0", "/home")).toBe(false);
    expect(readdirSync(storeLayout(root).temporary)).toEqual([]);
    // The operation is in flight until it ends.
    expect(readdirSync(storeLayout(root).inflight)).toHaveLength(1);
    store.end();
    expect(readdirSync(storeLayout(root).inflight)).toEqual([]);
  });

  it("hands a placer only the files under its prefix", async () => {
    const home = temp();
    const store = open(join(home, "store"));
    const placer = store.placer("rel/payload/");
    const data = Buffer.from("x");
    const request = (path: string, name: string) => ({
      path,
      data,
      digest: digest(data),
      output: join(home, name),
      exec: false,
    });
    expect(await placer(request("rel/release.json", "a"))).toBe(false);
    expect(await placer(request("rel/payload/resources/a.md", "b"))).toBe(
      false,
    );
    expect(await placer(request("rel/payload/node_modules/x/i.js", "c"))).toBe(
      true,
    );
    expect(existsSync(join(home, "c"))).toBe(true);
  });
});
