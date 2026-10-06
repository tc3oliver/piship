// The security review's store cases (docs/security.md, "v0.11 security
// review"), stated as the attack each one is: a distribution that ships
// another distribution's package name and version with other bytes, a
// collection that runs while a release is still using an object, and a
// collection that removes an object an installed file still names. The
// mechanisms are tested in store.test.ts and collect.test.ts; these tests
// name the cases the review asks about and fail if one regresses.
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectStore, type Liveness } from "./collect.js";
import { ContentStore, type Primitive } from "./store.js";

const homes: string[] = [];
afterEach(() => {
  for (const home of homes.splice(0))
    rmSync(home, { recursive: true, force: true });
});

/** A clock past every file's modification time, so a zero grace period is deterministic. */
const later = () => Date.now() + 60_000;

const digestOf = (text: string) =>
  createHash("sha256").update(text).digest("hex");

function home(): string {
  const directory = mkdtempSync(join(tmpdir(), "piship-store-review-"));
  homes.push(directory);
  return directory;
}

/** One install operation: the files it places, then its reference. */
async function install(
  root: string,
  primitive: Primitive,
  release: { id: string; version: string; home: string },
  files: Record<string, string>,
): Promise<ContentStore> {
  const store = ContentStore.open(root, { primitive }) as ContentStore;
  const tree = join(release.home, "apps", release.id, release.version);
  for (const [path, text] of Object.entries(files)) {
    const output = join(tree, path);
    mkdirSync(join(output, ".."), { recursive: true });
    expect(
      await store.place({
        path,
        data: Buffer.from(text),
        digest: digestOf(text),
        output,
        exec: false,
      }),
    ).toBe(true);
  }
  store.record(release.id, release.version, release.home);
  store.end();
  return store;
}

const installed = (
  h: string,
  id: string,
  version: string,
  path: string,
): string => join(h, "apps", id, version, path);

describe("store security cases", () => {
  it("dependency confusion: two distributions that ship one package name and version with different bytes each install their own", async () => {
    const h = home();
    const root = join(h, "store");
    const path = "node_modules/left-pad/index.js";
    const left = { id: "left", version: "1.0.0", home: h };
    const right = { id: "right", version: "1.0.0", home: h };
    const a = await install(root, "copy", left, {
      [path]: "bytes the left reviewed",
    });
    const b = await install(root, "copy", right, {
      [path]: "bytes the right shipped",
    });
    expect(readFileSync(installed(h, "left", "1.0.0", path), "utf8")).toBe(
      "bytes the left reviewed",
    );
    expect(readFileSync(installed(h, "right", "1.0.0", path), "utf8")).toBe(
      "bytes the right shipped",
    );
    // Neither lookup found the other's object: a name and a version are not a key.
    expect(a.counts).toMatchObject({ created: 1, reused: 0 });
    expect(b.counts).toMatchObject({ created: 1, reused: 0 });
    expect(b.objectPath(digestOf("bytes the left reviewed"), false)).not.toBe(
      b.objectPath(digestOf("bytes the right shipped"), false),
    );
  });

  it("a release of the same name and version with other bytes is a different object, and a rollback keeps its own", async () => {
    const h = home();
    const root = join(h, "store");
    const path = "node_modules/dep/index.js";
    await install(
      root,
      "copy",
      { id: "acme", version: "1.0.0", home: h },
      { [path]: "dep as 1.0.0 shipped it" },
    );
    // A rebuilt 1.1.0 reuses the name and version of the dependency and changes its bytes.
    await install(
      root,
      "copy",
      { id: "acme", version: "1.1.0", home: h },
      { [path]: "dep, same version, other bytes" },
    );
    const liveness = (): Liveness => "live";
    expect(
      collectStore({ root, liveness, graceMs: 0, now: later }),
    ).toMatchObject({
      removedObjects: 0,
      pinnedObjects: 2,
    });
    expect(readFileSync(installed(h, "acme", "1.0.0", path), "utf8")).toBe(
      "dep as 1.0.0 shipped it",
    );
    expect(readFileSync(installed(h, "acme", "1.1.0", path), "utf8")).toBe(
      "dep, same version, other bytes",
    );
  });

  it("an object two distributions share stays while either one retains it, and goes when neither does", async () => {
    const h = home();
    const root = join(h, "store");
    const path = "node_modules/shared/index.js";
    const first = { id: "first", version: "1.0.0", home: h };
    const second = { id: "second", version: "1.0.0", home: h };
    await install(root, "copy", first, { [path]: "the one shared object" });
    await install(root, "copy", second, { [path]: "the one shared object" });
    const state = new Map<string, Liveness>([
      ["first", "dead"],
      ["second", "live"],
    ]);
    const liveness = (release: { id: string }) =>
      state.get(release.id) ?? "dead";
    const reopened = ContentStore.open(root, {
      primitive: "copy",
    }) as ContentStore;
    const objectPath = reopened.objectPath(
      digestOf("the one shared object"),
      false,
    );
    const swept = collectStore({ root, liveness, graceMs: 0, now: later });
    expect(swept.removedReferences).toBe(1);
    expect(swept.removedObjects).toBe(0);
    expect(existsSync(objectPath)).toBe(true);
    state.set("second", "dead");
    expect(
      collectStore({ root, liveness, graceMs: 0, now: later }).removedObjects,
    ).toBe(1);
    expect(existsSync(objectPath)).toBe(false);
    // What each distribution installed is its own file and is untouched.
    expect(readFileSync(installed(h, "first", "1.0.0", path), "utf8")).toBe(
      "the one shared object",
    );
    expect(readFileSync(installed(h, "second", "1.0.0", path), "utf8")).toBe(
      "the one shared object",
    );
  });

  it("GC deleting a live runtime: an object a collection removes under a running install is never placed damaged, and the caller writes the file itself", async () => {
    const h = home();
    const root = join(h, "store");
    const store = ContentStore.open(root, {
      primitive: "copy",
    }) as ContentStore;
    const path = "node_modules/dep/index.js";
    const place = async (name: string) => {
      const output = join(h, "tree", name);
      mkdirSync(join(output, ".."), { recursive: true });
      const placed = await store.place({
        path,
        data: Buffer.from("runtime bytes"),
        digest: digestOf("runtime bytes"),
        output,
        exec: false,
      });
      return { output, placed };
    };
    const first = await place("a.js");
    expect(first.placed).toBe(true);
    // A collection that ignored the in-flight marker, or outlived its grace
    // period, removes the object between two placements of one operation.
    rmSync(store.objectPath(digestOf("runtime bytes"), false));
    const second = await place("b.js");
    expect(second.placed).toBe(false);
    // Nothing partial is left for the caller to trip over, and the first file is whole.
    expect(existsSync(second.output)).toBe(false);
    expect(readFileSync(first.output, "utf8")).toBe("runtime bytes");
    expect(store.counts.declined).toBe(1);
    store.end();
  });

  it("an installed hard link keeps its bytes when the collection removes the object it was linked from", async () => {
    const h = home();
    const root = join(h, "store");
    const path = "node_modules/dep/index.js";
    const release = { id: "acme", version: "1.0.0", home: h };
    const store = await install(root, "hardlink", release, {
      [path]: "linked runtime bytes",
    });
    const file = installed(h, "acme", "1.0.0", path);
    const object = store.objectPath(digestOf("linked runtime bytes"), false);
    expect(lstatSync(file).ino).toBe(lstatSync(object).ino);
    const result = collectStore({
      root,
      liveness: () => "dead",
      graceMs: 0,
      now: later,
    });
    expect(result.removedObjects).toBe(1);
    expect(existsSync(object)).toBe(false);
    expect(readFileSync(file, "utf8")).toBe("linked runtime bytes");
    // The bytes are still in use, so none was freed.
    expect(result.freedBytes).toBe(0);
  });
});
