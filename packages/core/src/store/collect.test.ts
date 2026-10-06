import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectStore, type Liveness, verifyStore } from "./collect.js";
import { ContentStore, storeLayout } from "./store.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const digest = (text: string) =>
  createHash("sha256").update(text).digest("hex");

interface World {
  readonly home: string;
  readonly root: string;
  /** Release states by `<id>@<version>`; the installation's answer. */
  readonly state: Map<string, Liveness>;
  /** Install a release that placed these files; returns its store. */
  release(
    id: string,
    version: string,
    files: Record<string, string>,
  ): Promise<ContentStore>;
  collect(options?: {
    graceMs?: number;
    budgetMs?: number;
    now?: () => number;
  }): ReturnType<typeof collectStore>;
  has(text: string): boolean;
}

function world(): World {
  const home = mkdtempSync(join(tmpdir(), "piship-collect-test-"));
  roots.push(home);
  const root = join(home, "store");
  const state = new Map<string, Liveness>();
  return {
    home,
    root,
    state,
    async release(id, version, files) {
      const store = ContentStore.open(root, {
        primitive: "copy",
      }) as ContentStore;
      const tree = join(home, "apps", id, version);
      for (const [path, text] of Object.entries(files)) {
        const output = join(tree, path);
        mkdirSync(join(output, ".."), { recursive: true });
        await store.place({
          path,
          data: Buffer.from(text),
          digest: digest(text),
          output,
          exec: false,
        });
      }
      store.record(id, version, home);
      store.end();
      state.set(`${id}@${version}`, "dead");
      return store;
    },
    collect: (options = {}) =>
      collectStore({
        root,
        liveness: (release) =>
          state.get(`${release.id}@${release.version}`) ?? "dead",
        graceMs: 0,
        ...options,
      }),
    has: (text) =>
      existsSync(
        join(storeLayout(root).objects, digest(text).slice(0, 2), digest(text)),
      ),
  };
}

const NODE = (name: string) => `node_modules/${name}/index.js`;

describe("collecting the file store", () => {
  it("keeps what the active and the rollback release pin, and collects the rest", async () => {
    const w = world();
    await w.release("acme", "1.0.0", {
      [NODE("old")]: "only in 1.0.0",
      [NODE("common")]: "in every release",
    });
    await w.release("acme", "1.1.0", {
      [NODE("rollback")]: "only in 1.1.0",
      [NODE("common")]: "in every release",
    });
    await w.release("acme", "1.2.0", {
      [NODE("active")]: "only in 1.2.0",
      [NODE("common")]: "in every release",
    });
    w.state.set("acme@1.1.0", "live");
    w.state.set("acme@1.2.0", "live");
    const result = w.collect();
    expect(result).toMatchObject({
      busy: false,
      deferred: false,
      removedObjects: 1,
      removedReferences: 1,
      remaining: false,
    });
    expect(w.has("only in 1.0.0")).toBe(false);
    expect(w.has("only in 1.1.0")).toBe(true);
    expect(w.has("only in 1.2.0")).toBe(true);
    expect(w.has("in every release")).toBe(true);
    expect(readdirSync(join(storeLayout(w.root).refs, "acme")).sort()).toEqual([
      "1.1.0.json",
      "1.2.0.json",
    ]);
  });

  it("collects everything of a distribution that is no longer installed, and nothing of another", async () => {
    const w = world();
    await w.release("gone", "1.0.0", { [NODE("a")]: "gone" });
    await w.release("here", "1.0.0", { [NODE("b")]: "here" });
    w.state.set("here@1.0.0", "live");
    w.collect();
    expect(w.has("gone")).toBe(false);
    expect(w.has("here")).toBe(true);
    expect(existsSync(join(storeLayout(w.root).refs, "gone"))).toBe(false);
  });

  it("keeps the objects of a release it cannot judge", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("a")]: "unjudged" });
    w.state.set("acme@1.0.0", "unknown");
    expect(w.collect().removedObjects).toBe(0);
    expect(w.has("unjudged")).toBe(true);
  });

  it("collects nothing within the grace period, and the unpinned afterwards", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("a")]: "young" });
    expect(w.collect({ graceMs: 60_000 }).removedObjects).toBe(0);
    expect(w.has("young")).toBe(true);
    const later = Date.now() + 120_000;
    expect(
      w.collect({ graceMs: 60_000, now: () => later }).removedObjects,
    ).toBe(1);
    expect(w.has("young")).toBe(false);
  });

  it("sweeps nothing while an install or update is filling the store", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("a")]: "dead but wanted soon" });
    const running = ContentStore.open(w.root, {
      primitive: "copy",
    }) as ContentStore;
    await running.place({
      path: NODE("b"),
      data: Buffer.from("in flight"),
      digest: digest("in flight"),
      output: join(w.home, "tree", "f"),
      exec: false,
    });
    expect(readdirSync(storeLayout(w.root).inflight)).toHaveLength(1);
    const during = w.collect({ graceMs: 60_000 });
    expect(during).toMatchObject({
      deferred: true,
      removedObjects: 0,
      removedReferences: 0,
    });
    expect(w.has("dead but wanted soon")).toBe(true);
    expect(w.has("in flight")).toBe(true);
    running.end();
    expect(w.collect().deferred).toBe(false);
  });

  it("recovers from an operation that died, without touching a live release", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("live")]: "live bytes" });
    w.state.set("acme@1.0.0", "live");
    // An update that was killed: objects written, no reference, marker left.
    const killed = ContentStore.open(w.root, {
      primitive: "copy",
    }) as ContentStore;
    await killed.place({
      path: NODE("half"),
      data: Buffer.from("half an update"),
      digest: digest("half an update"),
      output: join(w.home, "half", "f"),
      exec: false,
    });
    writeFileSync(join(storeLayout(w.root).temporary, "torn-object"), "torn");
    // A collection straight after must not guess: the operation may be alive.
    expect(w.collect({ graceMs: 60_000 })).toMatchObject({ deferred: true });
    expect(w.has("half an update")).toBe(true);
    // Once the marker is old, the debris goes and the live release stays.
    const later = Date.now() + 120_000;
    for (const directory of [
      storeLayout(w.root).inflight,
      storeLayout(w.root).temporary,
    ])
      for (const name of readdirSync(directory))
        utimesSync(
          join(directory, name),
          new Date(later - 90_000),
          new Date(later - 90_000),
        );
    const result = w.collect({ graceMs: 60_000, now: () => later });
    expect(result).toMatchObject({
      deferred: false,
      removedObjects: 1,
      removedTemporaries: 1,
    });
    expect(w.has("half an update")).toBe(false);
    expect(w.has("live bytes")).toBe(true);
    expect(verifyStore({ root: w.root })).toMatchObject({
      checked: 1,
      damaged: [],
    });
  });

  it("stops at its time budget and continues next time", async () => {
    const w = world();
    const files: Record<string, string> = {};
    for (let index = 0; index < 200; index += 1)
      files[NODE(`p${index}`)] = `content ${index}`;
    await w.release("acme", "1.0.0", files);
    let tick = 0;
    const first = w.collect({ budgetMs: 100, now: () => (tick += 50) });
    expect(first.remaining).toBe(true);
    expect(first.removedObjects).toBeLessThan(200);
    const rest = w.collect();
    expect(rest.remaining).toBe(false);
    expect(first.removedObjects + rest.removedObjects).toBe(200);
  });

  it("yields to another collection that holds the store", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("a")]: "kept" });
    const first = ContentStore.open(w.root, { primitive: "copy" });
    expect(first).toBeDefined();
    const { acquireLifecycleLock } = await import(
      "../install/lifecycle-lock.js"
    );
    const hold = acquireLifecycleLock(
      storeLayout(w.root).lock,
      () => new Error("busy"),
      () => new Error("unavailable"),
    );
    try {
      expect(w.collect()).toMatchObject({ busy: true, removedObjects: 0 });
      expect(w.has("kept")).toBe(true);
    } finally {
      hold.release();
    }
  });

  it("does nothing, and creates nothing, where there is no store", () => {
    const w = world();
    expect(w.collect()).toMatchObject({ removedObjects: 0, busy: false });
    expect(existsSync(w.root)).toBe(false);
  });

  it("ignores names that are not objects, and a reference it cannot read pins nothing", async () => {
    const w = world();
    await w.release("acme", "1.0.0", { [NODE("a")]: "x" });
    const { refs, objects } = storeLayout(w.root);
    writeFileSync(join(refs, "acme", "1.0.0.json"), "not json");
    writeFileSync(join(objects, "stray"), "x");
    mkdirSync(join(refs, "stray-dir"));
    w.state.set("acme@1.0.0", "live");
    w.collect();
    expect(existsSync(join(objects, "stray"))).toBe(true);
    expect(w.has("x")).toBe(false);
  });
});

describe("verifying the file store", () => {
  it("finds a damaged object and removes it so the next install writes it again", async () => {
    const w = world();
    await w.release("acme", "1.0.0", {
      [NODE("a")]: "good",
      [NODE("b")]: "will be damaged",
    });
    const path = join(
      storeLayout(w.root).objects,
      digest("will be damaged").slice(0, 2),
      digest("will be damaged"),
    );
    rmSync(path);
    writeFileSync(path, "tampered");
    const found = verifyStore({ root: w.root });
    expect(found).toMatchObject({ checked: 2, repaired: 0, remaining: false });
    expect(found.damaged).toEqual([digest("will be damaged")]);
    expect(readFileSync(path, "utf8")).toBe("tampered");
    const repaired = verifyStore({ root: w.root, repair: true });
    expect(repaired.repaired).toBe(1);
    expect(existsSync(path)).toBe(false);
    expect(verifyStore({ root: w.root })).toMatchObject({
      checked: 1,
      damaged: [],
    });
    // The next release that carries the bytes writes the object again.
    await w.release("acme", "1.1.0", { [NODE("b")]: "will be damaged" });
    expect(w.has("will be damaged")).toBe(true);
  });
});
