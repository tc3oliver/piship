// Threads that cannot run, or that meet a refusal, never fail a build: the same
// work is done on one thread. The workers here are stand-ins, so nothing
// depends on how fast a real thread starts.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hash } from "./digest.js";

const stand = vi.hoisted(() => ({
  /** What a stand-in worker does with the shared state it is given. */
  behaviour: "refuse-start" as "refuse-start" | "busy",
  /** Called with the first file a busy worker "placed" before it was refused. */
  placed: undefined as undefined | ((data: Record<string, unknown>) => void),
  slots: { DONE: 0, FAILED: 0, MESSAGE_LENGTH: 0, STARTED: 0 },
}));
vi.mock("node:worker_threads", () => ({
  Worker: class {
    constructor(
      _code: string,
      options: { workerData: Record<string, unknown> },
    ) {
      if (stand.behaviour === "refuse-start")
        throw new Error("no threads here");
      const data = options.workerData;
      const state = new Int32Array(data.state as SharedArrayBuffer);
      const message = new Uint8Array(data.message as SharedArrayBuffer);
      stand.placed?.(data);
      const text = new TextEncoder().encode("EBUSY: resource busy or locked");
      message.set(text);
      Atomics.store(state, stand.slots.MESSAGE_LENGTH, text.length);
      Atomics.store(state, stand.slots.FAILED, 1);
      Atomics.add(state, stand.slots.STARTED, 1);
      Atomics.add(state, stand.slots.DONE, 1);
    }
    terminate() {
      return Promise.resolve(0);
    }
    once() {}
  },
}));

import {
  hashFilesInParallel,
  SLOTS,
  placeFilesInParallel,
  removeTree,
  WorkerFailure,
} from "./parallel-files.js";
import {
  adoptInstallTree,
  type InstallTree,
  materializeInstallTree,
  type RuntimeCache,
} from "./runtime-cache.js";

Object.assign(stand.slots, SLOTS);

const roots: string[] = [];
const temp = () => {
  const root = mkdtempSync(join(tmpdir(), "piship-fallback-"));
  roots.push(root);
  return root;
};
afterEach(() => {
  vi.unstubAllEnvs();
  stand.behaviour = "refuse-start";
  stand.placed = undefined;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fill(root: string, count: number): string[] {
  const names: string[] = [];
  for (let index = 0; index < count; index++) {
    const name = `d${index % 3}/f${index}.js`;
    mkdirSync(join(root, `d${index % 3}`), { recursive: true });
    writeFileSync(join(root, name), `export const v = ${index};\n`);
    names.push(name);
  }
  return names;
}

describe("threads that cannot start", () => {
  it("are reported as a start failure by the thread helpers", () => {
    const root = temp();
    const names = fill(root, 8);
    expect(() =>
      placeFilesInParallel(2, root, join(temp(), "x"), names, [], false),
    ).toThrowError(WorkerFailure);
  });

  it("hash the files on one thread instead", () => {
    const root = temp();
    const names = fill(root, 20);
    const digests = hashFilesInParallel(4, root, names);
    expect(digests).toEqual(
      names.map((name) => hash(readFileSync(join(root, name)))),
    );
  });

  it("remove a tree on one thread instead", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    const root = join(temp(), "tree");
    mkdirSync(root);
    fill(root, 30);
    removeTree(root);
    expect(existsSync(root)).toBe(false);
  });
});

describe("placing a cached tree when threads fail", () => {
  const entry = (count: number) => {
    const root = temp();
    const stage = join(root, "stage");
    fill(join(stage, "node_modules"), count);
    const cache = {
      root: join(root, "cache"),
      key: "a".repeat(64),
      framework: "b".repeat(64),
      strip: false,
    } satisfies RuntimeCache;
    const tree = adoptInstallTree(cache, stage)?.tree as InstallTree;
    return { root, tree };
  };

  it("places every file on one thread when no thread started", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    const { root, tree } = entry(25);
    const target = join(root, "payload");
    const placed = materializeInstallTree(tree, target, {
      strip: false,
      link: false,
    });
    expect(placed).toEqual({ linked: 0, copied: 25 });
    for (const name of Object.keys(tree.files))
      expect(readFileSync(join(target, name), "utf8")).toBe(
        readFileSync(join(tree.tree, name), "utf8"),
      );
  });

  it("keeps what a refused thread already placed, places the rest, and still refuses a file that is in the way", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    stand.behaviour = "busy";
    const { root, tree } = entry(25);
    const names = Object.keys(tree.files).sort();
    const target = join(root, "payload");
    // The refused thread had already placed the first file.
    stand.placed = () => {
      const first = join(target, ...(names[0] as string).split("/"));
      mkdirSync(join(first, ".."), { recursive: true });
      writeFileSync(
        first,
        readFileSync(join(tree.tree, ...(names[0] as string).split("/"))),
      );
    };
    const placed = materializeInstallTree(tree, target, {
      strip: false,
      link: false,
    });
    expect(placed.copied).toBe(24);
    for (const name of names)
      expect(readFileSync(join(target, ...name.split("/")), "utf8")).toBe(
        readFileSync(join(tree.tree, ...name.split("/")), "utf8"),
      );
    // A file of the wrong size where one belongs is not mistaken for placed.
    const other = join(root, "other");
    stand.placed = () => {
      const first = join(other, ...(names[0] as string).split("/"));
      mkdirSync(join(first, ".."), { recursive: true });
      writeFileSync(first, "wrong size");
    };
    expect(() =>
      materializeInstallTree(tree, other, { strip: false, link: false }),
    ).toThrow(/EEXIST/);
  });
});
