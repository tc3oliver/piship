import {
  existsSync,
  linkSync,
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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hash } from "./digest.js";
import type { DistributionLock } from "./lock-schema.js";
import {
  adoptInstallTree,
  type InstallTree,
  lookupBundle,
  lookupInstallTree,
  lookupTree,
  materializeInstallTree,
  placeBundle,
  plainInventory,
  publishFrameworkTree,
  type RuntimeCache,
  runtimeCacheFor,
  storeBundle,
} from "./runtime-cache.js";

const fixture = vi.hoisted(() => ({
  input: `${process.env.TEMP ?? process.env.TMPDIR ?? "/tmp"}/piship-runtime-cache-input-${process.pid}-${Math.random().toString(16).slice(2)}`,
  npm: "11.19.0",
  linkError: undefined as string | undefined,
  renameFailures: [] as string[],
}));

vi.mock("./runtime-dependencies.js", async (original) => ({
  ...(await original<typeof import("./runtime-dependencies.js")>()),
  buildInput: fixture.input,
  workspacePackages: ["schema", "core"],
}));
vi.mock("node:child_process", async (original) => ({
  ...(await original<typeof import("node:child_process")>()),
  execFileSync: vi.fn(() => `${fixture.npm}\n`),
}));
vi.mock("node:fs", async (original) => {
  const fs = await original<typeof import("node:fs")>();
  return {
    ...fs,
    linkSync: vi.fn((from: string, to: string) => {
      if (fixture.linkError)
        throw Object.assign(new Error("link refused"), {
          code: fixture.linkError,
        });
      return fs.linkSync(from, to);
    }),
    renameSync: vi.fn((from: string, to: string) => {
      const code = fixture.renameFailures.shift();
      if (code) throw Object.assign(new Error("rename refused"), { code });
      return fs.renameSync(from, to);
    }),
  };
});

/** The adopted tree, whether the stage's tree was moved or copied in. */
const adopt = (cache: RuntimeCache, stage: string) =>
  adoptInstallTree(cache, stage)?.tree;

const roots: string[] = [];
const temp = () => {
  const root = mkdtempSync(join(tmpdir(), "piship-runtime-cache-"));
  roots.push(root);
  return root;
};
beforeEach(() => {
  mkdirSync(fixture.input, { recursive: true });
  writeFileSync(
    join(fixture.input, ".piship-build-input.json"),
    JSON.stringify({ schema: "piship-build-input/v1", sha256: "a".repeat(64) }),
  );
});
const platform = Object.getOwnPropertyDescriptor(process, "platform");
afterEach(() => {
  fixture.linkError = undefined;
  fixture.renameFailures.length = 0;
  vi.clearAllMocks();
  if (platform) Object.defineProperty(process, "platform", platform);
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  rmSync(fixture.input, { recursive: true, force: true });
});

const lock = (npmLockSha256 = "b".repeat(64), strip = false) =>
  ({
    runtime: { package: "pi", version: "1.0.3", npmLockSha256 },
    release: { strip },
  }) as unknown as DistributionLock;
const cacheOf = (root: string, key = "c".repeat(64), strip = false) =>
  ({
    root: join(root, "cache"),
    key,
    framework: "d".repeat(64),
    strip,
  }) satisfies RuntimeCache;

/** A staged third-party tree as `installRuntime` leaves it for the cache. */
function stageTree(stage: string): Record<string, string> {
  const files: Record<string, string> = {
    "node_modules/dep/package.json": '{"name":"dep"}\n',
    "node_modules/dep/index.js": "module.exports = 1;\n",
    "node_modules/dep/index.d.ts": "export {};\n",
    "node_modules/dep/index.js.map": "{}\n",
    "node_modules/dep/types/only.d.mts": "export {};\n",
    "node_modules/dep/nested/deep/only.d.cts": "export {};\n",
    "node_modules/@scope/pkg/lib.js": "exports.lib = 1;\n",
  };
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(stage, path, ".."), { recursive: true });
    writeFileSync(join(stage, path), body);
  }
  return files;
}

function walk(root: string, prefix = ""): string[] {
  return readdirSync(join(root, prefix), { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory()
        ? [`${prefix}${entry.name}/`, ...walk(root, `${prefix}${entry.name}/`)]
        : [`${prefix}${entry.name}`],
    )
    .sort();
}

describe("runtimeCacheFor", () => {
  const env = (home: string) => ({ PISHIP_CACHE_HOME: home });

  it("keys the third-party tree by the dependency set, not by PiShip's own output, and keeps it under the cache home", () => {
    const home = temp();
    const first = runtimeCacheFor(lock(), env(home));
    expect(first.root).toBe(join(home, "runtime"));
    expect(runtimeCacheFor(lock(), env(home)).key).toBe(first.key);
    // Where it lives does not decide what is in it.
    expect(runtimeCacheFor(lock(), env(temp())).key).toBe(first.key);
    // The distribution lock's dependency set: Pi version and the npm lock.
    expect(runtimeCacheFor(lock("d".repeat(64)), env(home)).key).not.toBe(
      first.key,
    );
    // PiShip's compiled output and version decide only its own layer.
    writeFileSync(
      join(fixture.input, ".piship-build-input.json"),
      JSON.stringify({
        schema: "piship-build-input/v1",
        sha256: "e".repeat(64),
      }),
    );
    const changed = runtimeCacheFor(lock(), env(home));
    expect(changed.key).toBe(first.key);
    expect(changed.framework).not.toBe(first.framework);
    const upgraded = lock();
    (upgraded.runtime as { pishipVersion?: string }).pishipVersion = "9.9.9";
    expect(runtimeCacheFor(upgraded, env(home)).key).toBe(first.key);
  });

  it("keys the tree by the major and minor of npm, and by the libc family on Linux", async () => {
    const home = temp();
    const keyWith = async (npm: string) => {
      fixture.npm = npm;
      vi.resetModules();
      const fresh = await import("./runtime-cache.js");
      return fresh.runtimeCacheFor(lock(), env(home)).key;
    };
    const base = await keyWith("11.19.0");
    // A patch release of npm installs the same tree; a minor or major may not.
    expect(await keyWith("11.19.7")).toBe(base);
    expect(await keyWith("11.20.0")).not.toBe(base);
    expect(await keyWith("10.9.2")).not.toBe(base);
    // An npm that cannot say is its own line, never one that matches.
    const unknown = await keyWith("not a version");
    expect(unknown).not.toBe(base);
    expect(await keyWith("")).toBe(unknown);

    const report = vi.spyOn(
      process.report as NodeJS.ProcessReport,
      "getReport",
    );
    const libc = async (header: object) => {
      report.mockReturnValue({ header } as never);
      return keyWith("11.19.0");
    };
    try {
      // Off Linux the libc is not part of the key.
      expect(await libc({ glibcVersionRuntime: "2.39" })).toBe(await libc({}));
      Object.defineProperty(process, "platform", { value: "linux" });
      const glibc = await libc({ glibcVersionRuntime: "2.39" });
      expect(glibc).not.toBe(await libc({}));
      expect(await libc({ glibcVersionRuntime: "2.31" })).toBe(glibc);
    } finally {
      report.mockRestore();
    }
  });

  it("does not let release.strip decide the installed tree, only how it is placed", () => {
    const home = temp();
    const stripped = runtimeCacheFor(lock("b".repeat(64), true), env(home));
    const full = runtimeCacheFor(lock(), env(home));
    expect(stripped.strip).toBe(true);
    expect(full.strip).toBe(false);
    expect(stripped.key).toBe(full.key);
  });
});

describe("install tree entries", () => {
  it("adopts a staged tree by moving it, then places it again without maps and declarations", () => {
    const root = temp();
    const stage = join(root, "stage");
    mkdirSync(stage);
    const files = stageTree(stage);
    const cache = cacheOf(root, undefined, true);
    expect(lookupInstallTree(cache)).toBeUndefined();
    const tree = adopt(cache, stage);
    expect(tree).toBeDefined();
    // The tree moved: nothing of it is left in the stage.
    expect(readdirSync(stage)).toEqual([]);
    expect(Object.keys(tree?.files ?? {}).sort()).toEqual(
      Object.keys(files).sort(),
    );
    expect(tree?.files["node_modules/dep/index.js"]).toBe(
      files["node_modules/dep/index.js"]?.length,
    );
    expect(lookupInstallTree(cache)?.path).toBe(tree?.path);

    const target = join(root, "placed");
    materializeInstallTree(tree as never, target, { strip: true });
    // The directories only declarations lived in are never created.
    expect(walk(target)).toEqual([
      "node_modules/",
      "node_modules/@scope/",
      "node_modules/@scope/pkg/",
      "node_modules/@scope/pkg/lib.js",
      "node_modules/dep/",
      "node_modules/dep/index.js",
      "node_modules/dep/package.json",
    ]);
    // The entry itself keeps everything.
    expect(
      existsSync(join(tree?.tree as string, "node_modules/dep/index.d.ts")),
    ).toBe(true);
    const whole = join(root, "whole");
    materializeInstallTree(tree as never, whole, { strip: false });
    expect(walk(whole).filter((name) => !name.endsWith("/"))).toHaveLength(
      Object.keys(files).length,
    );
  });

  it("refuses an entry whose key, schema, target, or file set does not match its record", () => {
    const root = temp();
    const cache = cacheOf(root);
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const tree = adopt(cache, stage);
    const record = join((tree as InstallTree).path, "entry.json");
    const original = readFileSync(record, "utf8");
    const damage = (patch: Record<string, unknown>) => {
      writeFileSync(
        record,
        JSON.stringify({ ...JSON.parse(original), ...patch }),
      );
      return lookupInstallTree(cache);
    };
    expect(damage({})).toBeDefined();
    expect(damage({ schema: "other/v1" })).toBeUndefined();
    expect(damage({ key: "f".repeat(64) })).toBeUndefined();
    expect(damage({ arch: "mips" })).toBeUndefined();
    expect(damage({ files: { "../escape": 1 } })).toBeUndefined();
    writeFileSync(record, "not json");
    expect(lookupInstallTree(cache)).toBeUndefined();
    writeFileSync(record, original);
    expect(lookupInstallTree(cache)).toBeDefined();
    // A file that went missing, and one nobody recorded.
    const lib = join(tree?.tree as string, "node_modules/@scope/pkg/lib.js");
    rmSync(lib);
    expect(lookupInstallTree(cache)).toBeUndefined();
    writeFileSync(lib, "exports.lib = 1;\n");
    expect(lookupInstallTree(cache)).toBeDefined();
    writeFileSync(join(tree?.tree as string, "extra.js"), "");
    expect(lookupInstallTree(cache)).toBeUndefined();
  });

  it("refuses a record whose file list no longer matches its digest, and names the entry by that digest", () => {
    const root = temp();
    const cache = cacheOf(root);
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const tree = adopt(cache, stage) as InstallTree;
    expect(tree.digest).toMatch(/^[0-9a-f]{64}$/);
    const record = join(tree.path, "entry.json");
    const original = JSON.parse(readFileSync(record, "utf8")) as {
      files: Record<string, number>;
      filesSha256: string;
    };
    expect(original.filesSha256).toBe(tree.digest);
    // A file's size edited in the record, or the digest dropped or replaced.
    for (const change of [
      { files: { ...original.files, "node_modules/dep/package.json": 1 } },
      { filesSha256: undefined },
      { filesSha256: "0".repeat(64) },
    ]) {
      writeFileSync(record, JSON.stringify({ ...original, ...change }));
      expect(lookupInstallTree(cache)).toBeUndefined();
    }
    writeFileSync(record, JSON.stringify(original));
    expect(lookupInstallTree(cache)?.digest).toBe(tree.digest);
  });

  it("refuses to place a file whose size is not the recorded one", () => {
    const root = temp();
    const cache = cacheOf(root);
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const tree = adopt(cache, stage);
    writeFileSync(
      join(tree?.tree as string, "node_modules/dep/index.js"),
      "truncated",
    );
    expect(() =>
      materializeInstallTree(tree as never, join(root, "placed"), {
        strip: false,
      }),
    ).toThrow(/damaged/);
  });

  it("leaves the stage as it was when the tree cannot be adopted", () => {
    if (process.platform === "win32") return;
    const root = temp();
    const stage = join(root, "stage");
    mkdirSync(stage);
    const files = stageTree(stage);
    symlinkSync("dep", join(stage, "node_modules", "linked"));
    expect(adopt(cacheOf(root), stage)).toBeUndefined();
    for (const [path, body] of Object.entries(files))
      expect(readFileSync(join(stage, path), "utf8")).toBe(body);
    // No half-published entry and no holding directory is left behind.
    expect(readdirSync(join(root, "cache"))).toEqual([]);
  });

  it("copies the tree in, and leaves the stage whole, when the cache is on another volume", () => {
    const root = temp();
    const cache = cacheOf(root);
    const stage = join(root, "stage");
    mkdirSync(stage);
    const files = stageTree(stage);
    // The first rename, the move of node_modules into the entry, crosses volumes.
    fixture.renameFailures.push("EXDEV");
    const adopted = adoptInstallTree(cache, stage);
    expect(adopted?.moved).toBe(false);
    for (const [path, body] of Object.entries(files))
      expect(readFileSync(join(stage, path), "utf8")).toBe(body);
    expect(Object.keys(adopted?.tree.files ?? {}).sort()).toEqual(
      Object.keys(files).sort(),
    );
    expect(lookupInstallTree(cache)?.digest).toBe(adopted?.tree.digest);
    // The entry holds its own copies, not the stage's files.
    expect(
      statSync(join(adopted?.tree.tree as string, "node_modules/dep/index.js"))
        .ino,
    ).not.toBe(statSync(join(stage, "node_modules/dep/index.js")).ino);
    // A later build can place it, copying where links cannot cross volumes.
    const target = join(root, "placed");
    fixture.linkError = "EXDEV";
    expect(
      materializeInstallTree(adopted?.tree as InstallTree, target, {
        strip: false,
        link: true,
      }),
    ).toEqual({ linked: 0, copied: Object.keys(files).length });
  });

  it("puts the tree back, and takes the entry out of use, when it cannot read what it published", () => {
    // A name no entry accepts: the record is refused, though it was written.
    if (process.platform === "win32") return;
    const root = temp();
    const stage = join(root, "stage");
    mkdirSync(stage);
    const files = stageTree(stage);
    writeFileSync(join(stage, "node_modules", "dep", "a:b.js"), "colon");
    const cache = cacheOf(root);
    expect(adopt(cache, stage)).toBeUndefined();
    for (const [path, body] of Object.entries(files))
      expect(readFileSync(join(stage, path), "utf8")).toBe(body);
    expect(
      readFileSync(join(stage, "node_modules", "dep", "a:b.js"), "utf8"),
    ).toBe("colon");
    expect(lookupInstallTree(cache)).toBeUndefined();
    expect(
      readdirSync(cache.root).filter(
        (name) => /^[it]/.test(name) || name.startsWith(".t"),
      ),
    ).toEqual([]);
  });

  it("uses the entry another build published first instead of replacing it", () => {
    const root = temp();
    const cache = cacheOf(root);
    const first = join(root, "first");
    const second = join(root, "second");
    for (const stage of [first, second]) {
      mkdirSync(stage);
      stageTree(stage);
    }
    const winner = adopt(cache, first);
    // The loser's own moved tree is discarded; its stage is emptied the same way.
    const loser = adopt(cache, second);
    expect(loser?.path).toBe(winner?.path);
    expect(readdirSync(second)).toEqual([]);
    expect(
      readdirSync(cache.root).filter((name) => name.startsWith("i-")),
    ).toEqual([winner?.path.split(/[\\/]/).at(-1)]);
    expect(
      readdirSync(cache.root).filter((name) => name.startsWith(".t")),
    ).toEqual([]);
  });

  it("replaces an unusable entry that occupies its name", () => {
    const root = temp();
    const cache = cacheOf(root);
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const tree = adopt(cache, stage);
    rmSync(join(tree?.tree as string, "node_modules/dep/package.json"));
    expect(lookupInstallTree(cache)).toBeUndefined();
    const again = join(root, "again");
    mkdirSync(again);
    stageTree(again);
    expect(adopt(cache, again)).toBeDefined();
    expect(lookupInstallTree(cache)).toBeDefined();
  });

  it("keeps the newest entries and hides the rest from builds immediately", () => {
    const root = temp();
    const keys = ["1", "2", "3", "4", "5"].map((digit) => digit.repeat(64));
    for (const [index, key] of keys.entries()) {
      const stage = join(root, `stage-${index}`);
      mkdirSync(stage);
      stageTree(stage);
      adopt(cacheOf(root, key), stage);
      // Strictly increasing use times, whatever the file system's resolution.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
    const kept = readdirSync(join(root, "cache")).filter(
      (name) => name.startsWith("i-") && !name.endsWith(".d"),
    );
    expect(kept).toHaveLength(3);
    expect(lookupInstallTree(cacheOf(root, keys[0]))).toBeUndefined();
    expect(lookupInstallTree(cacheOf(root, keys[1]))).toBeUndefined();
    for (const key of keys.slice(2))
      expect(lookupInstallTree(cacheOf(root, key))).toBeDefined();
  });

  it("uses an entry's recent use, not its age, to decide what stays", () => {
    const root = temp();
    const keys = ["1", "2", "3", "4"].map((digit) => digit.repeat(64));
    for (const key of keys.slice(0, 3)) {
      const stage = join(root, `stage-${key.slice(0, 1)}`);
      mkdirSync(stage);
      stageTree(stage);
      adopt(cacheOf(root, key), stage);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
    // The oldest entry is used again, so the next oldest goes instead.
    const used = new Date();
    utimesSync(
      join(root, "cache", `i-${keys[0]?.slice(0, 20)}`, "entry.json"),
      used,
      used,
    );
    const stage = join(root, "stage-4");
    mkdirSync(stage);
    stageTree(stage);
    adopt(cacheOf(root, keys[3]), stage);
    expect(lookupInstallTree(cacheOf(root, keys[1]))).toBeUndefined();
    expect(lookupInstallTree(cacheOf(root, keys[0]))).toBeDefined();
  });
});

/** The PiShip build input the fixture stands in for: a root manifest and lock, and two packages. */
function stageBuildInput(): Record<string, string> {
  const files: Record<string, string> = {
    "package.json": '{"name":"piship-workspace"}\n',
    "package-lock.json": "{}\n",
  };
  for (const name of ["schema", "core"]) {
    files[`packages/${name}/package.json`] = `{"name":"@piship/${name}"}\n`;
    files[`packages/${name}/dist/index.js`] = `export const ${name} = 1;\n`;
    files[`packages/${name}/dist/index.d.ts`] = "export {};\n";
  }
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(fixture.input, path, ".."), { recursive: true });
    writeFileSync(join(fixture.input, path), body);
  }
  return files;
}

describe("PiShip's own layer", () => {
  it("is published from the build input as a payload's own files, beside the third-party tree", () => {
    const root = temp();
    stageBuildInput();
    const cache = cacheOf(root);
    expect(lookupTree(cache, "framework")).toBeUndefined();
    const tree = publishFrameworkTree(cache) as InstallTree;
    expect(Object.keys(tree.files).sort()).toEqual(
      [
        "package.json",
        "package-lock.json",
        "node_modules/@piship/schema/package.json",
        "node_modules/@piship/schema/dist/index.js",
        "node_modules/@piship/schema/dist/index.d.ts",
        "node_modules/@piship/core/package.json",
        "node_modules/@piship/core/dist/index.js",
        "node_modules/@piship/core/dist/index.d.ts",
        // The snapshot management commands read, the build input itself.
        ...Object.keys(stageBuildInputFiles()).map(
          (name) => `node_modules/@piship/core/dist/build-input/${name}`,
        ),
        "node_modules/@piship/core/dist/build-input/.piship-build-input.json",
      ].sort(),
    );
    expect(tree.layer).toBe("framework");
    expect(lookupTree(cache, "framework")?.digest).toBe(tree.digest);
    // Another layer, another directory: neither replaces the other.
    expect(
      readdirSync(cache.root).filter((name) => /^[if]-/.test(name)),
    ).toEqual([`f-${cache.framework.slice(0, 20)}`]);
    expect(lookupInstallTree(cache)).toBeUndefined();
  });

  it("is placed with the third-party tree into one payload, without maps and declarations", () => {
    const root = temp();
    stageBuildInput();
    const cache = cacheOf(root, undefined, true);
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const third = adopt(cache, stage) as InstallTree;
    const own = publishFrameworkTree(cache) as InstallTree;
    const target = join(root, "payload");
    materializeInstallTree(third, target, { strip: true });
    materializeInstallTree(own, target, { strip: true });
    const placed = walk(target).filter((name) => !name.endsWith("/"));
    expect(placed).toContain("package.json");
    expect(placed).toContain("node_modules/@piship/core/dist/index.js");
    expect(placed).toContain("node_modules/dep/index.js");
    expect(placed.filter((name) => /\.d\.ts$|\.map$/.test(name))).toEqual([]);
    // The two layers' digests together describe every file of the payload.
    const digests = {
      ...plainInventory(third, cache),
      ...plainInventory(own, cache),
    };
    expect(Object.keys(digests).sort()).toEqual(placed.sort());
    for (const [path, digest] of Object.entries(digests))
      expect(hash(readFileSync(join(target, path)))).toBe(digest);
  });

  it("is replaced, and the third-party tree kept, when the build input changes", () => {
    const home = temp();
    stageBuildInput();
    const before = runtimeCacheFor(lock(), { PISHIP_CACHE_HOME: home });
    const stage = join(home, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const third = adopt(before, stage) as InstallTree;
    const first = publishFrameworkTree(before) as InstallTree;
    writeFileSync(
      join(fixture.input, ".piship-build-input.json"),
      JSON.stringify({
        schema: "piship-build-input/v1",
        sha256: "9".repeat(64),
      }),
    );
    writeFileSync(
      join(fixture.input, "packages/core/dist/index.js"),
      "changed\n",
    );
    const after = runtimeCacheFor(lock(), { PISHIP_CACHE_HOME: home });
    expect(after.key).toBe(before.key);
    expect(lookupInstallTree(after)?.digest).toBe(third.digest);
    expect(lookupTree(after, "framework")).toBeUndefined();
    const second = publishFrameworkTree(after) as InstallTree;
    expect(second.key).not.toBe(first.key);
    expect(
      readFileSync(
        join(second.tree, "node_modules/@piship/core/dist/index.js"),
        "utf8",
      ),
    ).toBe("changed\n");
    // The first build's layer is still there for a build of that input.
    expect(lookupTree(before, "framework")?.digest).toBe(first.digest);
  });
});

function stageBuildInputFiles(): Record<string, string> {
  return Object.fromEntries(
    readdirSyncRecursive(fixture.input).map((name) => [name, ""]),
  );
}

/** Relative paths of the regular files under `root`, without the generation marker. */
function readdirSyncRecursive(root: string, prefix = ""): string[] {
  return readdirSync(join(root, prefix), { withFileTypes: true }).flatMap(
    (entry) =>
      entry.isDirectory()
        ? readdirSyncRecursive(root, `${prefix}${entry.name}/`)
        : entry.name === ".piship-build-input.json"
          ? []
          : [`${prefix}${entry.name}`],
  );
}

describe("placing and hashing by several threads", () => {
  const adoptedMany = (count: number) => {
    const root = temp();
    const stage = join(root, "stage");
    for (let index = 0; index < count; index++) {
      const path = join(
        stage,
        "node_modules",
        `pkg-${index % 7}`,
        `dir-${index % 3}`,
        `file-${index}.js`,
      );
      mkdirSync(join(path, ".."), { recursive: true });
      writeFileSync(path, `export const value = ${index};\n`);
    }
    // And files placement leaves out.
    writeFileSync(join(stage, "node_modules", "pkg-0", "x.d.ts"), "");
    const cache = cacheOf(root, undefined, true);
    return { root, cache, tree: adopt(cache, stage) as InstallTree };
  };

  it("places the same files, checks their sizes, and counts them, as one thread does", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    try {
      const { root, tree } = adoptedMany(97);
      const threaded = join(root, "threaded");
      const placed = materializeInstallTree(tree, threaded, {
        strip: true,
        link: false,
      });
      expect(placed).toEqual({ linked: 0, copied: 97 });
      vi.stubEnv("PISHIP_FILE_WORKERS", "1");
      const single = join(root, "single");
      materializeInstallTree(tree, single, { strip: true, link: false });
      expect(walk(threaded)).toEqual(walk(single));
      for (const name of walk(threaded).filter((n) => n.endsWith(".js")))
        expect(readFileSync(join(threaded, name), "utf8")).toBe(
          readFileSync(join(single, name), "utf8"),
        );
      // Links, where they work, and one copy fallback that stays a fallback.
      const linked = join(root, "linked");
      if (process.platform !== "win32") {
        vi.stubEnv("PISHIP_FILE_WORKERS", "3");
        expect(
          materializeInstallTree(tree, linked, { strip: true, link: true }),
        ).toEqual({ linked: 97, copied: 0 });
        const any = walk(linked).find((n) => n.endsWith(".js")) as string;
        expect(statSync(join(linked, any)).ino).toBe(
          statSync(join(tree.tree, any)).ino,
        );
      }
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("reports the first failure of any thread, and never overwrites a file", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    try {
      const { root, tree } = adoptedMany(40);
      const target = join(root, "occupied");
      const victim = Object.keys(tree.files).sort()[17] as string;
      mkdirSync(join(target, victim, ".."), { recursive: true });
      writeFileSync(join(target, victim), "mine");
      expect(() =>
        materializeInstallTree(tree, target, { strip: true, link: false }),
      ).toThrow(/EEXIST/);
      expect(readFileSync(join(target, victim), "utf8")).toBe("mine");
      // A size that is not the recorded one is the damaged-entry error.
      const other = join(root, "damaged");
      const file = Object.keys(tree.files).sort()[3] as string;
      writeFileSync(join(tree.tree, file), "truncated");
      expect(() =>
        materializeInstallTree(tree, other, { strip: true, link: false }),
      ).toThrow(/damaged/);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("hashes files by several threads to the digests one thread gives", () => {
    vi.stubEnv("PISHIP_FILE_WORKERS", "4");
    try {
      const { cache, tree } = adoptedMany(61);
      const threaded = plainInventory(tree, cache);
      rmSync(join(tree.path, "plain-stripped.json"));
      vi.stubEnv("PISHIP_FILE_WORKERS", "1");
      const single = plainInventory(tree, cache);
      expect(threaded).toEqual(single);
      expect(Object.keys(threaded)).toHaveLength(61);
      const [name] = Object.keys(threaded);
      expect(threaded[name as string]).toBe(
        hash(readFileSync(join(tree.tree, name as string))),
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("placing files", () => {
  const adopted = () => {
    const root = temp();
    const stage = join(root, "stage");
    mkdirSync(stage);
    stageTree(stage);
    const tree = adopt(cacheOf(root), stage);
    return { root, tree: tree as NonNullable<typeof tree> };
  };

  it("hardlinks files when asked, which shares their bytes with the entry", () => {
    if (process.platform === "win32") return;
    const { root, tree } = adopted();
    const target = join(root, "linked");
    expect(
      materializeInstallTree(tree, target, { strip: false, link: true }),
    ).toEqual({ linked: Object.keys(tree.files).length, copied: 0 });
    const entryFile = join(tree.tree, "node_modules/dep/index.js");
    const placed = join(target, "node_modules/dep/index.js");
    expect(statSync(placed).ino).toBe(statSync(entryFile).ino);
    expect(statSync(entryFile).nlink).toBe(2);
    // Removing the placed name never touches the entry.
    rmSync(target, { recursive: true });
    expect(readFileSync(entryFile, "utf8")).toBe("module.exports = 1;\n");
    expect(lookupInstallTree(cacheOf(root))).toBeDefined();
  });

  it("copies files by default off Windows, so writing one never reaches the entry", () => {
    if (process.platform === "win32") return;
    const { root, tree } = adopted();
    const target = join(root, "copied");
    materializeInstallTree(tree, target, { strip: false });
    const placed = join(target, "node_modules/dep/index.js");
    expect(statSync(placed).ino).not.toBe(
      statSync(join(tree.tree, "node_modules/dep/index.js")).ino,
    );
    writeFileSync(placed, "changed");
    expect(
      readFileSync(join(tree.tree, "node_modules/dep/index.js"), "utf8"),
    ).toBe("module.exports = 1;\n");
  });

  it.each(["EXDEV", "EPERM", "EMLINK", "UNKNOWN"])(
    "falls back to copying, once, when a link fails with %s",
    (code) => {
      const { root, tree } = adopted();
      fixture.linkError = code;
      const target = join(root, "fallback");
      materializeInstallTree(tree, target, { strip: false, link: true });
      expect(vi.mocked(linkSync)).toHaveBeenCalledTimes(1);
      expect(
        readFileSync(join(target, "node_modules/dep/index.js"), "utf8"),
      ).toBe("module.exports = 1;\n");
      expect(walk(target).filter((name) => !name.endsWith("/"))).toHaveLength(
        Object.keys(tree.files).length,
      );
    },
  );

  it("never overwrites a file that is already there", () => {
    const { root, tree } = adopted();
    const target = join(root, "occupied");
    mkdirSync(join(target, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(target, "node_modules", "dep", "index.js"), "mine");
    expect(() =>
      materializeInstallTree(tree, target, { strip: false, link: false }),
    ).toThrow(/EEXIST/);
    expect(
      readFileSync(join(target, "node_modules", "dep", "index.js"), "utf8"),
    ).toBe("mine");
  });
});

describe("plain inventory", () => {
  it("hashes the placed files once, from their bytes, and keeps the digests beside the entry", () => {
    const root = temp();
    const stage = join(root, "stage");
    mkdirSync(stage);
    const files = stageTree(stage);
    const cache = cacheOf(root, undefined, true);
    const tree = adopt(cache, stage) as InstallTree;
    const inventory = plainInventory(tree, cache);
    expect(Object.keys(inventory).sort()).toEqual(
      Object.keys(files)
        .filter((name) => !/\.(?:map|d\.[cm]?ts)$/.test(name))
        .sort(),
    );
    for (const [path, digest] of Object.entries(inventory))
      expect(digest).toBe(hash(files[path] as string));
    const sidecar = join(tree.path, "plain-stripped.json");
    expect(existsSync(sidecar)).toBe(true);
    // A second call takes the stored digests rather than reading the files.
    const stored = JSON.parse(readFileSync(sidecar, "utf8")) as {
      inventory: Record<string, string>;
    };
    stored.inventory["node_modules/dep/package.json"] = "0".repeat(64);
    writeFileSync(sidecar, JSON.stringify(stored));
    expect(plainInventory(tree, cache)["node_modules/dep/package.json"]).toBe(
      "0".repeat(64),
    );
    // A record for another file set is not trusted.
    delete stored.inventory["node_modules/@scope/pkg/lib.js"];
    writeFileSync(sidecar, JSON.stringify(stored));
    expect(plainInventory(tree, cache)["node_modules/@scope/pkg/lib.js"]).toBe(
      hash("exports.lib = 1;\n"),
    );
    // The unstripped inventory is a separate record.
    expect(
      Object.keys(plainInventory(tree, { ...cache, strip: false })),
    ).toHaveLength(Object.keys(files).length);
  });
});

describe("bundle entries", () => {
  const key = "9".repeat(64);
  const bundled = () => {
    const root = temp();
    const payload = join(root, "payload");
    const files: Record<string, string> = {
      "runtime/main.js": "export const main = 1;\n",
      "runtime/chunk-abc.js": "export const chunk = 1;\n",
      "node_modules/@piship/core/package.json": "{}\n",
    };
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(join(payload, path, ".."), { recursive: true });
      writeFileSync(join(payload, path), body);
    }
    writeFileSync(join(payload, "package.json"), "{}\n");
    const inventory = Object.fromEntries(
      Object.entries(files).map(([path, body]) => [path, hash(body)]),
    );
    const cache = cacheOf(root);
    storeBundle(cache, key, payload, inventory, Object.keys(files));
    return { root, cache, files, inventory };
  };

  it("stores the bundled files and verifies their content when reading them back", () => {
    const { root, cache, files, inventory } = bundled();
    const entry = lookupBundle(cache, key);
    expect(entry?.inventory).toEqual(inventory);
    const target = join(root, "placed");
    placeBundle(entry as never, target);
    for (const [path, body] of Object.entries(files))
      expect(readFileSync(join(target, path), "utf8")).toBe(body);
    expect(lookupBundle(cache, "8".repeat(64))).toBeUndefined();
  });

  it("refuses an entry with one byte changed, a file missing, or an extra file", () => {
    const { cache } = bundled();
    const tree = join(
      cache.root,
      `b-${key.slice(0, 20)}`,
      "tree",
      "runtime",
      "main.js",
    );
    // Same size, different byte: only the content hash can tell.
    writeFileSync(tree, "export const main = 2;\n");
    expect(lookupBundle(cache, key)).toBeUndefined();
    writeFileSync(tree, "export const main = 1;\n");
    expect(lookupBundle(cache, key)).toBeDefined();
    writeFileSync(join(tree, "..", "extra.js"), "");
    expect(lookupBundle(cache, key)).toBeUndefined();
    rmSync(join(tree, "..", "extra.js"));
    rmSync(tree);
    expect(lookupBundle(cache, key)).toBeUndefined();
  });

  it("publishes once: a second store of the same key leaves the first entry", () => {
    const { root, cache, files, inventory } = bundled();
    const payload = join(root, "payload");
    writeFileSync(join(payload, "runtime", "main.js"), "export const x = 3;\n");
    storeBundle(cache, key, payload, inventory, Object.keys(files));
    expect(
      readFileSync(
        join(cache.root, `b-${key.slice(0, 20)}`, "tree", "runtime", "main.js"),
        "utf8",
      ),
    ).toBe("export const main = 1;\n");
    expect(
      readdirSync(cache.root).filter((name) => name.startsWith(".t")),
    ).toEqual([]);
  });
});
