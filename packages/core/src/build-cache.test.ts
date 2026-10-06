import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { buildDistribution, type RuntimeCacheReport } from "./build.js";
import { buildCachePath, buildInputDigest } from "./build-cache.js";
import { lockManifest, requireCurrentLock } from "./lock.js";
import { verifyPayload } from "./payload.js";
import { lookupInstallTree, runtimeCacheFor } from "./runtime-cache.js";

const fixture = vi.hoisted(() => ({
  input: `${process.env.TEMP ?? process.env.TMPDIR ?? "/tmp"}/piship-build-cache-input-${process.pid}-${Math.random().toString(16).slice(2)}`,
  installs: 0,
  /** Also install maps and declarations, as real packages ship them. */
  declarations: false,
  /** File operations that create files, and the `npm --version` the cache key asks for. */
  copies: 0,
  links: 0,
  cps: 0,
  removals: 0,
  versions: 0,
  /** The command and arguments of each npm run. */
  runs: [] as [string, readonly string[]][],
}));

vi.mock("./runtime-dependencies.js", async (original) => ({
  ...(await original<typeof import("./runtime-dependencies.js")>()),
  buildInput: fixture.input,
  workspacePackages: ["core"],
}));
vi.mock("node:fs", async (original) => {
  const fs = await original<typeof import("node:fs")>();
  return {
    ...fs,
    copyFileSync: vi.fn((...args: Parameters<typeof fs.copyFileSync>) => {
      fixture.copies++;
      return fs.copyFileSync(...args);
    }),
    linkSync: vi.fn((...args: Parameters<typeof fs.linkSync>) => {
      fixture.links++;
      return fs.linkSync(...args);
    }),
    cpSync: vi.fn((...args: Parameters<typeof fs.cpSync>) => {
      fixture.cps++;
      return fs.cpSync(...args);
    }),
    rmSync: vi.fn((...args: Parameters<typeof fs.rmSync>) => {
      fixture.removals++;
      return fs.rmSync(...args);
    }),
  };
});
vi.mock("node:child_process", async (original) => ({
  ...(await original<typeof import("node:child_process")>()),
  execFileSync: vi.fn((...args: unknown[]) => {
    fixture.versions++;
    return `${(args[1] as string[])[0] === "--version" ? "11.19.0" : ""}\n`;
  }),
  spawnSync: vi.fn((command, args, options) => {
    fixture.installs++;
    fixture.runs.push([command, args]);
    const dependency = join(options.cwd, "node_modules", "dependency");
    mkdirSync(dependency, { recursive: true });
    writeFileSync(
      join(dependency, "index.js"),
      "export const unchanged = true;\n",
    );
    if (fixture.declarations) {
      writeFileSync(join(dependency, "index.d.ts"), "export {};\n");
      writeFileSync(join(dependency, "index.js.map"), "{}\n");
      mkdirSync(join(dependency, "types", "deep"), { recursive: true });
      writeFileSync(join(dependency, "types", "deep", "only.d.ts"), "");
    }
    return { status: 0, stdout: "", stderr: "" };
  }),
}));

const roots: string[] = [];
beforeAll(() => {
  mkdirSync(join(fixture.input, "packages", "core", "dist"), {
    recursive: true,
  });
  for (const file of ["package.json", "package-lock.json"])
    copyFileSync(resolve(file), join(fixture.input, file));
  writeFileSync(
    join(fixture.input, "packages", "core", "package.json"),
    '{"name":"@piship/core","type":"module"}\n',
  );
  writeFileSync(
    join(fixture.input, "packages", "core", "dist", "index.js"),
    "export const framework = 1;\n",
  );
});
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  fixture.installs = 0;
  fixture.declarations = false;
  fixture.copies = fixture.links = fixture.cps = fixture.removals = 0;
  fixture.versions = 0;
  fixture.runs.length = 0;
});
afterAll(() => rmSync(fixture.input, { recursive: true, force: true }));

function project() {
  const root = mkdtempSync(join(tmpdir(), "piship-build-cache-"));
  roots.push(root);
  const manifest = join(root, "piship.yaml");
  const resource = join(root, "AGENTS.md");
  const writeManifest = (command = "cachepi", name = "Cache Pi") =>
    writeFileSync(
      manifest,
      `schema: piship/v1alpha1\napp:\n  id: cachepi\n  name: ${name}\n  version: "1.0.0"\n  command: ${command}\ndeployment:\n  mode: personal\nruntime:\n  pi: "1.0.3"\nresources:\n  instructions: [./AGENTS.md]\n`,
    );
  writeManifest();
  writeFileSync(resource, "# first\n");
  lockManifest(manifest);
  return {
    root,
    manifest,
    resource,
    writeManifest,
    output: join(root, "dist"),
  };
}
const options = { supplyChainGates: false };

describe("local payload reuse", () => {
  it("returns an unchanged payload without npm, rewriting files, or inventory hashing", () => {
    const p = project();
    const output = buildDistribution(p.manifest, p.output, options);
    const dependency = join(output, "node_modules", "dependency", "index.js");
    const before = statSync(dependency).mtimeMs;
    const stamp = statSync(buildCachePath(output)).mtimeMs;
    expect(buildDistribution(p.manifest, p.output, options)).toBe(output);
    expect(fixture.installs).toBe(1);
    expect(statSync(dependency).mtimeMs).toBe(before);
    expect(statSync(buildCachePath(output)).mtimeMs).toBe(stamp);
    expect(verifyPayload(output).app.id).toBe("cachepi");
  });

  it("reuses dependencies after manifest, resource, and command edits and keeps an accurate inventory", () => {
    const p = project();
    const output = buildDistribution(p.manifest, p.output, options);
    const dependency = join(output, "node_modules", "dependency", "index.js");
    const before = statSync(dependency).mtimeMs;
    p.writeManifest("renamed", "Updated name");
    writeFileSync(p.resource, "# changed\n");
    lockManifest(p.manifest);
    expect(buildDistribution(p.manifest, p.output, options)).toBe(output);
    expect(fixture.installs).toBe(1);
    expect(statSync(dependency).mtimeMs).toBe(before);
    expect(readFileSync(join(output, "resources", "AGENTS.md"), "utf8")).toBe(
      "# changed\n",
    );
    expect(existsSync(join(output, "bin", "cachepi"))).toBe(false);
    expect(readFileSync(join(output, "bin", "renamed.cmd"), "utf8")).toContain(
      "renamed",
    );
    expect(verifyPayload(output).app.command).toBe("renamed");
  });

  it("rebuilds when framework bytes change, when the cache is disabled, or when its stamp is invalid", () => {
    const p = project();
    const output = buildDistribution(p.manifest, p.output, options);
    const framework = join(
      fixture.input,
      "packages",
      "core",
      "dist",
      "index.js",
    );
    const prior = readFileSync(framework);
    try {
      writeFileSync(framework, "export const framework = 2;\n");
      buildDistribution(p.manifest, p.output, options);
      expect(fixture.installs).toBe(2);
      expect(
        readFileSync(
          join(output, "node_modules", "@piship", "core", "dist", "index.js"),
          "utf8",
        ),
      ).toContain("framework = 2");
      buildDistribution(p.manifest, p.output, { ...options, cache: false });
      expect(fixture.installs).toBe(3);
      writeFileSync(buildCachePath(output), "damaged");
      buildDistribution(p.manifest, p.output, options);
      expect(fixture.installs).toBe(4);
    } finally {
      writeFileSync(framework, prior);
    }
  });

  it("rejects stale resource locks before taking a cache hit", () => {
    const p = project();
    buildDistribution(p.manifest, p.output, options);
    writeFileSync(p.resource, "# unlocked edit\n");
    expect(() => buildDistribution(p.manifest, p.output, options)).toThrow(
      /Lockfile is stale/,
    );
    expect(fixture.installs).toBe(1);
  });

  it("uses the prepared content generation without reading its entire framework tree", () => {
    const root = mkdtempSync(join(tmpdir(), "piship-build-input-marker-"));
    roots.push(root);
    const sha256 = "a".repeat(64);
    writeFileSync(
      join(root, ".piship-build-input.json"),
      JSON.stringify({ schema: "piship-build-input/v1", sha256 }),
    );
    expect(buildInputDigest(root)).toBe(sha256);
    writeFileSync(
      join(root, ".piship-build-input.json"),
      JSON.stringify({
        schema: "piship-build-input/v1",
        sha256: "b".repeat(64),
      }),
    );
    expect(buildInputDigest(root)).toBe("b".repeat(64));
  });
});

describe("immutable runtime cache", () => {
  const home = () => {
    const root = mkdtempSync(join(tmpdir(), "piship-runtime-cache-home-"));
    roots.push(root);
    return root;
  };
  const cacheOf = (manifest: string, directory: string) =>
    runtimeCacheFor(
      requireCurrentLock(manifest),
      { PISHIP_CACHE_HOME: directory },
      { npm: "11.19", libc: undefined },
    );
  /** The personal example, a piship/v1alpha6 manifest, with the release settings the caller gives. */
  function example(release: string) {
    const root = mkdtempSync(join(tmpdir(), "piship-runtime-cache-example-"));
    roots.push(root);
    cpSync(resolve("examples", "personal"), root, { recursive: true });
    const manifest = join(root, "piship.yaml");
    writeFileSync(
      manifest,
      readFileSync(manifest, "utf8")
        // The example ships bundled and stripped; the caller picks its own.
        .replace(/^ {2}(strip|bundle): .*\n/gm, "")
        // And it bundles fd and rg, whose archives a build reads from the
        // download cache: a test needs no network and no warm cache.
        .replace(
          /^ {2}# fd and rg ship[^\n]*\n[^\n]*\n {2}searchTools:\n {4}mode: bundled\n/m,
          "",
        )
        .replace("release:\n", `release:\n${release}`),
    );
    lockManifest(manifest);
    return { root, manifest };
  }
  const walk = (root: string, prefix = ""): string[] =>
    readdirSync(join(root, prefix), { withFileTypes: true })
      .flatMap((entry) =>
        entry.isDirectory()
          ? [
              `${prefix}${entry.name}/`,
              ...walk(root, `${prefix}${entry.name}/`),
            ]
          : [`${prefix}${entry.name}`],
      )
      .sort();

  it("installs once for any number of outputs, and every payload verifies", () => {
    const p = project();
    const runtimeCache = cacheOf(p.manifest, home());
    const reports: RuntimeCacheReport[] = [];
    const build = (name: string) =>
      buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache: false,
        runtimeCache,
        onRuntimeCache: (report) => reports.push(report),
      });
    const first = build("first");
    const second = build("second");
    const third = build("third");
    expect(fixture.installs).toBe(1);
    // Each build says where its tree came from, and the entry is the same one.
    expect(reports.map((report) => report.status)).toEqual([
      "miss",
      "hit",
      "hit",
    ]);
    expect(new Set(reports.map((report) => report.entry)).size).toBe(1);
    expect(reports[0]?.entry).toMatch(/^[0-9a-f]{64}$/);
    for (const report of reports.slice(1))
      expect(report.linked + report.copied).toBeGreaterThan(0);
    for (const output of [first, second, third]) {
      expect(verifyPayload(output).app.id).toBe("cachepi");
      expect(
        readFileSync(
          join(output, "node_modules", "dependency", "index.js"),
          "utf8",
        ),
      ).toContain("unchanged");
    }
    expect(
      readFileSync(join(second, "metadata", "inventory.json"), "utf8"),
    ).toBe(readFileSync(join(first, "metadata", "inventory.json"), "utf8"));
    expect(lookupInstallTree(runtimeCache)).toBeDefined();
  });

  it("takes everything outside the cached runtime from the current manifest and resources", () => {
    const p = project();
    const runtimeCache = cacheOf(p.manifest, home());
    const build = () =>
      buildDistribution(p.manifest, p.output, {
        ...options,
        cache: false,
        runtimeCache,
      });
    build();
    p.writeManifest("renamed", "Updated name");
    writeFileSync(p.resource, "# changed\n");
    lockManifest(p.manifest);
    const output = build();
    expect(fixture.installs).toBe(1);
    expect(readFileSync(join(output, "resources", "AGENTS.md"), "utf8")).toBe(
      "# changed\n",
    );
    expect(existsSync(join(output, "bin", "renamed"))).toBe(true);
    expect(existsSync(join(output, "bin", "cachepi"))).toBe(false);
    // The inventory, derived from the entry's digests, still matches every file.
    expect(verifyPayload(output).app.command).toBe("renamed");
  });

  it("builds again, and publishes again, when the entry has lost a file", () => {
    const p = project();
    const home1 = home();
    const runtimeCache = cacheOf(p.manifest, home1);
    const build = (name: string) =>
      buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache: false,
        runtimeCache,
      });
    build("a");
    const tree = lookupInstallTree(runtimeCache);
    rmSync(
      join(tree?.tree as string, "node_modules", "dependency", "index.js"),
    );
    expect(lookupInstallTree(runtimeCache)).toBeUndefined();
    expect(verifyPayload(build("b")).app.id).toBe("cachepi");
    expect(fixture.installs).toBe(2);
    expect(lookupInstallTree(runtimeCache)).toBeDefined();
    build("c");
    expect(fixture.installs).toBe(2);
  });

  it("recovers from an entry that cannot be read while it is being placed", () => {
    if (process.platform === "win32" || process.getuid?.() === 0) return;
    const p = project();
    const runtimeCache = cacheOf(p.manifest, home());
    const build = (name: string) =>
      buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache: false,
        runtimeCache,
      });
    build("a");
    const tree = lookupInstallTree(runtimeCache);
    // Its name and size still match, so only placing the file can fail.
    const victim = join(
      tree?.tree as string,
      "node_modules",
      "dependency",
      "index.js",
    );
    chmodSync(victim, 0);
    try {
      expect(verifyPayload(build("b")).app.id).toBe("cachepi");
    } finally {
      for (const path of [victim]) if (existsSync(path)) chmodSync(path, 0o644);
    }
    expect(fixture.installs).toBe(2);
    expect(lookupInstallTree(runtimeCache)).toBeDefined();
    build("c");
    expect(fixture.installs).toBe(2);
  });

  it("installs once, and only places PiShip's layer again, when PiShip's own output changes", () => {
    const p = project();
    const where = home();
    const framework = join(
      fixture.input,
      "packages",
      "core",
      "dist",
      "index.js",
    );
    const prior = readFileSync(framework);
    const reports: RuntimeCacheReport[] = [];
    const build = (name: string) => {
      const runtimeCache = cacheOf(p.manifest, where);
      return buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache: false,
        runtimeCache,
        onRuntimeCache: (report) => reports.push(report),
      });
    };
    try {
      build("a");
      build("b");
      expect(fixture.installs).toBe(1);
      expect(reports.map((r) => [r.status, r.framework])).toEqual([
        ["miss", "miss"],
        ["hit", "hit"],
      ]);
      writeFileSync(framework, "export const framework = 3;\n");
      // The build input marker is what a real change to PiShip moves.
      const marker = join(fixture.input, ".piship-build-input.json");
      writeFileSync(
        marker,
        JSON.stringify({
          schema: "piship-build-input/v1",
          sha256: "7".repeat(64),
        }),
      );
      const changed = build("c");
      // No npm: the third-party tree is the same entry. PiShip's layer is new.
      expect(fixture.installs).toBe(1);
      expect(reports.at(-1)).toMatchObject({
        status: "hit",
        framework: "miss",
      });
      expect(reports.at(-1)?.entry).toBe(reports[0]?.entry);
      expect(
        readFileSync(
          join(changed, "node_modules", "@piship", "core", "dist", "index.js"),
          "utf8",
        ),
      ).toContain("framework = 3");
      expect(verifyPayload(changed).app.id).toBe("cachepi");
      build("d");
      expect(reports.at(-1)).toMatchObject({ status: "hit", framework: "hit" });
    } finally {
      writeFileSync(framework, prior);
      rmSync(join(fixture.input, ".piship-build-input.json"), { force: true });
    }
  });

  it("only places the changed resource when one resource changes and the dependencies do not", () => {
    const p = project();
    const runtimeCache = cacheOf(p.manifest, home());
    const build = () =>
      buildDistribution(p.manifest, p.output, {
        ...options,
        runtimeCache,
      });
    const first = build();
    const dependency = join(first, "node_modules", "dependency", "index.js");
    const before = statSync(dependency).mtimeMs;
    fixture.copies = fixture.links = fixture.cps = 0;
    writeFileSync(p.resource, "# one resource changed\n");
    lockManifest(p.manifest);
    expect(build()).toBe(first);
    // No npm, no strip, no bundle, no placement of the tree: the resource,
    // the manifest, and the lock are the only files copied.
    expect(fixture.installs).toBe(1);
    expect(fixture.copies).toBeLessThanOrEqual(3);
    expect(fixture.links + fixture.cps).toBe(0);
    expect(statSync(dependency).mtimeMs).toBe(before);
    expect(readFileSync(join(first, "resources", "AGENTS.md"), "utf8")).toBe(
      "# one resource changed\n",
    );
    expect(verifyPayload(first).app.id).toBe("cachepi");
  });

  it("places the cached tree, with no npm and no strip, when a manifest change alters the whole payload but not the dependencies", () => {
    fixture.declarations = true;
    const { manifest, root } = example("  strip: true\n  bundle: false\n");
    const runtimeCache = cacheOf(manifest, home());
    const output = join(root, "dist");
    const build = () =>
      buildDistribution(manifest, output, { ...options, runtimeCache });
    const first = build();
    expect(fixture.installs).toBe(1);
    const placed = walk(first).filter((name) => !name.endsWith("/")).length;
    // The release policy is part of what the local output cache keys, so it
    // misses; the runtime cache still holds the tree.
    writeFileSync(
      manifest,
      readFileSync(manifest, "utf8").replace(
        "failOn: high",
        "failOn: critical",
      ),
    );
    lockManifest(manifest);
    fixture.copies = fixture.links = fixture.cps = fixture.removals = 0;
    const second = build();
    expect(second).toBe(first);
    expect(fixture.installs).toBe(1);
    expect(
      existsSync(join(second, "node_modules", "dependency", "index.d.ts")),
    ).toBe(false);
    // Every file of the payload was copied once, the maps and declarations
    // never were, and nothing was deleted to strip them.
    expect(fixture.copies + fixture.cps).toBeGreaterThan(0);
    expect(fixture.copies).toBeLessThanOrEqual(placed + 10);
    expect(fixture.removals).toBeLessThan(10);
    expect(verifyPayload(second).app.id).toBe("mypi");
  });

  it("does not look for npm's version to key the cache when an unchanged payload is reused", async () => {
    const p = project();
    const where = home();
    const build = async () => {
      vi.resetModules();
      const fresh = await import("./build.js");
      const cache = await import("./runtime-cache.js");
      const lockModule = await import("./lock.js");
      return fresh.buildDistribution(p.manifest, p.output, {
        ...options,
        runtimeCache: cache.runtimeCacheFor(
          lockModule.requireCurrentLock(p.manifest),
          { PISHIP_CACHE_HOME: where },
          { npm: "11.19", libc: undefined },
        ),
      });
    };
    await build();
    // Asking for the cache is the caller's; a payload that is unchanged
    // returns before any entry is read.
    fixture.versions = 0;
    const lazy = async () => {
      vi.resetModules();
      const fresh = await import("./build.js");
      return fresh.buildDistribution(p.manifest, p.output, {
        ...options,
        runtimeCache: true,
      });
    };
    await lazy();
    expect(fixture.versions).toBe(0);
    expect(fixture.installs).toBe(1);
  });

  it("asks npm only for the locked runtime tree, from the npm cache, with no audit, funding, progress, or warning output", () => {
    const p = project();
    buildDistribution(p.manifest, p.output, {
      ...options,
      cache: false,
      runtimeCache: cacheOf(p.manifest, home()),
    });
    expect(fixture.runs).toHaveLength(1);
    const [command, args] = fixture.runs[0] ?? ["", []];
    // Windows reaches npm through cmd.exe, with the same words.
    const words =
      process.platform === "win32" ? (args.at(-1) ?? "").split(" ") : args;
    expect(command).toBe(process.platform === "win32" ? "cmd.exe" : "npm");
    for (const word of [
      "ci",
      "--omit=dev",
      "--no-audit",
      "--no-fund",
      "--prefer-offline",
      "--loglevel=error",
      "--progress=false",
    ])
      expect(words, word).toContain(word);
    // Lifecycle scripts stay on: esbuild's postinstall validates its binary.
    expect(words).not.toContain("--ignore-scripts");
  });

  it("builds without the cache, and says so, when the cache directory cannot be created", () => {
    const p = project();
    const blocker = join(p.root, "blocker");
    writeFileSync(blocker, "a file where the cache directory would go");
    const runtimeCache = cacheOf(p.manifest, blocker);
    const steps: string[] = [];
    const reports: RuntimeCacheReport[] = [];
    const build = (name: string) =>
      buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache: false,
        runtimeCache,
        progress: (step) => steps.push(step),
        onRuntimeCache: (report) => reports.push(report),
      });
    expect(verifyPayload(build("a")).app.id).toBe("cachepi");
    expect(verifyPayload(build("b")).app.id).toBe("cachepi");
    expect(fixture.installs).toBe(2);
    expect(
      steps.filter((step) => /runtime cache is not usable/.test(step)),
    ).toHaveLength(2);
    expect(reports.map((report) => report.status)).toEqual([
      "unusable",
      "unusable",
    ]);
  });

  it("leaves the maps and declarations out by omission, the same files an in-place strip leaves", () => {
    fixture.declarations = true;
    const { manifest, root } = example("  strip: true\n  bundle: false\n");
    const runtimeCache = cacheOf(manifest, home());
    const build = (name: string, cached: boolean) =>
      buildDistribution(manifest, join(root, name), {
        ...options,
        cache: false,
        ...(cached ? { runtimeCache } : {}),
      });
    const plain = build("plain", false);
    const cold = build("cold", true);
    const warm = build("warm", true);
    expect(fixture.installs).toBe(2);
    const dependency = join("node_modules", "dependency");
    for (const output of [plain, cold, warm]) {
      expect(existsSync(join(output, dependency, "index.js"))).toBe(true);
      expect(existsSync(join(output, dependency, "index.d.ts"))).toBe(false);
      expect(existsSync(join(output, dependency, "index.js.map"))).toBe(false);
      // A directory only declarations were in is gone, not left empty.
      expect(existsSync(join(output, dependency, "types"))).toBe(false);
      expect(verifyPayload(output).app.id).toBe("mypi");
    }
    // The cache entry itself keeps what the payload leaves out.
    const tree = lookupInstallTree(runtimeCache);
    expect(
      existsSync(join(tree?.tree as string, dependency, "index.d.ts")),
    ).toBe(true);
    expect(walk(cold)).toEqual(walk(plain));
    expect(walk(warm)).toEqual(walk(plain));
    for (const output of [cold, warm])
      expect(
        readFileSync(join(output, "metadata", "inventory.json"), "utf8"),
      ).toBe(readFileSync(join(plain, "metadata", "inventory.json"), "utf8"));
  });

  it("never writes through a hardlink into the entry, whatever a later step rewrites", () => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    const digests = (directory: string): Record<string, string> =>
      Object.fromEntries(
        walk(directory)
          .filter((name) => !name.endsWith("/"))
          .map((name) => [name, readFileSync(join(directory, name), "utf8")]),
      );
    const p = project();
    const runtimeCache = cacheOf(p.manifest, home());
    const build = (name: string, cache = false) =>
      buildDistribution(p.manifest, join(p.root, name), {
        ...options,
        cache,
        runtimeCache,
      });
    // Windows is where files are linked from the entry; stand in for it here.
    Object.defineProperty(process, "platform", { value: "win32" });
    try {
      const first = build("first");
      const tree = lookupInstallTree(runtimeCache);
      const before = digests(tree?.tree as string);
      const placed = join(first, "node_modules", "dependency", "index.js");
      // The placed file is the entry's own bytes under a second name.
      expect(statSync(placed).ino).toBe(
        statSync(join(tree?.tree as string, "node_modules/dependency/index.js"))
          .ino,
      );
      // Everything a payload rewrites after placement: its manifest and lock,
      // resources, launcher, metadata, inventory, and the refresh of an
      // earlier output, with a changed command, in the same output directory.
      p.writeManifest("renamed", "Updated name");
      writeFileSync(p.resource, "# changed\n");
      lockManifest(p.manifest);
      build("first", true);
      build("first", true);
      p.writeManifest("again", "Renamed again");
      lockManifest(p.manifest);
      build("first", true);
      build("second");
      expect(digests(tree?.tree as string)).toEqual(before);
      expect(lookupInstallTree(runtimeCache)?.files).toEqual(tree?.files);
    } finally {
      if (platform) Object.defineProperty(process, "platform", platform);
    }
  });

  it("hands strip and the inventory to the bundler when the caller will bundle", () => {
    fixture.declarations = true;
    const { manifest, root } = example("  strip: true\n  bundle: true\n");
    const runtimeCache = cacheOf(manifest, home());
    const deferred = (name: string, cached: boolean) =>
      buildDistribution(manifest, join(root, name), {
        ...options,
        cache: false,
        deferBundle: true,
        ...(cached ? { runtimeCache } : {}),
      });
    const dependency = join("node_modules", "dependency");
    const uncached = deferred("uncached", false);
    // Nothing was stripped or hashed: the bundler drops this tree anyway.
    expect(existsSync(join(uncached, dependency, "index.d.ts"))).toBe(true);
    expect(existsSync(join(uncached, "metadata", "inventory.json"))).toBe(
      false,
    );
    const cached = deferred("cached", true);
    expect(existsSync(join(cached, dependency, "index.d.ts"))).toBe(false);
    expect(existsSync(join(cached, "metadata", "inventory.json"))).toBe(false);
    expect(existsSync(join(cached, "runtime"))).toBe(false);
  });
});
