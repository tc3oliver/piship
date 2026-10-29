import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { SEARCH_TOOLS } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createArchive, extractArchive } from "../archive.js";
import { lockManifest, requireCurrentLock } from "../index.js";
import {
  SEARCH_TOOL_SPECS,
  searchToolAsset,
  searchToolFileName,
} from "../search-tools/index.js";
import { generateSigningKey } from "../signing.js";
import {
  buildPack,
  packageClosureProblems,
  type PackOptions,
  type PackRuntime,
  readRuntimeArchive,
} from "./pack.js";

const KEY = generateSigningKey("test-pack");
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-pack-"));
  roots.push(dir);
  return dir;
}

function manifest(extra = "", release = ""): string {
  return `schema: piship/v1alpha6
app:
  id: acmepi
  name: AcmePi
  command: acmepi
  version: 1.0.0
runtime:
  pi: "1.1.0"
deployment:
  mode: personal
variables:
  - ACMEPI_UPDATE_SOURCE
resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  channels: [stable, candidate]
  source: \${ACMEPI_UPDATE_SOURCE}
  rollback: true
  trust:
    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: ${KEY.id}
          publicKey: ${KEY.publicKey}
      roles:
        root: { keyIds: [${KEY.id}], threshold: 1 }
        channel: { keyIds: [${KEY.id}], threshold: 1 }
release:
${release}  vulnerabilities:
    failOn: high
${extra}`;
}

function project(
  extra?: string,
  release?: string,
  agents: string | Buffer = "# AcmePi\n",
) {
  const dir = temp();
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), agents);
  const path = join(dir, "piship.yaml");
  writeFileSync(path, manifest(extra, release));
  lockManifest(path);
  return { dir, path };
}

const described = new Map<string, PackRuntime>();
const pack = (manifest: string, options: PackOptions) =>
  buildPack(manifest, {
    ...options,
    readRuntime: async (path) => described.get(path) as PackRuntime,
  });

/** A runtime archive as `piship-runtime/v1` describes it. */
async function runtime(
  path: string,
  target: string,
  change: Partial<PackRuntime> = {},
): Promise<string> {
  const lock = requireCurrentLock(path);
  const root = `piship-runtime-${lock.runtime.pishipVersion}-${target}`;
  const source = temp();
  mkdirSync(join(source, root), { recursive: true });
  writeFileSync(join(source, root, "runtime.json"), "{}");
  const out = join(temp(), `${root}.tar.gz`);
  const archive = await createArchive(join(source, root), root, out);
  writeFileSync(`${out}.sha256`, `${archive.sha256}  ${root}.tar.gz\n`);
  described.set(out, {
    name: `${root}.tar.gz`,
    target,
    sha256: archive.sha256,
    bytes: archive.bytes,
    pishipVersion: lock.runtime.pishipVersion,
    piVersion: lock.runtime.version,
    npmLockSha256: lock.runtime.npmLockSha256,
    inventorySha256: "a".repeat(64),
    searchTools: {},
    ...change,
  });
  return out;
}

const all = (path: string) =>
  Promise.all(
    ["linux-x64", "darwin-arm64", "win32-x64"].map((t) => runtime(path, t)),
  );

async function rejection(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string };
  }
  throw new Error("expected a rejection");
}

describe("piship pack", () => {
  it("builds a pack bound to the exact runtime archives", async () => {
    const { path } = project();
    const runtimes = await all(path);
    const out = temp();
    const built = await pack(path, { runtimes, outputRoot: out });
    const lock = requireCurrentLock(path);
    expect(built.metadata.schema).toBe("piship-pack/v1");
    expect(built.metadata.targets).toEqual(lock.release?.targets);
    expect(built.metadata.excluded).toEqual({});
    expect(built.metadata.runtime.npmLockSha256).toBe(
      lock.runtime.npmLockSha256,
    );
    expect(Object.keys(built.metadata.runtime.archives)).toHaveLength(3);
    const read = described.get(runtimes[0] as string) as PackRuntime;
    expect(built.metadata.runtime.archives[read.target]?.sha256).toBe(
      read.sha256,
    );
    const unpacked = join(temp(), "x");
    await extractArchive(built.archive, unpacked, { expectedRoot: built.name });
    expect(
      readFileSync(join(unpacked, built.name, "pack", "piship.lock")),
    ).toEqual(readFileSync(join(path, "..", "piship.lock")));
    expect(
      readFileSync(join(unpacked, built.name, "checksums.txt"), "utf8"),
    ).toContain("pack/resources/AGENTS.md");
  });

  it("is deterministic", async () => {
    const { path } = project();
    const runtimes = await all(path);
    const first = await pack(path, { runtimes, outputRoot: temp() });
    const second = await pack(path, { runtimes, outputRoot: temp() });
    expect(second.sha256).toBe(first.sha256);
  });

  it("drops win32 when a sandbox is required, with the sandbox gate text", async () => {
    const { path } = project("sandbox:\n  required: true\n");
    const built = await pack(path, {
      runtimes: await all(path),
      outputRoot: temp(),
    });
    expect(built.metadata.targets).not.toContain("win32-x64");
    expect(built.metadata.excluded["win32-x64"]).toMatch(
      /Release gate sandbox: the distribution requires an OS sandbox and PiShip has no sandbox adapter for win32-x64/,
    );
  });

  it("records a target without a runtime archive as excluded", async () => {
    const { path } = project();
    const built = await pack(path, {
      runtimes: [await runtime(path, "linux-x64")],
      outputRoot: temp(),
    });
    expect(built.metadata.targets).toEqual(["linux-x64"]);
    expect(built.metadata.excluded["darwin-arm64"]).toMatch(/no runtime/);
  });

  it("allows release.bundle and release.strip false: the runtime is always bundled and stripped", async () => {
    const { path } = project(undefined, "  bundle: false\n  strip: false\n");
    const built = await pack(path, {
      runtimes: await all(path),
      outputRoot: temp(),
    });
    expect(built.metadata.targets).toHaveLength(3);
    expect(built.metadata.runtimeSettings).toEqual({
      bundle: true,
      strip: true,
      overridden: ["release.bundle", "release.strip"],
    });
  });

  it("detects a package closure that is not pure JavaScript", () => {
    const lockfile = (packages: Record<string, unknown>) =>
      JSON.stringify({ lockfileVersion: 3, packages });
    expect(
      packageClosureProblems(
        lockfile({ "": {}, "node_modules/a": { version: "1.0.0" } }),
      ),
    ).toEqual([]);
    expect(
      packageClosureProblems(
        lockfile({ "node_modules/b": { hasInstallScript: true } }),
      ),
    ).toEqual([
      "node_modules/b runs install scripts, which are not allowed in a pack",
    ]);
    expect(
      packageClosureProblems(
        lockfile({ "node_modules/c": { hasInstallScript: false } }),
      ),
    ).toEqual([]);
    for (const field of ["os", "cpu", "libc"])
      expect(
        packageClosureProblems(
          lockfile({ "node_modules/d": { [field]: ["x"] } }),
        ),
      ).toEqual([`node_modules/d is bound to a platform (${field})`]);
    expect(
      packageClosureProblems(lockfile({}), { "linux-x64": ["x"] }),
    ).toEqual(["it has per-target optional dependencies"]);
    expect(
      packageClosureProblems(lockfile({}), {
        "linux-x64": [],
        "win32-x64": [],
      }),
    ).toEqual([]);
  });

  it("refuses a native resource file and points to per-target releases", async () => {
    const elf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      Buffer.alloc(64),
    ]);
    const { path } = project(undefined, undefined, elf);
    const error = await rejection(
      pack(path, { runtimes: await all(path), outputRoot: temp() }),
    );
    expect(error.code).toBe("PACK_INELIGIBLE");
    expect(error.message).toMatch(/resources\/AGENTS\.md is a native artifact/);
    expect((error as { userAction?: string }).userAction).toMatch(
      /piship release/,
    );
  });

  it("tells a Java class file from a fat Mach-O binary", async () => {
    const header = (second: number) => {
      const bytes = Buffer.alloc(64);
      bytes.writeUInt32BE(0xcafebabe, 0);
      bytes.writeUInt32BE(second, 4);
      return bytes;
    };
    const klass = project(undefined, undefined, header(65));
    expect(
      (
        await pack(klass.path, {
          runtimes: await all(klass.path),
          outputRoot: temp(),
        })
      ).metadata.targets,
    ).toHaveLength(3);
    const fat = project(undefined, undefined, header(2));
    const error = await rejection(
      pack(fat.path, {
        runtimes: await all(fat.path),
        outputRoot: temp(),
      }),
    );
    expect(error.code).toBe("PACK_INELIGIBLE");
  });

  it("refuses a runtime bound to another npm lock or PiShip version", async () => {
    const { path } = project();
    for (const change of [
      { npmLockSha256: "b".repeat(64) },
      { pishipVersion: "0.0.1" },
      { piVersion: "0.0.1" },
    ]) {
      const error = await rejection(
        pack(path, {
          runtimes: [await runtime(path, "linux-x64", change)],
          outputRoot: temp(),
        }),
      );
      expect(error.code).toBe("LOCK_INVALID");
      expect(error.message).toMatch(/Release gate runtime/);
    }
  });

  it("refuses a runtime for a target outside release.targets and duplicates", async () => {
    const { path } = project();
    const odd = await rejection(
      pack(path, {
        runtimes: [await runtime(path, "linux-arm64")],
        outputRoot: temp(),
      }),
    );
    expect(odd.message).toMatch(/not in release\.targets/);
    const twice = await rejection(
      pack(path, {
        runtimes: [
          await runtime(path, "linux-x64"),
          await runtime(path, "linux-x64"),
        ],
        outputRoot: temp(),
      }),
    );
    expect(twice.message).toMatch(/two runtime archives/);
  });

  it("refuses a stale lock before looking at any runtime", async () => {
    const { dir, path } = project();
    const runtimes = await all(path);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# edited\n");
    const error = await rejection(pack(path, { runtimes, outputRoot: temp() }));
    expect(error.code).toBe("LOCK_INVALID");
  });

  it("rejects a tampered runtime archive", async () => {
    const { path } = project();
    const archive = await runtime(path, "linux-x64");
    writeFileSync(`${archive}.sha256`, `${"0".repeat(64)}  x.tar.gz\n`);
    const error = await rejection(
      buildPack(path, { runtimes: [archive], outputRoot: temp() }),
    );
    expect(error.code).toBe("INTEGRITY_FAILED");
    const corrupt = join(temp(), "piship-runtime-1-linux-x64.tar.gz");
    writeFileSync(corrupt, "not an archive");
    expect((await rejection(readRuntimeArchive(corrupt))).code).toBe(
      "INTEGRITY_FAILED",
    );
  });

  it("refuses a runtime given as a folder", async () => {
    const error = await rejection(readRuntimeArchive(temp()));
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toMatch(/not an archive file/);
  });
});

/** A gzip ustar archive of regular files: the shape of an upstream tool asset. */
function tarGz(files: Record<string, string>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "utf8");
    header.write("0000755\0", 100);
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    header.write("00000000000\0", 136);
    header.write("        ", 148);
    header.write("0", 156);
    header.write("ustar\0", 257);
    header.write("00", 263);
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

describe("piship pack with bundled search tools", () => {
  const targets = ["linux-x64", "darwin-arm64"];
  let cache: string;
  const saved = process.env.PISHIP_CACHE_HOME;
  beforeEach(() => {
    cache = temp();
    process.env.PISHIP_CACHE_HOME = cache;
    mkdirSync(join(cache, "search-tools"));
    for (const tool of SEARCH_TOOLS)
      for (const target of targets) {
        const version = SEARCH_TOOL_SPECS[tool].defaultVersion;
        const asset = searchToolAsset(tool, version, target);
        const root = asset.name.replace(/\.tar\.gz$/, "");
        writeFileSync(
          join(cache, "search-tools", asset.name),
          tarGz({
            [`${root}/${searchToolFileName(tool, target)}`]: `#!/bin/sh\necho ${tool} ${target}\n`,
            [`${root}/LICENSE-MIT`]: "MIT\n",
          }),
        );
      }
  });
  afterEach(() => {
    if (saved === undefined) delete process.env.PISHIP_CACHE_HOME;
    else process.env.PISHIP_CACHE_HOME = saved;
  });

  function bundled() {
    const dir = temp();
    mkdirSync(join(dir, "resources"));
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
    const path = join(dir, "piship.yaml");
    writeFileSync(
      path,
      manifest(
        "",
        "  targets: [linux-x64, darwin-arm64]\n  sources: [https://registry.npmjs.org, https://github.com]\n",
      ).replace(
        'runtime:\n  pi: "1.1.0"\n',
        'runtime:\n  pi: "1.1.0"\n  searchTools: { mode: bundled }\n',
      ),
    );
    lockManifest(path);
    return path;
  }
  const defaults = Object.fromEntries(
    SEARCH_TOOLS.map((tool) => [tool, SEARCH_TOOL_SPECS[tool].defaultVersion]),
  );

  it("excludes a target whose runtime lacks the locked tools, and keeps the rest", async () => {
    const path = bundled();
    const built = await pack(path, {
      runtimes: [
        await runtime(path, "linux-x64", { searchTools: {} }),
        await runtime(path, "darwin-arm64", { searchTools: defaults }),
      ],
      outputRoot: temp(),
    });
    expect(built.metadata.targets).toEqual(["darwin-arm64"]);
    expect(built.metadata.excluded["linux-x64"]).toMatch(
      /does not bundle the locked search tools: fd .*\(the runtime has none\)/,
    );
  });

  it("includes runtimes that bundle the locked versions", async () => {
    const path = bundled();
    const built = await pack(path, {
      runtimes: [
        await runtime(path, "linux-x64", { searchTools: defaults }),
        await runtime(path, "darwin-arm64", { searchTools: defaults }),
      ],
      outputRoot: temp(),
    });
    expect(built.metadata.targets).toEqual(targets);
  });

  it("refuses when no runtime bundles them", async () => {
    const path = bundled();
    const error = await rejection(
      pack(path, {
        runtimes: [
          await runtime(path, "linux-x64"),
          await runtime(path, "darwin-arm64"),
        ],
        outputRoot: temp(),
      }),
    );
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toMatch(/no release target can be served/);
  });
});
