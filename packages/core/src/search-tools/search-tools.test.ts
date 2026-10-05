// Bundled search tools: lock entries and digest, the source gate, the
// archive reader's safety rules, payload staging and verification, the
// download path, and the diff. Every archive is a local fixture; nothing
// here reaches the network.
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32, deflateRawSync, gzipSync } from "node:zlib";
import { PiShipError } from "@piship/contracts";
import { readManifest, type SearchTool } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { diffLocks } from "../diff/index.js";
import {
  type DistributionLock,
  explainConfiguration,
  lockManifest,
  payloadInventory,
  requireCurrentLock,
  verifyPayloadContents,
} from "../index.js";
import { buildInput } from "../runtime-dependencies.js";
import { generateSbom, verifySbom } from "../supply-chain.js";
import {
  checkSearchToolSources,
  currentSearchTools,
  downloadLockedSearchTools,
  downloadSearchToolArchives,
  readSearchToolArchive,
  SEARCH_TOOL_SPECS,
  searchToolAsset,
  searchToolFileName,
  stageSearchTools,
} from "./index.js";

const roots: string[] = [];
let cache: string;
beforeEach(() => {
  cache = temp("piship-search-cache-");
  process.env.PISHIP_CACHE_HOME = cache;
});
afterEach(() => {
  delete process.env.PISHIP_CACHE_HOME;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function temp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  roots.push(dir);
  return dir;
}

const sha = (content: Buffer | string) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

// ---------------------------------------------------------------- fixtures

interface TarEntry {
  readonly name: string;
  readonly type?: "0" | "1" | "2" | "5";
  readonly data?: string | Buffer;
  readonly mode?: number;
}

/** A gzip-compressed ustar archive, with any entry type a test needs. */
function tarGz(entries: readonly TarEntry[]): Buffer {
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? "");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    header.write(
      `${(entry.mode ?? 0o644).toString(8).padStart(7, "0")}\0`,
      100,
    );
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    header.write("00000000000\0", 136);
    header.write("        ", 148);
    header.write(entry.type ?? "0", 156);
    if (entry.type === "1" || entry.type === "2") header.write("target", 157);
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

interface ZipEntry {
  readonly name: string;
  readonly data?: string;
  /** Unix mode in the external attributes (host 3), as zip tools record it. */
  readonly unixMode?: number;
}

/** A deflate zip archive with a central directory. */
function zip(entries: readonly ZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const data = Buffer.from(entry.data ?? "");
    const packed = deflateRawSync(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(
      entry.unixMode === undefined ? 0x0014 : (3 << 8) | 0x14,
      4,
    );
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(((entry.unixMode ?? 0) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, packed);
    centrals.push(central, name);
    offset += local.length + name.length + packed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** The fake executable a fixture archive holds for a tool and target. */
const binary = (tool: SearchTool, target: string, version: string) =>
  `#!/bin/sh\necho ${tool} ${version} ${target}\n`;

/** An archive shaped like the upstream release asset. */
function upstreamArchive(
  tool: SearchTool,
  version: string,
  target: string,
): Buffer {
  const asset = searchToolAsset(tool, version, target);
  const root = asset.name.replace(/\.(tar\.gz|zip)$/, "");
  const name = searchToolFileName(tool, target);
  const content = binary(tool, target, version);
  return asset.format === "zip"
    ? zip([
        { name: `${root}/` },
        { name: `${root}/${name}`, data: content },
        { name: `${root}/LICENSE-MIT`, data: `${tool} MIT license\n` },
        { name: `${root}/README.md`, data: "readme\n" },
      ])
    : tarGz([
        { name: `${root}/`, type: "5", mode: 0o755 },
        { name: `${root}/${name}`, data: content, mode: 0o755 },
        { name: `${root}/LICENSE-MIT`, data: `${tool} MIT license\n` },
        { name: `${root}/doc/README.md`, data: "readme\n" },
      ]);
}

/** Put the fixture archives a manifest needs in the download cache. */
function cacheArchives(
  targets: readonly string[],
  versions: Partial<Record<SearchTool, string>> = {},
): void {
  const directory = join(cache, "search-tools");
  mkdirSync(directory, { recursive: true });
  for (const tool of ["fd", "rg"] as const) {
    const version = versions[tool] ?? SEARCH_TOOL_SPECS[tool].defaultVersion;
    for (const target of targets)
      writeFileSync(
        join(directory, searchToolAsset(tool, version, target).name),
        upstreamArchive(tool, version, target),
      );
  }
}

const MANIFEST = `schema: piship/v1alpha6
app: { id: acmepi, name: AcmePi, command: acmepi, version: 1.0.0 }
runtime:
  pi: "1.0.2"
  searchTools: { mode: bundled }
deployment: { mode: personal }
updates: { channel: stable, channels: [stable] }
release:
  targets: [linux-x64, win32-x64]
  sources: [https://registry.npmjs.org, https://github.com]
`;

function project(source = MANIFEST): string {
  const dir = temp("piship-search-tools-");
  const path = join(dir, "piship.yaml");
  writeFileSync(path, source);
  return path;
}

function locked(path: string): DistributionLock {
  lockManifest(path);
  return JSON.parse(
    readFileSync(join(path, "..", "piship.lock"), "utf8"),
  ) as DistributionLock;
}

function code(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    return error instanceof PiShipError ? error.code : (error as Error).message;
  }
  return undefined;
}

// ---------------------------------------------------------------- the lock

describe("piship lock with runtime.searchTools", () => {
  it("pins each tool's version, archive, and executable for every release target", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const lock = locked(project());
    const fd = lock.searchTools?.fd;
    expect(fd?.version).toBe(SEARCH_TOOL_SPECS.fd.defaultVersion);
    expect(fd?.source).toBe(SEARCH_TOOL_SPECS.fd.source);
    expect(Object.keys(fd?.targets ?? {})).toEqual(["linux-x64", "win32-x64"]);
    const version = SEARCH_TOOL_SPECS.fd.defaultVersion;
    const linux = searchToolAsset("fd", version, "linux-x64");
    expect(fd?.targets["linux-x64"]).toEqual({
      url: linux.url,
      archive: sha(upstreamArchive("fd", version, "linux-x64")),
      entry: `${linux.name.replace(".tar.gz", "")}/fd`,
      binary: sha(binary("fd", "linux-x64", version)),
      size: Buffer.byteLength(binary("fd", "linux-x64", version)),
    });
    // Windows: the zip's fd.exe.
    expect(fd?.targets["win32-x64"]?.entry).toMatch(/\/fd\.exe$/);
    expect(fd?.targets["win32-x64"]?.url).toMatch(
      /^https:\/\/github\.com\/sharkdp\/fd\/releases\/download\/v[\d.]+\/fd-v[\d.]+-x86_64-pc-windows-msvc\.zip$/,
    );
    expect(lock.searchTools?.rg?.targets["linux-x64"]?.url).toMatch(
      /^https:\/\/github\.com\/BurntSushi\/ripgrep\/releases\/download\/[\d.]+\/ripgrep-[\d.]+-x86_64-unknown-linux-musl\.tar\.gz$/,
    );
    expect(lock.digests?.searchTools).toMatch(/^sha256-[0-9a-f]{64}$/);
  });

  it("is reproducible and checked offline: the stale-lock check never reads the cache", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const first = locked(path);
    expect(locked(path)).toEqual(first);
    rmSync(join(cache, "search-tools"), { recursive: true });
    expect(requireCurrentLock(path).searchTools).toEqual(first.searchTools);
  });

  it("pins a declared version, and a version change makes the lock stale", () => {
    cacheArchives(["linux-x64", "win32-x64"], { fd: "10.4.2" });
    const path = project(
      MANIFEST.replace("{ mode: bundled }", '{ mode: bundled, fd: "10.4.2" }'),
    );
    expect(locked(path).searchTools?.fd?.version).toBe("10.4.2");
    writeFileSync(
      path,
      MANIFEST.replace("{ mode: bundled }", '{ mode: bundled, fd: "10.4.1" }'),
    );
    expect(() => requireCurrentLock(path)).toThrow(/Lockfile is stale/);
  });

  it("needs the upstream host in release.sources", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project(
      MANIFEST.replace(
        "[https://registry.npmjs.org, https://github.com]",
        "[https://registry.npmjs.org]",
      ),
    );
    expect(() => lockManifest(path)).toThrow(
      /Release gate source: fd .* comes from https:\/\/github\.com, which is not in release\.sources/,
    );
  });

  it("reads only the download cache, and says how to fill it", () => {
    expect(code(() => lockManifest(project()))).toBe("LOCK_INVALID");
  });

  it("records nothing for a manifest without the setting", () => {
    const lock = locked(
      project(MANIFEST.replace("  searchTools: { mode: bundled }\n", "")),
    );
    expect(lock).not.toHaveProperty("searchTools");
    expect(lock.digests).not.toHaveProperty("searchTools");
  });
});

// ---------------------------------------------------------- archive reader

describe("the search tool archive reader", () => {
  const root = "fd-v1.0.0-x86_64-unknown-linux-musl";

  it("takes the executable and the license files beside it", () => {
    const files = readSearchToolArchive(
      tarGz([
        { name: `${root}/fd`, data: "binary", mode: 0o755 },
        { name: `${root}/LICENSE-APACHE`, data: "apache" },
        { name: `${root}/UNLICENSE`, data: "unlicense" },
        { name: `${root}/autocomplete/LICENSE-MIT`, data: "nested" },
      ]),
      "tar.gz",
      "fd",
    );
    expect(files.entry).toBe(`${root}/fd`);
    expect(files.binary.toString()).toBe("binary");
    expect([...files.licenses.keys()]).toEqual(["LICENSE-APACHE", "UNLICENSE"]);
  });

  it.each([
    ["a symlink", [{ name: `${root}/fd`, type: "2" as const }], /links/],
    ["a hard link", [{ name: `${root}/fd`, type: "1" as const }], /links/],
    ["a parent traversal", [{ name: "../fd", data: "x" }], /Unsafe/],
    ["an absolute path", [{ name: "/usr/bin/fd", data: "x" }], /Unsafe/],
    [
      "a duplicate",
      [
        { name: `${root}/fd`, data: "a" },
        { name: `${root}/fd`, data: "b" },
      ],
      /duplicate/,
    ],
    ["no executable", [{ name: `${root}/README.md`, data: "x" }], /no fd/],
    [
      "an executable nested too deep",
      [{ name: `${root}/bin/fd`, data: "x" }],
      /no fd/,
    ],
  ])("refuses a tar with %s", (_, entries, message) => {
    expect(() => readSearchToolArchive(tarGz(entries), "tar.gz", "fd")).toThrow(
      message,
    );
  });

  it("refuses a symlink anywhere in the archive, not only at the executable", () => {
    expect(() =>
      readSearchToolArchive(
        tarGz([
          { name: `${root}/fd`, data: "binary" },
          { name: `${root}/escape`, type: "2" },
        ]),
        "tar.gz",
        "fd",
      ),
    ).toThrow(/links/);
  });

  it("reads a Windows zip and refuses zip links and traversal", () => {
    const win = "fd-v1.0.0-x86_64-pc-windows-msvc";
    expect(
      readSearchToolArchive(
        zip([{ name: `${win}/fd.exe`, data: "exe" }]),
        "zip",
        "fd.exe",
      ).binary.toString(),
    ).toBe("exe");
    expect(() =>
      readSearchToolArchive(
        zip([
          { name: `${win}/fd.exe`, data: "/etc/passwd", unixMode: 0o120777 },
        ]),
        "zip",
        "fd.exe",
      ),
    ).toThrow(/links/);
    expect(() =>
      readSearchToolArchive(
        zip([{ name: "..\\fd.exe", data: "x" }]),
        "zip",
        "fd.exe",
      ),
    ).toThrow(/Unsafe/);
  });
});

// ------------------------------------------------------- build and payload

describe("bundled search tools in the payload", () => {
  function payload(lock: DistributionLock, path: string, target: string) {
    const dir = temp("piship-search-payload-");
    stageSearchTools(lock, dir, target);
    copyFileSync(path, join(dir, "piship.yaml"));
    copyFileSync(join(path, "..", "piship.lock"), join(dir, "piship.lock"));
    copyFileSync(
      join(buildInput, "package-lock.json"),
      join(dir, "package-lock.json"),
    );
    mkdirSync(join(dir, "metadata"));
    writeFileSync(
      join(dir, "metadata", "target.json"),
      JSON.stringify({ platform: process.platform, arch: process.arch }),
    );
    writeFileSync(
      join(dir, "metadata", "inventory.json"),
      JSON.stringify(payloadInventory(dir)),
    );
    return dir;
  }

  it("places each verified executable, executable on POSIX, with its licenses", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const lock = locked(path);
    const linux = payload(lock, path, "linux-x64");
    const fd = join(linux, "tools", "fd");
    expect(readFileSync(fd, "utf8")).toBe(
      binary("fd", "linux-x64", SEARCH_TOOL_SPECS.fd.defaultVersion),
    );
    if (process.platform !== "win32")
      expect(statSync(fd).mode & 0o111).toBe(0o111);
    expect(
      readFileSync(
        join(linux, "tools", "licenses", "rg", "LICENSE-MIT"),
        "utf8",
      ),
    ).toBe("rg MIT license\n");
    const windows = payload(lock, path, "win32-x64");
    expect(existsSync(join(windows, "tools", "fd.exe"))).toBe(true);
    expect(existsSync(join(windows, "tools", "rg.exe"))).toBe(true);
    expect(() => verifyPayloadContents(linux)).not.toThrow();
  });

  it("fails verification when a bundled executable is tampered with or removed", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const lock = locked(path);
    const dir = payload(lock, path, "linux-x64");
    writeFileSync(join(dir, "tools", "fd"), "#!/bin/sh\necho tampered\n");
    let error: unknown;
    try {
      verifyPayloadContents(dir);
    } catch (caught) {
      error = caught;
    }
    expect((error as PiShipError).code).toBe("INTEGRITY_FAILED");
    expect((error as PiShipError).message).toContain("modified: tools/fd");
    rmSync(join(dir, "tools", "rg"));
    expect(() => verifyPayloadContents(dir)).toThrow(/missing: tools\/rg/);
  });

  it("lists each bundled executable in the SBOM, which verification requires", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const lock = locked(path);
    const dir = payload(lock, path, "linux-x64");
    writeFileSync(
      join(dir, "metadata", "target.json"),
      JSON.stringify({ platform: "linux", arch: "x64" }),
    );
    const sbom = generateSbom({
      payloadDir: dir,
      distribution: { id: "acmepi", name: "AcmePi", version: "1.0.0" },
      target: "linux-x64",
      created: "2026-10-05T00:00:00Z",
      lockPackages: [],
    });
    const tools = sbom.packages.filter((item) =>
      item.sourceInfo?.startsWith("payload:tools/"),
    );
    expect(tools.map((item) => [item.name, item.sourceInfo])).toEqual([
      ["fd", "payload:tools/fd"],
      ["rg", "payload:tools/rg"],
    ]);
    expect(tools[0]?.externalRefs?.[0]?.referenceLocator).toBe(
      `pkg:github/sharkdp/fd@v${SEARCH_TOOL_SPECS.fd.defaultVersion}`,
    );
    expect(() => verifySbom(dir, sbom)).not.toThrow();
    const without = {
      ...sbom,
      packages: sbom.packages.filter((item) => item.name !== "rg"),
    };
    expect(() => verifySbom(dir, without)).toThrow(/SBOM is missing rg@/);
  });

  it("refuses a cached archive or executable that differs from the lock", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const lock = locked(path);
    const asset = searchToolAsset(
      "fd",
      SEARCH_TOOL_SPECS.fd.defaultVersion,
      "linux-x64",
    );
    writeFileSync(join(cache, "search-tools", asset.name), "not the archive");
    expect(
      code(() => stageSearchTools(lock, temp("piship-stage-"), "linux-x64")),
    ).toBe("INTEGRITY_FAILED");
    expect(
      code(() => stageSearchTools(lock, temp("piship-stage-"), "darwin-arm64")),
    ).toBe("LOCK_INVALID");
  });

  it("gates a lock whose archive is not the official upstream asset or source", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const lock = locked(project());
    const fd = lock.searchTools?.fd;
    if (!fd) throw new Error("fd not locked");
    const moved = {
      ...lock,
      searchTools: {
        ...lock.searchTools,
        fd: {
          ...fd,
          targets: {
            ...fd.targets,
            "linux-x64": {
              ...(fd.targets["linux-x64"] as NonNullable<
                (typeof fd.targets)[string]
              >),
              url: "https://github.com/someone/fd/releases/download/v1/fd.tar.gz",
            },
          },
        },
      },
    } as DistributionLock;
    expect(code(() => checkSearchToolSources(moved, "Build"))).toBe(
      "LOCK_INVALID",
    );
    const narrowed = {
      ...lock,
      release: {
        ...(lock.release as NonNullable<DistributionLock["release"]>),
        sources: ["https://registry.npmjs.org"],
      },
    } as DistributionLock;
    expect(code(() => checkSearchToolSources(narrowed, "Build"))).toBe(
      "POLICY_DENIED",
    );
  });
});

// ------------------------------------------------------------- downloading

describe("downloading the upstream archives", () => {
  type Fetch = (url: URL, init: RequestInit) => Promise<Response>;
  function host(serve: (url: URL) => Response): {
    fetch: Fetch;
    requests: string[];
  } {
    const requests: string[] = [];
    return {
      requests,
      fetch: async (url) => {
        requests.push(url.toString());
        return serve(url);
      },
    };
  }
  const redirect = (location: string) =>
    new Response(null, { status: 302, headers: { location } });

  it("follows GitHub's redirect to its asset storage and caches each archive once", async () => {
    const path = project();
    const server = host((url) =>
      url.hostname === "github.com"
        ? redirect(
            `https://release-assets.githubusercontent.com/asset${url.pathname}`,
          )
        : (() => {
            const parts = url.pathname.split("/");
            const tool = parts.includes("sharkdp") ? "fd" : "rg";
            const target = url.pathname.includes("windows")
              ? "win32-x64"
              : "linux-x64";
            return new Response(
              new Uint8Array(
                upstreamArchive(
                  tool,
                  SEARCH_TOOL_SPECS[tool].defaultVersion,
                  target,
                ),
              ),
            );
          })(),
    );
    await downloadSearchToolArchives(path, { fetch: server.fetch });
    expect(server.requests).toHaveLength(8);
    expect(server.requests[0]).toMatch(/^https:\/\/github\.com\/sharkdp\/fd\//);
    const lock = locked(path);
    expect(Object.keys(lock.searchTools?.rg?.targets ?? {})).toEqual([
      "linux-x64",
      "win32-x64",
    ]);
    await downloadSearchToolArchives(path, { fetch: server.fetch });
    expect(server.requests).toHaveLength(8);
  });

  it("refuses a redirect off GitHub's release hosts", async () => {
    const server = host(() =>
      redirect("https://downloads.example.org/fd.tar.gz"),
    );
    await expect(
      downloadSearchToolArchives(project(), { fetch: server.fetch }),
    ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
  });

  it("checks the source gate before downloading anything", async () => {
    const server = host(() => new Response("never"));
    await expect(
      downloadSearchToolArchives(
        project(MANIFEST.replace(", https://github.com]", "]")),
        { fetch: server.fetch },
      ),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    expect(server.requests).toEqual([]);
  });

  it("at build, downloads a missing archive again and refuses one that differs from the lock", async () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const lock = locked(project());
    rmSync(join(cache, "search-tools"), { recursive: true });
    const version = SEARCH_TOOL_SPECS.fd.defaultVersion;
    const good = host(
      (url) =>
        new Response(
          new Uint8Array(
            upstreamArchive(
              url.pathname.includes("sharkdp") ? "fd" : "rg",
              url.pathname.includes("sharkdp")
                ? version
                : SEARCH_TOOL_SPECS.rg.defaultVersion,
              "linux-x64",
            ),
          ),
        ),
    );
    await downloadLockedSearchTools(lock, "linux-x64", { fetch: good.fetch });
    expect(good.requests).toHaveLength(2);
    expect(() =>
      stageSearchTools(lock, temp("piship-stage-"), "linux-x64"),
    ).not.toThrow();
    rmSync(join(cache, "search-tools"), { recursive: true });
    const bad = host(() => new Response("tampered"));
    await expect(
      downloadLockedSearchTools(lock, "linux-x64", { fetch: bad.fetch }),
    ).rejects.toMatchObject({ code: "INTEGRITY_FAILED" });
    expect(
      existsSync(
        join(
          cache,
          "search-tools",
          searchToolAsset("fd", version, "linux-x64").name,
        ),
      ),
    ).toBe(false);
  });
});

describe("a lock whose archive URL is not the official one", () => {
  type Fetch = (url: URL, init: RequestInit) => Promise<Response>;
  const version = SEARCH_TOOL_SPECS.fd.defaultVersion;
  const official = searchToolAsset("fd", version, "linux-x64");
  const evil = "https://github.com/attacker/fd/releases/download/v1/x.tar.gz";

  /** The lock with fd's linux-x64 URL rewritten, as a hand edit would. */
  function tampered(lock: DistributionLock, url: string): DistributionLock {
    const fd = lock.searchTools?.fd;
    const linux = fd?.targets["linux-x64"];
    if (!fd || !linux) throw new Error("fd not locked");
    return {
      ...lock,
      searchTools: {
        ...lock.searchTools,
        fd: { ...fd, targets: { ...fd.targets, "linux-x64": { ...linux, url } } },
      },
    } as DistributionLock;
  }

  it("is refused at download and at staging before any fetch or cache write", async () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const lock = tampered(locked(project()), evil);
    rmSync(join(cache, "search-tools"), { recursive: true });
    const requests: string[] = [];
    const fetch: Fetch = async (url) => {
      requests.push(url.toString());
      return new Response("evil");
    };
    await expect(
      downloadLockedSearchTools(lock, "linux-x64", { fetch }),
    ).rejects.toMatchObject({ code: "LOCK_INVALID" });
    expect(requests).toEqual([]);
    expect(existsSync(join(cache, "search-tools"))).toBe(false);
    expect(
      code(() => stageSearchTools(lock, temp("piship-stage-"), "linux-x64")),
    ).toBe("LOCK_INVALID");
  });

  it("makes the lock stale, so piship lock resolves the official URL again", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const path = project();
    const lock = locked(path);
    writeFileSync(
      join(path, "..", "piship.lock"),
      JSON.stringify(tampered(lock, evil), null, 2),
    );
    expect(() => requireCurrentLock(path)).toThrow(/Lockfile is stale/);
    // Stale even when the edit also rewrote the digests: the recorded entry
    // is not carried over.
    const current = currentSearchTools(readManifest(path), join(path, ".."));
    expect(current?.fd).toBeUndefined();
    expect(current?.rg).toEqual(lock.searchTools?.rg);
    expect(locked(path).searchTools?.fd?.targets["linux-x64"]?.url).toBe(
      official.url,
    );
  });

  it("cannot get a file planted in the cache pinned by a fresh lock", async () => {
    const path = project();
    const directory = join(cache, "search-tools");
    mkdirSync(directory, { recursive: true });
    const planted = tarGz([
      { name: "x/fd", data: "#!/bin/sh\necho planted\n", mode: 0o755 },
    ]);
    writeFileSync(join(directory, official.name), planted);
    const requests: string[] = [];
    const fetch: Fetch = async (url) => {
      requests.push(url.toString());
      const tool = url.pathname.includes("sharkdp") ? "fd" : "rg";
      return new Response(
        new Uint8Array(
          upstreamArchive(
            tool,
            SEARCH_TOOL_SPECS[tool].defaultVersion,
            url.pathname.includes("windows") ? "win32-x64" : "linux-x64",
          ),
        ),
      );
    };
    await downloadSearchToolArchives(path, { fetch });
    expect(requests).toContain(official.url);
    const lock = locked(path);
    expect(lock.searchTools?.fd?.targets["linux-x64"]?.archive).toBe(
      sha(upstreamArchive("fd", version, "linux-x64")),
    );
    expect(lock.searchTools?.fd?.targets["linux-x64"]?.archive).not.toBe(
      sha(planted),
    );
    // Once the lock pins it, the cached archive is reused without a request.
    requests.length = 0;
    await downloadSearchToolArchives(path, { fetch });
    expect(requests).toEqual([]);
    // A cached file that differs from what the lock pins is downloaded again.
    writeFileSync(join(directory, official.name), planted);
    await downloadSearchToolArchives(path, { fetch });
    expect(requests).toEqual([official.url]);
    expect(sha(readFileSync(join(directory, official.name)))).toBe(
      sha(upstreamArchive("fd", version, "linux-x64")),
    );
  });
});

// --------------------------------------------------------------- piship diff

describe("piship diff of bundled search tools", () => {
  it("reports adding a tool as high, removing one or a version change as medium, and new bytes at the same version as high", () => {
    cacheArchives(["linux-x64", "win32-x64"]);
    const withTools = locked(project());
    const without = { ...withTools } as Record<string, unknown>;
    delete without.searchTools;
    const added = diffLocks(without as unknown as DistributionLock, withTools);
    expect(
      added.changes.filter((change) => change.item.startsWith("search tool")),
    ).toEqual([
      expect.objectContaining({
        area: "packages",
        kind: "added",
        item: "search tool fd",
        risk: "high",
      }),
      expect.objectContaining({
        kind: "added",
        item: "search tool rg",
        risk: "high",
      }),
    ]);
    const removed = diffLocks(
      withTools,
      without as unknown as DistributionLock,
    ).changes.filter((change) => change.item.startsWith("search tool"));
    expect(removed.map((change) => [change.kind, change.risk])).toEqual([
      ["removed", "medium"],
      ["removed", "medium"],
    ]);
    const fd = withTools.searchTools?.fd;
    if (!fd) throw new Error("fd not locked");
    const bumped = {
      ...withTools,
      searchTools: {
        ...withTools.searchTools,
        fd: { ...fd, version: "10.6.0" },
      },
    } as DistributionLock;
    const version = diffLocks(withTools, bumped).changes.filter((change) =>
      change.item.startsWith("search tool"),
    );
    expect(version).toEqual([
      expect.objectContaining({
        item: "search tool fd version",
        risk: "medium",
        before: fd.version,
        after: "10.6.0",
      }),
    ]);
    const linux = fd.targets["linux-x64"];
    if (!linux) throw new Error("no linux entry");
    const swapped = {
      ...withTools,
      searchTools: {
        ...withTools.searchTools,
        fd: {
          ...fd,
          targets: {
            ...fd.targets,
            "linux-x64": { ...linux, binary: sha("other") },
          },
        },
      },
    } as DistributionLock;
    const content = diffLocks(withTools, swapped);
    expect(content.risk).toBe("high");
    expect(
      content.changes.find(
        (change) => change.item === "search tool fd linux-x64 binary",
      )?.risk,
    ).toBe("high");
  });
});

// ----------------------------------------------------------- config explain

describe("config explain of bundled search tools", () => {
  it("shows the bundled tools and their versions as distribution-enforced", async () => {
    const stateDir = temp("piship-search-explain-");
    const options = {
      app: {
        id: "acmepi",
        name: "AcmePi",
        command: "acmepi",
        version: "1.0.0",
      },
      mode: "personal" as const,
      access: undefined,
      stateDir,
      distributionDir: stateDir,
      schema: "piship/v1alpha6",
    };
    expect(
      (await explainConfiguration(options)).some(
        (row) => row.key === "runtime.searchTools",
      ),
    ).toBe(false);
    const rows = await explainConfiguration({
      ...options,
      searchTools: { fd: "10.5.0", rg: "15.2.0" },
    });
    expect(rows.find((row) => row.key === "runtime.searchTools")).toEqual({
      key: "runtime.searchTools",
      value: "bundled",
      source: "distribution-enforced",
      overridable: false,
      note: expect.stringContaining(
        "fd 10.5.0, rg 15.2.0 pinned in piship.lock",
      ),
    });
  });
});
