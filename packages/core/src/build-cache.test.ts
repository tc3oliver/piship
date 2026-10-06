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
import { buildDistribution } from "./build.js";
import { buildCachePath, buildInputDigest } from "./build-cache.js";
import { lockManifest } from "./lock.js";
import { verifyPayload } from "./payload.js";

const fixture = vi.hoisted(() => ({
  input: `${process.env.TEMP ?? process.env.TMPDIR ?? "/tmp"}/piship-build-cache-input-${process.pid}-${Math.random().toString(16).slice(2)}`,
  installs: 0,
}));

vi.mock("./runtime-dependencies.js", async (original) => ({
  ...(await original<typeof import("./runtime-dependencies.js")>()),
  buildInput: fixture.input,
  workspacePackages: ["core"],
}));
vi.mock("node:child_process", async (original) => ({
  ...(await original<typeof import("node:child_process")>()),
  spawnSync: vi.fn((_command, _args, options) => {
    fixture.installs++;
    const dependency = join(options.cwd, "node_modules", "dependency");
    mkdirSync(dependency, { recursive: true });
    writeFileSync(
      join(dependency, "index.js"),
      "export const unchanged = true;\n",
    );
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
