import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readManifest } from "@piship/schema";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const esmImport = (path: string) => JSON.stringify(pathToFileURL(path).href);

const repository = fileURLToPath(new URL("../../", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "pb-"));
let payload: string;
const env = {
  ...process.env,
  PISHIP_STATE_HOME: join(root, "state"),
  PI_OFFLINE: "1",
  PI_TELEMETRY: "0",
  PI_SKIP_VERSION_CHECK: "1",
};
function run(args: string[]) {
  return spawnSync(process.execPath, args, {
    cwd: payload,
    encoding: "utf8",
    env,
    timeout: 60_000,
  });
}
/** The size of a file, or the number of entries of a directory. */
function readdirSyncOrFile(path: string): number {
  const stat = statSync(path, { throwIfNoEntry: false });
  return !stat ? 0 : stat.isDirectory() ? readdirSync(path).length : stat.size;
}
function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(directory, entry.name))
      : [join(directory, entry.name)],
  );
}

beforeAll(() => {
  const source = join(root, "source");
  cpSync(join(repository, "examples", "personal"), source, { recursive: true });
  const manifest = join(source, "piship.yaml");
  // The example also bundles fd and rg, whose archives a build reads from the
  // download cache; this test needs no network and no warm cache, so its copy
  // leaves them out and is locked as it stands.
  writeFileSync(
    manifest,
    readFileSync(manifest, "utf8").replace(
      /^ {2}# fd and rg ship[^\n]*\n[^\n]*\n {2}searchTools:\n {4}mode: bundled\n/m,
      "",
    ),
  );
  // The personal example ships bundled and stripped: build it as it is.
  expect(readManifest(manifest).lifecycle?.release).toMatchObject({
    bundle: true,
    strip: true,
  });
  const buildEnv: NodeJS.ProcessEnv = { ...env };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const script = `import {buildDistribution, lockManifest} from ${esmImport(join(repository, "packages/core/dist/index.js"))}; lockManifest(${JSON.stringify(manifest)}); console.log(buildDistribution(${JSON.stringify(manifest)}, ${JSON.stringify(join(root, "output"))}, {supplyChainGates:false}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  payload = result.stdout.trim();
}, 120_000);
// The runtime cache built under `root` holds a whole installed tree.
afterAll(() => rmSync(root, { recursive: true, force: true }), 120_000);

/** Build the same bundled example through the runtime cache in `cache`. */
function cachedBuild(cache: string, output: string) {
  const buildEnv: NodeJS.ProcessEnv = { ...env, PISHIP_CACHE_HOME: cache };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const manifest = join(root, "source", "piship.yaml");
  const core = join(repository, "packages/core/dist");
  const script = `import {buildDistribution, requireCurrentLock} from ${esmImport(join(core, "index.js"))}; import {runtimeCacheFor} from ${esmImport(join(core, "runtime-cache.js"))}; const steps = []; const built = buildDistribution(${JSON.stringify(manifest)}, ${JSON.stringify(output)}, {supplyChainGates: false, cache: false, runtimeCache: runtimeCacheFor(requireCurrentLock(${JSON.stringify(manifest)})), progress: (step) => steps.push(step)}); console.log(JSON.stringify({built, steps}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as { built: string; steps: string[] };
}

/** A real release of the bundled example, built through `cache` or, without one, cold. */
function releaseBuild(cache: string | undefined, outputRoot: string) {
  const buildEnv: NodeJS.ProcessEnv = {
    ...env,
    ...(cache ? { PISHIP_CACHE_HOME: cache } : {}),
  };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const manifest = join(root, "source", "piship.yaml");
  const core = join(repository, "packages/core/dist/index.js");
  // The registry scans need the network; their results are not under test.
  const script = `import {buildRelease} from ${esmImport(core)}; const built = await buildRelease(${JSON.stringify(manifest)}, {outputRoot: ${JSON.stringify(outputRoot)}, ${cache ? "" : "cache: false, "}scanner: () => ({auditReportVersion: 2, vulnerabilities: {}}), signatureAuditor: () => ({status: 0, stdout: JSON.stringify({invalid: [], missing: []}), stderr: ""})}); console.log(JSON.stringify({directory: built.directory, archive: built.archive, runtimeCache: built.runtimeCache}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 300_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    directory: string;
    archive: string;
    runtimeCache: {
      status: string;
      entry?: string;
      bundle?: string;
    };
  };
}

describe("real bundled Pi runtime", () => {
  it("keeps the Node runtime at 50 JavaScript files or fewer", () => {
    const runtime = [
      ...files(join(payload, "runtime")),
      ...files(join(payload, "node_modules")),
    ].filter((path) => /\.[cm]?js$/.test(path));
    expect(runtime.length).toBeLessThanOrEqual(50);
  });
  it("boots with its TypeScript extension, theme, skills and MCP server", () => {
    const result = run([join(payload, "bin", "mypi"), "--smoke"]);
    expect(result.status, result.stderr).toBe(0);
    const smoke = JSON.parse(result.stdout);
    expect(smoke.initialized).toBe(true);
    expect(smoke.extensions).toBe(1);
    expect(smoke.themes).toContain("mypi");
    expect(smoke.skills).toContain("demo-skill");
    expect(smoke.activeTools).toContain("mcp__notes__list_notes");
  });
  it("keeps public adapter contracts identical and runs the real isolated codemode worker", () => {
    const script = join(payload, "bundle-test.mjs");
    writeFileSync(
      script,
      `import {PiShipError} from '@piship/contracts';\nimport {PiShipError as AdapterError, defineIdentityAdapter} from '@piship/adapter-sdk';\nimport {CodemodeSandbox} from '@earendil-works/pi-codemode';\nif(PiShipError !== AdapterError || typeof defineIdentityAdapter !== 'function') throw new Error('adapter identity changed');\nconst sandbox = new CodemodeSandbox();\nconst result = await sandbox.execute('text(1+2)');\nawait sandbox.close();\nif(!result.ok || result.output[0]?.text !== '3') throw new Error(JSON.stringify(result));\nconsole.log('passed');\n`,
    );
    const result = run([script]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("passed");
  });
  it("preserves structured runtime errors across the boot bundle boundary", () => {
    const result = run([join(payload, "bin", "mypi"), "--model"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CONFIG_INVALID");
    expect(result.stderr).toContain("--model needs a model id");
  });
  it("runs governance inspection and portable management CLI", () => {
    const result = run([
      join(payload, "bin", "mypi"),
      "capabilities",
      "--json",
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toBeInstanceOf(Array);
    const cli = run([join(payload, "piship.mjs"), "--help"]);
    expect(cli.status, cli.stderr).toBe(0);
    expect(cli.stdout).toContain("PiShip");
  });
  // The bundler reads these Pi paths by name. Those it only copies are skipped
  // quietly when they are missing, so a Pi release that moves one would ship a
  // payload without it; this test fails instead. Paths it must read to bundle
  // (pi-codemode dist/runtime/worker.js, pi-coding-agent dist/utils/image-
  // resize-worker.js, and the exports patterns) already fail the build, and
  // their entries are pinned below.
  it("pins every Pi path the bundler reads by name", () => {
    const modules = join(payload, "node_modules");
    const upstream = join(modules, "@earendil-works");
    const present = (...parts: string[]) => {
      const path = join(...parts);
      expect(readdirSyncOrFile(path), `${path} is missing`).toBeGreaterThan(0);
    };
    for (const name of [
      "pi-coding-agent",
      "pi-ai",
      "pi-agent-core",
      "pi-codemode",
      "pi-tui",
      "chord",
    ])
      present(upstream, name, "package.json");
    const agent = join(upstream, "pi-coding-agent");
    for (const asset of [
      "README.md",
      "CHANGELOG.md",
      "dist/modes/interactive/theme/dark.json",
      "dist/modes/interactive/theme/light.json",
      "dist/modes/interactive/assets",
      "dist/core/export-html/template.html",
      "dist/core/export-html/template.css",
      "dist/core/export-html/template.js",
      "dist/core/export-html/vendor",
    ])
      present(agent, ...asset.split("/"));
    present(
      upstream,
      "pi-tui",
      "native",
      process.platform,
      "prebuilds",
      `${process.platform}-${process.arch}`,
    );
    present(modules, "typebox", "package.json");
    present(modules, "quickjs-wasi", "package.json");
    present(modules, "quickjs-wasi", "quickjs.wasm");
    for (const file of [
      "package.json",
      "lib/jiti.mjs",
      "lib/jiti-static.mjs",
      "dist/jiti.cjs",
      "dist/babel.cjs",
    ])
      present(modules, "jiti", ...file.split("/"));
    present(modules, "@silvia-odwyer", "photon-node", "package.json");
    for (const output of [
      "main.js",
      "boot.js",
      "codemode-worker.js",
      "image-resize-worker.js",
    ])
      present(payload, "runtime", output);
    const { entries } = JSON.parse(
      readFileSync(join(payload, "metadata", "bundle.json"), "utf8"),
    ) as { entries: string[] };
    // An exports key an upstream package drops is skipped, not an error.
    for (const entry of [
      "pi-coding-agent",
      "pi-ai",
      "pi-ai-compat",
      "pi-ai-oauth",
      "pi-ai-providers-all",
      "pi-agent-core",
      "pi-codemode",
      "pi-tui",
      "chord",
      "chord-context",
      "chord-node",
      "typebox",
      "codemode-worker",
      "image-resize-worker",
    ])
      expect(entries, entry).toContain(entry);
  });
  it("takes the installed tree and the bundle from the runtime cache and ships the same bytes", () => {
    const cache = join(root, "runtime-cache");
    const cold = cachedBuild(cache, join(root, "cached-cold"));
    expect(cold.steps).toContain("Installing the runtime packages (npm ci)");
    const warm = cachedBuild(cache, join(root, "cached-warm"));
    expect(warm.steps).toContain("Reusing the cached runtime packages");
    expect(warm.steps).not.toContain(
      "Installing the runtime packages (npm ci)",
    );
    expect(
      readdirSync(join(cache, "runtime")).filter((name) =>
        /^[ifb]-[0-9a-f]{20}$/.test(name),
      ),
    ).toHaveLength(3);
    const inventory = (directory: string) =>
      readFileSync(join(directory, "metadata", "inventory.json"), "utf8");
    // Neither the cache nor skipping the strip first changes a shipped byte.
    expect(inventory(cold.built)).toBe(inventory(payload));
    expect(inventory(warm.built)).toBe(inventory(payload));
    const smoke = spawnSync(
      process.execPath,
      [join(warm.built, "bin", "mypi"), "--smoke"],
      { cwd: warm.built, encoding: "utf8", env, timeout: 60_000 },
    );
    expect(smoke.status, smoke.stderr).toBe(0);
    expect(JSON.parse(smoke.stdout).initialized).toBe(true);
  }, 300_000);
  it("ships the same release bytes from a cache miss, a cache hit, and a cold rebuild", () => {
    const cache = join(root, "release-cache");
    const miss = releaseBuild(cache, join(root, "release-miss"));
    const hit = releaseBuild(cache, join(root, "release-hit"));
    const cold = releaseBuild(undefined, join(root, "release-cold"));
    expect(miss.runtimeCache).toMatchObject({
      status: "miss",
      framework: "miss",
      bundle: "miss",
    });
    expect(hit.runtimeCache).toMatchObject({
      status: "hit",
      framework: "hit",
      bundle: "hit",
    });
    expect(hit.runtimeCache.entry).toBe(miss.runtimeCache.entry);
    expect(cold.runtimeCache).toEqual({ status: "disabled" });
    // Where the runtime came from is reported beside the release: nothing
    // the archive, release.json, or checksums.txt holds depends on it.
    for (const built of [miss, hit, cold]) {
      const info = JSON.parse(
        readFileSync(
          `${built.archive.replace(/\.tar\.gz$/, "")}.build-info.json`,
          "utf8",
        ),
      );
      expect(info.runtimeCache).toEqual(built.runtimeCache);
    }
    for (const built of [hit, miss])
      for (const file of ["release.json", "checksums.txt"])
        expect(readFileSync(join(built.directory, file))).toEqual(
          readFileSync(join(cold.directory, file)),
        );
    for (const built of [hit, miss])
      expect(
        readFileSync(built.archive).equals(readFileSync(cold.archive)),
      ).toBe(true);
  }, 600_000);
});
