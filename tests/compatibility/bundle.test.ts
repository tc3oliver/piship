import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readManifest } from "@piship/schema";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

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
  // The personal example ships bundled and stripped: build it as it is.
  expect(readManifest(manifest).lifecycle?.release).toMatchObject({
    bundle: true,
    strip: true,
  });
  const buildEnv: NodeJS.ProcessEnv = { ...env };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const script = `import {buildDistribution, lockManifest} from ${JSON.stringify(pathToFileURL(join(repository, "packages/core/dist/index.js")).href)}; lockManifest(${JSON.stringify(manifest)}); console.log(buildDistribution(${JSON.stringify(manifest)}, ${JSON.stringify(join(root, "output"))}, {supplyChainGates:false}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  payload = result.stdout.trim();
}, 120_000);
afterAll(() => rmSync(root, { recursive: true, force: true }));

/** Build the same bundled example through the runtime cache in `cache`. */
function cachedBuild(cache: string, output: string) {
  const buildEnv: NodeJS.ProcessEnv = { ...env, PISHIP_CACHE_HOME: cache };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const manifest = join(root, "source", "piship.yaml");
  const core = join(repository, "packages/core/dist");
  const script = `import {buildDistribution, requireCurrentLock} from ${JSON.stringify(join(core, "index.js"))}; import {runtimeCacheFor} from ${JSON.stringify(join(core, "runtime-cache.js"))}; const steps = []; const built = buildDistribution(${JSON.stringify(manifest)}, ${JSON.stringify(output)}, {supplyChainGates: false, cache: false, runtimeCache: runtimeCacheFor(requireCurrentLock(${JSON.stringify(manifest)})), progress: (step) => steps.push(step)}); console.log(JSON.stringify({built, steps}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as { built: string; steps: string[] };
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
        /^[ib]-[0-9a-f]{20}$/.test(name),
      ),
    ).toHaveLength(2);
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
});
