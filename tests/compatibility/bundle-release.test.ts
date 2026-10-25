import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { esmImport, prepareBundledSource } from "./bundle-fixture.js";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "pb-"));
const env = {
  ...process.env,
  PISHIP_STATE_HOME: join(root, "state"),
  PI_OFFLINE: "1",
  PI_TELEMETRY: "0",
  PI_SKIP_VERSION_CHECK: "1",
};

beforeAll(() => {
  const manifest = prepareBundledSource(repository, root);
  const buildEnv: NodeJS.ProcessEnv = { ...env };
  delete buildEnv.PISHIP_BUILD_INPUT;
  const script = `import {lockManifest} from ${esmImport(join(repository, "packages/core/dist/index.js"))}; lockManifest(${JSON.stringify(manifest)});`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env: buildEnv, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
}, 120_000);
// The runtime cache built under `root` holds a whole installed tree.
afterAll(() => rmSync(root, { recursive: true, force: true }), 120_000);

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

describe("real bundled Pi runtime release", () => {
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
