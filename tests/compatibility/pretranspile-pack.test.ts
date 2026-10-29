// `resources.packages[].pretranspile` through `piship pack`: the JavaScript is
// written once at pack time, lands in the pack, and is covered by its
// checksums, so no install has to make it.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pretranspileProject } from "../helpers/pretranspile-project.js";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "ptp-"));
const core = pathToFileURL(
  join(repository, "packages/core/dist/index.js"),
).href;
const manifest = join(root, "source", "piship.yaml");

let directory: string;
let digests: string[];
beforeAll(() => {
  pretranspileProject(join(root, "source"));
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.PISHIP_BUILD_INPUT;
  // The runtime archive is described, not built: the pack only reads it.
  const script = `import {buildPack, lockManifest, requireCurrentLock, currentTarget} from ${JSON.stringify(core)};
lockManifest(${JSON.stringify(manifest)});
const lock = requireCurrentLock(${JSON.stringify(manifest)});
const target = currentTarget();
const build = (out) => buildPack(${JSON.stringify(manifest)}, {
  outputRoot: out,
  runtimes: ["runtime"],
  readRuntime: async () => ({ name: "runtime.tar.gz", target, sha256: "a".repeat(64), bytes: 1, pishipVersion: lock.runtime.pishipVersion, piVersion: lock.runtime.version, npmLockSha256: lock.runtime.npmLockSha256, inventorySha256: "b".repeat(64), searchTools: {} }),
});
const first = await build(${JSON.stringify(join(root, "out"))});
const second = await build(${JSON.stringify(join(root, "again"))});
console.log(JSON.stringify([first.directory, first.sha256, second.sha256]));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  const [found, ...sums] = JSON.parse(result.stdout) as string[];
  directory = found as string;
  digests = sums;
}, 180_000);
afterAll(() => rmSync(root, { recursive: true, force: true }), 120_000);

describe("pretranspile in a pack", () => {
  const generated = "pack/pi-packages/ts/package/lib/values.js";

  it("carries the generated JavaScript, and the TypeScript it came from", () => {
    expect(existsSync(join(directory, generated))).toBe(true);
    expect(readFileSync(join(directory, generated), "utf8")).toContain(
      "const value = 2",
    );
    expect(
      existsSync(join(directory, "pack/pi-packages/ts/package/lib/values.ts")),
    ).toBe(true);
  });

  it("builds the same archive twice", () => {
    expect(digests[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(digests[1]).toBe(digests[0]);
  });

  it("covers it in the checksums", () => {
    expect(readFileSync(join(directory, "checksums.txt"), "utf8")).toContain(
      `  ${generated}\n`,
    );
  });
});
