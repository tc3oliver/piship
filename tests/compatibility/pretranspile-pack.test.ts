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
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "ptp-"));
const core = pathToFileURL(
  join(repository, "packages/core/dist/index.js"),
).href;
const manifest = join(root, "source", "piship.yaml");

function put(files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, "source", path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

let directory: string;
beforeAll(() => {
  cpSync(join(repository, "examples", "personal"), join(root, "source"), {
    recursive: true,
  });
  // No network and no warm download cache: the search tools are left out.
  writeFileSync(
    manifest,
    readFileSync(manifest, "utf8")
      .replace(
        /^ {2}# fd and rg ship[^\n]*\n[^\n]*\n {2}searchTools:\n {4}mode: bundled\n/m,
        "",
      )
      .replace(
        /^resources:\n/m,
        `resources:
  packages:
    - id: ts
      source: local
      path: ./packages/ts
      class: user
      pretranspile: true
`,
      )
      .replace(
        /^policy:\n/m,
        "packageTrust:\n  local: { paths: [./packages] }\n\npolicy:\n",
      ),
  );
  put({
    "packages/ts/package.json": JSON.stringify({
      name: "ts",
      version: "1.0.0",
      type: "module",
      pi: { extensions: ["./extensions"] },
    }),
    "packages/ts/extensions/main.ts": `import { value } from "../lib/values.js";
export default () => value;
`,
    "packages/ts/lib/values.ts": "export const value: number = 2;\n",
  });
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.PISHIP_BUILD_INPUT;
  // The runtime archive is described, not built: the pack only reads it.
  const script = `import {buildPack, lockManifest, requireCurrentLock, currentTarget} from ${JSON.stringify(core)};
lockManifest(${JSON.stringify(manifest)});
const lock = requireCurrentLock(${JSON.stringify(manifest)});
const target = currentTarget();
const built = await buildPack(${JSON.stringify(manifest)}, {
  outputRoot: ${JSON.stringify(join(root, "out"))},
  runtimes: ["runtime"],
  readRuntime: async () => ({ name: "runtime.tar.gz", target, sha256: "a".repeat(64), bytes: 1, pishipVersion: lock.runtime.pishipVersion, piVersion: lock.runtime.version, npmLockSha256: lock.runtime.npmLockSha256, inventorySha256: "b".repeat(64), searchTools: {} }),
});
console.log(built.directory);`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  directory = result.stdout.trim();
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

  it("covers it in the checksums", () => {
    expect(readFileSync(join(directory, "checksums.txt"), "utf8")).toContain(
      `  ${generated}\n`,
    );
  });
});
