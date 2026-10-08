// `resources.packages[].pretranspile` through a real build: the step runs
// after the footprint and before the inventory, so the files it writes are
// inventoried, and a release that strips and bundles keeps them.
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
import { readManifest } from "@piship/schema";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "pt-"));
const core = pathToFileURL(
  join(repository, "packages/core/dist/index.js"),
).href;
const manifest = join(root, "source", "piship.yaml");
const PACKAGE = "packages/ts/";

function put(files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, "source", path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

/** Lock and build the copy in `source`; the build's progress lines come back. */
function build(output: string) {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.PISHIP_BUILD_INPUT;
  const script = `import {buildDistribution, lockManifest} from ${JSON.stringify(core)}; lockManifest(${JSON.stringify(manifest)}); const steps = []; const built = buildDistribution(${JSON.stringify(manifest)}, ${JSON.stringify(output)}, {supplyChainGates: false, cache: false, progress: (step) => steps.push(step)}); console.log(JSON.stringify({built, steps}));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: repository, encoding: "utf8", env, timeout: 120_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as { built: string; steps: string[] };
}

const json = <T>(path: string) => JSON.parse(readFileSync(path, "utf8")) as T;

let built: { built: string; steps: string[] };
beforeAll(() => {
  cpSync(join(repository, "examples", "personal"), join(root, "source"), {
    recursive: true,
  });
  // As in bundle.test.ts: no network, no warm download cache.
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
    [`${PACKAGE}package.json`]: JSON.stringify({
      name: "ts",
      version: "1.0.0",
      type: "module",
      pi: { extensions: ["./extensions"] },
    }),
    [`${PACKAGE}extensions/main.ts`]: `import { value } from "../lib/values.js";
export default () => value;
`,
    [`${PACKAGE}lib/values.ts`]: "export const value: number = 2;\n",
    // Declarations are stripped by a release; the generated file is not.
    [`${PACKAGE}lib/values.d.ts`]: "export declare const value: number;\n",
  });
  expect(readManifest(manifest).lifecycle?.release).toMatchObject({
    bundle: true,
    strip: true,
  });
  built = build(join(root, "output"));
}, 180_000);
afterAll(() => rmSync(root, { recursive: true, force: true }), 120_000);

describe("pretranspile in a build", () => {
  const generated = "pi-packages/ts/package/lib/values.js";

  it("runs after the footprint and before the bundler's inventory, and says how many modules it wrote", () => {
    const at = (text: RegExp) =>
      built.steps.findIndex((step) => text.test(step));
    expect(at(/Sharing and bundling the Pi package/)).toBeGreaterThanOrEqual(0);
    expect(at(/Writing the TypeScript closure of ts/)).toBeGreaterThan(
      at(/Sharing and bundling the Pi package/),
    );
    expect(at(/Bundling the portable runtime/)).toBeGreaterThan(
      at(/Writing the TypeScript closure of ts/),
    );
    expect(built.steps).toContain(
      "pi package pretranspile: ts: 1 modules written",
    );
  });

  it("decides the closure before the JavaScript exists: it is still vendored as TypeScript", () => {
    const footprint = json<{
      closures: {
        id: string;
        closure: string;
        findings?: { reason: string }[];
      }[];
    }>(join(built.built, "metadata", "pi-package-footprint.json"));
    const ts = footprint.closures.find((item) => item.id === "ts");
    expect(ts?.closure).toBe("vendored");
    expect(ts?.findings?.map((finding) => finding.reason)).toContain(
      "typescript-closure",
    );
  });

  it("puts the written file in the inventory beside the sources, which a strip keeps or removes as before", () => {
    const inventory = json<{ files: Record<string, unknown> }>(
      join(built.built, "metadata", "inventory.json"),
    );
    const names = Object.keys(inventory.files ?? inventory);
    expect(existsSync(join(built.built, generated))).toBe(true);
    expect(names).toContain(generated);
    expect(names).toContain("pi-packages/ts/package/lib/values.ts");
    expect(names).not.toContain("pi-packages/ts/package/lib/values.d.ts");
    expect(
      existsSync(join(built.built, "pi-packages/ts/package/lib/values.d.ts")),
    ).toBe(false);
    expect(readFileSync(join(built.built, generated), "utf8")).not.toMatch(
      /: number/,
    );
  });
});
