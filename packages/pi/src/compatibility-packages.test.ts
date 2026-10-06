// Pi compatibility: Pi's own extension loader loads the extension files of a
// vendored Pi package the same way after PiShip has shared its identical
// dependencies and bundled its bundle-safe closure. Each load runs in a fresh
// Node process, so nothing the first load imported (a module cache, jiti's
// cache) can stand in for what the second resolves.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadEsbuild, optimizePiPackages } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const esbuild = loadEsbuild(join(repo, "package.json"));
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function write(root: string, files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
}

/** A dependency with an exports map, both module formats, and files exports does not reach. */
const shared = (name: string): Record<string, string> => ({
  [`node_modules/${name}/package.json`]: JSON.stringify({
    name,
    version: "1.0.0",
    type: "module",
    exports: {
      ".": { import: "./index.js", require: "./index.cjs" },
      "./extra": { import: "./extra.js", require: "./extra.cjs" },
    },
  }),
  [`node_modules/${name}/LICENSE`]: "MIT\n",
  [`node_modules/${name}/index.js`]: `import { word } from "./lib/word.js";\nexport const label = "label-" + word;\nexport default function describe() { return "described-" + word; }\n`,
  [`node_modules/${name}/index.cjs`]: `exports.label = "label-cjs";\n`,
  [`node_modules/${name}/extra.js`]: `export const extra = "extra";\n`,
  [`node_modules/${name}/extra.cjs`]: `exports.extra = "extra-cjs";\n`,
  [`node_modules/${name}/lib/word.js`]: `export const word = "word";\n`,
  ...Object.fromEntries(
    Array.from({ length: 12 }, (_, index) => [
      `node_modules/${name}/lib/internal-${index}.js`,
      `export const value${index} = ${index};\n`,
    ]),
  ),
});

/** The extension of a package whose dependency is `shared-dep`, with a closure that bundles safely. */
const extension = (id: string): Record<string, string> => ({
  "package.json": JSON.stringify({
    name: `piship-package-${id}`,
    private: true,
  }),
  "package-lock.json": JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/shared-dep": {
        version: "1.0.0",
        integrity: "sha512-shared-dep-1.0.0",
      },
    },
  }),
  [`node_modules/ext-${id}/package.json`]: JSON.stringify({
    name: `ext-${id}`,
    version: "1.0.0",
    type: "module",
  }),
  [`node_modules/ext-${id}/extension.js`]: `import describe, { label } from "shared-dep";
import { extra } from "shared-dep/extra";
import { createRequire } from "node:module";
import { greet } from "./lib/greet.js";
const cjs = createRequire(import.meta.url)("shared-dep");
export default function register(pi) {
  pi.registerCommand("${id}-" + label + "-" + describe() + "-" + extra + "-" + cjs.label + "-" + greet("x"), {
    handler: async () => {},
  });
}
`,
  [`node_modules/ext-${id}/lib/greet.js`]: `import { deep } from "./deep/deep.js";\nexport const greet = (text) => "greet-" + deep(text);\n`,
  [`node_modules/ext-${id}/lib/deep/deep.js`]: `export const deep = (text) => "deep-" + text;\n`,
  ...shared("shared-dep"),
});

/** Every command Pi's loader registers from `paths`, and its errors, in a fresh process. */
function load(paths: readonly string[], cwd: string, agentDir: string) {
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const { DefaultResourceLoader, SettingsManager } = await import("@earendil-works/pi-coding-agent");
const { paths, cwd, agentDir } = JSON.parse(process.env.FIXTURE);
const loader = new DefaultResourceLoader({
  cwd, agentDir, settingsManager: SettingsManager.inMemory(),
  additionalExtensionPaths: paths,
  noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
});
await loader.reload();
const loaded = loader.getExtensions();
console.log(JSON.stringify({
  errors: loaded.errors,
  commands: loaded.extensions.flatMap((item) => [...item.commands.keys()]).sort(),
}));`,
    ],
    {
      cwd: repo,
      encoding: "utf8",
      env: {
        ...process.env,
        FIXTURE: JSON.stringify({ paths, cwd, agentDir }),
      },
    },
  );
  expect(result.stderr).toBe("");
  expect(result.status).toBe(0);
  return JSON.parse(result.stdout.trim().split("\n").at(-1) ?? "") as {
    errors: unknown[];
    commands: string[];
  };
}

function files(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(directory, entry.name), `${prefix}${entry.name}/`)
      : [`${prefix}${entry.name}`],
  );
}

describe("Pi's extension loader and the shared and bundled Pi package footprint", () => {
  it("loads the same extensions from shared dependencies and a bundled closure", () => {
    const payload = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-compat-footprint-")),
    );
    roots.push(payload);
    for (const id of ["one", "two", "three"])
      write(join(payload, "pi-packages", id), extension(id));
    const cwd = join(payload, "project");
    const agentDir = join(payload, "agent");
    mkdirSync(cwd);
    mkdirSync(agentDir);
    const entry = (id: string) =>
      join(payload, "pi-packages", id, `node_modules/ext-${id}/extension.js`);
    const paths = ["one", "two", "three"].map(entry);
    const entryBytes = paths.map((path) => readFileSync(path));
    const before = load(paths, cwd, agentDir);
    expect(before.errors).toEqual([]);
    expect(before.commands).toEqual([
      "one-label-word-described-word-extra-label-cjs-greet-deep-x",
      "three-label-word-described-word-extra-label-cjs-greet-deep-x",
      "two-label-word-described-word-extra-label-cjs-greet-deep-x",
    ]);
    const footprint = optimizePiPackages(payload, {
      bundle: true,
      esbuild,
      packages: ["one", "two", "three"].map((id) => ({
        id,
        directory: join(payload, "pi-packages", id),
        packageRoot: join(payload, "pi-packages", id, `node_modules/ext-${id}`),
        resources: [
          {
            kind: "extensions" as const,
            path: "extension.js",
            sha256: createHash("sha256")
              .update(readFileSync(entry(id)))
              .digest("hex"),
          },
        ],
      })),
    });
    // The extensions use createRequire, so no closure is bundle-safe here; the
    // identical dependency is shared three ways.
    expect(footprint.closures.map((item) => item.closure)).toEqual([
      "vendored",
      "vendored",
      "vendored",
    ]);
    expect(footprint.shared).toHaveLength(1);
    expect(footprint.shared[0]?.locations).toHaveLength(3);
    expect(footprint.files.after).toBeLessThan(footprint.files.before);
    expect(files(join(payload, "pi-packages/.shared")).length).toBeGreaterThan(
      0,
    );
    // The locked files are the same bytes, and Pi loads what it loaded.
    expect(paths.map((path) => readFileSync(path))).toEqual(entryBytes);
    expect(load(paths, cwd, agentDir)).toEqual(before);
  });

  it("loads an extension whose closure was bundled", () => {
    const payload = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-compat-bundled-")),
    );
    roots.push(payload);
    const id = "bundled";
    write(join(payload, "pi-packages", id), {
      "package.json": JSON.stringify({ name: "piship-package-bundled" }),
      "node_modules/ext/package.json": JSON.stringify({
        name: "ext",
        version: "1.0.0",
        type: "module",
      }),
      "node_modules/ext/extension.js": `import { greet } from "./lib/greet.js";
import { fmt } from "util-lib";
export default function register(pi) {
  pi.registerCommand("bundled-" + greet(fmt("x")), { handler: async () => {} });
}
`,
      "node_modules/ext/lib/greet.js": `import { deep } from "./deep.js";\nexport const greet = (text) => "greet-" + deep(text);\n`,
      "node_modules/ext/lib/deep.js": `export const deep = (text) => "deep-" + text;\n`,
      "node_modules/util-lib/package.json": JSON.stringify({
        name: "util-lib",
        version: "1.0.0",
        type: "module",
        exports: "./index.js",
      }),
      "node_modules/util-lib/index.js": `export { fmt } from "./fmt.js";\n`,
      "node_modules/util-lib/fmt.js": `export const fmt = (text) => "[" + text + "]";\n`,
    });
    const cwd = join(payload, "project");
    const agentDir = join(payload, "agent");
    mkdirSync(cwd);
    mkdirSync(agentDir);
    const path = join(
      payload,
      "pi-packages",
      id,
      "node_modules/ext/extension.js",
    );
    const bytes = readFileSync(path);
    const before = load([path], cwd, agentDir);
    expect(before).toEqual({
      errors: [],
      commands: ["bundled-greet-deep-[x]"],
    });
    const footprint = optimizePiPackages(payload, {
      bundle: true,
      esbuild,
      packages: [
        {
          id,
          directory: join(payload, "pi-packages", id),
          packageRoot: join(payload, "pi-packages", id, "node_modules/ext"),
          resources: [
            {
              kind: "extensions" as const,
              path: "extension.js",
              sha256: createHash("sha256").update(bytes).digest("hex"),
            },
          ],
        },
      ],
    });
    expect(footprint.closures).toEqual([
      expect.objectContaining({ id, closure: "bundled" }),
    ]);
    expect(
      files(join(payload, "pi-packages", id)).some((file) =>
        file.endsWith("lib/deep.js"),
      ),
    ).toBe(false);
    expect(readFileSync(path)).toEqual(bytes);
    expect(load([path], cwd, agentDir)).toEqual(before);
  });
});
