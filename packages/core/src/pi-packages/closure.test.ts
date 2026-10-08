import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
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
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  analyzeClosure,
  bundleClosure,
  CLOSURE_DIRECTORY,
  closureKey,
  type FallbackReason,
  pretranspileClosures,
} from "./closure.js";
import {
  describeFootprint,
  optimizePiPackages,
  readFootprint,
} from "./footprint.js";
import { loadEsbuild } from "./module-scan.js";
import type { LockedPackageResource } from "./types.js";

const esbuild = loadEsbuild(
  fileURLToPath(new URL("../../package.json", import.meta.url)),
);
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** A package that bundles safely: ES modules, static imports, a dependency, a file nothing imports. */
const SAFE: Record<string, string> = {
  "package.json": JSON.stringify({
    name: "ext",
    version: "1.0.0",
    type: "module",
  }),
  "dist/extension.js": `import { greet } from "./lib/greet.js";
import { fmt } from "util-lib";
import { counter } from "./lib/state.js";
export default function register() {
  return { greeting: greet(fmt("x")), count: counter() };
}
export const order = () => globalThis.__order;
`,
  "dist/other.js": `import { counter } from "./lib/state.js";
export const second = () => counter();
`,
  "dist/lib/greet.js": `import { deep } from "./deep/deep.js";
(globalThis.__order ??= []).push("greet");
export const greet = (text) => "hi " + deep(text);
`,
  "dist/lib/deep/deep.js": `(globalThis.__order ??= []).push("deep");
export const deep = (text) => "deep:" + text;
`,
  "dist/lib/state.js": `let count = 0;
export const counter = () => ++count;
`,
  "dist/lib/unused.js": "export const unused = 1;\n",
  "README.md": "docs\n",
};
const UTIL: Record<string, string> = {
  "util-lib/package.json": JSON.stringify({
    name: "util-lib",
    version: "2.0.0",
    type: "module",
    exports: "./index.js",
    license: "MIT",
  }),
  "util-lib/LICENSE": "MIT util-lib\n",
  "util-lib/index.js": `export { fmt } from "./fmt.js";\n`,
  "util-lib/fmt.js": `(globalThis.__order ??= []).push("fmt");
export const fmt = (text) => "[" + text + "]";\n`,
};

function vendor(
  overrides: Record<string, string | null> = {},
  entries = ["dist/extension.js", "dist/other.js"],
): { root: string; resources: LockedPackageResource[] } {
  const root = mkdtempSync(join(tmpdir(), "piship-closure-"));
  roots.push(root);
  const files: Record<string, string> = {};
  for (const [path, content] of Object.entries(SAFE))
    files[`node_modules/ext/${path}`] = content;
  for (const [path, content] of Object.entries(UTIL))
    files[`node_modules/${path}`] = content;
  for (const [path, content] of Object.entries(overrides)) {
    const full = path.startsWith("node_modules/")
      ? path
      : `node_modules/ext/${path}`;
    if (content === null) delete files[full];
    else files[full] = content;
  }
  files["package.json"] = JSON.stringify({ name: "piship-package-x" });
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return {
    root,
    resources: entries.map((path) => ({
      kind: "extensions" as const,
      path,
      sha256: createHash("sha256")
        .update(readFileSync(join(root, "node_modules/ext", path)))
        .digest("hex"),
    })),
  };
}

const analyze = (fixture: ReturnType<typeof vendor>) =>
  analyzeClosure({
    root: fixture.root,
    packagePath: "node_modules/ext",
    resources: fixture.resources,
    esbuild,
  });

const reasonsOf = (fixture: ReturnType<typeof vendor>): FallbackReason[] => {
  const analysis = analyze(fixture);
  if (analysis.safe) throw new Error("expected a fallback");
  return [...new Set(analysis.findings.map((finding) => finding.reason))];
};

function tree(root: string, prefix = ""): string[] {
  return readdirSync(root, { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory()
        ? tree(join(root, entry.name), `${prefix}${entry.name}/`)
        : [`${prefix}${entry.name}`],
    )
    .sort();
}

/** What loading the extensions reports: their results, the order modules ran in, shared state. */
function load(fixture: ReturnType<typeof vendor>): unknown {
  const entry = pathToFileURL(
    join(fixture.root, "node_modules/ext/dist/extension.js"),
  ).href;
  const other = pathToFileURL(
    join(fixture.root, "node_modules/ext/dist/other.js"),
  ).href;
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const extension = await import(${JSON.stringify(entry)});
const first = extension.default();
const other = await import(${JSON.stringify(other)});
console.log(JSON.stringify({ first, second: other.second(), order: extension.order(), names: Object.keys(extension).sort() }));`,
    ],
    { encoding: "utf8" },
  );
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout);
}

describe("bundle-safe Pi package closures", () => {
  it("bundles below the extension files and leaves them byte for byte", () => {
    const fixture = vendor();
    const before = load(fixture);
    const entryBytes = readFileSync(
      join(fixture.root, "node_modules/ext/dist/extension.js"),
    );
    const analysis = analyze(fixture);
    if (!analysis.safe) throw new Error(JSON.stringify(analysis.findings));
    expect(analysis.plan.entries).toEqual([
      "node_modules/ext/dist/extension.js",
      "node_modules/ext/dist/other.js",
    ]);
    // Only what the extensions import is replaced; the rest is inlined.
    expect(analysis.plan.replaced).toEqual([
      "node_modules/ext/dist/lib/greet.js",
      "node_modules/ext/dist/lib/state.js",
      "node_modules/util-lib/index.js",
    ]);
    expect(analysis.plan.inlined).toEqual([
      "node_modules/ext/dist/lib/deep/deep.js",
      "node_modules/util-lib/fmt.js",
    ]);
    const result = bundleClosure(
      {
        root: fixture.root,
        packagePath: "node_modules/ext",
        resources: fixture.resources,
        esbuild,
      },
      analysis.plan,
    );
    expect(result).toMatchObject({ replaced: 3, inlined: 2 });
    // Locked files are the same bytes; what they import answers as before.
    expect(
      readFileSync(join(fixture.root, "node_modules/ext/dist/extension.js")),
    ).toEqual(entryBytes);
    expect(load(fixture)).toEqual(before);
    expect(existsSync(join(fixture.root, "node_modules/util-lib/fmt.js"))).toBe(
      false,
    );
    expect(
      existsSync(join(fixture.root, "node_modules/ext/dist/lib/deep")),
    ).toBe(false);
    // package.json, the license, and code nothing imports stay.
    expect(
      existsSync(join(fixture.root, "node_modules/util-lib/package.json")),
    ).toBe(true);
    expect(
      existsSync(join(fixture.root, "node_modules/util-lib/LICENSE")),
    ).toBe(true);
    expect(
      existsSync(join(fixture.root, "node_modules/ext/dist/lib/unused.js")),
    ).toBe(true);
    expect(
      readdirSync(join(fixture.root, CLOSURE_DIRECTORY)).every((name) =>
        name.endsWith(".mjs"),
      ),
    ).toBe(true);
  });

  it("keeps a module shared by two extensions one module", () => {
    const fixture = vendor();
    const analysis = analyze(fixture);
    if (!analysis.safe) throw new Error("expected a safe closure");
    bundleClosure(
      {
        root: fixture.root,
        packagePath: "node_modules/ext",
        resources: fixture.resources,
        esbuild,
      },
      analysis.plan,
    );
    // The counter state.js holds is shared by extension.js and other.js.
    expect(load(fixture)).toMatchObject({ first: { count: 1 }, second: 2 });
  });

  it("leaves host-provided modules as imports", () => {
    const fixture = vendor({
      "dist/extension.js": `import { Type } from "typebox";
import { complete } from "@earendil-works/pi-ai";
import { greet } from "./lib/greet.js";
export default () => [Type, complete, greet];\n`,
    });
    expect(analyze(fixture).safe).toBe(true);
  });

  describe("falls back, saying why", () => {
    it("for a native addon", () => {
      expect(
        reasonsOf(vendor({ "node_modules/util-lib/build/x.node": "ELF" })),
      ).toEqual(["native-addon"]);
      expect(
        reasonsOf(vendor({ "node_modules/util-lib/binding.gyp": "{}" })),
      ).toEqual(["native-addon"]);
    });

    it("for external WebAssembly", () => {
      expect(
        reasonsOf(vendor({ "node_modules/util-lib/engine.wasm": "wasm" })),
      ).toEqual(["wasm-asset"]);
    });

    it("for an install script", () => {
      expect(
        reasonsOf(
          vendor({
            "node_modules/util-lib/package.json": JSON.stringify({
              name: "util-lib",
              version: "2.0.0",
              type: "module",
              exports: "./index.js",
              scripts: { postinstall: "node build.js" },
            }),
          }),
        ),
      ).toEqual(["install-script"]);
    });

    it("for a dynamic import or require", () => {
      for (const body of [
        "export const fmt = (name) => import(name);\n",
        'import { createRequire } from "node:module";\nexport const fmt = (n) => createRequire(import.meta.url)(n);\n',
        "export const fmt = async () => import('./index.js');\n",
      ])
        expect(
          reasonsOf(vendor({ "node_modules/util-lib/fmt.js": body })),
        ).toEqual(
          expect.arrayContaining([
            expect.stringMatching(
              /dynamic-import|runtime-discovery|self-location/,
            ),
          ]),
        );
    });

    it("for code that locates its own files", () => {
      for (const body of [
        "export const fmt = new URL('./data.txt', import.meta.url);\n",
        "import { dirname } from 'node:path';\nexport const fmt = dirname(import.meta.dirname);\n",
      ])
        expect(
          reasonsOf(vendor({ "node_modules/util-lib/fmt.js": body })),
        ).toContain("self-location");
      expect(
        reasonsOf(
          vendor({
            "dist/lib/deep/deep.js": "export const deep = () => __dirname;\n",
          }),
        ),
      ).toContain("self-location");
    });

    it("for module discovery at run time", () => {
      expect(
        reasonsOf(
          vendor({
            "dist/lib/deep/deep.js":
              "export const deep = () => require.resolve('x');\n",
          }),
        ),
      ).toContain("runtime-discovery");
    });

    it("for a CommonJS file an extension imports directly", () => {
      expect(
        reasonsOf(
          vendor({
            "node_modules/util-lib/package.json": JSON.stringify({
              name: "util-lib",
              version: "2.0.0",
              exports: "./index.cjs",
            }),
            "node_modules/util-lib/index.cjs":
              "exports.fmt = (text) => '[' + text + ']';\n",
            "node_modules/util-lib/index.js": null,
            "node_modules/util-lib/fmt.js": null,
          }),
        ),
      ).toContain("commonjs-import");
    });

    it("for JSON or TypeScript in the closure", () => {
      expect(
        reasonsOf(
          vendor({
            "node_modules/util-lib/fmt.js":
              "import data from './data.json' with { type: 'json' };\nexport const fmt = () => data;\n",
            "node_modules/util-lib/data.json": "{}",
          }),
        ),
      ).toContain("non-javascript-module");
      expect(
        reasonsOf(
          vendor({
            "dist/lib/deep/deep.js": null,
            "dist/lib/deep/deep.ts": "export const deep = (t: string) => t;\n",
            "dist/lib/greet.js":
              'import { deep } from "./deep/deep.ts";\nexport const greet = deep;\n',
          }),
        ),
      ).toContain("typescript-closure");
    });

    it("when an extension imports another extension", () => {
      expect(
        reasonsOf(
          vendor({
            "dist/extension.js":
              'import { second } from "./other.js";\nexport default second;\n',
          }),
        ),
      ).toContain("entry-imports-entry");
    });

    it("for an import the tree does not hold", () => {
      expect(
        reasonsOf(
          vendor({
            "dist/lib/deep/deep.js":
              'import "not-installed";\nexport const deep = 1;\n',
          }),
        ),
      ).toContain("unresolved-import");
    });

    it("for a file that does not parse", () => {
      expect(
        reasonsOf(vendor({ "dist/lib/deep/deep.js": "export const = ;\n" })),
      ).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/unparsable|unresolved/),
        ]),
      );
    });

    it("when code left behind imports what would be bundled away", () => {
      expect(
        reasonsOf(
          vendor({
            "skills/run/run.mjs":
              'import { deep } from "../../dist/lib/deep/deep.js";\nconsole.log(deep("x"));\n',
          }),
        ),
      ).toContain("left-behind-code");
    });

    it("for a package with no extension files", () => {
      expect(reasonsOf(vendor({}, []))).toEqual(["nothing-to-bundle"]);
    });
  });
});

describe("the footprint report", () => {
  it("records each closure's decision and describes it", () => {
    const payload = mkdtempSync(join(tmpdir(), "piship-footprint-"));
    roots.push(payload);
    const safe = vendor();
    const unsafe = vendor({ "node_modules/util-lib/x.wasm": "wasm" });
    const move = (from: string, id: string) => {
      const files = tree(from);
      for (const file of files) {
        mkdirSync(dirname(join(payload, "pi-packages", id, file)), {
          recursive: true,
        });
        writeFileSync(
          join(payload, "pi-packages", id, file),
          readFileSync(join(from, file)),
        );
      }
    };
    move(safe.root, "safe");
    move(unsafe.root, "unsafe");
    const packages = [
      { id: "safe", resources: safe.resources },
      { id: "unsafe", resources: unsafe.resources },
    ].map((item) => ({
      ...item,
      directory: join(payload, "pi-packages", item.id),
      packageRoot: join(payload, "pi-packages", item.id, "node_modules/ext"),
    }));
    const footprint = optimizePiPackages(payload, {
      packages,
      esbuild,
      bundle: true,
    });
    expect(footprint.closures.map((item) => [item.id, item.closure])).toEqual([
      ["safe", "bundled"],
      ["unsafe", "vendored"],
    ]);
    expect(footprint.files.after).toBeLessThan(footprint.files.before);
    expect(readFootprint(payload)).toEqual(footprint);
    // A closure that falls back is left exactly as it was.
    expect(tree(join(payload, "pi-packages/unsafe"))).toEqual(
      tree(unsafe.root),
    );
    const lines = describeFootprint(footprint);
    expect(lines[0]).toMatch(/1 of 2 bundled; vendored: unsafe \(wasm-asset\)/);
    // Bundling off: closures are not touched, dependencies still shared.
    const off = optimizePiPackages(payload, {
      packages,
      esbuild,
      bundle: false,
    });
    expect(off.closures).toEqual([]);
  });
});

/** A TypeScript package: imports written `./x.js` where only `x.ts` exists. */
const TYPESCRIPT_PACKAGE: Record<string, string> = {
  "node_modules/ext/package.json": JSON.stringify({
    name: "ext",
    version: "1.0.0",
    type: "module",
  }),
  "node_modules/ext/extensions/main.ts": `import type { Shape } from "../lib/types.js";
import { Mode, value, where } from "../lib/values.js";
import { other } from "./other.js";
import data from "../lib/data.json" with { type: "json" };
import { kept } from "../lib/kept.ts";
const ready: Shape = { size: await Promise.resolve(value) };
export default () => ({ ready, other: other(), mode: Mode.On, where, data, kept });
`,
  "node_modules/ext/extensions/other.ts":
    "export const other = (): string => 'other';\n",
  "node_modules/ext/lib/types.ts": "export interface Shape { size: number }\n",
  "node_modules/ext/lib/values.ts": `export enum Mode { Off, On }
export const value: number = 2;
export const where: string | undefined = import.meta.dirname;
`,
  "node_modules/ext/lib/data.json": JSON.stringify({ ok: true }),
  "node_modules/ext/lib/kept.ts": "export const kept = 'ts';\n",
  "node_modules/ext/lib/kept.js": "export const kept = 'js';\n",
  "node_modules/ext/lib/unused.ts": "export const unused = 1;\n",
  "package.json": JSON.stringify({ name: "piship-package-x" }),
};

function typescriptPackage(overrides: Record<string, string> = {}) {
  // The real path: macOS reports its temporary directory through a symlink
  // (/var is /private/var), and the test compares it with `import.meta` paths
  // that Node reports resolved.
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-pretranspile-")),
  );
  roots.push(root);
  for (const [path, content] of Object.entries({
    ...TYPESCRIPT_PACKAGE,
    ...overrides,
  })) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  const resources = ["extensions/main.ts", "extensions/other.ts"].map(
    (path) => ({
      kind: "extensions" as const,
      path,
      sha256: createHash("sha256")
        .update(readFileSync(join(root, "node_modules/ext", path)))
        .digest("hex"),
    }),
  );
  return { root, resources };
}

const pretranspile = (fixture: ReturnType<typeof typescriptPackage>) =>
  pretranspileClosures(
    [
      {
        id: "ext",
        root: fixture.root,
        packagePath: "node_modules/ext",
        resources: fixture.resources,
        esbuild,
      },
    ],
    esbuild,
  )[0];

describe("pretranspiling a TypeScript closure", () => {
  it("writes each imported module as JavaScript beside it, and nothing else", () => {
    const fixture = typescriptPackage();
    const before = tree(fixture.root);
    const result = pretranspile(fixture);
    expect(result).toEqual({
      // `other.ts` is an extension another one imports; `main.ts` is imported by none.
      written: [
        "node_modules/ext/extensions/other.js",
        "node_modules/ext/lib/values.js",
      ],
      kept: ["node_modules/ext/lib/kept.ts"],
      warnings: [],
    });
    expect(tree(fixture.root)).toEqual(
      [...before, ...(result?.written ?? [])].sort(),
    );
    // The extension files are the locked bytes, the existing sibling is untouched.
    for (const resource of fixture.resources)
      expect(
        createHash("sha256")
          .update(
            readFileSync(join(fixture.root, "node_modules/ext", resource.path)),
          )
          .digest("hex"),
      ).toBe(resource.sha256);
    expect(
      readFileSync(join(fixture.root, "node_modules/ext/lib/kept.js"), "utf8"),
    ).toBe("export const kept = 'js';\n");
    // ES modules, loadable by Node as they are, import.meta kept.
    const values = pathToFileURL(
      join(fixture.root, "node_modules/ext/lib/values.js"),
    ).href;
    const run = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `const m = await import(${JSON.stringify(values)}); console.log(JSON.stringify([m.Mode.On, m.value, m.where]));`,
      ],
      { encoding: "utf8" },
    );
    expect(run.stderr).toBe("");
    expect(JSON.parse(run.stdout)).toEqual([
      1,
      2,
      join(fixture.root, "node_modules/ext/lib"),
    ]);
    expect(
      readFileSync(
        join(fixture.root, "node_modules/ext/lib/values.js"),
        "utf8",
      ),
    ).not.toMatch(/sourceMappingURL|: number/);
  });

  it("writes the same bytes from the same input", () => {
    const first = typescriptPackage();
    const second = typescriptPackage();
    const written = pretranspile(first)?.written ?? [];
    expect(pretranspile(second)?.written).toEqual(written);
    for (const file of written)
      expect(readFileSync(join(second.root, file))).toEqual(
        readFileSync(join(first.root, file)),
      );
  });

  it.each([
    ["export =", "export = 1;\n", /CommonJS/],
    [
      "require",
      "export const other = (): string => require('../lib/values.js').where;\n",
      /requires/,
    ],
    ["a syntax error", "export const = ;\n", /cannot/],
  ])("fails on %s and writes nothing", (_, source, message) => {
    const fixture = typescriptPackage({
      "node_modules/ext/extensions/other.ts": source,
    });
    const before = tree(fixture.root);
    let error: unknown;
    try {
      pretranspile(fixture);
    } catch (caught) {
      error = caught;
    }
    expect((error as { code?: string }).code).toBe("CONFIG_INVALID");
    expect(String((error as Error).message)).toMatch(message);
    expect(tree(fixture.root)).toEqual(before);
  });
});

describe("pretranspile scope and failures", () => {
  const WRITTEN = [
    "node_modules/ext/extensions/other.js",
    "node_modules/ext/lib/values.js",
  ];

  it("follows only the package's own imports: a dependency with a native file does not matter", () => {
    const plain = pretranspile(typescriptPackage());
    const fixture = typescriptPackage({
      "node_modules/ext/extensions/other.ts":
        "import dep from 'dep';\nexport const other = (): string => dep;\n",
      "node_modules/ext/node_modules/dep/package.json": JSON.stringify({
        name: "dep",
        version: "1.0.0",
        type: "module",
        main: "index.js",
      }),
      "node_modules/ext/node_modules/dep/index.js":
        "import addon from './addon.node';\nexport default addon;\n",
      "node_modules/ext/node_modules/dep/addon.node": "not a real addon",
      // A tsconfig above the package must not be read.
      "tsconfig.json": JSON.stringify({
        compilerOptions: { jsx: "preserve", target: "es5", baseUrl: "nowhere" },
      }),
    });
    const result = pretranspile(fixture);
    expect(result?.written).toEqual(plain?.written);
    expect(result?.written).toEqual(WRITTEN);
  });

  it("fails on a decorator, which Node cannot read, and writes nothing", () => {
    const fixture = typescriptPackage({
      "node_modules/ext/extensions/other.ts":
        "function dec(target: unknown) { return target; }\n@dec\nclass Thing {}\nexport const other = (): string => String(Thing);\n",
    });
    const before = tree(fixture.root);
    let error: unknown;
    try {
      pretranspile(fixture);
    } catch (caught) {
      error = caught;
    }
    expect((error as { code?: string }).code).toBe("CONFIG_INVALID");
    expect(String((error as Error).message)).toMatch(
      /extensions\/other\.js.*cannot read/,
    );
    expect(tree(fixture.root)).toEqual(before);
  });

  it("fails, writing nothing, when a package has nothing to write", () => {
    const fixture = typescriptPackage({
      "node_modules/ext/extensions/main.ts": "export default () => 1;\n",
      "node_modules/ext/extensions/other.ts": "export const other = 1;\n",
    });
    const before = tree(fixture.root);
    expect(() => pretranspile(fixture)).toThrow(/no TypeScript module/);
    expect(tree(fixture.root)).toEqual(before);
  });

  it("writes .mts as .mjs, follows dynamic import, and drops an un-annotated type import", () => {
    const fixture = typescriptPackage({
      "node_modules/ext/extensions/main.ts": `import { other } from "./other.js";
export default async () => ({ other, late: (await import("../lib/late.js")).late });
`,
      "node_modules/ext/extensions/other.ts": `import { Shape } from "../lib/types.js";
import { helper } from "../lib/helper.mjs";
const shape: Shape = { size: 1 };
export const other = helper(shape.size);
`,
      "node_modules/ext/lib/types.ts":
        "export interface Shape { size: number }\n",
      "node_modules/ext/lib/helper.mts":
        "export const helper = (n: number): number => n + 1;\n",
      "node_modules/ext/lib/late.ts": "export const late: string = 'late';\n",
    });
    const result = pretranspile(fixture);
    expect(result?.written).toEqual([
      "node_modules/ext/extensions/other.js",
      "node_modules/ext/lib/helper.mjs",
      "node_modules/ext/lib/late.js",
    ]);
    // esbuild erases the un-annotated type import, so types.ts is never reached.
    expect(
      existsSync(join(fixture.root, "node_modules/ext/lib/types.js")),
    ).toBe(false);
    const other = readFileSync(
      join(fixture.root, "node_modules/ext/extensions/other.js"),
      "utf8",
    );
    expect(other).not.toMatch(/types\.js|Shape/);
    expect(other).toMatch(/helper\.mjs/);
  });
});

describe("pretranspile warns where Node, not Pi's loader, would fail", () => {
  const OTHER = "node_modules/ext/extensions/other.ts";
  const warnings = (overrides: Record<string, string>) =>
    pretranspile(typescriptPackage(overrides))?.warnings ?? [];

  it("says nothing for a package Node can import as it is", () => {
    expect(warnings({})).toEqual([]);
    // Declared by the module itself, and import.meta, are fine in an ES module.
    expect(
      warnings({
        [OTHER]: `import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const __dirname = fileURLToPath(new URL(".", import.meta.url));
const require = createRequire(import.meta.url);
export const other = (): string => __dirname + require.resolve("node:fs");
`,
      }),
    ).toEqual([]);
  });

  it("names a type re-exported as a value, which Node fails to link", () => {
    expect(
      warnings({
        [OTHER]: `export { Shape } from "../lib/types.js";
export const other = (): string => "other";
`,
      }),
    ).toEqual([
      expect.stringMatching(
        /extensions\/other\.js imports Shape from node_modules\/ext\/lib\/types\.js.*does not export it/,
      ),
    ]);
    // Written without the extension, it is the same module and the same finding.
    expect(
      warnings({
        [OTHER]: `export { Shape } from "../lib/types";
export const other = (): string => "other";
`,
      }),
    ).toEqual([expect.stringMatching(/imports Shape from .*lib\/types\.js/)]);
    // A real export of the same module is not one.
    expect(
      warnings({
        [OTHER]: `export { value } from "../lib/values.js";
export const other = (): string => "other";
`,
      }),
    ).toEqual([]);
  });

  it("names __dirname, __filename, and require left in the output", () => {
    const found = warnings({
      [OTHER]:
        "export const other = (): string => __dirname + __filename + require.resolve('x');\n",
    });
    expect(found).toHaveLength(3);
    for (const name of ["__dirname", "__filename", "require"])
      expect(found.join("\n")).toContain(`extensions/other.js uses ${name}`);
  });

  it.each([
    ["called through a comma expression", "(0, require)('node:fs')"],
    ["passed as an argument", "[1].map(require)"],
    ["held as a value", "(() => { const load = require; return load; })()"],
    ["with its property read", "require.main"],
  ])("names a require %s", (_, expression) => {
    const found = warnings({
      [OTHER]: `export const other = (): unknown => ${expression};\n`,
    });
    expect(found.join("\n")).toContain("extensions/other.js uses require");
  });

  it("refuses a require call outright (esbuild sees it), and lets a typeof guard pass", () => {
    // A call is a build error, not a warning: it is never written.
    expect(() =>
      warnings({
        [OTHER]:
          "export const other = (): string => String(require('node:fs'));\n",
      }),
    ).toThrow(/calls require/);
    expect(
      warnings({
        [OTHER]:
          "export const other = (): boolean => typeof require === 'function';\n",
      }),
    ).toEqual([]);
  });

  it("names a package.json without type: module", () => {
    expect(
      warnings({
        "node_modules/ext/package.json": JSON.stringify({
          name: "ext",
          version: "1.0.0",
        }),
      }),
    ).toEqual([
      expect.stringMatching(
        /node_modules\/ext\/package\.json has no "type": "module"/,
      ),
    ]);
  });

  it("names a module imported both as ./x and as ./x.js", () => {
    expect(
      warnings({
        [OTHER]: `import { value } from "../lib/values";
export const other = (): number => value;
`,
      }),
    ).toEqual([
      expect.stringMatching(
        /node_modules\/ext\/lib\/values\.ts is imported both/,
      ),
    ]);
  });
});

describe("closureKey", () => {
  it.each([
    ["/r/pkg", "node_modules/ext/a.ts", "node_modules/ext/a.ts"],
    ["/r/pkg", "node_modules\\ext\\a.ts", "node_modules/ext/a.ts"],
    ["/r/pkg", "./node_modules/ext/a.ts", "node_modules/ext/a.ts"],
    ["/r/pkg", "/r/pkg/node_modules/ext/a.ts", "node_modules/ext/a.ts"],
    [
      "C:\\Users\\me\\pkg",
      "c:\\users\\me\\pkg\\node_modules\\ext\\a.ts",
      "node_modules/ext/a.ts",
    ],
    ["c:/Users/me/pkg/", "C:\\Users\\me\\pkg\\lib\\a.ts", "lib/a.ts"],
    [
      "C:\\Users\\me\\pkg",
      "C:\\Users\\me\\pkg2\\a.ts",
      "C:/Users/me/pkg2/a.ts",
    ],
    // POSIX roots stay case sensitive.
    ["/r/Pkg", "/r/pkg/a.ts", "/r/pkg/a.ts"],
  ])("%s + %s", (root, path, expected) => {
    expect(closureKey(root, path)).toBe(expected);
  });
});
