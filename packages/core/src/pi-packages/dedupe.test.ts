import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateNotices,
  generateSbom,
  listPayloadPackages,
} from "../supply-chain.js";
import {
  dedupePiPackages,
  type RetainedReason,
  SHARED_DIRECTORY,
} from "./dedupe.js";
import { loadEsbuild } from "./module-scan.js";

const esbuild = loadEsbuild(
  fileURLToPath(new URL("../../package.json", import.meta.url)),
);
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

interface Dependency {
  readonly name: string;
  readonly version: string;
  readonly files: Record<string, string>;
  /** Fields of the package's npm lockfile entry; integrity defaults to one per name@version. */
  readonly lock?: Record<string, unknown>;
}

/** A leaf package with an exports map, an ES module, a CommonJS twin, and files exports does not reach. */
function leaf(
  name = "leaf",
  version = "1.0.0",
  extra: Record<string, unknown> = {},
  files: Record<string, string> = {},
): Dependency {
  return {
    name,
    version,
    files: {
      "package.json": JSON.stringify({
        name,
        version,
        type: "module",
        license: "MIT",
        main: "./index.cjs",
        exports: {
          ".": { import: "./index.js", require: "./index.cjs" },
          "./sub": { import: "./sub.js", require: "./sub.cjs" },
          "./data": "./data.json",
          "./package.json": "./package.json",
        },
        ...extra,
      }),
      LICENSE: `MIT ${name}\n`,
      "README.md": "documentation\n",
      "index.js": `import { helper } from "./lib/helper.js";\nglobalThis.__loads = (globalThis.__loads ?? 0) + 1;\nexport const value = "esm:" + helper;\nexport default { kind: "default" };\n`,
      "index.cjs": `const { helper } = require("./lib/helper.cjs");\nexports.value = "cjs:" + helper;\nexports.extra = 1;\n`,
      "sub.js": `export const sub = "sub-esm";\n`,
      "sub.cjs": `module.exports = { sub: "sub-cjs" };\n`,
      "data.json": `{"data":1}\n`,
      "lib/helper.js": `export const helper = "helper";\n`,
      "lib/helper.cjs": `exports.helper = "helper";\n`,
      "lib/unused.js": `export const unused = 1;\n`,
      // Enough files no exports entry reaches that sharing two copies pays.
      ...Object.fromEntries(
        Array.from({ length: 12 }, (_, index) => [
          `lib/internal-${index}.js`,
          `export const value${index} = ${index};\n`,
        ]),
      ),
      ...files,
    },
  };
}

interface Layout {
  readonly [id: string]: {
    /** The declared package's own directory name under node_modules. */
    readonly dependencies: readonly Dependency[];
  };
}

/** `<root>/<id>/{package.json,package-lock.json,node_modules/**}` as vendoring leaves it. */
function vendor(layout: Layout, where?: string): string {
  const root = where ?? mkdtempSync(join(tmpdir(), "piship-dedupe-"));
  mkdirSync(root, { recursive: true });
  roots.push(root);
  for (const [id, { dependencies }] of Object.entries(layout)) {
    mkdirSync(join(root, id), { recursive: true });
    const packages: Record<string, unknown> = {};
    for (const dependency of dependencies) {
      const at = `node_modules/${dependency.name}`;
      packages[at] = {
        version: dependency.version,
        integrity: `sha512-${dependency.name}-${dependency.version}`,
        ...dependency.lock,
      };
      for (const [path, content] of Object.entries(dependency.files)) {
        const file = join(root, id, ...at.split("/"), path);
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, content);
      }
    }
    writeFileSync(
      join(root, id, "package.json"),
      JSON.stringify({ name: `piship-package-${id}`, private: true }),
    );
    writeFileSync(
      join(root, id, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages }),
    );
    // The declared package: a consumer of the dependencies, never shared.
    const declared = join(root, id, "node_modules", `declared-${id}`);
    mkdirSync(declared, { recursive: true });
    writeFileSync(
      join(declared, "package.json"),
      JSON.stringify({ name: `declared-${id}`, version: "1.0.0" }),
    );
    writeFileSync(join(declared, "extension.js"), "export {};\n");
  }
  return root;
}

const run = (root: string, ids: readonly string[]) =>
  dedupePiPackages(root, {
    esbuild,
    keep: ids.map((id) => join(root, id, "node_modules", `declared-${id}`)),
  });

const reasons = (report: ReturnType<typeof run>): RetainedReason[] =>
  report.retained.map((item) => item.reason);

function files(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) =>
      entry.isDirectory()
        ? files(join(directory, entry.name), `${prefix}${entry.name}/`)
        : [`${prefix}${entry.name}`],
    )
    .sort();
}

/** What a consumer in `id` sees when it loads the dependency in each way Node allows. */
function consume(root: string, id: string, name = "leaf"): string {
  const consumer = join(root, id, "consumer.mjs");
  writeFileSync(
    consumer,
    `import { createRequire } from "node:module";
import def, { value } from ${JSON.stringify(name)};
import { sub } from ${JSON.stringify(`${name}/sub`)};
import * as namespace from ${JSON.stringify(name)};
import data from ${JSON.stringify(`${name}/data`)} with { type: "json" };
const require = createRequire(import.meta.url);
const cjs = require(${JSON.stringify(name)});
const cjsSub = require(${JSON.stringify(`${name}/sub`)});
const attempt = (specifier) => { try { require(specifier); return "loaded"; } catch (error) { return error.code; } };
let escape;
try { await import(${JSON.stringify(`${name}/lib/helper.js`)}); escape = "loaded"; } catch (error) { escape = error.code; }
console.log(JSON.stringify({
  value, def, sub, data, names: Object.keys(namespace).sort(),
  cjs: cjs.value, extra: cjs.extra, cjsSub: cjsSub.sub,
  version: require(${JSON.stringify(`${name}/package.json`)}).version,
  deepRequire: attempt(${JSON.stringify(`${name}/lib/helper.cjs`)}), escape,
}));\n`,
  );
  const result = spawnSync(process.execPath, [consumer], { encoding: "utf8" });
  expect(result.stderr).toBe("");
  expect(result.status).toBe(0);
  return result.stdout.trim();
}

describe("dependency sharing across vendored Pi packages", () => {
  it("shares identical copies and keeps Node's resolution exactly", () => {
    const root = vendor({
      a: { dependencies: [leaf()] },
      b: { dependencies: [leaf()] },
      c: { dependencies: [leaf()] },
    });
    const before = ["a", "b", "c"].map((id) => consume(root, id));
    const report = run(root, ["a", "b", "c"]);
    expect(report.shared).toHaveLength(1);
    const [shared] = report.shared;
    expect(shared).toMatchObject({
      name: "leaf",
      version: "1.0.0",
      locations: [
        "pi-packages/a/node_modules/leaf",
        "pi-packages/b/node_modules/leaf",
        "pi-packages/c/node_modules/leaf",
      ],
    });
    // The real files exist once, everything else is stand-ins.
    const directory = join(root, SHARED_DIRECTORY);
    expect(readdirSync(directory)).toHaveLength(1);
    expect(
      files(join(directory, readdirSync(directory)[0] as string)),
    ).toContain("lib/unused.js");
    expect(existsSync(join(root, "a/node_modules/leaf/lib/unused.js"))).toBe(
      false,
    );
    expect(report.filesAfter).toBeLessThan(report.filesBefore);
    const after = ["a", "b", "c"].map((id) => consume(root, id));
    expect(after).toEqual(before);
    // import and require, named and default exports, the exports map's own
    // refusal of a file it does not list, and package.json all behave alike.
    expect(JSON.parse(after[0] as string)).toMatchObject({
      value: "esm:helper",
      cjs: "cjs:helper",
      sub: "sub-esm",
      escape: "ERR_PACKAGE_PATH_NOT_EXPORTED",
      deepRequire: "ERR_PACKAGE_PATH_NOT_EXPORTED",
    });
  });

  it("lists the same payload packages before and after sharing", () => {
    const payload = mkdtempSync(join(tmpdir(), "piship-dedupe-payload-"));
    roots.push(payload);
    const root = vendor(
      { a: { dependencies: [leaf()] }, b: { dependencies: [leaf()] } },
      join(payload, "pi-packages"),
    );
    const documents = () => {
      const sbom = generateSbom({
        payloadDir: payload,
        distribution: { id: "devcode", name: "DevCode", version: "1.0.0" },
        target: "linux-x64",
        created: "2026-01-01T00:00:00Z",
        lockPackages: [],
      });
      const notices = generateNotices(payload, listPayloadPackages(payload));
      return { sbom, notices };
    };
    const documentsBefore = documents();
    const before = listPayloadPackages(payload);
    expect(before.map((item) => item.path)).toContain(
      "pi-packages/a/node_modules/leaf",
    );
    const report = run(root, ["a", "b"]);
    expect(report.shared).toHaveLength(1);
    // The same packages at the same paths, with the same license files.
    expect(listPayloadPackages(payload)).toEqual(before);
    // And the SBOM and the notices (each license text) say the same.
    const documentsAfter = documents();
    expect(documentsAfter.sbom).toEqual(documentsBefore.sbom);
    expect(documentsAfter.notices).toEqual(documentsBefore.notices);
    expect(
      documentsAfter.sbom.packages.filter((item) => item.name === "leaf"),
    ).toHaveLength(2);
    expect(documentsAfter.notices.text.match(/MIT leaf/g)).toHaveLength(2);
    expect(
      before.find((item) => item.path === "pi-packages/b/node_modules/leaf")
        ?.licenseFiles,
    ).toEqual(["pi-packages/b/node_modules/leaf/LICENSE"]);
  });

  it("keeps the named exports of a CommonJS dependency an ES module imports", () => {
    const common = (name: string): Dependency =>
      leaf(
        name,
        "1.0.0",
        {
          type: undefined,
          exports: { ".": "./index.cjs", "./package.json": "./package.json" },
        },
        {
          "index.cjs": `exports.named = "n"; exports.other = function other() { return 1; }; module.exports.third = 3;\n`,
        },
      );
    const root = vendor({
      a: { dependencies: [common("cjsleaf")] },
      b: { dependencies: [common("cjsleaf")] },
      c: { dependencies: [common("cjsleaf")] },
    });
    const consumer = (id: string) => {
      const file = join(root, id, "named.mjs");
      writeFileSync(
        file,
        `import def, { named, other, third } from "cjsleaf";
import * as ns from "cjsleaf";
console.log(JSON.stringify({ named, other: other(), third, def: Object.keys(def).sort(), ns: Object.keys(ns).sort() }));\n`,
      );
      const result = spawnSync(process.execPath, [file], { encoding: "utf8" });
      expect(result.stderr).toBe("");
      return result.stdout.trim();
    };
    const before = consumer("a");
    expect(run(root, ["a", "b", "c"]).shared).toHaveLength(1);
    expect(consumer("a")).toBe(before);
    expect(consumer("c")).toBe(before);
  });

  it("follows a nested package.json that changes a directory's module type", () => {
    const dual = (): Dependency =>
      leaf(
        "dual",
        "1.0.0",
        {
          exports: {
            ".": {
              import: "./dist/esm/index.js",
              require: "./dist/cjs/index.js",
            },
            "./package.json": "./package.json",
          },
        },
        {
          "dist/esm/index.js": `export const kind = "esm"; export default "esm-default";\n`,
          "dist/cjs/package.json": JSON.stringify({ type: "commonjs" }),
          "dist/cjs/index.js": `exports.kind = "cjs"; exports.default = "cjs-default";\n`,
        },
      );
    const root = vendor({
      a: { dependencies: [dual()] },
      b: { dependencies: [dual()] },
      c: { dependencies: [dual()] },
    });
    const consumer = (id: string) => {
      const file = join(root, id, "dual.mjs");
      writeFileSync(
        file,
        `import { createRequire } from "node:module";
import def, { kind } from "dual";
const require = createRequire(import.meta.url);
console.log(JSON.stringify({ def, kind, cjs: require("dual").kind }));\n`,
      );
      const result = spawnSync(process.execPath, [file], { encoding: "utf8" });
      expect(result.stderr).toBe("");
      return result.stdout.trim();
    };
    const before = consumer("b");
    expect(before).toBe('{"def":"esm-default","kind":"esm","cjs":"cjs"}');
    expect(run(root, ["a", "b", "c"]).shared).toHaveLength(1);
    expect(consumer("b")).toBe(before);
  });

  it("shares a copy nested inside several places of one package", () => {
    const root = vendor({ a: { dependencies: [leaf()] } });
    const nested = leaf();
    for (const where of ["x", "y"]) {
      for (const [path, content] of Object.entries(nested.files)) {
        const file = join(
          root,
          "a/node_modules",
          `host-${where}`,
          "node_modules/leaf",
          path,
        );
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, content);
      }
      writeFileSync(
        join(root, "a/node_modules", `host-${where}`, "package.json"),
        JSON.stringify({ name: `host-${where}`, version: "1.0.0" }),
      );
    }
    const lock = JSON.parse(
      readFileSync(join(root, "a/package-lock.json"), "utf8"),
    );
    for (const where of ["x", "y"])
      lock.packages[`node_modules/host-${where}/node_modules/leaf`] = {
        version: "1.0.0",
        integrity: "sha512-leaf-1.0.0",
      };
    writeFileSync(join(root, "a/package-lock.json"), JSON.stringify(lock));
    const report = run(root, ["a"]);
    expect(report.shared[0]?.locations).toHaveLength(3);
  });

  describe("keeps package-local copies", () => {
    const pair = (a: Dependency, b: Dependency) =>
      vendor({ a: { dependencies: [a] }, b: { dependencies: [b] } });
    const kept = (a: Dependency, b: Dependency) => {
      const root = pair(a, b);
      const before = files(root);
      const report = run(root, ["a", "b"]);
      expect(report.shared).toEqual([]);
      expect(files(root)).toEqual(before);
      return reasons(report);
    };

    it("when the versions differ", () => {
      const root = pair(leaf("leaf", "1.0.0"), leaf("leaf", "1.0.1"));
      const report = run(root, ["a", "b"]);
      expect(report.shared).toEqual([]);
      expect(reasons(report)).toEqual(["single-copy", "single-copy"]);
      expect(existsSync(join(root, "a/node_modules/leaf/lib/unused.js"))).toBe(
        true,
      );
    });

    it("when the content differs at the same version", () => {
      expect(
        kept(
          leaf(),
          leaf(
            "leaf",
            "1.0.0",
            {},
            { "lib/helper.js": "export const helper = 'patched';\n" },
          ),
        ),
      ).toEqual(["copies-differ", "copies-differ"]);
    });

    it("when only an executable bit differs", () => {
      // Content is equal, but the registry says otherwise: integrity differs.
      expect(
        kept(leaf(), { ...leaf(), lock: { integrity: "sha512-other" } }),
      ).toEqual(["copies-differ", "copies-differ"]);
    });

    it("when a copy has no registry integrity", () => {
      expect(
        kept(leaf(), { ...leaf(), lock: { integrity: undefined } }),
      ).toContain("no-integrity");
    });

    it("when the package has dependencies of its own", () => {
      expect(
        kept(
          leaf("leaf", "1.0.0", { dependencies: { other: "1.0.0" } }),
          leaf("leaf", "1.0.0", { dependencies: { other: "1.0.0" } }),
        ),
      ).toEqual(["has-dependencies"]);
    });

    it("when it needs a peer", () => {
      expect(
        kept(
          leaf("leaf", "1.0.0", { peerDependencies: { other: "1.0.0" } }),
          leaf("leaf", "1.0.0", { peerDependencies: { other: "1.0.0" } }),
        ),
      ).toEqual(["has-dependencies"]);
    });

    it("when it imports a package it does not declare", () => {
      const phantom = leaf(
        "leaf",
        "1.0.0",
        {},
        { "lib/helper.js": 'import "ghost";\nexport const helper = 1;\n' },
      );
      expect(kept(phantom, phantom)).toEqual(["imports-other-packages"]);
    });

    it("when there is no exports map", () => {
      const open = (extra: Record<string, unknown> = {}) => ({
        name: "open",
        version: "1.0.0",
        files: {
          "package.json": JSON.stringify({
            name: "open",
            version: "1.0.0",
            main: "index.js",
            ...extra,
          }),
          "index.js": "module.exports = 1;\n",
          "deep.js": "module.exports = 2;\n",
        },
      });
      expect(kept(open(), open())).toEqual(["no-exports"]);
    });

    it("when it carries native code or WebAssembly", () => {
      const native = leaf("leaf", "1.0.0", {}, { "build/addon.node": "ELF" });
      expect(kept(native, native)).toEqual(["native-or-wasm"]);
      const wasm = leaf("leaf", "1.0.0", {}, { "lib/engine.wasm": "wasm" });
      expect(kept(wasm, wasm)).toEqual(["native-or-wasm"]);
    });

    it("when it has an install script or a binding.gyp", () => {
      const scripted = leaf("leaf", "1.0.0", {
        scripts: { postinstall: "node setup.js" },
      });
      expect(kept(scripted, scripted)).toEqual(["install-script"]);
      const gyp = leaf("leaf", "1.0.0", {}, { "binding.gyp": "{}" });
      expect(kept(gyp, gyp)).toEqual(["install-script"]);
    });

    it("when it is specific to a platform", () => {
      const darwin = leaf("leaf", "1.0.0", { os: ["darwin"] });
      expect(kept(darwin, darwin)).toEqual(["platform-specific"]);
      const optional = { ...leaf(), lock: { cpu: ["arm64"], optional: true } };
      expect(kept(optional, optional)).toEqual(["platform-specific"]);
    });

    it("when it has executables", () => {
      const cli = leaf("leaf", "1.0.0", { bin: { leaf: "./bin.js" } });
      expect(kept(cli, cli)).toEqual(["bin"]);
    });

    it("when its code finds modules or files at run time", () => {
      for (const body of [
        'import { createRequire } from "node:module";\nexport const helper = createRequire(import.meta.url);\n',
        "export const helper = require.resolve('x');\n",
        "export const helper = (name) => import(name);\n",
        "export const helper = (name) => require(name);\n",
        "export const helper = process.mainModule;\n",
        "export const helper = 'node_modules';\n",
      ]) {
        const searching = leaf("leaf", "1.0.0", {}, { "lib/helper.js": body });
        expect(kept(searching, searching)).toEqual(["runtime-discovery"]);
      }
    });

    it("does not read a comment as code", () => {
      const root = pair(
        leaf(
          "leaf",
          "1.0.0",
          {},
          {
            "lib/helper.js":
              "// a circular require(name) may not have settled\nexport const helper = 1;\n",
          },
        ),
        leaf(
          "leaf",
          "1.0.0",
          {},
          {
            "lib/helper.js":
              "// a circular require(name) may not have settled\nexport const helper = 1;\n",
          },
        ),
      );
      expect(run(root, ["a", "b"]).shared).toHaveLength(1);
    });

    it("when its exports reach a file it cannot stand in for", () => {
      const typescript = leaf(
        "leaf",
        "1.0.0",
        {
          exports: { ".": { import: "./index.ts" } },
        },
        { "index.ts": "export const x = 1;\n" },
      );
      expect(kept(typescript, typescript)).toEqual(["unsupported-exports"]);
      const folder = leaf("leaf", "1.0.0", {
        exports: { "./features/": "./lib/" },
      });
      expect(kept(folder, folder)).toEqual(["unsupported-exports"]);
    });

    it("when a file does not parse", () => {
      const broken = leaf(
        "leaf",
        "1.0.0",
        {},
        { "lib/broken.js": "export const = ;\n" },
      );
      expect(kept(broken, broken)).toEqual(["unparsable"]);
    });

    it("when a path would not survive an ES module specifier", () => {
      const odd = leaf("leaf", "1.0.0", {}, { "lib/a#b.js": "export {};\n" });
      expect(kept(odd, odd)).toEqual(["unsafe-path"]);
    });

    it("when it has its own node_modules", () => {
      const nested = leaf(
        "leaf",
        "1.0.0",
        {},
        { "node_modules/inner/index.js": "" },
      );
      expect(kept(nested, nested)).toEqual([
        "nested-node-modules",
        "nested-node-modules",
      ]);
    });

    it("when sharing would save nothing", () => {
      const tiny = {
        name: "tiny",
        version: "1.0.0",
        files: {
          "package.json": JSON.stringify({
            name: "tiny",
            version: "1.0.0",
            exports: "./index.cjs",
          }),
          "index.cjs": "module.exports = 1;\n",
        },
      };
      expect(kept(tiny, tiny)).toEqual(["no-saving"]);
    });

    it("never shares the declared package, whatever it holds", () => {
      const root = vendor({
        a: { dependencies: [] },
        b: { dependencies: [] },
      });
      for (const id of ["a", "b"]) {
        const declared = join(root, id, "node_modules", `declared-${id}`);
        writeFileSync(
          join(declared, "package.json"),
          JSON.stringify({
            name: "same",
            version: "1.0.0",
            exports: "./extension.js",
          }),
        );
      }
      expect(run(root, ["a", "b"]).shared).toEqual([]);
    });
  });

  it("shares what is identical and keeps what differs, in one tree", () => {
    const root = vendor({
      a: { dependencies: [leaf("x", "1.0.0"), leaf("y", "1.0.0")] },
      b: { dependencies: [leaf("x", "1.0.0"), leaf("y", "2.0.0")] },
    });
    const report = run(root, ["a", "b"]);
    expect(report.shared.map((item) => item.name)).toEqual(["x"]);
    expect(existsSync(join(root, "a/node_modules/y/lib/unused.js"))).toBe(true);
    expect(existsSync(join(root, "b/node_modules/y/lib/unused.js"))).toBe(true);
    expect(consume(root, "a", "x")).toBe(consume(root, "b", "x"));
  });

  it("keeps copies of one content apart when their registry integrity differs", () => {
    const other = { ...leaf(), lock: { integrity: "sha512-mirror" } };
    const root = vendor({
      a: { dependencies: [leaf()] },
      b: { dependencies: [leaf()] },
      c: { dependencies: [other] },
      d: { dependencies: [other] },
    });
    const report = run(root, ["a", "b", "c", "d"]);
    // Two sets of two: each is shared on its own, under its own directory, and
    // no place is served from the other set's files.
    expect(report.shared.map((item) => item.locations)).toEqual(
      expect.arrayContaining([
        ["pi-packages/a/node_modules/leaf", "pi-packages/b/node_modules/leaf"],
        ["pi-packages/c/node_modules/leaf", "pi-packages/d/node_modules/leaf"],
      ]),
    );
    expect(report.shared).toHaveLength(2);
    expect(new Set(report.shared.map((item) => item.directory)).size).toBe(2);
    expect(readdirSync(join(root, SHARED_DIRECTORY))).toHaveLength(2);
    expect(
      new Set(["a", "b", "c", "d"].map((id) => consume(root, id))).size,
    ).toBe(1);
  });

  it("keeps a set package-local when its shared directory name is already taken", () => {
    const layout = {
      a: { dependencies: [leaf()] },
      b: { dependencies: [leaf()] },
    };
    // The name a set gets is a function of its bytes and integrity; learn it.
    const [taken] = run(vendor(layout), ["a", "b"]).shared;
    const root = vendor(layout);
    const stranger = join(
      root,
      taken?.directory.replace("pi-packages/", "") as string,
    );
    mkdirSync(stranger, { recursive: true });
    writeFileSync(join(stranger, "other.js"), "export const other = 1;\n");
    const before = files(root);
    const report = run(root, ["a", "b"]);
    expect(report.shared).toEqual([]);
    expect(report.retained).toEqual([
      expect.objectContaining({
        name: "leaf",
        reason: "copies-differ",
        detail: expect.stringContaining("another set's"),
      }),
    ]);
    // Nothing moved, nothing mixed into the other directory.
    expect(files(root)).toEqual(before);
    expect(files(stranger)).toEqual(["other.js"]);
    expect(consume(root, "a")).toBe(consume(root, "b"));
  });

  it("never makes a file's path longer than its package-local path by more than the shared directory's own name", () => {
    // Windows stops at 260 characters. A shared file lives at
    // `.shared/<name>@<version>-<12 hex>/<file>`: one directory level up from
    // `<id>/node_modules/<name>/<file>`, with the version and a short digest in
    // its name. That costs at most `.shared/` and the version over any place
    // (an id is at least one character, and `node_modules/` stays out of it).
    // A longer digest in the name, or a deeper directory, breaks the budget.
    const scoped = leaf("@acme/long-package-name-for-the-budget", "12.34.56");
    const root = vendor({
      "a-package": { dependencies: [scoped] },
      "another-package": { dependencies: [scoped] },
    });
    const report = run(root, ["a-package", "another-package"]);
    expect(report.shared).toHaveLength(1);
    const [shared] = report.shared;
    const place = shared?.locations[0] as string;
    expect(shared?.directory).toMatch(
      /^pi-packages\/\.shared\/@acme\+long-package-name-for-the-budget@12\.34\.56-[0-9a-f]{12}$/,
    );
    const real = join(root, ...(shared?.directory ?? "").split("/").slice(1));
    const paths = files(real);
    expect(paths.length).toBeGreaterThan(10);
    for (const file of paths)
      expect(`${shared?.directory}/${file}`.length).toBeLessThanOrEqual(
        `${place}/${file}`.length + ".shared/".length + "12.34.56".length,
      );
  });

  it("produces the same tree for the same input", () => {
    const build = () => {
      const root = vendor({
        a: { dependencies: [leaf()] },
        b: { dependencies: [leaf()] },
      });
      run(root, ["a", "b"]);
      return files(root).map((file) => [
        relative(root, join(root, file)),
        readFileSync(join(root, file), "utf8"),
      ]);
    };
    expect(build()).toEqual(build());
  });
});
