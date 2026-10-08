// Bundling the dependency closure of a Pi package, where that is safe.
//
// A Pi package loads through its extension files, which the lock pins by
// SHA-256 and every launch checks. Those files stay exactly as they are. What
// they import is replaced: each file an extension imports directly becomes a
// small module of the same name and the same exports that forwards to shared
// chunks, and the modules those pull in (the rest of the closure) are bundled
// into the chunks and removed. The extension, its resolution, and its module
// identities are unchanged; the thousands of files below it are not on disk.
//
// A closure is bundle-safe only when nothing in it needs its files to exist:
// pure JavaScript modules, statically imported, resolvable in the vendored
// tree, with no native addon, no WebAssembly, no install script, no dynamic
// import or require, nothing that locates its own files or discovers modules
// at run time, no CommonJS or non-JavaScript module an extension imports
// directly, and no other file left behind that imports a bundled module. Any
// closure that fails a test keeps its vendored files and says which test.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import {
  type BuildOutcome,
  type EsbuildApi,
  runtimeDiscovery,
  type ScanResult,
  scanModulesMany,
} from "./module-scan.js";
import { packageError } from "./refs.js";
import type { LockedPackageResource } from "./types.js";

/** Where the shared chunks of a package's bundled closure are written. */
export const CLOSURE_DIRECTORY = ".piship-closure";

export type FallbackReason =
  | "native-addon"
  | "wasm-asset"
  | "install-script"
  | "commonjs-entry"
  | "commonjs-import"
  | "dynamic-import"
  | "runtime-discovery"
  | "self-location"
  | "unresolved-import"
  | "non-javascript-module"
  | "typescript-closure"
  | "entry-imports-entry"
  | "unparsable"
  | "left-behind-code"
  | "nothing-to-bundle";

export interface FallbackFinding {
  readonly reason: FallbackReason;
  /** The file, or `file: specifier`, that decided it. */
  readonly detail?: string;
}

export interface ClosurePlan {
  /** Extension files that stay, relative to the package's npm root. */
  readonly entries: readonly string[];
  /** Files an extension imports directly: rewritten as forwarding modules. */
  readonly replaced: readonly string[];
  /** The rest of the closure: bundled into the chunks and removed. */
  readonly inlined: readonly string[];
}

export type ClosureAnalysis =
  | { readonly safe: true; readonly plan: ClosurePlan }
  | { readonly safe: false; readonly findings: readonly FallbackFinding[] };

export interface ClosureOptions {
  /** `pi-packages/<id>`: the package's npm root, which holds its closure. */
  readonly root: string;
  /** The package's own directory under `root`, `/`-separated: `node_modules/<name>` or `package`. */
  readonly packagePath: string;
  readonly resources: readonly LockedPackageResource[];
  readonly esbuild: EsbuildApi;
}

const posixPath = (path: string) => path.split(sep).join("/");
const JAVASCRIPT = /\.(?:js|mjs|cjs)$/;
const TYPESCRIPT = /\.(?:ts|mts|cts)$/;
const SELF_LOCATION =
  /\b__dirname\b|\b__filename\b|\bimport\s*\.\s*meta\s*\.\s*(?:url|dirname|filename)\b/;
// The part of SELF_LOCATION an ES module does not have: `import.meta` works in
// a module read natively, `__dirname` does not.
const CJS_LOCATION = /\b__dirname\b|\b__filename\b/;

function listTree(root: string): string[] {
  const files: string[] = [];
  const visit = (directory: string, prefix: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory())
        visit(join(directory, entry.name), `${prefix}${entry.name}/`);
      else files.push(`${prefix}${entry.name}`);
    }
  };
  visit(root, "");
  return files.sort();
}

interface Graph {
  readonly inputs: Record<
    string,
    {
      readonly format?: string;
      readonly imports: readonly {
        readonly path: string;
        readonly kind: string;
        readonly external?: boolean;
        /** The specifier as written, when esbuild resolved it to another path. */
        readonly original?: string;
      }[];
    }
  >;
}

/** esbuild's bundling options for this closure: the host's modules stay imports. */
function bundleOptions(root: string): Record<string, unknown> {
  return {
    absWorkingDir: root,
    bundle: true,
    write: false,
    metafile: true,
    format: "esm",
    platform: "node",
    logLevel: "silent",
    // Nothing is rewritten that does not have to be: no shaking, no renaming of
    // what a module exports, names kept as written.
    treeShaking: false,
    keepNames: true,
    external: ["@earendil-works/pi-*", "typebox", "typebox/*"],
    loader: { ".json": "json" },
  };
}

interface State {
  readonly options: ClosureOptions;
  readonly root: string;
  readonly findings: FallbackFinding[];
  readonly tree: readonly string[];
  readonly entryPaths: readonly string[];
  /** Set once the answer is known. */
  result?: ClosureAnalysis;
  reachable: string[];
  replaced: Set<string>;
  inlined: string[];
  /** The files left behind that nothing reaches, to be read for what they import. */
  importers: string[];
}

const refused = (state: State): ClosureAnalysis => ({
  safe: false,
  findings: dedupeFindings(state.findings),
});

/** The findings that need nothing but the tree: native code, WebAssembly, install scripts, no entries. */
function prepare(options: ClosureOptions): State {
  const root = resolve(options.root);
  const tree = listTree(root);
  const entryPaths = options.resources
    .filter((resource) => resource.kind === "extensions")
    .map((resource) => `${options.packagePath}/${resource.path}`);
  const state: State = {
    options,
    root,
    findings: [],
    tree,
    entryPaths,
    reachable: [],
    replaced: new Set(),
    inlined: [],
    importers: [],
  };
  const deny = (reason: FallbackReason, detail?: string) =>
    state.findings.push({ reason, ...(detail ? { detail } : {}) });
  for (const file of tree) {
    if (/\.node$/i.test(file) || file.endsWith("binding.gyp"))
      deny("native-addon", file);
    else if (/\.wasm$/i.test(file)) deny("wasm-asset", file);
    else if (posix.basename(file) === "package.json") {
      try {
        const scripts =
          (
            JSON.parse(
              readFileSync(join(root, ...file.split("/")), "utf8"),
            ) as { scripts?: Record<string, unknown> }
          ).scripts ?? {};
        if (
          ["preinstall", "install", "postinstall"].some(
            (name) => name in scripts,
          )
        )
          deny("install-script", file);
      } catch {
        // A package.json that is not JSON is not read by Node either.
      }
    }
  }
  if (!state.findings.length) {
    if (!entryPaths.length || entryPaths.some((entry) => !tree.includes(entry)))
      deny("nothing-to-bundle", "no extension files");
    for (const entry of entryPaths)
      if (!JAVASCRIPT.test(entry) && !TYPESCRIPT.test(entry))
        deny("non-javascript-module", entry);
  }
  if (state.findings.length) state.result = refused(state);
  return state;
}

const graphBuild = (
  root: string,
  entryPaths: readonly string[],
): Record<string, unknown> => ({
  ...bundleOptions(root),
  entryPoints: Object.fromEntries(
    entryPaths.map((entry) => [entry, join(root, ...entry.split("/"))]),
  ),
  outdir: join(root, CLOSURE_DIRECTORY, ".scan"),
});

/**
 * The graph the pretranspile reads: the package's own relative imports only.
 * Dependencies stay external (a `.node` file or an odd loader below
 * `node_modules` must not fail the scan), and no tsconfig above the package
 * is read, as Pi's loader reads none.
 */
const transpileGraphBuild = (
  root: string,
  entryPaths: readonly string[],
): Record<string, unknown> => ({
  ...graphBuild(root, entryPaths),
  packages: "external",
  tsconfigRaw: {},
});

/**
 * A metafile path as a `/`-separated path relative to `root`, whatever the
 * platform wrote: backslashes become `/`, and an absolute path under `root`
 * (drive letters compared without case) loses the root.
 */
export function closureKey(root: string, path: string): string {
  const slashed = (value: string) => value.replace(/\\/g, "/");
  let base = slashed(root);
  while (base.endsWith("/")) base = base.slice(0, -1);
  let key = slashed(path);
  const windows = /^[A-Za-z]:(?:\/|$)/.test(base) || base.startsWith("//");
  const head = key.slice(0, base.length + 1);
  const prefix = `${base}/`;
  if (windows ? head.toLowerCase() === prefix.toLowerCase() : head === prefix)
    key = key.slice(prefix.length);
  return key.replace(/^(?:\.\/)+/, "");
}

/** What the import graph says: what is replaced, what is bundled away, what is refused. */
function readGraph(state: State, outcome: BuildOutcome): void {
  const deny = (reason: FallbackReason, detail?: string) =>
    state.findings.push({ reason, ...(detail ? { detail } : {}) });
  if ("failure" in outcome) {
    const message =
      outcome.failure.errors[0]?.text ??
      outcome.failure.message.split("\n")[0] ??
      "";
    deny(
      /resolve/i.test(message) ? "unresolved-import" : "unparsable",
      message,
    );
    state.result = refused(state);
    return;
  }
  const graph = outcome.build.metafile as Graph;
  const key = (path: string) => posixPath(path);
  const entrySet = new Set(state.entryPaths);
  state.reachable = Object.keys(graph.inputs).map(key);
  for (const entry of state.entryPaths) {
    const input = graph.inputs[entry];
    if (!input) continue;
    for (const item of input.imports) {
      if (item.external) continue;
      const target = key(item.path);
      if (item.kind === "require-call" || input.format === "cjs")
        deny("commonjs-entry", entry);
      else if (entrySet.has(target))
        deny("entry-imports-entry", `${entry}: ${target}`);
      else if (item.kind === "dynamic-import")
        deny("dynamic-import", `${entry}: ${target}`);
      else state.replaced.add(target);
    }
  }
  state.inlined = state.reachable.filter(
    (file) => !entrySet.has(file) && !state.replaced.has(file),
  );
  for (const file of state.replaced) {
    if (!JAVASCRIPT.test(file))
      deny(
        TYPESCRIPT.test(file) ? "typescript-closure" : "non-javascript-module",
        file,
      );
    else if (graph.inputs[file]?.format === "cjs")
      deny("commonjs-import", file);
  }
  for (const file of state.inlined)
    if (!JAVASCRIPT.test(file))
      deny(
        TYPESCRIPT.test(file) ? "typescript-closure" : "non-javascript-module",
        file,
      );
  // A refusal the graph already holds needs no scan of the closure: reading
  // every module for more reasons costs a parse of all of them.
  if (state.findings.length) state.result = refused(state);
}

/** Every module the closure runs, the extensions included, is read for what locates files or code at run time. */
function readScan(state: State, scan: ScanResult): void {
  const deny = (reason: FallbackReason, detail?: string) =>
    state.findings.push({ reason, ...(detail ? { detail } : {}) });
  for (const [file, message] of scan.failed)
    deny("unparsable", `${file}: ${message}`);
  for (const [file, info] of scan.modules) {
    if (SELF_LOCATION.test(info.source)) deny("self-location", file);
    const found = runtimeDiscovery(info.source);
    if (found === "computed require or import" || found === "indirect require")
      deny("dynamic-import", `${file}: ${found}`);
    else if (found) deny("runtime-discovery", `${file}: ${found}`);
    for (const item of info.imports)
      if (item.kind === "dynamic" && !item.specifier.startsWith("node:"))
        deny("dynamic-import", `${file}: ${item.specifier}`);
  }
  if (!state.replaced.size && !state.inlined.length)
    deny("nothing-to-bundle", "the extensions import nothing from the package");
  if (state.findings.length) {
    state.result = refused(state);
    return;
  }
  // Code left behind must not import what is bundled away: a script a skill
  // runs, a bin file, a module only a computed path reaches.
  const gone = new Set(state.inlined);
  const entrySet = new Set(state.entryPaths);
  const reached = new Set(state.reachable);
  state.importers = state.tree.filter(
    (file) =>
      JAVASCRIPT.test(file) &&
      !gone.has(file) &&
      !state.replaced.has(file) &&
      !entrySet.has(file) &&
      !reached.has(file),
  );
}

/**
 * Package names are looked up as Node does; a package that lost any file
 * counts as lost.
 */
function readLeftBehind(state: State, left: ScanResult): void {
  const deny = (reason: FallbackReason, detail?: string) =>
    state.findings.push({ reason, ...(detail ? { detail } : {}) });
  const gone = new Set(state.inlined);
  const lostPackages = new Set(
    state.inlined.flatMap((file) => {
      const at = file.lastIndexOf("node_modules/");
      if (at === -1) return [];
      const rest = file.slice(at + "node_modules/".length).split("/");
      const name = rest[0]?.startsWith("@")
        ? rest.slice(0, 2)
        : rest.slice(0, 1);
      return [`${file.slice(0, at)}node_modules/${name.join("/")}`];
    }),
  );
  const present = new Set(state.tree);
  for (const [file, info] of left.modules)
    for (const item of info.imports) {
      if (item.specifier.startsWith(".")) {
        const target = posix.normalize(
          posix.join(posix.dirname(file), item.specifier),
        );
        if (
          [target, `${target}.js`, `${target}.mjs`, `${target}/index.js`].some(
            (name) => gone.has(name),
          )
        )
          deny("left-behind-code", `${file}: ${item.specifier}`);
        continue;
      }
      const parts = item.specifier.split("/");
      const name = parts
        .slice(0, item.specifier.startsWith("@") ? 2 : 1)
        .join("/");
      for (
        let directory = posix.dirname(file);
        ;
        directory = posix.dirname(directory)
      ) {
        const base = directory === "." ? "" : `${directory}/`;
        if (present.has(`${base}node_modules/${name}/package.json`)) {
          if (lostPackages.has(`${base}node_modules/${name}`))
            deny("left-behind-code", `${file}: ${item.specifier}`);
          break;
        }
        if (directory === ".") break;
      }
    }
}

/**
 * Whether the closure of each package can be bundled, and what bundling would
 * do. Reads the trees; writes nothing. Every package's builds of one kind run
 * together in one esbuild process.
 */
export function analyzeClosures(
  list: readonly ClosureOptions[],
  esbuild: EsbuildApi,
): ClosureAnalysis[] {
  const states = list.map(prepare);
  const live = () => states.filter((state) => !state.result);
  const graphing = live();
  const graphs = esbuild.buildAll(
    graphing.map((state) => graphBuild(state.root, state.entryPaths)),
  );
  graphing.forEach((state, index) => {
    readGraph(state, graphs[index] as BuildOutcome);
  });
  const scanning = live();
  const scans = scanModulesMany(
    esbuild,
    scanning.map((state) => ({
      root: state.root,
      files: state.reachable.filter(
        (file) => JAVASCRIPT.test(file) || TYPESCRIPT.test(file),
      ),
    })),
  );
  scanning.forEach((state, index) => {
    readScan(state, scans[index] as ScanResult);
  });
  const leftBehind = live();
  const lefts = scanModulesMany(
    esbuild,
    leftBehind.map((state) => ({
      root: state.root,
      files: state.importers,
    })),
  );
  leftBehind.forEach((state, index) => {
    readLeftBehind(state, lefts[index] as ScanResult);
    state.result = state.findings.length
      ? refused(state)
      : {
          safe: true,
          plan: {
            entries: [...state.entryPaths],
            replaced: [...state.replaced].sort(),
            inlined: [...state.inlined].sort(),
          },
        };
  });
  return states.map((state) => state.result as ClosureAnalysis);
}

/** `analyzeClosures` for one package. */
export function analyzeClosure(options: ClosureOptions): ClosureAnalysis {
  return analyzeClosures([options], options.esbuild)[0] as ClosureAnalysis;
}

function dedupeFindings(
  findings: readonly FallbackFinding[],
): FallbackFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const id = `${finding.reason}\0${finding.detail ?? ""}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

export interface ClosureResult {
  readonly replaced: number;
  readonly inlined: number;
  readonly chunks: number;
}

/**
 * Apply a safe plan: bundle the closure below the extensions into shared
 * chunks, rewrite the files the extensions import as forwarding modules, and
 * remove the files that were bundled.
 */
export function bundleClosure(
  options: ClosureOptions,
  plan: ClosurePlan,
): ClosureResult {
  const { esbuild } = options;
  const root = resolve(options.root);
  const built = esbuild.buildSync({
    ...bundleOptions(root),
    // Named by path, so entries that differ only in extension stay apart.
    entryPoints: Object.fromEntries(
      plan.replaced.map((file) => [file, join(root, ...file.split("/"))]),
    ),
    outdir: join(root, ".piship-out"),
    splitting: true,
    chunkNames: `${CLOSURE_DIRECTORY}/[name]-[hash]`,
    outExtension: { ".js": ".mjs" },
  }) as unknown as {
    readonly outputFiles: readonly {
      readonly path: string;
      readonly text: string;
    }[];
    readonly metafile: {
      readonly outputs: Record<string, { readonly entryPoint?: string }>;
    };
  };
  const entryOf = new Map<string, string>();
  for (const [path, output] of Object.entries(built.metafile.outputs))
    if (output.entryPoint)
      entryOf.set(resolve(root, path), posixPath(output.entryPoint));
  const outRoot = resolve(root, ".piship-out");
  let chunks = 0;
  const writes: { path: string; text: string }[] = [];
  for (const file of built.outputFiles) {
    const absolute = resolve(file.path);
    const entry = entryOf.get(absolute);
    if (entry)
      writes.push({ path: join(root, ...entry.split("/")), text: file.text });
    else {
      chunks += 1;
      writes.push({
        path: join(root, relative(outRoot, absolute)),
        text: file.text,
      });
    }
  }
  for (const write of writes) {
    mkdirSync(dirname(write.path), { recursive: true });
    writeFileSync(write.path, write.text);
  }
  for (const file of plan.inlined)
    rmSync(join(root, ...file.split("/")), { force: true });
  // Directories the removal emptied do not stay: an extracted payload has none.
  const prune = (directory: string): boolean => {
    let empty = true;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && prune(join(directory, entry.name))) continue;
      empty = false;
    }
    if (empty && resolve(directory) !== resolve(root)) {
      rmdirSync(directory);
      return true;
    }
    return false;
  };
  prune(root);
  return {
    replaced: plan.replaced.length,
    inlined: plan.inlined.length,
    chunks,
  };
}

/** What `pretranspileClosures` did for one package, `/`-separated from its root. */
export interface TranspileResult {
  /** The `.js` (or `.mjs`) files written beside their TypeScript sources. */
  readonly written: readonly string[];
  /** Closure modules left as they are because a JavaScript sibling exists. */
  readonly kept: readonly string[];
  /**
   * What works under Pi's loader but not when Node imports the written files
   * itself (docs/manifest.md, "pretranspile"). The build goes on: the files
   * are written for the loader.
   */
  readonly warnings: readonly string[];
}

const TRANSPILED: Readonly<Record<string, string>> = {
  ".ts": ".js",
  ".mts": ".mjs",
};

/** The output a TypeScript module gets, or undefined when it gets none. */
function transpiledName(file: string): string | undefined {
  if (/\.d\.m?ts$/.test(file)) return undefined;
  const extension = /\.m?ts$/.exec(file)?.[0];
  return extension
    ? file.slice(0, -extension.length) + TRANSPILED[extension]
    : undefined;
}

/**
 * Writes each TypeScript module of a package's own files that its extensions
 * import (directly or not) as JavaScript beside it: `lib/x.ts` gets `lib/x.js`,
 * so an import written `./x.js` names a file that exists. One file per module,
 * in place, so `import.meta` and relative paths mean what they meant; type-only
 * imports are erased, JSON stays JSON, and nothing else is rewritten. The
 * extension files themselves are never touched, a module whose JavaScript
 * sibling already exists is kept, and a module that needs CommonJS (`export =`,
 * a `require` of a closure module) or does not parse, or whose output Node
 * cannot read as an ES module (decorators), fails the build: its ESM
 * output would not be the module it was.
 *
 * Deterministic for a given esbuild: no source maps, a fixed target, no
 * tsconfig read from the package (Pi's loader reads none either).
 */
export function pretranspileClosures(
  list: readonly (ClosureOptions & { readonly id: string })[],
  esbuild: EsbuildApi,
): TranspileResult[] {
  // Real paths, so a symlinked or 8.3-style root compares like the metafile.
  const roots = list.map((options) => realpathSync(resolve(options.root)));
  const entries = list.map((options) =>
    options.resources
      .filter((resource) => resource.kind === "extensions")
      .map((resource) => `${options.packagePath}/${resource.path}`),
  );
  const graphs = esbuild.buildAll(
    list.map((_, index) =>
      transpileGraphBuild(roots[index] as string, entries[index] as string[]),
    ),
  );
  const plans = list.map((options, index) => {
    const outcome = graphs[index] as BuildOutcome;
    if ("failure" in outcome)
      throw packageError(
        "CONFIG_INVALID",
        options.id,
        `its TypeScript closure cannot be read for pretranspile: ${outcome.failure.errors[0]?.text ?? outcome.failure.message.split("\n")[0]}`,
        "Fix the import, or remove pretranspile from the package",
      );
    const graph = outcome.build.metafile as Graph;
    const root = roots[index] as string;
    const key = (path: string) => closureKey(root, path);
    const inputs = new Map(
      Object.entries(graph.inputs).map(([file, input]) => [key(file), input]),
    );
    const own = `${options.packagePath}/`;
    const imported = new Set<string>();
    // How each module is named by the imports that reach it.
    const spellings = new Map<string, Set<string>>();
    for (const [file, input] of inputs)
      for (const item of input.imports) {
        if (item.external) continue;
        const target = key(item.path);
        if (item.kind === "require-call" && transpiledName(target))
          throw unsupported(options.id, `${file} requires ${target}`);
        imported.add(target);
        if (item.original && /^\.\.?\//.test(item.original)) {
          const kind = /\.m?js$/.test(item.original)
            ? "x.js"
            : /\.m?ts$/.test(item.original)
              ? "x.ts"
              : "x";
          spellings.set(target, (spellings.get(target) ?? new Set()).add(kind));
        }
      }
    const files = [...imported]
      .filter(
        (file) =>
          file.startsWith(own) &&
          !file.slice(own.length).split("/").includes("node_modules") &&
          transpiledName(file),
      )
      .sort();
    for (const file of files) {
      if (inputs.get(file)?.format === "cjs")
        throw unsupported(options.id, `${file} is a CommonJS module`);
      const usesRequire = inputs
        .get(file)
        ?.imports.some((item) => item.kind === "require-call");
      if (usesRequire) throw unsupported(options.id, `${file} calls require`);
    }
    const exists = (file: string) => existsSync(join(root, ...file.split("/")));
    return {
      transpile: files.filter(
        (file) => !exists(transpiledName(file) as string),
      ),
      kept: files.filter((file) => exists(transpiledName(file) as string)),
      split: files.filter((file) => (spellings.get(file)?.size ?? 0) > 1),
    };
  });
  const builds = plans.flatMap((plan, index) =>
    Object.keys(TRANSPILED).flatMap((extension) => {
      const files = plan.transpile.filter((file) => file.endsWith(extension));
      if (!files.length) return [];
      const root = roots[index] as string;
      return [
        {
          index,
          options: {
            absWorkingDir: root,
            entryPoints: files.map((file) => join(root, ...file.split("/"))),
            outbase: root,
            outdir: root,
            outExtension: { ".js": TRANSPILED[extension] },
            write: false,
            bundle: false,
            format: "esm",
            platform: "node",
            target: "esnext",
            sourcemap: false,
            metafile: true,
            logLevel: "silent",
            tsconfigRaw: {},
          } as Record<string, unknown>,
        },
      ];
    }),
  );
  const outcomes = builds.length
    ? esbuild.buildAll(builds.map((build) => build.options))
    : [];
  const written: string[][] = list.map(() => []);
  const outputs: { path: string; text: string; index: number }[] = [];
  // What each written module exports, by absolute path.
  const exported = new Map<string, ReadonlySet<string>>();
  builds.forEach((build, position) => {
    const outcome = outcomes[position] as BuildOutcome;
    const id = (list[build.index] as { id: string }).id;
    if ("failure" in outcome)
      throw unsupported(
        id,
        outcome.failure.errors[0]?.text ??
          outcome.failure.message.split("\n")[0] ??
          "esbuild failed",
      );
    for (const [path, output] of Object.entries(
      outcome.build.metafile?.outputs ?? {},
    ))
      exported.set(
        resolve(roots[build.index] as string, path),
        new Set(output.exports),
      );
    for (const file of outcome.build.outputFiles ?? []) {
      outputs.push({ path: file.path, text: file.text, index: build.index });
      (written[build.index] as string[]).push(
        posixPath(relative(roots[build.index] as string, file.path)),
      );
    }
  });
  list.forEach((options, index) => {
    if (!(written[index] as string[]).length && !plans[index]?.kept.length)
      throw packageError(
        "CONFIG_INVALID",
        options.id,
        "pretranspile found no TypeScript module to write as JavaScript",
        "Remove pretranspile from the package, or check that its extensions import TypeScript modules of the package",
      );
  });
  readableAsModules(outputs, list, roots);
  // Every module is transpiled and read before any file is written.
  for (const output of outputs) writeFileSync(output.path, output.text);
  return plans.map((plan, index) => ({
    written: (written[index] as string[]).sort(),
    kept: plan.kept,
    warnings: nativeImportProblems(
      outputs.filter((output) => output.index === index),
      exported,
      roots[index] as string,
      plan.split,
    ),
  }));
}

// A named import or re-export from a relative module, as esbuild writes it
// (one statement at the start of a line).
const NAMED_IMPORT =
  /^(?:import|export)\s+(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*["'](\.\.?\/[^"']+)["']/gm;

/** Whether a free name is declared in the module (`const require = createRequire(...)`). */
const declares = (text: string, name: string) =>
  new RegExp(`\\b(?:const|let|var|function|class)\\s+${name}\\b`).test(text);

/**
 * What Pi's loader (jiti) accepts in the written files and Node's own module
 * loader does not. The files are written for the loader, so these are
 * reported, not refused:
 *
 * - a named import or re-export of a name the transpiled module does not
 *   export: `export { T } from "./a.js"` survives esbuild when `T` is a type,
 *   and the loader reads it as `undefined` where Node fails to link;
 * - `__dirname`, `__filename`, or `require` used without being declared, which
 *   an ES module does not have;
 * - a package.json without `"type": "module"`, which makes Node read a
 *   written `.js` file as CommonJS;
 * - a module imported both as `./x` and as `./x.js`, which the loader may
 *   resolve to `x.ts` and to the written `x.js`: two instances of one module.
 */
function nativeImportProblems(
  outputs: readonly { path: string; text: string }[],
  exported: ReadonlyMap<string, ReadonlySet<string>>,
  root: string,
  split: readonly string[],
): string[] {
  const problems: string[] = [];
  const name = (path: string) => closureKey(root, path);
  // `export *` hides what a module exports from its own metafile entry.
  const reexportsAll = new Set(
    outputs
      .filter(({ text }) => /^export\s*\*/m.test(text))
      .map(({ path }) => resolve(path)),
  );
  for (const { path, text } of outputs) {
    for (const match of text.matchAll(NAMED_IMPORT)) {
      const written = resolve(dirname(path), match[2] as string);
      // `./x` as well as `./x.js`: the loader finds the written file either way.
      const target = [written, `${written}.js`, `${written}.mjs`].find((file) =>
        exported.has(file),
      );
      const names = target && exported.get(target);
      if (!target || !names || reexportsAll.has(target)) continue;
      const missing = (match[1] as string)
        .split(",")
        .map((item) => item.trim().split(/\s+as\s+/)[0] as string)
        .filter((item) => item && !names.has(item));
      if (missing.length)
        problems.push(
          `${name(path)} imports ${missing.join(", ")} from ${name(target)}, which does not export ${missing.length > 1 ? "them" : "it"} once transpiled (a type imported or re-exported as a value); Node fails to link it`,
        );
    }
    for (const global of ["__dirname", "__filename", "require"] as const) {
      const used =
        global === "require"
          ? // The free name used as a call, a property, an argument, or a value
            // (`(0, require)(x)`, `map(require)`, `const r = require;`);
            // `typeof require` is a guard and passes.
            /(?<![.\w$])(?<!\btypeof\s+)require\s*(?:[(.),;]|$)/m.test(text)
          : CJS_LOCATION.test(text) && new RegExp(`\\b${global}\\b`).test(text);
      if (used && !declares(text, global))
        problems.push(
          `${name(path)} uses ${global}, which an ES module does not have; Node fails on it`,
        );
    }
  }
  const typed = new Set<string>();
  for (const { path } of outputs) {
    if (!path.endsWith(".js")) continue;
    let directory = dirname(path);
    for (;;) {
      const manifest = join(directory, "package.json");
      if (existsSync(manifest)) {
        let type: unknown;
        try {
          type = (
            JSON.parse(readFileSync(manifest, "utf8")) as { type?: unknown }
          ).type;
        } catch {
          // read as CommonJS, like a manifest without a type
        }
        if (type !== "module" && !typed.has(manifest)) {
          typed.add(manifest);
          problems.push(
            `${name(manifest)} has no "type": "module", so Node reads the written .js files below it as CommonJS`,
          );
        }
        break;
      }
      if (directory === root || dirname(directory) === directory) break;
      directory = dirname(directory);
    }
  }
  for (const file of split)
    problems.push(
      `${file} is imported both as ./x and as ./x.js (or ./x.ts): the loader can resolve them to two files, so two instances of the module`,
    );
  return problems.sort();
}

/**
 * Every output is parsed as an ES module by the Node that builds, in one
 * process: a module it cannot read (a decorator esbuild passed through at the
 * esnext target) would ship as a file Pi's loader fails on.
 */
function readableAsModules(
  outputs: readonly { path: string; text: string; index: number }[],
  list: readonly { readonly id: string; readonly root: string }[],
  roots: readonly string[],
): void {
  if (!outputs.length) return;
  const script = `const vm = require("node:vm");
const bad = [];
for (const [path, text] of JSON.parse(require("node:fs").readFileSync(0, "utf8"))) {
  try { new vm.SourceTextModule(text, { identifier: path }); }
  catch (error) { bad.push([path, String(error && error.message).split("\\n")[0]]); }
}
process.stdout.write(JSON.stringify(bad));`;
  const run = spawnSync(
    process.execPath,
    ["--experimental-vm-modules", "--no-warnings", "-e", script],
    {
      input: JSON.stringify(outputs.map((item) => [item.path, item.text])),
      encoding: "utf8",
      maxBuffer: 1 << 30,
    },
  );
  let bad: [string, string][];
  try {
    bad = JSON.parse(run.stdout) as [string, string][];
  } catch {
    throw packageError(
      "CONFIG_INVALID",
      list[0]?.id ?? "",
      `pretranspile could not check its output: ${run.stderr.split("\n")[0] || "no result"}`,
      "Remove pretranspile from the package",
    );
  }
  const [path, message] = bad[0] ?? [];
  if (path === undefined) return;
  const index = outputs.find((item) => item.path === path)?.index ?? 0;
  throw unsupported(
    list[index]?.id ?? "",
    `${closureKey(roots[index] as string, path)}, which Node cannot read once transpiled (${message})`,
  );
}

const unsupported = (id: string, detail: string) =>
  packageError(
    "CONFIG_INVALID",
    id,
    `pretranspile cannot write an ES module for ${detail}`,
    "Remove pretranspile from the package, which then loads as TypeScript",
  );
