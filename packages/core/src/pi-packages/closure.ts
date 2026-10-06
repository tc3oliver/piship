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
import {
  mkdirSync,
  readdirSync,
  readFileSync,
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

const graphBuild = (state: State): Record<string, unknown> => ({
  ...bundleOptions(state.root),
  entryPoints: Object.fromEntries(
    state.entryPaths.map((entry) => [
      entry,
      join(state.root, ...entry.split("/")),
    ]),
  ),
  outdir: join(state.root, CLOSURE_DIRECTORY, ".scan"),
});

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
  const graphs = esbuild.buildAll(graphing.map(graphBuild));
  graphing.forEach((state, index) =>
    readGraph(state, graphs[index] as BuildOutcome),
  );
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
  scanning.forEach((state, index) =>
    readScan(state, scans[index] as ScanResult),
  );
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
