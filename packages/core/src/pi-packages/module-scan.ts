// What a Pi package's JavaScript does, read without running it: the imports a
// module makes, the names it exports, and the constructs that find code or
// files at run time. Dependency sharing and bundling both rest on this: a
// module that a scan cannot account for is never rewritten.
import { builtinModules, createRequire } from "node:module";
import { join, posix, resolve } from "node:path";

/** The part of esbuild's API a scan uses (`esbuild` resolves it from the payload). */
export interface EsbuildApi {
  buildSync(options: Record<string, unknown>): {
    readonly errors: readonly { readonly text: string }[];
    readonly outputFiles?: readonly {
      readonly path: string;
      readonly text: string;
    }[];
    readonly metafile: {
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
      readonly outputs: Record<
        string,
        { readonly entryPoint?: string; readonly exports: readonly string[] }
      >;
    };
  };
}

/** esbuild as `from` (a package.json path or directory) resolves it. */
export function loadEsbuild(from: string): EsbuildApi {
  const base = from.endsWith("package.json")
    ? from
    : join(from, "package.json");
  return createRequire(base)("esbuild") as EsbuildApi;
}

export interface ModuleImport {
  readonly specifier: string;
  readonly kind: "import" | "require" | "dynamic";
}

export interface ModuleInfo {
  /** How the syntax reads: `esm` has import/export statements, `cjs` does not. */
  readonly format: "esm" | "cjs";
  readonly imports: readonly ModuleImport[];
  /** Names the module exports, `default` included. Meaningful for `esm`. */
  readonly exports: readonly string[];
  /** The code without its comments, as written otherwise. */
  readonly source: string;
}

const BUILTINS = new Set(builtinModules);

/** A Node built-in specifier, with or without the `node:` prefix. */
export function isBuiltin(specifier: string): boolean {
  if (specifier.startsWith("node:")) return true;
  return BUILTINS.has(specifier) || BUILTINS.has(specifier.split("/")[0] ?? "");
}

const KINDS: Record<string, ModuleImport["kind"] | undefined> = {
  "import-statement": "import",
  "require-call": "require",
  "dynamic-import": "dynamic",
  "import-rule": "import",
};

/**
 * Parse `files` (`/`-separated, relative to `root`) with esbuild, one entry
 * each, nothing bundled: every import is left as written. A file esbuild
 * cannot parse is in `failed`, with its first error.
 */
export function scanModules(
  esbuild: EsbuildApi,
  root: string,
  files: readonly string[],
): {
  readonly modules: ReadonlyMap<string, ModuleInfo>;
  readonly failed: ReadonlyMap<string, string>;
} {
  root = resolve(root);
  const modules = new Map<string, ModuleInfo>();
  const failed = new Map<string, string>();
  if (!files.length) return { modules, failed };
  const run = (batch: readonly string[], bundle: boolean) => {
    try {
      return esbuild.buildSync({
        entryPoints: batch.map((file) => join(root, ...file.split("/"))),
        absWorkingDir: root,
        outdir: join(root, ".piship-scan"),
        outbase: root,
        bundle,
        write: false,
        metafile: true,
        platform: "node",
        legalComments: "none",
        minifyWhitespace: !bundle,
        logLevel: "silent",
        ...(bundle ? { format: "esm", external: ["*"] } : {}),
      });
    } catch (error) {
      return error as Error;
    }
  };
  // Imports come from a bundling pass that leaves every import external; the
  // text without comments from a pass that changes nothing else.
  const linked = run(files, true);
  const plain = linked instanceof Error ? linked : run(files, false);
  if (linked instanceof Error || plain instanceof Error) {
    const error = (linked instanceof Error ? linked : plain) as Error;
    // One unparsable file fails the whole batch: scan each alone to say which.
    if (files.length === 1) {
      failed.set(files[0] as string, error.message.split("\n")[0] ?? "");
      return { modules, failed };
    }
    for (const file of files) {
      const single = scanModules(esbuild, root, [file]);
      for (const [key, value] of single.modules) modules.set(key, value);
      for (const [key, value] of single.failed) failed.set(key, value);
    }
    return { modules, failed };
  }
  const exportsOf = new Map<string, readonly string[]>();
  for (const output of Object.values(linked.metafile.outputs))
    if (output.entryPoint)
      exportsOf.set(output.entryPoint.replaceAll("\\", "/"), output.exports);
  const sourceOf = new Map<string, string>();
  const written = new Map(
    (plain.outputFiles ?? []).map((file) => [resolve(file.path), file.text]),
  );
  for (const [path, output] of Object.entries(plain.metafile.outputs))
    if (output.entryPoint)
      sourceOf.set(
        output.entryPoint.replaceAll("\\", "/"),
        written.get(resolve(root, path)) ?? "",
      );
  for (const [path, input] of Object.entries(linked.metafile.inputs)) {
    const key = path.replaceAll("\\", "/");
    if (!files.includes(key)) continue;
    modules.set(key, {
      format: input.format === "esm" ? "esm" : "cjs",
      imports: input.imports.flatMap((item) => {
        const kind = KINDS[item.kind];
        return kind && item.path !== "<runtime>"
          ? [{ specifier: item.path, kind }]
          : [];
      }),
      exports: exportsOf.get(key) ?? [],
      source: sourceOf.get(key) ?? "",
    });
  }
  return { modules, failed };
}

/**
 * Constructs that locate code or files when they run, which no static import
 * list accounts for. A text match, deliberately loose: a false positive keeps
 * a package as it is, a false negative would rewrite one that must not be.
 */
const RUNTIME_DISCOVERY: readonly (readonly [string, RegExp])[] = [
  ["require.resolve", /\brequire\s*\.\s*resolve\b/],
  ["createRequire", /\bcreateRequire\b/],
  ["import.meta.resolve", /\bimport\s*\.\s*meta\s*\.\s*resolve\b/],
  [
    "module resolution internals",
    /\b(?:module\s*\.\s*(?:paths|parent|children|constructor)|require\s*\.\s*(?:main|cache|extensions)|process\s*\.\s*mainModule|Module\s*\.\s*_[A-Za-z]+|process\s*\.\s*binding)\b/,
  ],
  ["node_modules path", /node_modules/],
  [
    "computed require or import",
    /\b(?:require|import)\s*\(\s*(?!["'`][^"'`$]*["'`]\s*[,)])/,
  ],
  // `const r = require; r(x)` or `module["require"]`.
  ["indirect require", /\brequire\b(?!\s*[(.])|\[\s*["']require["']\s*\]/],
];

/** The first run-time discovery construct in `source`, by name, or undefined. */
export function runtimeDiscovery(source: string): string | undefined {
  for (const [name, pattern] of RUNTIME_DISCOVERY)
    if (pattern.test(source)) return name;
  return undefined;
}

/** `file` relative to `root` as `/` segments, when `specifier` stays inside `root`. */
export function relativeTarget(
  file: string,
  specifier: string,
): string | undefined {
  const joined = posix.normalize(posix.join(posix.dirname(file), specifier));
  return joined === ".." || joined.startsWith("../") ? undefined : joined;
}
