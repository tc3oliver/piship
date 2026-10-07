// What a Pi package's JavaScript does, read without running it: the imports a
// module makes, the names it exports, and the constructs that find code or
// files at run time. Dependency sharing and bundling both rest on this: a
// module that a scan cannot account for is never rewritten.
import { spawnSync } from "node:child_process";
import { builtinModules, createRequire } from "node:module";
import { join, posix, resolve } from "node:path";

/** What one esbuild build returns, as far as a scan reads it. */
export interface BuildResult {
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
}

/** A build that failed: esbuild's message and the errors it reported. */
export interface BuildFailure {
  readonly message: string;
  readonly errors: readonly {
    readonly text: string;
    readonly location?: { readonly file?: string } | null;
  }[];
}

export type BuildOutcome =
  | { readonly build: BuildResult }
  | { readonly failure: BuildFailure };

/** The part of esbuild's API a scan uses (`esbuild` resolves it from the payload). */
export interface EsbuildApi {
  /** Builds run together in one process; each has its own outcome. */
  buildAll(builds: readonly Record<string, unknown>[]): readonly BuildOutcome[];
  /** One build; throws an error carrying `errors` when it fails. */
  buildSync(options: Record<string, unknown>): BuildResult;
}

/**
 * Runs esbuild builds in a Node process of their own, through esbuild's
 * asynchronous API. Its synchronous API waits on a worker thread with
 * Atomics.wait and never returns when that thread dies (it does, on a failed
 * build that asked for a metafile); a separate process with a time limit
 * cannot hang the build, and the options and results are plain JSON. Builds
 * handed over together share one process, which is most of what one costs.
 */
/** A build that is not done by now never will be. */
const BUILD_LIMIT_MS = 120_000;

const RUNNER = `
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const { build } = require(input.tool);
const failed = (error) => ({ failure: { message: String(error && error.message), errors: (error && error.errors) ?? [] } });
Promise.all(input.builds.map((options) => build(options).then(
  (result) => ({ build: {
    errors: result.errors,
    metafile: result.metafile,
    outputFiles: (result.outputFiles ?? []).map((file) => ({ path: file.path, text: file.text })),
  } }),
  failed,
))).then((outcomes) =>
  process.stdout.write(JSON.stringify(outcomes), () => process.exit(0)),
);
`;

/** esbuild as `from` (a package.json path or directory) resolves it. */
export function loadEsbuild(from: string): EsbuildApi {
  const base = from.endsWith("package.json")
    ? from
    : join(from, "package.json");
  const tool = createRequire(base).resolve("esbuild");
  const attempt = (
    builds: readonly Record<string, unknown>[],
  ): readonly BuildOutcome[] | { readonly crashed: string } => {
    const result = spawnSync(process.execPath, ["-e", RUNNER], {
      input: JSON.stringify({ tool, builds }),
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 1024,
      timeout: BUILD_LIMIT_MS,
      windowsHide: true,
    });
    if (result.error || result.status !== 0)
      return { crashed: result.error?.message ?? result.stderr.trim() };
    return JSON.parse(result.stdout) as BuildOutcome[];
  };
  const alone = (options: Record<string, unknown>): BuildOutcome => {
    let output = attempt([options]);
    // esbuild 0.28 crashes with a JSON error of its own, instead of reporting
    // the failure, when it is asked for a metafile of a build that fails.
    // Without the metafile it reports the failure itself.
    if ("crashed" in output && options.metafile)
      output = attempt([{ ...options, metafile: false }]);
    if ("crashed" in output)
      return {
        failure: {
          message: `esbuild did not run: ${output.crashed}`,
          errors: [],
        },
      };
    return output[0] as BuildOutcome;
  };
  const api: EsbuildApi = {
    buildAll(builds) {
      if (!builds.length) return [];
      const together = attempt(builds);
      // One build that crashed esbuild took the process with it: run each on
      // its own to find which, and to give the others their results.
      return "crashed" in together ? builds.map(alone) : together;
    },
    buildSync(options) {
      const [outcome] = api.buildAll([options]);
      if (outcome && "build" in outcome) return outcome.build;
      const failure = (outcome as { failure: BuildFailure }).failure;
      throw Object.assign(new Error(failure.message), {
        errors: failure.errors,
      });
    },
  };
  return api;
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

export interface ScanJob {
  readonly root: string;
  /** `/`-separated, relative to `root`. */
  readonly files: readonly string[];
}

export interface ScanResult {
  readonly modules: ReadonlyMap<string, ModuleInfo>;
  readonly failed: ReadonlyMap<string, string>;
}

function scanBuild(
  root: string,
  files: readonly string[],
  bundle: boolean,
): Record<string, unknown> {
  return {
    // Named entries: two files with the same name and different extensions
    // (`index.js`, `index.cjs`) would share an output path.
    entryPoints: Object.fromEntries(
      files.map((file, index) => [
        String(index),
        join(root, ...file.split("/")),
      ]),
    ),
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
  };
}

/**
 * Parse each job's files with esbuild, one entry each, nothing bundled: every
 * import is left as written. A file esbuild cannot parse is in `failed`, with
 * its first error. All the jobs' builds run in one process.
 */
export function scanModulesMany(
  esbuild: EsbuildApi,
  jobs: readonly ScanJob[],
): ScanResult[] {
  const results = jobs.map(() => ({
    modules: new Map<string, ModuleInfo>(),
    failed: new Map<string, string>(),
  }));
  let pending = jobs
    .map((job, index) => ({
      index,
      root: resolve(job.root),
      files: [...job.files],
    }))
    .filter((item) => item.files.length);
  while (pending.length) {
    // Imports come from a bundling build that leaves every import external;
    // the text without comments from one that changes nothing else.
    const outcomes = esbuild.buildAll(
      pending.flatMap((item) => [
        scanBuild(item.root, item.files, true),
        scanBuild(item.root, item.files, false),
      ]),
    );
    const next: typeof pending = [];
    pending.forEach((item, position) => {
      const result = results[item.index] as (typeof results)[number];
      const linked = outcomes[position * 2] as BuildOutcome;
      const plain = outcomes[position * 2 + 1] as BuildOutcome;
      const failure =
        "failure" in linked
          ? linked.failure
          : "failure" in plain
            ? plain.failure
            : undefined;
      if (failure) {
        // One unparsable file fails the whole batch. esbuild names the files
        // that failed: scan again without them.
        const listed = new Set(item.files);
        const named = new Map<string, string>();
        for (const error of failure.errors) {
          const file = error.location?.file?.replaceAll("\\", "/");
          if (file && listed.has(file) && !named.has(file))
            named.set(file, error.text);
        }
        if (named.size) {
          for (const [file, text] of named) result.failed.set(file, text);
          const rest = item.files.filter((file) => !named.has(file));
          if (rest.length) next.push({ ...item, files: rest });
        } else {
          // Not attributable to a file (esbuild itself failed): the whole
          // batch is unscanned, which callers treat as not safe.
          const first = failure.message.split("\n")[0] ?? "";
          for (const file of item.files) result.failed.set(file, first);
        }
        return;
      }
      if (!("build" in linked) || !("build" in plain)) return;
      const exportsOf = new Map<string, readonly string[]>();
      for (const output of Object.values(linked.build.metafile.outputs))
        if (output.entryPoint)
          exportsOf.set(
            output.entryPoint.replaceAll("\\", "/"),
            output.exports,
          );
      const written = new Map(
        (plain.build.outputFiles ?? []).map((file) => [
          resolve(file.path),
          file.text,
        ]),
      );
      const sourceOf = new Map<string, string>();
      for (const [path, output] of Object.entries(plain.build.metafile.outputs))
        if (output.entryPoint)
          sourceOf.set(
            output.entryPoint.replaceAll("\\", "/"),
            written.get(resolve(item.root, path)) ?? "",
          );
      const listed = new Set(item.files);
      for (const [path, input] of Object.entries(
        linked.build.metafile.inputs,
      )) {
        const key = path.replaceAll("\\", "/");
        if (!listed.has(key)) continue;
        result.modules.set(key, {
          format: input.format === "esm" ? "esm" : "cjs",
          imports: input.imports.flatMap((entry) => {
            const kind = KINDS[entry.kind];
            return kind && entry.path !== "<runtime>"
              ? [{ specifier: entry.path, kind }]
              : [];
          }),
          exports: exportsOf.get(key) ?? [],
          source: sourceOf.get(key) ?? "",
        });
      }
    });
    pending = next;
  }
  return results;
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
