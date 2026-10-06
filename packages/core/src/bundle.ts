import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, sep } from "node:path";
import { inventory } from "./payload.js";
import { listPayloadPackages } from "./supply-chain.js";
import { workspacePackages } from "./runtime-dependencies.js";

const posix = (path: string) => path.split(sep).join("/");

/** An `exports` pattern target with every `*` replaced, as Node resolves it. */
export function wildcardTarget(target: string, subpath: string): string {
  return target.replaceAll("*", () => subpath);
}

const TRANSIENT_ATTEMPTS = 10;
const TRANSIENT_RETRY_MS = 100;

/** Windows scanners and indexers briefly hold a freshly written tree open. */
export function renameWithRetry(from: string, to: string): void {
  for (let attempt = 1; ; attempt++)
    try {
      renameSync(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (
        attempt === TRANSIENT_ATTEMPTS ||
        (code !== "EPERM" && code !== "EBUSY" && code !== "EACCES")
      )
        throw error;
      Atomics.wait(
        new Int32Array(new SharedArrayBuffer(4)),
        0,
        0,
        TRANSIENT_RETRY_MS * attempt,
      );
    }
}

/** Build-time only: combine JS while retaining upstream assets and public exports. */
export function bundleDistribution(payload: string): void {
  // The native form also expands Windows 8.3 short names (RUNNER~1), so the
  // paths esbuild reports and the root they are made relative to agree.
  payload = realpathSync.native(payload);
  const components = listPayloadPackages(payload);
  const runtime = join(payload, "runtime");
  mkdirSync(runtime, { recursive: true });
  const entries: Record<string, string> = {};
  const shims: { file: string; entry: string }[] = [];
  const add = (name: string, file: string, source = file) => {
    entries[name] = source;
    shims.push({ file, entry: name });
  };
  for (const name of workspacePackages) {
    const directory = join(payload, "node_modules", "@piship", name);
    const manifest = JSON.parse(
      readFileSync(join(directory, "package.json"), "utf8"),
    );
    for (const [key, value] of Object.entries(manifest.exports ?? {})) {
      const target =
        typeof value === "string"
          ? value
          : (value as { import?: string }).import;
      if (!target?.endsWith(".js")) continue;
      const file = join(directory, target);
      const entry = `piship-${name}${key === "." ? "" : key.slice(1).replaceAll("/", "-")}`;
      add(
        entry,
        file,
        name === "pi" && key === "."
          ? join(directory, "dist", "bundle.js")
          : file,
      );
    }
  }
  // Public module shims preserve extension imports and Chord's module identity.
  const upstream = join(payload, "node_modules", "@earendil-works");
  for (const name of [
    "pi-coding-agent",
    "pi-ai",
    "pi-agent-core",
    "pi-codemode",
    "pi-tui",
    "chord",
  ]) {
    const directory = join(upstream, name);
    const manifest = JSON.parse(
      readFileSync(join(directory, "package.json"), "utf8"),
    );
    const keys =
      name === "chord"
        ? [".", "./context", "./node"]
        : name === "pi-ai"
          ? [".", "./compat", "./oauth", "./providers/all"]
          : ["."];
    for (const key of keys) {
      const declared =
        manifest.exports?.[key] ??
        (key.startsWith("./providers/")
          ? {
              import: wildcardTarget(
                manifest.exports["./providers/*"].import,
                key.slice("./providers/".length),
              ),
            }
          : undefined);
      const target =
        typeof declared === "string"
          ? declared
          : (declared?.import ?? (key === "." ? manifest.main : undefined));
      if (target)
        add(
          `${name}${key === "." ? "" : key.slice(1).replaceAll("/", "-")}`,
          join(directory, target),
        );
    }
  }
  const typebox = join(payload, "node_modules", "typebox");
  const typeboxManifest = JSON.parse(
    readFileSync(join(typebox, "package.json"), "utf8"),
  );
  for (const [key, value] of Object.entries(typeboxManifest.exports)) {
    const target = (value as { import: string }).import;
    add(
      `typebox${key === "." ? "" : key.slice(1).replaceAll("/", "-")}`,
      join(typebox, target),
    );
  }
  add(
    "codemode-worker",
    join(upstream, "pi-codemode", "dist", "runtime", "worker.js"),
    join(payload, "node_modules", "@piship", "pi", "dist", "bundle-worker.js"),
  );
  // This is an upstream runtime asset, not an integration import. Preserve its
  // code untouched and let the bundler follow its own relative dependencies.
  add(
    "image-resize-worker",
    join(
      upstream,
      "pi-coding-agent",
      "dist",
      "utils",
      "image-resize-worker.js",
    ),
  );
  const tool = createRequire(import.meta.url).resolve("esbuild");
  const script = `
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
const require = createRequire(import.meta.url);
const { build } = require(${JSON.stringify(tool)});
const root = ${JSON.stringify(payload)};
const options = {
 entryPoints: ${JSON.stringify(entries)}, outdir: ${JSON.stringify(runtime)},
 bundle: true, splitting: true, metafile: true, write: false, format: 'esm', platform: 'node', target: 'node22',
 minify: true, sourcemap: false, chunkNames: 'chunk-[hash]',
 external: ['esbuild', 'jiti', '@silvia-odwyer/photon-node'],
 banner: {js: 'import {createRequire as __pishipRequire} from "node:module"; const require=__pishipRequire(import.meta.url);'},
 plugins: [{ name: 'preserve-module-asset-urls', setup(build) {
  build.onLoad({filter: /\\.[cm]?js$/}, ({path}) => {
   const text = readFileSync(path, 'utf8');
   if (!text.includes('import.meta.url')) return;
   const source = relative(root,path).split(sep).join('/');
   return {contents: text.replaceAll('import.meta.url', 'new URL('+JSON.stringify('../'+source)+', import.meta.url).href'), loader:'js'};
  });
 }}]
};
const scan = await build(options);
const sources = [];
const mapping = {};
for (const [name, path] of Object.entries(options.entryPoints)) {
 if (name.endsWith('worker') || name === 'piship-pi-environment') continue;
 const output = Object.entries(scan.metafile.outputs).find(([file]) => file.replaceAll('\\\\','/').endsWith('/'+name+'.js'))?.[1];
 if (!output) throw new Error('Missing bundle entry '+name);
 const names = output.exports;
 const prefix = name.replaceAll('-', '_');
 mapping[name] = names.map(key => [key, prefix+'_'+key]);
 sources.push('export {'+mapping[name].map(([key, renamed])=>key+' as '+renamed).join(',')+'} from '+JSON.stringify(path)+';');
}
const mainSource = ${JSON.stringify(join(runtime, ".main.mjs"))};
const bootSource = ${JSON.stringify(join(runtime, ".boot.mjs"))};
const { writeFileSync, rmSync } = require('node:fs');
writeFileSync(mainSource, sources.join('\\n'));
const dependency = (name, file) => JSON.stringify(join(root, 'node_modules', '@piship', name, 'dist', file));
writeFileSync(bootSource, 'export {formatError} from '+dependency('contracts', 'index.js')+'; export {verifyLaunchPayload} from '+dependency('core', 'index.js')+'; export {preparePiEnvironment} from '+dependency('pi', 'environment.js')+';');
await build({...options, entryPoints: { main: mainSource, boot: bootSource, 'codemode-worker': options.entryPoints['codemode-worker'], 'image-resize-worker': options.entryPoints['image-resize-worker'] }, splitting: false, write:true});
writeFileSync(${JSON.stringify(join(runtime, "exports.json"))}, JSON.stringify(mapping));
rmSync(mainSource); rmSync(bootSource);`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-"], {
    input: script,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0)
    throw new Error(
      `Runtime bundling failed: ${result.stderr || result.error?.message}`,
    );
  const original = join(payload, ".bundle-input");
  renameWithRetry(join(payload, "node_modules"), original);
  const keep = (path: string) => {
    const source = join(original, path);
    if (!existsSync(source)) return;
    const target = join(payload, "node_modules", path);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source, target, { recursive: true });
  };
  try {
    // Package metadata and the small number of paths opened at runtime.
    for (const name of workspacePackages) keep(`@piship/${name}/package.json`);
    for (const name of [
      "pi-coding-agent",
      "pi-ai",
      "pi-agent-core",
      "pi-codemode",
      "pi-tui",
      "chord",
    ])
      keep(`@earendil-works/${name}/package.json`);
    for (const asset of [
      "package.json",
      "README.md",
      "CHANGELOG.md",
      "dist/modes/interactive/theme/dark.json",
      "dist/modes/interactive/theme/light.json",
      "dist/modes/interactive/assets",
      "dist/core/export-html/template.html",
      "dist/core/export-html/template.css",
      "dist/core/export-html/template.js",
      "dist/core/export-html/vendor",
    ])
      keep(`@earendil-works/pi-coding-agent/${asset}`);
    keep(
      `@earendil-works/pi-tui/native/${process.platform}/prebuilds/${process.platform}-${process.arch}`,
    );
    keep("typebox/package.json");
    keep("quickjs-wasi/package.json");
    keep("quickjs-wasi/quickjs.wasm");
    const jiti = "@earendil-works/pi-coding-agent/node_modules/jiti";
    if (existsSync(join(original, jiti))) {
      for (const file of [
        "package.json",
        "lib/jiti.mjs",
        "lib/jiti-static.mjs",
        "dist/jiti.cjs",
        "dist/babel.cjs",
      ]) {
        const target = join(payload, "node_modules", "jiti", file);
        mkdirSync(dirname(target), { recursive: true });
        cpSync(join(original, jiti, file), target);
      }
    }
    const photon =
      "@earendil-works/pi-coding-agent/node_modules/@silvia-odwyer/photon-node";
    if (existsSync(join(original, photon))) {
      mkdirSync(join(payload, "node_modules", "@silvia-odwyer"), {
        recursive: true,
      });
      cpSync(
        join(original, photon),
        join(payload, "node_modules", "@silvia-odwyer", "photon-node"),
        { recursive: true },
      );
    }
    // Installed management commands still need the exact dependency metadata,
    // but do not ship a second copy of every JS source in build-input.
    const input = "@piship/core/dist/build-input";
    keep(`${input}/package.json`);
    keep(`${input}/package-lock.json`);
    for (const name of workspacePackages)
      keep(`${input}/packages/${name}/package.json`);
    for (const shim of shims) {
      mkdirSync(dirname(shim.file), { recursive: true });
      const mapping = JSON.parse(
        readFileSync(join(runtime, "exports.json"), "utf8"),
      ) as Record<string, [string, string][]>;
      const output = shim.entry.endsWith("worker")
        ? `${shim.entry}.js`
        : shim.entry === "piship-pi-environment"
          ? "boot.js"
          : "main.js";
      const target = posix(relative(dirname(shim.file), join(runtime, output)));
      const exports = mapping[shim.entry]
        ?.map(([key, renamed]) => `${renamed} as ${key}`)
        .join(", ");
      writeFileSync(
        shim.file,
        exports
          ? `export {${exports}} from ${JSON.stringify(target)};\n`
          : `export * from ${JSON.stringify(target)};\n`,
      );
    }
    const commandDirectory = join(payload, "bin");
    for (const command of readdirSync(commandDirectory)) {
      const path = join(commandDirectory, command);
      if (command.endsWith(".cmd")) continue;
      const source = readFileSync(path, "utf8");
      writeFileSync(
        path,
        source
          .replace(
            'import { formatError } from "@piship/contracts";',
            'import { formatError as bootFormatError } from "../runtime/boot.js";\nlet formatError = bootFormatError;',
          )
          .replaceAll('"@piship/core"', '"../runtime/boot.js"')
          .replaceAll('"@piship/pi/environment"', '"../runtime/boot.js"')
          .replace(
            "preparePiEnvironment(metadata.app.id);",
            `preparePiEnvironment(metadata.app.id);\n  process.env.PI_PACKAGE_DIR = fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/", import.meta.url));\n  formatError = (await import("@piship/contracts")).formatError;`,
          ),
      );
    }
    rmSync(join(runtime, "exports.json"));
    writeFileSync(
      join(payload, "metadata", "bundle.json"),
      `${JSON.stringify(
        {
          format: "esbuild-node-esm",
          components,
          entries: Object.keys(entries),
          files: readdirSync(runtime).length,
        },
        null,
        2,
      )}\n`,
    );
  } finally {
    rmSync(original, {
      recursive: true,
      force: true,
      maxRetries: TRANSIENT_ATTEMPTS,
      retryDelay: TRANSIENT_RETRY_MS,
    });
  }
  writeFileSync(
    join(payload, "metadata", "inventory.json"),
    `${JSON.stringify(inventory(payload), null, 2)}\n`,
  );
}
