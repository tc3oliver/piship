import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { createTemporaryDirectory, debugTiming } from "@piship/contracts";
import { readManifest, releaseOptions } from "@piship/schema";
import { authoringBuildInput } from "./authoring-input.js";
import { startBackgroundProcess } from "./background-process.js";
import {
  buildCacheKeys,
  buildCachePath,
  readBuildCache,
  refreshCachedDistribution,
  writeBuildCache,
} from "./build-cache.js";
import { bundleDistribution } from "./bundle.js";
import { launcherSource, portableCliSource } from "./launcher-source.js";
import { requireCurrentLock } from "./lock.js";
import { removeTree } from "./parallel-files.js";
import {
  inventory,
  removeForeignPlatformPackages,
  removeNpmBins,
  stripRuntimeIrrelevant,
} from "./payload.js";
import { pretranspileClosures } from "./pi-packages/closure.js";
import { PI_PACKAGE_VENDOR_DIRECTORY } from "./pi-packages/gates.js";
import {
  optimizePiPackages,
  type PackageFootprint,
} from "./pi-packages/footprint.js";
import { vendorPiPackages } from "./pi-packages/lock.js";
import { loadEsbuild } from "./pi-packages/module-scan.js";
import type { VendoredPiPackage } from "./pi-packages/resolve.js";
import { checkPackageSources } from "./release/index.js";
import { renameWithRetry } from "./rename-retry.js";
import {
  adoptInstallTree,
  discardInstallTree,
  discardTree,
  type InstallTree,
  lookupInstallTree,
  lookupTree,
  materializeInstallTree,
  plainInventory,
  publishFrameworkTree,
  type RuntimeCache,
  runtimeCacheFor,
  writeFrameworkFiles,
} from "./runtime-cache.js";
import { workspacePackages } from "./runtime-dependencies.js";
import { stageSearchTools } from "./search-tools/index.js";
import {
  type OutputStagingOptions,
  sweepOutputStaging,
} from "./temporary-directories.js";

/**
 * What `npm ci` is asked for: the locked runtime tree only, from the npm cache
 * where it already holds the pinned tarballs (an integrity mismatch still
 * fetches), without the audit and funding requests, progress drawing, or
 * warnings, which cost time on a console and are not read. Lifecycle scripts
 * run: three runtime packages declare one, reviewed in
 * REVIEWED_INSTALL_SCRIPTS, and esbuild's postinstall validates (and where
 * needed fetches) its platform binary.
 */
const NPM_CI_ARGUMENTS = [
  "ci",
  "--omit=dev",
  "--no-audit",
  "--no-fund",
  "--prefer-offline",
  "--loglevel=error",
  "--progress=false",
] as const;

/**
 * npm-install the runtime dependencies into the empty `stage`: the locked
 * third-party tree, minus npm's `.bin` links and the optional packages built
 * for other platforms, with any dependency npm could not hoist (it installs
 * them beside PiShip's workspace manifests) moved under `node_modules/@piship`.
 * Nothing is stripped here. PiShip's own packages are npm links until they are
 * replaced: with `framework` they become real copies of the build input and
 * the stage keeps its root manifest and lock; without it the stage is left
 * for the cache, which places PiShip's layer from its own entry.
 */
function installRuntime(
  stage: string,
  progress: ((step: string) => void) | undefined,
  framework: boolean,
  meanwhile: { readonly run: () => void; readonly overlap: boolean },
): void {
  const buildInput = authoringBuildInput();
  let phase = process.hrtime.bigint();
  copyFileSync(join(buildInput, "package.json"), join(stage, "package.json"));
  copyFileSync(
    join(buildInput, "package-lock.json"),
    join(stage, "package-lock.json"),
  );
  // npm resolves its workspace links from the manifests alone, so the
  // compiled output is copied once, into its final place below.
  for (const name of workspacePackages) {
    const folder = join(stage, "packages", name);
    mkdirSync(folder, { recursive: true });
    copyFileSync(
      join(buildInput, "packages", name, "package.json"),
      join(folder, "package.json"),
    );
  }
  debugTiming("build input copy", phase);
  phase = process.hrtime.bigint();
  progress?.("Installing the runtime packages (npm ci)");
  const [file, args] =
    process.platform === "win32"
      ? ["cmd.exe", ["/d", "/s", "/c", `npm ${NPM_CI_ARGUMENTS.join(" ")}`]]
      : ["npm", [...NPM_CI_ARGUMENTS]];
  let install: { status: number | null; output: string };
  let running: ReturnType<typeof startBackgroundProcess> | undefined;
  if (meanwhile.overlap)
    try {
      running = startBackgroundProcess(file, args, stage);
    } catch {
      // No thread to run it: npm runs here, as it does without overlap.
    }
  if (running) {
    // npm runs in a thread while this one assembles the files that do not
    // need it. A failure there still waits for npm: the stage is not removed
    // from under a running install.
    try {
      meanwhile.run();
    } finally {
      try {
        install = running.wait();
      } catch {
        // The thread never ran npm: nothing was installed, so run it here.
        const done = spawnSync(file, args, { cwd: stage, encoding: "utf8" });
        install = {
          status: done.status,
          output: done.stderr || done.error?.message || done.stdout,
        };
      }
    }
  } else {
    const done = spawnSync(file, args, { cwd: stage, encoding: "utf8" });
    install = {
      status: done.status,
      output: done.stderr || done.error?.message || done.stdout,
    };
    meanwhile.run();
  }
  if (install.status !== 0)
    throw new Error(`Portable runtime assembly failed: ${install.output}`);
  debugTiming("npm ci --omit=dev", phase);
  phase = process.hrtime.bigint();
  for (const name of workspacePackages) {
    const target = join(stage, "node_modules", "@piship", name);
    rmSync(target, { recursive: true, force: true });
    // Dependencies npm could not hoist were installed beside the manifest.
    const nested = join(stage, "packages", name, "node_modules");
    if (existsSync(nested) || framework) mkdirSync(target, { recursive: true });
    if (framework) {
      copyFileSync(
        join(buildInput, "packages", name, "package.json"),
        join(target, "package.json"),
      );
      cpSync(join(buildInput, "packages", name, "dist"), join(target, "dist"), {
        recursive: true,
      });
    }
    if (existsSync(nested))
      renameWithRetry(nested, join(target, "node_modules"));
  }
  if (framework)
    cpSync(
      buildInput,
      join(stage, "node_modules", "@piship", "core", "dist", "build-input"),
      { recursive: true },
    );
  rmSync(join(stage, "packages"), { recursive: true, force: true });
  debugTiming("PiShip/build-input copying", phase);
  phase = process.hrtime.bigint();
  removeNpmBins(join(stage, "node_modules"));
  removeForeignPlatformPackages(stage);
  if (!framework)
    for (const name of ["package.json", "package-lock.json"])
      rmSync(join(stage, name));
  debugTiming("removeNpmBins/foreign platform packages", phase);
}

/** What a build says about where its runtime tree came from. */
export interface RuntimeCacheReport {
  /** A hit placed an entry, a miss installed and published one, unusable built without the cache. */
  readonly status: "hit" | "miss" | "unusable";
  /** The third-party tree's identity (the digest of its file list), when there was one. */
  readonly entry?: string;
  /**
   * PiShip's own layer: placed from its entry (`hit`), published first from
   * the build input (`miss`), or copied straight from the build input because
   * the cache could not take it (`direct`).
   */
  readonly framework?: "hit" | "miss" | "direct";
  /** How the files reached the payload: hardlinked from the entries, or copied. */
  readonly linked: number;
  readonly copied: number;
  /** The cache is on another volume than the build, so the entry was copied in. */
  readonly crossVolume?: true;
}

/** Files placed so far, and the cache layers they came from. */
interface Placed {
  linked: number;
  copied: number;
  trees: InstallTree[];
}

/**
 * Put PiShip's own layer into `stage`: placed from its cache entry, which is
 * first published from the build input when the cache has none, or, where the
 * cache cannot take it, copied from the build input directly.
 */
function placeFramework(
  stage: string,
  cache: RuntimeCache,
  strip: boolean,
  into: Placed,
): "hit" | "miss" | "direct" {
  const hit = lookupTree(cache, "framework");
  const tree = hit ?? publishFrameworkTree(cache);
  if (!tree) {
    writeFrameworkFiles(stage);
    return "direct";
  }
  const placed = materializeInstallTree(tree, stage, { strip });
  into.linked += placed.linked;
  into.copied += placed.copied;
  into.trees.push(tree);
  return hit ? "hit" : "miss";
}

/**
 * Put the runtime dependency tree into the empty `stage`. With a cache both
 * layers are placed from their entries (the third-party tree, then PiShip's);
 * the third-party tree is installed and moved into the cache first when it has
 * no entry. Without one the tree is installed in the stage and stripped in
 * place. Returns the cache entries the files came from, whose digests a
 * payload inventory can take.
 */
function placeRuntime(
  stage: string,
  options: {
    readonly cache: RuntimeCache | undefined;
    readonly strip: boolean;
    readonly leaveWhole: boolean;
    readonly progress: ((step: string) => void) | undefined;
    readonly found: ((report: RuntimeCacheReport) => void) | undefined;
    /**
     * The files of the payload that do not need the tree, assembled once: with
     * `overlap` while npm installs it, otherwise when the tree is in place.
     */
    readonly meanwhile: () => void;
    readonly overlap: boolean;
  },
): InstallTree[] {
  const { cache, strip, progress, found } = options;
  let assembled = false;
  const meanwhile = {
    overlap: options.overlap,
    run: () => {
      if (assembled) return;
      assembled = true;
      options.meanwhile();
    },
  };
  let phase = process.hrtime.bigint();
  if (cache) {
    const hit = lookupInstallTree(cache);
    if (hit) {
      progress?.("Reusing the cached runtime packages");
      let placed: Placed | undefined;
      try {
        placed = { linked: 0, copied: 0, trees: [hit] };
        const own = materializeInstallTree(hit, stage, { strip });
        placed.linked += own.linked;
        placed.copied += own.copied;
        const framework = placeFramework(stage, cache, strip, placed);
        debugTiming("runtime cache placement", phase);
        found?.({
          status: "hit",
          entry: hit.digest,
          framework,
          linked: placed.linked,
          copied: placed.copied,
        });
      } catch {
        // Damaged or evicted underneath this build: install again, and publish
        // that tree in its place.
        placed = undefined;
        discardInstallTree(cache);
        discardTree(cache, "framework");
        rmSync(stage, { recursive: true, force: true });
        mkdirSync(stage);
      }
      if (placed) {
        // An error of the assembly is not the entry's.
        meanwhile.run();
        return placed.trees;
      }
    }
  }
  installRuntime(stage, progress, cache === undefined, meanwhile);
  phase = process.hrtime.bigint();
  const adopted = cache && adoptInstallTree(cache, stage);
  if (cache && adopted) {
    const placed: Placed = { linked: 0, copied: 0, trees: [adopted.tree] };
    let framework: "hit" | "miss" | "direct";
    try {
      if (adopted.moved) {
        const own = materializeInstallTree(adopted.tree, stage, { strip });
        placed.linked += own.linked;
        placed.copied += own.copied;
      }
      framework = placeFramework(stage, cache, strip, placed);
    } catch (error) {
      // What is left of the install is in the entries: never reuse them.
      discardInstallTree(cache);
      discardTree(cache, "framework");
      throw error;
    }
    debugTiming("runtime cache publish and placement", phase);
    found?.({
      status: "miss",
      entry: adopted.tree.digest,
      framework,
      linked: placed.linked,
      copied: placed.copied,
      ...(adopted.moved ? {} : { crossVolume: true as const }),
    });
    // Copied across volumes, the stage kept its whole third-party tree: strip
    // it in place.
    if (!adopted.moved && strip && !options.leaveWhole)
      stripRuntimeIrrelevant(join(stage, "node_modules"));
    return placed.trees;
  }
  if (cache) {
    // The stage holds the third-party tree only: add PiShip's layer from the
    // build input.
    writeFrameworkFiles(stage);
    found?.({ status: "unusable", linked: 0, copied: 0 });
    progress?.(
      "The runtime cache is not usable here (the directory is locked or cannot be written); building without it",
    );
  }
  if (strip && !options.leaveWhole)
    stripRuntimeIrrelevant(join(stage, "node_modules"));
  debugTiming("strip runtime-irrelevant files", phase);
  return [];
}

/**
 * Assemble the portable payload from a current lock. By default the release
 * `source` and `install-script` gates run first (piship/v1alpha4 locks), so a
 * distributable build never installs an unapproved source or an unreviewed
 * npm lifecycle script; `dev` and `test` pass `supplyChainGates: false` to
 * stay lenient while iterating. The staging of builds that were killed is
 * not removed from `outputRoot` unless `reclaimStaging` says it may be (see
 * `sweepOutputStaging`).
 */
export function buildDistribution(
  manifestPath: string,
  outputRoot = resolve("dist"),
  options: {
    readonly supplyChainGates?: boolean;
    /** Release builds defer bundling until dependency evidence is collected. */
    readonly bundle?: boolean;
    /**
     * The caller runs `bundleDistribution` on the result once it has collected
     * evidence from the full dependency tree. For a manifest that asks for a
     * bundle, strip and the inventory are then left to the bundler, which
     * writes both for the bundled payload.
     */
    readonly deferBundle?: boolean;
    /** Local builds reuse runtime bytes; release qualification passes false. */
    readonly cache?: boolean;
    /**
     * The immutable runtime cache (`runtimeCacheFor`), or `true` for the
     * default one of this lock, which is only looked up when the build has to
     * assemble a payload (it runs `npm --version`). A hit replaces the npm
     * install, strip, and hashing of the dependency tree; a miss fills it.
     * Independent of `cache`, which reuses a whole earlier output.
     */
    readonly runtimeCache?: RuntimeCache | true;
    /** Told whether the runtime came from the cache, was installed into it, or could not use it. */
    readonly onRuntimeCache?: (report: RuntimeCacheReport) => void;
    /** Told what became of the vendored Pi packages' closures and shared dependencies. */
    readonly onPackageFootprint?: (report: PackageFootprint) => void;
    /** Receives a short line as each long step starts. */
    readonly progress?: (step: string) => void;
  } & OutputStagingOptions = {},
): string {
  const lock = requireCurrentLock(manifestPath);
  if (options.supplyChainGates !== false) checkPackageSources(lock, "Build");
  const buildInput = authoringBuildInput();
  const output = join(outputRoot, lock.app.id);
  const manifest = readManifest(manifestPath);
  const { strip, bundle: wantsBundle } = releaseOptions(
    manifest.schema,
    manifest.lifecycle?.release,
  );
  const deferred = wantsBundle && options.deferBundle === true;
  const bundling = wantsBundle && options.bundle !== false && !deferred;
  const cacheStarted = process.hrtime.bigint();
  const keys =
    options.cache === false || deferred
      ? undefined
      : buildCacheKeys(buildInput, manifestPath, lock, {
          bundle: bundling,
          strip,
          supplyChainGates: options.supplyChainGates !== false,
        });
  const cached = keys ? readBuildCache(output) : undefined;
  if (cached && keys && cached.runtimeKey === keys.runtimeKey) {
    if (cached.key !== keys.key) {
      options.progress?.(
        "Updating distribution files using the cached runtime",
      );
      refreshCachedDistribution(
        output,
        resolve(manifestPath),
        lock,
        cached,
        keys,
      );
    } else options.progress?.("Reusing the unchanged payload");
    debugTiming("build cache reuse", cacheStarted);
    return output;
  }
  debugTiming("build cache lookup", cacheStarted);
  const wanted =
    options.runtimeCache === true
      ? runtimeCacheFor(lock)
      : options.runtimeCache;
  // A cache built for another strip setting would place the wrong files.
  const runtimeCache = wanted?.strip === strip ? wanted : undefined;
  const base = dirname(resolve(manifestPath));
  mkdirSync(outputRoot, { recursive: true });
  sweepOutputStaging(outputRoot, "build", options);
  // The payload is assembled in `payload`, beside the staging directory's
  // ownership marker, so the marker never becomes part of the payload (its
  // inventory lists every file).
  const temporary = createTemporaryDirectory(outputRoot, "build", lock.app.id);
  const stage = join(temporary.path, "payload");
  mkdirSync(stage);
  try {
    let phase = process.hrtime.bigint();
    let vendored: readonly VendoredPiPackage[] = [];
    const assemble = (): void => {
      const started = process.hrtime.bigint();
      options.progress?.("Assembling and verifying the payload");
      mkdirSync(join(stage, "bin"), { recursive: true });
      mkdirSync(join(stage, "metadata"), { recursive: true });
      copyFileSync(manifestPath, join(stage, "piship.yaml"));
      for (const resource of lock.resources) {
        const target = join(stage, "resources", resource.path);
        mkdirSync(dirname(target), { recursive: true });
        copyFileSync(join(base, resource.path), target);
      }
      copyFileSync(join(base, "piship.lock"), join(stage, "piship.lock"));
      if (lock.packages?.length) {
        // Pi packages are vendored by PiShip from exactly what the lock pins,
        // without lifecycle scripts; Pi never installs one.
        options.progress?.(
          "Vendoring the Pi packages (npm ci --ignore-scripts)",
        );
        vendored = vendorPiPackages(
          lock,
          readManifest(manifestPath),
          base,
          stage,
          {
            supplyChainGates: options.supplyChainGates !== false,
          },
        );
        // The runtime was stripped before the packages were vendored, so the
        // maps and declarations they ship are removed here.
        if (strip)
          stripRuntimeIrrelevant(join(stage, PI_PACKAGE_VENDOR_DIRECTORY));
      }
      if (lock.searchTools) {
        // The executables come from the cached upstream archives, checked
        // against the lock; `downloadLockedSearchTools` fills the cache first.
        options.progress?.("Placing the bundled search tools");
        const skipped = stageSearchTools(lock, stage);
        if (skipped.length)
          options.progress?.(
            `Notice: no bundled ${skipped.join(" or ")} for ${process.platform}-${process.arch}, so this build runs without ${skipped.length > 1 ? "them" : "it"}. List the target in release.targets and run piship lock to bundle ${skipped.length > 1 ? "them" : "it"}.`,
          );
      }
      writeFileSync(
        join(stage, "metadata", "target.json"),
        `${JSON.stringify({ platform: process.platform, arch: process.arch }, null, 2)}\n`,
      );
      const command = join(stage, "bin", lock.app.command);
      writeFileSync(command, launcherSource());
      if (process.platform !== "win32") chmodSync(command, 0o755);
      writeFileSync(
        `${command}.cmd`,
        `@echo off\r\nnode "%~dp0\\${lock.app.command}" %*\r\n`,
      );
      writeFileSync(join(stage, "piship.mjs"), portableCliSource());
      debugTiming("resource/payload assembly", started);
    };
    const trees = placeRuntime(stage, {
      cache: runtimeCache,
      strip,
      // The bundler drops the whole tree, so deleting from it is wasted work.
      leaveWhole: bundling || deferred,
      progress: options.progress,
      found: options.onRuntimeCache,
      meanwhile: assemble,
      // Only a distribution with Pi packages to vendor has work worth a thread.
      overlap: (lock.packages?.length ?? 0) > 0,
    });
    phase = process.hrtime.bigint();
    if (vendored.length && wantsBundle) {
      // release.bundle covers the Pi packages too: a closure that is safe to
      // bundle is, identical dependencies are shared, and the rest stays as
      // vendored. What is decided is in metadata/pi-package-footprint.json.
      options.progress?.("Sharing and bundling the Pi package closures");
      const footprint = optimizePiPackages(stage, {
        esbuild: loadEsbuild(join(stage, "package.json")),
        bundle: true,
        packages: vendored.map((item) => ({
          id: item.locked.id,
          directory: item.directory,
          packageRoot: item.packageRoot,
          resources: item.locked.resources,
        })),
      });
      options.onPackageFootprint?.(footprint);
      debugTiming("pi package footprint", phase);
      phase = process.hrtime.bigint();
    }
    // After the footprint: a closure written as JavaScript would read as
    // bundle-safe there, and bundling decisions stay as documented.
    const transpiling = vendored.filter((item) => item.locked.pretranspile);
    if (transpiling.length) {
      options.progress?.(
        `Writing the TypeScript closure of ${transpiling.map((item) => item.locked.id).join(", ")} as JavaScript`,
      );
      const esbuild = loadEsbuild(join(stage, "package.json"));
      pretranspileClosures(
        transpiling.map((item) => ({
          id: item.locked.id,
          root: item.directory,
          packagePath: relative(item.directory, item.packageRoot)
            .split(sep)
            .join("/"),
          resources: item.locked.resources,
          esbuild,
        })),
        esbuild,
      ).forEach((result, index) => {
        options.progress?.(
          `pi package pretranspile: ${transpiling[index]?.locked.id}: ${result.written.length} modules written${result.kept.length ? `, ${result.kept.length} kept (JavaScript exists)` : ""}`,
        );
      });
      debugTiming("pi package pretranspile", phase);
      phase = process.hrtime.bigint();
    }
    if (bundling) {
      options.progress?.("Bundling the portable runtime");
      bundleDistribution(stage, {
        ...(runtimeCache ? { cache: runtimeCache } : {}),
        strip,
      });
      debugTiming("runtime bundling and inventory", phase);
    } else if (!deferred) {
      // Files placed from a cache entry keep the digests taken when it was
      // created; everything else is hashed from its bytes.
      writeFileSync(
        join(stage, "metadata", "inventory.json"),
        `${JSON.stringify(
          inventory(
            stage,
            runtimeCache
              ? Object.assign(
                  {},
                  ...trees.map((tree) => plainInventory(tree, runtimeCache)),
                )
              : {},
          ),
          null,
          2,
        )}\n`,
      );
      debugTiming("inventory hashing", phase);
    }
    phase = process.hrtime.bigint();
    rmSync(buildCachePath(output), { force: true });
    removeTree(output, { attempts: 3 });
    renameWithRetry(stage, output);
    if (keys)
      writeBuildCache(
        output,
        keys.key,
        keys.runtimeKey,
        lock.app.command,
        JSON.parse(
          readFileSync(join(output, "metadata", "inventory.json"), "utf8"),
        ) as Record<string, string>,
      );
    debugTiming("output replacement", phase);
    return output;
  } finally {
    temporary.remove();
  }
}
