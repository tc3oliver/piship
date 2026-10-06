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
import { dirname, join, resolve } from "node:path";
import { createTemporaryDirectory, debugTiming } from "@piship/contracts";
import { readManifest } from "@piship/schema";
import { bundleDistribution } from "./bundle.js";
import {
  buildCacheKeys,
  buildCachePath,
  readBuildCache,
  refreshCachedDistribution,
  writeBuildCache,
} from "./build-cache.js";
import { launcherSource, portableCliSource } from "./launcher-source.js";
import { requireCurrentLock } from "./lock.js";
import {
  inventory,
  removeForeignPlatformPackages,
  removeNpmBins,
  stripRuntimeIrrelevant,
} from "./payload.js";
import { PI_PACKAGE_VENDOR_DIRECTORY } from "./pi-packages/gates.js";
import { vendorPiPackages } from "./pi-packages/lock.js";
import { checkPackageSources } from "./release/index.js";
import {
  adoptInstallTree,
  discardInstallTree,
  type InstallTree,
  lookupInstallTree,
  materializeInstallTree,
  plainInventory,
  type RuntimeCache,
} from "./runtime-cache.js";
import { renameWithRetry } from "./rename-retry.js";
import { stageSearchTools } from "./search-tools/index.js";
import { buildInput, workspacePackages } from "./runtime-dependencies.js";
import {
  sweepOutputStaging,
  type OutputStagingOptions,
} from "./temporary-directories.js";

/**
 * npm-install the runtime dependencies into the empty `stage`: PiShip's own
 * packages as real copies of the build input (npm only links them, and keeps
 * any dependency it could not hoist beside their manifests), then the locked
 * third-party tree, minus npm's `.bin` links and the optional packages built
 * for other platforms. Nothing is stripped here.
 */
function installRuntime(
  stage: string,
  progress: ((step: string) => void) | undefined,
): void {
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
  const install =
    process.platform === "win32"
      ? spawnSync(
          "cmd.exe",
          ["/d", "/s", "/c", "npm ci --omit=dev --no-audit --no-fund"],
          { cwd: stage, encoding: "utf8" },
        )
      : spawnSync("npm", ["ci", "--omit=dev", "--no-audit", "--no-fund"], {
          cwd: stage,
          encoding: "utf8",
        });
  if (install.status !== 0)
    throw new Error(
      `Portable runtime assembly failed: ${install.stderr || install.error?.message || install.stdout}`,
    );
  debugTiming("npm ci --omit=dev", phase);
  phase = process.hrtime.bigint();
  for (const name of workspacePackages) {
    const target = join(stage, "node_modules", "@piship", name);
    rmSync(target, { recursive: true, force: true });
    mkdirSync(target, { recursive: true });
    copyFileSync(
      join(buildInput, "packages", name, "package.json"),
      join(target, "package.json"),
    );
    cpSync(join(buildInput, "packages", name, "dist"), join(target, "dist"), {
      recursive: true,
    });
    // Dependencies npm could not hoist were installed beside the manifest.
    const nested = join(stage, "packages", name, "node_modules");
    if (existsSync(nested))
      renameWithRetry(nested, join(target, "node_modules"));
  }
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
  debugTiming("removeNpmBins/foreign platform packages", phase);
}

/** What a build says about where its runtime tree came from. */
export interface RuntimeCacheReport {
  /** A hit placed an entry, a miss installed and published one, unusable built without the cache. */
  readonly status: "hit" | "miss" | "unusable";
  /** The entry's identity (the digest of its file list), when there was one. */
  readonly entry?: string;
  /** How the files reached the payload: hardlinked from the entry, or copied. */
  readonly linked: number;
  readonly copied: number;
  /** The cache is on another volume than the build, so the entry was copied in. */
  readonly crossVolume?: true;
}

/**
 * Put the runtime dependency tree into the empty `stage`: placed from the
 * runtime cache when it holds one, otherwise installed (and, with a cache,
 * moved into it and placed from there). Returns the cache entry the tree came
 * from, whose digests a payload inventory can take.
 */
function placeRuntime(
  stage: string,
  options: {
    readonly cache: RuntimeCache | undefined;
    readonly strip: boolean;
    readonly leaveWhole: boolean;
    readonly progress: ((step: string) => void) | undefined;
    readonly found: ((report: RuntimeCacheReport) => void) | undefined;
  },
): InstallTree | undefined {
  const { cache, strip, progress, found } = options;
  let phase = process.hrtime.bigint();
  if (cache) {
    const hit = lookupInstallTree(cache);
    if (hit) {
      progress?.("Reusing the cached runtime packages");
      try {
        const placed = materializeInstallTree(hit, stage, { strip });
        debugTiming("runtime cache placement", phase);
        found?.({ status: "hit", entry: hit.digest, ...placed });
        return hit;
      } catch {
        // Damaged or evicted underneath this build: install again, and publish
        // that tree in its place.
        discardInstallTree(cache);
        rmSync(stage, { recursive: true, force: true });
        mkdirSync(stage);
      }
    }
  }
  installRuntime(stage, progress);
  phase = process.hrtime.bigint();
  const adopted = cache && adoptInstallTree(cache, stage);
  if (cache && adopted) {
    let placed = { linked: 0, copied: 0 };
    if (adopted.moved)
      try {
        placed = materializeInstallTree(adopted.tree, stage, { strip });
      } catch (error) {
        // This tree is what is left of the install: never reuse it.
        discardInstallTree(cache);
        throw error;
      }
    debugTiming("runtime cache publish and placement", phase);
    found?.({
      status: "miss",
      entry: adopted.tree.digest,
      ...placed,
      ...(adopted.moved ? {} : { crossVolume: true as const }),
    });
    // Copied across volumes, the stage kept its whole tree: strip it in place.
    if (adopted.moved) return adopted.tree;
    if (strip && !options.leaveWhole) stripRuntimeIrrelevant(stage);
    return adopted.tree;
  }
  if (cache) {
    found?.({ status: "unusable", linked: 0, copied: 0 });
    progress?.(
      "The runtime cache is not usable here (the directory is locked or cannot be written); building without it",
    );
  }
  if (strip && !options.leaveWhole) stripRuntimeIrrelevant(stage);
  debugTiming("strip runtime-irrelevant files", phase);
  return undefined;
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
     * The immutable runtime cache (`runtimeCacheFor`). A hit replaces the npm
     * install, strip, and hashing of the dependency tree; a miss fills it.
     * Independent of `cache`, which reuses a whole earlier output.
     */
    readonly runtimeCache?: RuntimeCache;
    /** Told whether the runtime came from the cache, was installed into it, or could not use it. */
    readonly onRuntimeCache?: (report: RuntimeCacheReport) => void;
    /** Receives a short line as each long step starts. */
    readonly progress?: (step: string) => void;
  } & OutputStagingOptions = {},
): string {
  const lock = requireCurrentLock(manifestPath);
  if (options.supplyChainGates !== false) checkPackageSources(lock, "Build");
  if (!existsSync(join(buildInput, "packages", "core", "dist")))
    throw new Error(
      "This bundled payload contains runtime management commands only. Build distributions from the PiShip source checkout.",
    );
  const output = join(outputRoot, lock.app.id);
  const manifest = readManifest(manifestPath);
  const strip = manifest.lifecycle?.release.strip === true;
  const wantsBundle = manifest.lifecycle?.release.bundle === true;
  const deferred = wantsBundle && options.deferBundle === true;
  const bundling = wantsBundle && options.bundle !== false && !deferred;
  // A cache built for another strip setting would place the wrong files.
  const runtimeCache =
    options.runtimeCache?.strip === strip ? options.runtimeCache : undefined;
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
    const tree = placeRuntime(stage, {
      cache: runtimeCache,
      strip,
      // The bundler drops the whole tree, so deleting from it is wasted work.
      leaveWhole: bundling || deferred,
      progress: options.progress,
      found: options.onRuntimeCache,
    });
    phase = process.hrtime.bigint();
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
      options.progress?.("Vendoring the Pi packages (npm ci --ignore-scripts)");
      vendorPiPackages(lock, readManifest(manifestPath), base, stage, {
        supplyChainGates: options.supplyChainGates !== false,
      });
      // The runtime was stripped before the packages were vendored, so the
      // maps and declarations they ship are removed here.
      if (strip)
        stripRuntimeIrrelevant(join(stage, PI_PACKAGE_VENDOR_DIRECTORY));
    }
    if (lock.searchTools) {
      // The executables come from the cached upstream archives, checked
      // against the lock; `downloadLockedSearchTools` fills the cache first.
      options.progress?.("Placing the bundled search tools");
      stageSearchTools(lock, stage);
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
    debugTiming("resource/payload assembly", phase);
    phase = process.hrtime.bigint();
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
            tree && runtimeCache ? plainInventory(tree, runtimeCache) : {},
          ),
          null,
          2,
        )}\n`,
      );
      debugTiming("inventory hashing", phase);
    }
    phase = process.hrtime.bigint();
    rmSync(buildCachePath(output), { force: true });
    rmSync(output, { recursive: true, force: true });
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
