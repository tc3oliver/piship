import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
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
import { vendorPiPackages } from "./pi-packages/lock.js";
import { checkPackageSources } from "./release/index.js";
import { stageSearchTools } from "./search-tools/index.js";
import { buildInput, workspacePackages } from "./runtime-dependencies.js";
import {
  sweepOutputStaging,
  type OutputStagingOptions,
} from "./temporary-directories.js";

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
    /** Local builds reuse runtime bytes; release qualification passes false. */
    readonly cache?: boolean;
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
  const cacheStarted = process.hrtime.bigint();
  const keys =
    options.cache === false
      ? undefined
      : buildCacheKeys(buildInput, manifestPath, lock, {
          bundle:
            options.bundle !== false &&
            manifest.lifecycle?.release.bundle === true,
          strip: manifest.lifecycle?.release.strip === true,
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
    copyFileSync(join(buildInput, "package.json"), join(stage, "package.json"));
    copyFileSync(
      join(buildInput, "package-lock.json"),
      join(stage, "package-lock.json"),
    );
    for (const name of workspacePackages) {
      const folder = join(stage, "packages", name);
      mkdirSync(folder, { recursive: true });
      copyFileSync(
        join(buildInput, "packages", name, "package.json"),
        join(folder, "package.json"),
      );
      cpSync(join(buildInput, "packages", name, "dist"), join(folder, "dist"), {
        recursive: true,
      });
    }
    debugTiming("build input copy", phase);
    phase = process.hrtime.bigint();
    options.progress?.("Installing the runtime packages (npm ci)");
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
      cpSync(join(stage, "packages", name), target, { recursive: true });
    }
    cpSync(
      buildInput,
      join(stage, "node_modules", "@piship", "core", "dist", "build-input"),
      { recursive: true },
    );
    rmSync(join(stage, "packages"), { recursive: true, force: true });
    debugTiming("PiShip/build-input copying", phase);
    phase = process.hrtime.bigint();
    options.progress?.("Assembling and verifying the payload");
    removeNpmBins(join(stage, "node_modules"));
    removeForeignPlatformPackages(stage);
    debugTiming("removeNpmBins/foreign platform packages", phase);
    phase = process.hrtime.bigint();
    if (readManifest(manifestPath).lifecycle?.release.strip === true)
      stripRuntimeIrrelevant(stage);
    debugTiming("strip runtime-irrelevant files", phase);
    phase = process.hrtime.bigint();
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
    writeFileSync(
      join(stage, "metadata", "inventory.json"),
      `${JSON.stringify(inventory(stage), null, 2)}\n`,
    );
    debugTiming("inventory hashing", phase);
    phase = process.hrtime.bigint();
    if (
      options.bundle !== false &&
      readManifest(manifestPath).lifecycle?.release.bundle === true
    ) {
      options.progress?.("Bundling the portable runtime");
      bundleDistribution(stage);
    }
    debugTiming("runtime bundling", phase);
    phase = process.hrtime.bigint();
    rmSync(buildCachePath(output), { force: true });
    rmSync(output, { recursive: true, force: true });
    renameSync(stage, output);
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
