import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { launcherSource, portableCliSource } from "./launcher-source.js";
import { debugTiming, requireCurrentLock } from "./lock.js";
import { inventory, removeNpmBins } from "./payload.js";
import { checkPackageSources } from "./release.js";
import { buildInput, workspacePackages } from "./runtime-dependencies.js";

/**
 * Assemble the portable payload from a current lock. By default the release
 * `source` and `install-script` gates run first (piship/v1alpha4 locks), so a
 * distributable build never installs an unapproved source or an unreviewed
 * npm lifecycle script; `dev` and `test` pass `supplyChainGates: false` to
 * stay lenient while iterating.
 */
export function buildDistribution(
  manifestPath: string,
  outputRoot = resolve("dist"),
  options: { readonly supplyChainGates?: boolean } = {},
): string {
  const lock = requireCurrentLock(manifestPath);
  if (options.supplyChainGates !== false) checkPackageSources(lock, "Build");
  const output = join(outputRoot, lock.app.id);
  const base = dirname(resolve(manifestPath));
  mkdirSync(outputRoot, { recursive: true });
  const stage = mkdtempSync(join(outputRoot, `.piship-${lock.app.id}-`));
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
    removeNpmBins(join(stage, "node_modules"));
    debugTiming("removeNpmBins", phase);
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
    rmSync(output, { recursive: true, force: true });
    renameSync(stage, output);
    return output;
  } catch (error) {
    rmSync(stage, { recursive: true, force: true });
    throw error;
  }
}
