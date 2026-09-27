import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  renameSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ManifestError,
  readManifest,
  type Manifest,
  type PishipSchemaVersion,
} from "@piship/schema";

export interface DistributionId {
  readonly value: string;
}
export interface ResolvedDistribution {
  readonly id: DistributionId;
  readonly schema: PishipSchemaVersion;
  readonly piVersion: string;
}
export const LOCK_SCHEMA_VERSION = "piship-lock/v1alpha1";
export const PI_PACKAGE = "@earendil-works/pi-coding-agent";
export const PI_VERSION = "0.87.1";
export const PISHIP_VERSION = "0.1.0";
export interface LockedResource {
  readonly kind: "instructions" | "skills" | "extensions" | "prompts";
  readonly path: string;
  readonly sha256: string;
}
export interface DistributionLock {
  readonly schema: typeof LOCK_SCHEMA_VERSION;
  readonly manifest: {
    readonly schema: PishipSchemaVersion;
    readonly sha256: string;
  };
  readonly app: Manifest["app"];
  readonly deployment: Manifest["deployment"];
  readonly runtime: {
    readonly package: typeof PI_PACKAGE;
    readonly version: string;
    readonly pishipVersion: string;
    readonly npmLockSha256: string;
    readonly packages: readonly {
      path: string;
      version: string;
      integrity: string;
    }[];
  };
  readonly resources: readonly LockedResource[];
  readonly declared: Manifest["resources"];
}
const workspaceRoot = fileURLToPath(new URL("../../../", import.meta.url));
const workspacePackages = ["schema", "core", "pi", "cli"] as const;
function runtimeDependencies(): DistributionLock["runtime"] {
  const source = readFileSync(join(workspaceRoot, "package-lock.json"));
  const npmLock = JSON.parse(source.toString()) as {
    packages: Record<
      string,
      { version?: string; integrity?: string; dev?: boolean }
    >;
  };
  const packages = Object.entries(npmLock.packages)
    .filter(
      ([path, value]) =>
        path.startsWith("node_modules/") && !value.dev && value.integrity,
    )
    .map(([path, value]) => ({
      path,
      version: value.version ?? "",
      integrity: value.integrity ?? "",
    }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const pi = packages.find(
    (item) => item.path === `node_modules/${PI_PACKAGE}`,
  );
  if (pi?.version !== PI_VERSION)
    throw new Error("Committed npm lock does not pin the expected Pi runtime");
  return {
    package: PI_PACKAGE,
    version: PI_VERSION,
    pishipVersion: PISHIP_VERSION,
    npmLockSha256: hash(source),
    packages,
  };
}
export function distributionStateDirectory(id: DistributionId): string {
  if (!/^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(id.value))
    throw new Error(
      "Distribution id must contain lowercase letters, digits or hyphens",
    );
  return `.piship/${id.value}`;
}
export function runtimeStateDirectory(
  id: DistributionId,
  stateHome = process.env.PISHIP_STATE_HOME ?? join(homedir(), ".piship"),
): string {
  distributionStateDirectory(id);
  return join(resolve(stateHome), id.value);
}
function hash(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
function manifestDigest(manifest: Manifest): string {
  return hash(JSON.stringify(manifest));
}
export function checkPiVersion(manifest: Manifest): void {
  if (manifest.runtime.pi !== PI_VERSION)
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      `Pi ${manifest.runtime.pi} is not available in this PiShip build. Pinned runtime: ${PI_VERSION}.`,
    );
}
function walkResource(root: string, current: string, output: string[]): void {
  const stat = lstatSync(current);
  if (stat.isSymbolicLink())
    throw new ManifestError(
      "unsafe path/name",
      current,
      "Resource symlinks are not allowed",
    );
  if (stat.isDirectory()) {
    for (const child of readdirSync(current).sort())
      walkResource(root, join(current, child), output);
    return;
  }
  if (!stat.isFile())
    throw new ManifestError(
      "invalid field",
      current,
      "Expected a regular file or directory",
    );
  output.push(relative(root, current).split(sep).join("/"));
}
export function resolveResources(
  manifest: Manifest,
  manifestPath: string,
): LockedResource[] {
  const base = dirname(resolve(manifestPath));
  const output: LockedResource[] = [];
  for (const kind of [
    "instructions",
    "skills",
    "extensions",
    "prompts",
  ] as const) {
    for (const declared of manifest.resources[kind]) {
      const absolute = resolve(base, declared);
      if (!absolute.startsWith(`${base}${sep}`))
        throw new ManifestError(
          "unsafe path/name",
          `resources.${kind}`,
          `Path escapes manifest directory: ${declared}`,
        );
      if (!existsSync(absolute))
        throw new ManifestError(
          "missing resource",
          `resources.${kind}`,
          `${declared} does not exist`,
        );
      let component = base;
      for (const segment of relative(base, absolute).split(sep)) {
        component = join(component, segment);
        if (lstatSync(component).isSymbolicLink())
          throw new ManifestError(
            "unsafe path/name",
            `resources.${kind}`,
            `Resource symlinks are not allowed: ${declared}`,
          );
      }
      if (kind === "instructions" && !lstatSync(absolute).isFile())
        throw new ManifestError(
          "invalid field",
          `resources.${kind}`,
          `${declared} must be a file`,
        );
      const files: string[] = [];
      walkResource(base, absolute, files);
      if (files.length === 0)
        throw new ManifestError(
          "missing resource",
          `resources.${kind}`,
          `${declared} is empty`,
        );
      if (
        kind === "extensions" &&
        !files.some((file) => /\.[cm]?[jt]s$/.test(file))
      )
        throw new ManifestError(
          "invalid field",
          `resources.${kind}`,
          `${declared} has no JavaScript or TypeScript extension entry`,
        );
      for (const file of files)
        output.push({
          kind,
          path: file,
          sha256: hash(readFileSync(join(base, file))),
        });
    }
  }
  output.sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path),
  );
  const seen = new Set<string>();
  for (const item of output) {
    const key = `${item.kind}:${item.path}`;
    if (seen.has(key))
      throw new ManifestError(
        "invalid field",
        `resources.${item.kind}`,
        `Duplicate resource: ${item.path}`,
      );
    seen.add(key);
  }
  return output;
}
export function resolveLock(manifestPath: string): DistributionLock {
  const manifest = readManifest(manifestPath);
  checkPiVersion(manifest);
  return {
    schema: LOCK_SCHEMA_VERSION,
    manifest: { schema: manifest.schema, sha256: manifestDigest(manifest) },
    app: manifest.app,
    deployment: manifest.deployment,
    runtime: runtimeDependencies(),
    resources: resolveResources(manifest, manifestPath),
    declared: manifest.resources,
  };
}
export function lockManifest(manifestPath: string): string {
  const lock = resolveLock(manifestPath);
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`);
  return path;
}
export function requireCurrentLock(manifestPath: string): DistributionLock {
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  const expected = `${JSON.stringify(resolveLock(manifestPath), null, 2)}\n`;
  if (!existsSync(path))
    throw new Error(
      `Lockfile missing: ${path}. Run piship lock ${manifestPath}`,
    );
  if (readFileSync(path, "utf8") !== expected)
    throw new Error(
      `Lockfile is stale: ${path}. Run piship lock ${manifestPath}`,
    );
  return JSON.parse(expected) as DistributionLock;
}
function launcherSource(): string {
  return `#!/usr/bin/env node\nimport { fileURLToPath } from "node:url";\nimport { verifyPayload } from "@piship/core";\nconst directory = fileURLToPath(new URL("..", import.meta.url));\ntry {\n  const version = process.versions.node.split(".").map(Number);\n  if (version[0] < 22 || (version[0] === 22 && version[1] < 19)) throw new Error("Node.js 22.19.0 or newer is required; install Node separately before launch");\n  const metadata = verifyPayload(directory);\n  const { launchPiDistribution } = await import("@piship/pi");\n  await launchPiDistribution({ distributionDir: directory, metadata, args: process.argv.slice(2) });\n} catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }\n`;
}
function portableCliSource(): string {
  return `const version = process.versions.node.split(".").map(Number);\nif (version[0] < 22 || (version[0] === 22 && version[1] < 19)) { console.error("Node.js 22.19.0 or newer is required. Install Node separately."); process.exitCode = 1; } else { const { runCli } = await import("@piship/cli"); process.exitCode = runCli(process.argv.slice(2), { stdout: (message) => console.log(message), stderr: (message) => console.error(message) }); }\n`;
}
function inventory(root: string): Record<string, string> {
  const output: Record<string, string> = {};
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      const key = relative(root, path).split(sep).join("/");
      if (stat.isSymbolicLink())
        throw new Error(`Payload symlink is not allowed: ${key}`);
      if (stat.isDirectory()) visit(path);
      else if (stat.isFile() && key !== "metadata/inventory.json")
        output[key] = hash(readFileSync(path));
      else if (!stat.isFile())
        throw new Error(`Unsupported payload entry: ${key}`);
    }
  };
  visit(root);
  return output;
}
function removeNpmBins(directory: string): void {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (name === ".bin") rmSync(path, { recursive: true, force: true });
    else if (lstatSync(path).isDirectory()) removeNpmBins(path);
  }
}
export function verifyPayload(directory: string): DistributionLock {
  const root = resolve(directory);
  const inventoryPath = join(root, "metadata", "inventory.json");
  const expected = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
    string,
    string
  >;
  const actual = inventory(root);
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    throw new Error(
      "Installed payload integrity mismatch; reinstall this distribution",
    );
  const lock = JSON.parse(
    readFileSync(join(root, "metadata", "distribution.json"), "utf8"),
  ) as DistributionLock;
  const manifest = readManifest(join(root, "piship.yaml"));
  if (
    manifestDigest(manifest) !== lock.manifest.sha256 ||
    JSON.stringify(manifest.app) !== JSON.stringify(lock.app)
  )
    throw new Error(
      "Installed manifest and lock mismatch; reinstall this distribution",
    );
  if (
    lock.runtime.npmLockSha256 !==
    hash(readFileSync(join(root, "package-lock.json")))
  )
    throw new Error("Installed npm lock mismatch; reinstall this distribution");
  return lock;
}
export function buildDistribution(
  manifestPath: string,
  outputRoot = resolve("dist"),
): string {
  const lock = requireCurrentLock(manifestPath);
  const output = join(outputRoot, lock.app.id);
  const base = dirname(resolve(manifestPath));
  mkdirSync(outputRoot, { recursive: true });
  const stage = mkdtempSync(join(outputRoot, `.piship-${lock.app.id}-`));
  try {
    copyFileSync(
      join(workspaceRoot, "package.json"),
      join(stage, "package.json"),
    );
    copyFileSync(
      join(workspaceRoot, "package-lock.json"),
      join(stage, "package-lock.json"),
    );
    for (const name of workspacePackages) {
      const folder = join(stage, "packages", name);
      mkdirSync(folder, { recursive: true });
      copyFileSync(
        join(workspaceRoot, "packages", name, "package.json"),
        join(folder, "package.json"),
      );
      cpSync(
        join(workspaceRoot, "packages", name, "dist"),
        join(folder, "dist"),
        { recursive: true },
      );
    }
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
    for (const name of workspacePackages) {
      const target = join(stage, "node_modules", "@piship", name);
      rmSync(target, { recursive: true, force: true });
      cpSync(join(stage, "packages", name), target, { recursive: true });
    }
    rmSync(join(stage, "packages"), { recursive: true, force: true });
    removeNpmBins(join(stage, "node_modules"));
    mkdirSync(join(stage, "bin"), { recursive: true });
    mkdirSync(join(stage, "metadata"), { recursive: true });
    copyFileSync(manifestPath, join(stage, "piship.yaml"));
    for (const resource of lock.resources) {
      const target = join(stage, "resources", resource.path);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(join(base, resource.path), target);
    }
    writeFileSync(
      join(stage, "metadata", "distribution.json"),
      `${JSON.stringify(lock, null, 2)}\n`,
    );
    const command = join(stage, "bin", lock.app.command);
    writeFileSync(command, launcherSource());
    if (process.platform !== "win32") chmodSync(command, 0o755);
    writeFileSync(
      `${command}.cmd`,
      `@echo off\r\nnode "%~dp0\\${lock.app.command}" %*\r\n`,
    );
    writeFileSync(join(stage, "piship.mjs"), portableCliSource());
    writeFileSync(
      join(stage, "metadata", "inventory.json"),
      `${JSON.stringify(inventory(stage), null, 2)}\n`,
    );
    rmSync(output, { recursive: true, force: true });
    renameSync(stage, output);
    return output;
  } catch (error) {
    rmSync(stage, { recursive: true, force: true });
    throw error;
  }
}
export interface InstallReceipt {
  readonly app: DistributionLock["app"];
  readonly payload: string;
  readonly commandPath: string;
}
export function installHome(): string {
  return resolve(
    process.env.PISHIP_INSTALL_HOME ??
      join(homedir(), ".local", "share", "piship"),
  );
}
export function binHome(): string {
  return resolve(
    process.env.PISHIP_BIN_HOME ?? join(homedir(), ".local", "bin"),
  );
}
function receiptPath(id: string): string {
  distributionStateDirectory({ value: id });
  return join(installHome(), "receipts", `${id}.json`);
}
export function installDistribution(
  artifact: string,
  useExistingState = false,
): InstallReceipt {
  const source = resolve(artifact);
  const lock = verifyPayload(source);
  const { id, command, version } = lock.app;
  const appDirectory = join(installHome(), "apps", id);
  const target = join(appDirectory, version);
  const commandPath = join(
    binHome(),
    process.platform === "win32" ? `${command}.cmd` : command,
  );
  const targetScript = join(target, "bin", command);
  if (
    process.platform === "win32" &&
    ["%", "!", '"', "\r", "\n"].some((character) =>
      targetScript.includes(character),
    )
  )
    throw new Error(
      "Install path contains characters unsafe for a Windows command shim",
    );
  if (
    existsSync(receiptPath(id)) ||
    existsSync(appDirectory) ||
    existsSync(commandPath)
  )
    throw new Error(
      `Install collision for ${id}/${command}; uninstall the existing distribution first`,
    );
  if (!useExistingState && existsSync(runtimeStateDirectory({ value: id })))
    throw new Error(
      `State already exists for ${id}; pass --use-existing-state to explicitly reuse it`,
    );
  mkdirSync(dirname(target), { recursive: true });
  mkdirSync(dirname(commandPath), { recursive: true });
  mkdirSync(dirname(receiptPath(id)), { recursive: true });
  try {
    cpSync(source, target, { recursive: true });
    verifyPayload(target);
    if (process.platform === "win32")
      writeFileSync(
        commandPath,
        `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${targetScript}" %*\r\n`,
      );
    else {
      writeFileSync(
        commandPath,
        `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '${targetScript.replaceAll("'", "'\"'\"'")}' "$@"\n`,
      );
      chmodSync(commandPath, 0o755);
    }
    const receipt = { app: lock.app, payload: target, commandPath };
    writeFileSync(receiptPath(id), `${JSON.stringify(receipt, null, 2)}\n`);
    return receipt;
  } catch (error) {
    rmSync(commandPath, { force: true });
    rmSync(target, { recursive: true, force: true });
    if (existsSync(appDirectory)) rmdirSync(appDirectory);
    throw error;
  }
}
export function readInstallReceipt(id: string): InstallReceipt {
  const path = receiptPath(id);
  if (!existsSync(path))
    throw new Error(`No PiShip installation recorded for ${id}`);
  const receipt = JSON.parse(readFileSync(path, "utf8")) as InstallReceipt;
  const expectedPayload = join(installHome(), "apps", id, receipt.app.version);
  const expectedCommand = join(
    binHome(),
    process.platform === "win32"
      ? `${receipt.app.command}.cmd`
      : receipt.app.command,
  );
  if (
    receipt.app.id !== id ||
    receipt.payload !== expectedPayload ||
    receipt.commandPath !== expectedCommand
  )
    throw new Error(`Unsafe installation receipt for ${id}`);
  return receipt;
}
export function uninstallDistribution(id: string): string {
  const receipt = readInstallReceipt(id);
  rmSync(receipt.commandPath, { force: true });
  rmSync(receipt.payload, { recursive: true, force: true });
  if (existsSync(dirname(receipt.payload))) rmdirSync(dirname(receipt.payload));
  rmSync(receiptPath(id), { force: true });
  return runtimeStateDirectory({ value: id });
}
export function purgeDistributionState(id: string): string {
  distributionStateDirectory({ value: id });
  if (existsSync(receiptPath(id)))
    throw new Error(`Uninstall ${id} before purging its state`);
  const state = runtimeStateDirectory({ value: id });
  rmSync(state, { recursive: true, force: true });
  return state;
}
export function initDistribution(directory: string): string {
  const root = resolve(directory);
  if (existsSync(root) && readdirSync(root).length)
    throw new Error(`Directory is not empty: ${root}`);
  const id = basename(root).toLowerCase();
  distributionStateDirectory({ value: id });
  mkdirSync(join(root, "resources"), { recursive: true });
  writeFileSync(
    join(root, "piship.yaml"),
    `schema: piship/v1alpha1\napp:\n  id: ${id}\n  name: ${id}\n  command: ${id}\n  version: 1.0.0\nruntime:\n  pi: "${PI_VERSION}"\ndeployment:\n  mode: personal\nresources:\n  instructions:\n    - ./resources/AGENTS.md\n`,
  );
  writeFileSync(join(root, "resources", "AGENTS.md"), `# ${id}\n`);
  return join(root, "piship.yaml");
}
