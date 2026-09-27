import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
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
  };
  readonly resources: readonly LockedResource[];
  readonly declared: Manifest["resources"];
}
export function distributionStateDirectory(id: DistributionId): string {
  if (!/^[a-z][a-z0-9-]*$/.test(id.value))
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
    runtime: { package: PI_PACKAGE, version: PI_VERSION },
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
  return `#!/usr/bin/env node\nimport { readFileSync } from "node:fs";\nimport { fileURLToPath } from "node:url";\nimport { launchPiDistribution } from "@piship/pi";\nconst metadata = JSON.parse(readFileSync(new URL("../metadata/distribution.json", import.meta.url), "utf8"));\ntry { await launchPiDistribution({ distributionDir: fileURLToPath(new URL("..", import.meta.url)), metadata, args: process.argv.slice(2) }); } catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }\n`;
}
export function buildDistribution(
  manifestPath: string,
  outputRoot = resolve("dist"),
): string {
  const lock = requireCurrentLock(manifestPath);
  const output = join(outputRoot, lock.app.id);
  const base = dirname(resolve(manifestPath));
  rmSync(output, { recursive: true, force: true });
  mkdirSync(join(output, "bin"), { recursive: true });
  mkdirSync(join(output, "metadata"), { recursive: true });
  for (const resource of lock.resources) {
    const target = join(output, "resources", resource.path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(base, resource.path), target);
  }
  writeFileSync(
    join(output, "metadata", "distribution.json"),
    `${JSON.stringify(lock, null, 2)}\n`,
  );
  const command = join(output, "bin", lock.app.command);
  writeFileSync(command, launcherSource());
  if (process.platform !== "win32") chmodSync(command, 0o755);
  writeFileSync(
    `${command}.cmd`,
    `@echo off\r\nnode "%~dp0\\${lock.app.command}" %*\r\n`,
  );
  return output;
}
