// Local assembly caches trust previously built output. Release qualification
// opts out; these stamps are outside the payload and never shipped.
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, hash } from "./digest.js";
import type { DistributionLock } from "./lock-schema.js";

const SCHEMA = "piship-local-build/v1";
export interface BuildCache {
  readonly schema: typeof SCHEMA;
  readonly key: string;
  readonly runtimeKey: string;
  readonly command: string;
  readonly inventory: Record<string, string>;
}

/** Prepared inputs carry a content generation; custom inputs fall back to bytes. */
export function buildInputDigest(input: string): string {
  try {
    const marker = JSON.parse(
      readFileSync(join(input, ".piship-build-input.json"), "utf8"),
    ) as { schema?: string; sha256?: string };
    if (
      marker.schema === "piship-build-input/v1" &&
      /^[0-9a-f]{64}$/.test(marker.sha256 ?? "")
    )
      return marker.sha256 as string;
  } catch {}
  const files: [string, string][] = [];
  const visit = (directory: string, relative = ""): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      const path = join(directory, entry.name);
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(path, name);
      else if (entry.isFile()) files.push([name, hash(readFileSync(path))]);
      else throw new Error(`Unsupported build input entry: ${path}`);
    }
  };
  visit(input);
  return hash(canonicalJson(files));
}

export function buildCacheKeys(
  input: string,
  manifestPath: string,
  lock: DistributionLock,
  options: {
    readonly bundle: boolean;
    readonly strip: boolean;
    readonly supplyChainGates: boolean;
  },
): { key: string; runtimeKey: string } {
  const runtimeKey = hash(
    canonicalJson({
      input: buildInputDigest(input),
      npmLock: lock.runtime.npmLockSha256,
      packages: lock.packages,
      searchTools: lock.searchTools,
      releasePolicy: lock.release,
      packageTrust: lock.governance?.manifest.packageTrust,
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      ...options,
    }),
  );
  return {
    runtimeKey,
    key: hash(
      canonicalJson({
        runtimeKey,
        lock,
        manifest: hash(readFileSync(manifestPath)),
      }),
    ),
  };
}

export function buildCachePath(output: string): string {
  return `${output}.piship-build.json`;
}

export function safePath(path: string): boolean {
  return (
    path.length > 0 &&
    path
      .split("/")
      .every(
        (part) =>
          part.length > 0 &&
          part !== "." &&
          part !== ".." &&
          !part.includes("\\") &&
          !part.includes(":"),
      )
  );
}

export function readBuildCache(output: string): BuildCache | undefined {
  try {
    const cache = JSON.parse(
      readFileSync(buildCachePath(output), "utf8"),
    ) as BuildCache;
    if (
      cache.schema !== SCHEMA ||
      !/^[0-9a-f]{64}$/.test(cache.key) ||
      !/^[0-9a-f]{64}$/.test(cache.runtimeKey) ||
      !/^[a-z][a-z0-9-]*$/.test(cache.command)
    )
      return undefined;
    if (
      !cache.inventory ||
      typeof cache.inventory !== "object" ||
      Array.isArray(cache.inventory) ||
      Object.entries(cache.inventory).some(
        ([path, digest]) =>
          !safePath(path) ||
          typeof digest !== "string" ||
          !/^[0-9a-f]{64}$/.test(digest),
      )
    )
      return undefined;
    if (
      !lstatSync(output).isDirectory() ||
      !lstatSync(join(output, "node_modules")).isDirectory() ||
      !existsSync(join(output, "metadata", "inventory.json"))
    )
      return undefined;
    return cache;
  } catch {
    return undefined;
  }
}

export function writeBuildCache(
  output: string,
  key: string,
  runtimeKey: string,
  command: string,
  inventory: Record<string, string>,
): void {
  const cache: BuildCache = {
    schema: SCHEMA,
    key,
    runtimeKey,
    command,
    inventory,
  };
  writeFileSync(buildCachePath(output), `${JSON.stringify(cache)}\n`);
}

/** Update only distribution files; immutable dependencies and their hashes stay put. */
export function refreshCachedDistribution(
  output: string,
  manifestPath: string,
  lock: DistributionLock,
  cache: BuildCache,
  keys: { readonly key: string; readonly runtimeKey: string },
): void {
  // An interrupted refresh must never leave a valid stamp over mixed files.
  rmSync(buildCachePath(output), { force: true });
  const base = dirname(manifestPath);
  const inventory = { ...cache.inventory };
  const copy = (source: string, relative: string, digest?: string): void => {
    const target = join(output, ...relative.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    inventory[relative] = digest ?? hash(readFileSync(source));
  };
  const desiredResources = new Map(
    lock.resources.map((resource) => [`resources/${resource.path}`, resource]),
  );
  for (const relative of Object.keys(inventory)) {
    if (!relative.startsWith("resources/") || desiredResources.has(relative))
      continue;
    rmSync(join(output, ...relative.split("/")), { force: true });
    delete inventory[relative];
  }
  for (const [relative, resource] of desiredResources) {
    if (inventory[relative] !== resource.sha256)
      copy(join(base, resource.path), relative, resource.sha256);
  }
  copy(manifestPath, "piship.yaml");
  copy(join(base, "piship.lock"), "piship.lock");
  if (cache.command !== lock.app.command) {
    const previous = `bin/${cache.command}`;
    const next = `bin/${lock.app.command}`;
    renameSync(join(output, previous), join(output, next));
    inventory[next] = inventory[previous] as string;
    delete inventory[previous];
    rmSync(join(output, `${previous}.cmd`), { force: true });
    delete inventory[`${previous}.cmd`];
    const shim = `@echo off\r\nnode "%~dp0\\${lock.app.command}" %*\r\n`;
    writeFileSync(join(output, `${next}.cmd`), shim);
    inventory[`${next}.cmd`] = hash(shim);
  }
  writeFileSync(
    join(output, "metadata", "inventory.json"),
    `${JSON.stringify(inventory, null, 2)}\n`,
  );
  writeBuildCache(
    output,
    keys.key,
    keys.runtimeKey,
    lock.app.command,
    inventory,
  );
}
