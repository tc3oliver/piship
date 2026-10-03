import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  type Manifest,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  readManifest,
  type UpdateTrustKey,
  channelTrustKeys,
} from "@piship/schema";
import { PI_VERSION } from "./compatibility.js";
import { digest, hash } from "./digest.js";
import { governanceLock } from "./governance-lock.js";
import {
  type DistributionLock,
  LOCK_SCHEMA_V1ALPHA2,
  LOCK_SCHEMA_V1ALPHA3,
  LOCK_SCHEMA_V1ALPHA4,
  LOCK_SCHEMA_V1ALPHA5,
  LOCK_SCHEMA_VERSION,
} from "./lock-schema.js";
import { resolveResources } from "./resources.js";
import { runtimeDependencies } from "./runtime-dependencies.js";

export function debugTiming(label: string, started: bigint): void {
  if (process.env.PISHIP_DEBUG_TIMING === "1")
    process.stderr.write(
      `${label}: ${(Number(process.hrtime.bigint() - started) / 1e6).toFixed(1)} ms\n`,
    );
}
/**
 * The lock's manifest digest. From piship/v1alpha5 it is the canonical
 * `sha256-<hex>` of the parsed manifest, so YAML comments, key order, and
 * line endings never change it; older schemas keep the bare hex their locks
 * already record.
 */
export function manifestDigest(manifest: Manifest): string {
  return manifest.schema === PISHIP_SCHEMA_V1ALPHA5
    ? digest(manifest)
    : hash(JSON.stringify(manifest));
}

/**
 * The keys a lock trusts to sign update channels: the channel role of a
 * v1alpha5 bootstrap root, or every v1alpha4 `updates.trust.keys` entry.
 * Empty when updates are disabled.
 */
export function channelTrustFromLock(
  lock: Pick<DistributionLock, "updates">,
): readonly UpdateTrustKey[] {
  return channelTrustKeys(lock.updates);
}
export function checkPiVersion(manifest: Manifest): void {
  if (manifest.runtime.pi !== PI_VERSION)
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      `Pi ${manifest.runtime.pi} is not available in this PiShip build. Pinned runtime: ${PI_VERSION}.`,
    );
}

export function resolveLock(manifestPath: string): DistributionLock {
  const manifest = readManifest(manifestPath);
  checkPiVersion(manifest);
  const resources = resolveResources(manifest, manifestPath);
  const governance = governanceLock(
    manifest,
    dirname(resolve(manifestPath)),
    resources,
  );
  const v5 = manifest.schema === PISHIP_SCHEMA_V1ALPHA5;
  const v4 = manifest.schema === PISHIP_SCHEMA_V1ALPHA4 || v5;
  const policy = governance?.manifest;
  return {
    schema: v5
      ? LOCK_SCHEMA_V1ALPHA5
      : v4
        ? LOCK_SCHEMA_V1ALPHA4
        : manifest.schema === PISHIP_SCHEMA_V1ALPHA3
          ? LOCK_SCHEMA_V1ALPHA3
          : manifest.schema === PISHIP_SCHEMA_V1ALPHA2
            ? LOCK_SCHEMA_V1ALPHA2
            : LOCK_SCHEMA_VERSION,
    manifest: { schema: manifest.schema, sha256: manifestDigest(manifest) },
    app: manifest.app,
    deployment: manifest.deployment,
    runtime: runtimeDependencies(v4),
    resources,
    declared: manifest.resources,
    ...(manifest.access ? { access: manifest.access } : {}),
    ...(governance ? { governance } : {}),
    ...(v4 && manifest.lifecycle
      ? {
          digests: {
            resources: digest(
              resources.map((item) => [item.kind, item.path, item.sha256]),
            ),
            policy: digest(policy?.policy),
            capabilities: digest({
              capabilities: policy?.capabilities,
              providers: governance?.providers,
              certified: governance?.certified,
            }),
            mcp: digest(policy?.mcp),
            sandbox: digest(policy?.sandbox),
            audit: digest(policy?.audit),
            access: digest(manifest.access),
          },
          updates: manifest.lifecycle.updates,
          release: manifest.lifecycle.release,
        }
      : {}),
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
