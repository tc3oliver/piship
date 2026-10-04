import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { manifestContainment, seamEvidence } from "@piship/policy";
import {
  channelTrustKeys,
  DATA_CONTRACT_VERSION,
  type Manifest,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  readManifest,
  type UpdateTrustKey,
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
  LOCK_SCHEMA_V1ALPHA6,
  LOCK_SCHEMA_VERSION,
} from "./lock-schema.js";
import { checkDataContract } from "./data/contract.js";
import { sessionExportStatus } from "./data/session-export.js";
import { currentPiPackages, lockPiPackages } from "./pi-packages/lock.js";
import { resolveResources } from "./resources.js";
import { runtimeDependencies } from "./runtime-dependencies.js";
import { checkToolExposure, lockedTools } from "./tool-exposure.js";

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
  return manifest.schema === PISHIP_SCHEMA_V1ALPHA5 ||
    manifest.schema === PISHIP_SCHEMA_V1ALPHA6
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

/**
 * The lock for a manifest. Pi packages are resolved over the network only
 * when `packages` is `"resolve"` (`piship lock`); otherwise their recorded
 * entries are re-checked offline, so a stale-lock check never reaches a
 * registry.
 */
export function resolveLock(
  manifestPath: string,
  options: { readonly packages?: "resolve" | "recorded" } = {},
): DistributionLock {
  const manifest = readManifest(manifestPath);
  checkPiVersion(manifest);
  checkDataContract(manifest);
  checkToolExposure(manifest);
  const resources = resolveResources(manifest, manifestPath);
  const governance = governanceLock(
    manifest,
    dirname(resolve(manifestPath)),
    resources,
  );
  const v6 = manifest.schema === PISHIP_SCHEMA_V1ALPHA6;
  const v5 = manifest.schema === PISHIP_SCHEMA_V1ALPHA5 || v6;
  const v4 = manifest.schema === PISHIP_SCHEMA_V1ALPHA4 || v5;
  const policy = governance?.manifest;
  const runtime = runtimeDependencies(v4);
  const base = dirname(resolve(manifestPath));
  const packages = v6
    ? options.packages === "resolve"
      ? lockPiPackages(manifest, base)
      : currentPiPackages(manifest, base)
    : [];
  const virtualModels = (manifest.access?.models.catalog ?? []).flatMap(
    (model) =>
      model.virtual
        ? [
            {
              id: model.id,
              router: model.virtual.router,
              routes: model.virtual.routes,
            },
          ]
        : [],
  );
  return {
    schema: v6
      ? LOCK_SCHEMA_V1ALPHA6
      : v5
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
    runtime,
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
            ...(packages.length ? { packages: digest(packages) } : {}),
          },
          updates: manifest.lifecycle.updates,
          release: manifest.lifecycle.release,
        }
      : {}),
    ...(v6
      ? {
          ...(packages.length ? { packages } : {}),
          ...(virtualModels.length ? { virtualModels } : {}),
          ...(manifest.runtime.tools
            ? {
                tools: lockedTools(manifest),
                runtimeTools: manifest.runtime.tools,
              }
            : {}),
          ...(manifest.runtime.cacheWarming
            ? { cacheWarming: manifest.runtime.cacheWarming }
            : {}),
          enforcement: seamEvidence(runtime.version),
          data: {
            contract: DATA_CONTRACT_VERSION,
            ...(manifest.data ? { declared: manifest.data } : {}),
          },
          // Always recorded, whatever the manifest declares: the gaps of
          // Pi's /share and /export stay visible.
          sessionExportStatus: sessionExportStatus(
            manifestContainment(manifest.governance ?? {}),
          ),
        }
      : {}),
  };
}
export function lockManifest(manifestPath: string): string {
  const lock = resolveLock(manifestPath, { packages: "resolve" });
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
