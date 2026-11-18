import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { manifestContainment, seamEvidence } from "@piship/policy";
import {
  channelTrustKeys,
  DATA_CONTRACT_VERSION,
  type Manifest,
  ManifestError,
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  readManifest,
  type UpdateTrustKey,
  type ValidationDiagnostic,
} from "@piship/schema";
import { PI_VERSION, PISHIP_VERSION } from "./compatibility.js";
import { checkDataContract } from "./data/contract.js";
import { sessionExportStatus } from "./data/session-export.js";
import { canonicalJson, digest, hash } from "./digest.js";
import { governanceLock } from "./governance-lock.js";
import { pishipCommand, shellArg } from "./invocation.js";
import {
  type DistributionLock,
  LOCK_SCHEMA_V1,
  LOCK_SCHEMA_V1ALPHA2,
  LOCK_SCHEMA_V1ALPHA3,
  LOCK_SCHEMA_V1ALPHA4,
  LOCK_SCHEMA_V1ALPHA5,
  LOCK_SCHEMA_V1ALPHA6,
  LOCK_SCHEMA_VERSION,
  type LockedPiPackage,
} from "./lock-schema.js";
import { PI_PACKAGE_VENDOR_DIRECTORY } from "./pi-packages/gates.js";
import {
  currentPiPackages,
  declaredPackages,
  lockPiPackages,
  packageLockFiles,
} from "./pi-packages/lock.js";
import { resolveResources } from "./resources.js";
import { runtimeDependencies } from "./runtime-dependencies.js";
import { currentSearchTools, lockSearchTools } from "./search-tools/index.js";
import { checkToolExposure, lockedTools } from "./tool-exposure.js";

/**
 * The lock's manifest digest. From piship/v1alpha5 it is the canonical
 * `sha256-<hex>` of the parsed manifest, so YAML comments, key order, and
 * line endings never change it; older schemas keep the bare hex their locks
 * already record.
 */
export function manifestDigest(manifest: Manifest): string {
  return manifest.schema === PISHIP_SCHEMA_V1ALPHA5 ||
    manifest.schema === PISHIP_SCHEMA_V1ALPHA6 ||
    manifest.schema === PISHIP_SCHEMA_V1
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
/**
 * A manifest may leave `runtime.pi` out, which means the Pi this PiShip
 * pins, so it keeps working across PiShip upgrades. One that states a
 * version must state the pinned one.
 */
export function checkPiVersion(manifest: Manifest): void {
  const stated = manifest.runtime.pi;
  if (stated !== undefined && stated !== PI_VERSION)
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      `Pi ${stated} is not available in this PiShip build. Pinned runtime: ${PI_VERSION}. Remove the runtime.pi line to use the pinned Pi (it follows every PiShip upgrade), or set it to "${PI_VERSION}".`,
    );
}

/**
 * The lock for a manifest. Pi packages are resolved over the network, and
 * bundled search tools read from the download cache, only when `packages` is
 * `"resolve"` (`piship lock`); otherwise their recorded entries are
 * re-checked offline, so a stale-lock check never reaches a registry.
 * `"keep"` re-checks the recorded packages offline but reads search tools
 * from the download cache, for a relock that changes no package.
 */
export function resolveLock(
  manifestPath: string,
  options: { readonly packages?: "resolve" | "recorded" | "keep" } = {},
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
  // piship/v1 locks carry exactly the v1alpha6 content.
  const v6 =
    manifest.schema === PISHIP_SCHEMA_V1ALPHA6 ||
    manifest.schema === PISHIP_SCHEMA_V1;
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
  // Bundled search tools are read from the download cache only by `piship
  // lock`; the stale-lock check takes the recorded entries.
  const searchTools =
    v6 && manifest.runtime.searchTools
      ? options.packages === "resolve" || options.packages === "keep"
        ? lockSearchTools(manifest)
        : currentSearchTools(manifest, base)
      : undefined;
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
    schema:
      manifest.schema === PISHIP_SCHEMA_V1
        ? LOCK_SCHEMA_V1
        : v6
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
            ...(searchTools ? { searchTools: digest(searchTools) } : {}),
          },
          updates: manifest.lifecycle.updates,
          release: manifest.lifecycle.release,
        }
      : {}),
    ...(v6
      ? {
          ...(packages.length ? { packages } : {}),
          ...(searchTools ? { searchTools } : {}),
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
          ...(manifest.runtime.verifyAtLaunch === undefined
            ? {}
            : { verifyAtLaunch: manifest.runtime.verifyAtLaunch }),
          enforcement: seamEvidence(runtime.version),
          data: {
            contract: DATA_CONTRACT_VERSION,
            ...(manifest.data ? { declared: manifest.data } : {}),
          },
          // Always recorded, whatever the manifest declares: the gaps of
          // Pi's /share and /export stay visible.
          sessionExportStatus: sessionExportStatus(
            manifestContainment(
              manifest.governance ?? {},
              manifest.deployment.mode,
            ),
          ),
        }
      : {}),
  };
}
/**
 * The app id recorded by the piship.lock beside a manifest when that lock
 * belongs to another manifest in the same directory, else undefined. The lock
 * always sits beside the manifest as piship.lock, so locking a second
 * manifest there would silently replace the first's lock.
 */
export function lockOwnedByOther(manifestPath: string): string | undefined {
  // piship.yaml owns the directory's lock, so its relock always proceeds,
  // even after an app.id rename.
  if (basename(manifestPath) === "piship.yaml") return undefined;
  let recorded: string | undefined;
  try {
    recorded = (
      JSON.parse(
        readFileSync(
          join(dirname(resolve(manifestPath)), "piship.lock"),
          "utf8",
        ),
      ) as DistributionLock
    ).app?.id;
  } catch {
    return undefined;
  }
  return recorded !== undefined &&
    recorded !== readManifest(manifestPath).app.id
    ? recorded
    : undefined;
}

function checkLockOwner(manifestPath: string): void {
  const other = lockOwnedByOther(manifestPath);
  if (other === undefined) return;
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  throw new Error(
    `${path} is the lock of app ${other}, not of ${readManifest(manifestPath).app.id} (${manifestPath}); locking here would replace it. Copy this manifest into its own directory as piship.yaml and lock it there.`,
  );
}

export function lockManifest(manifestPath: string): string {
  checkLockOwner(manifestPath);
  if (recordedPackagesReusable(manifestPath)) {
    const kept = relockKeepingPackages(manifestPath);
    if (kept) return kept;
  }
  const lock = resolveLock(manifestPath, { packages: "resolve" });
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`);
  return path;
}

/** Locked Pi packages whose resource filters select nothing, so they load nothing. */
export function emptyPackageWarnings(lockPath: string): ValidationDiagnostic[] {
  const lock = JSON.parse(readFileSync(lockPath, "utf8")) as DistributionLock;
  return (lock.packages ?? [])
    .filter((item) => item.resources.length === 0)
    .map((item) => ({
      path: "resources.packages",
      message: `package ${item.id} provides no resources under its filters, so it loads nothing; check its filters or remove it`,
    }));
}
/**
 * `release.installScripts` entries that name nothing the lock resolved: no
 * package root at that commit or tree digest, and no npm lockfile entry at
 * that path and version. Left over after an upgrade, a removed package, or
 * a local package edit, they review nothing and can be removed.
 */
export function staleInstallScriptWarnings(
  lockPath: string,
): ValidationDiagnostic[] {
  const lock = JSON.parse(readFileSync(lockPath, "utf8")) as DistributionLock;
  const reviewed = lock.release?.installScripts ?? [];
  if (!reviewed.length) return [];
  const present = new Set<string>();
  for (const item of lock.packages ?? []) {
    const prefix = `${PI_PACKAGE_VENDOR_DIRECTORY}/${item.id}/`;
    present.add(`${prefix}package@${item.commit ?? item.tree}`);
    let npm: { packages?: Record<string, { version?: string }> } = {};
    try {
      npm = JSON.parse(
        readFileSync(
          packageLockFiles(dirname(lockPath), item.id).lockfile,
          "utf8",
        ),
      );
    } catch {}
    for (const [path, entry] of Object.entries(npm.packages ?? {}))
      if (path) present.add(`${prefix}${path}@${entry.version}`);
  }
  return reviewed
    .filter((entry) => !present.has(entry))
    .map((entry) => ({
      path: "release.installScripts",
      message: `${entry} matches nothing in the locked packages, so it reviews nothing; it can be removed`,
    }));
}
/**
 * Relocks offline when no Pi package can resolve differently: the package
 * declarations, `packageTrust`, the release settings, the deployment mode,
 * the stored npm lockfiles, and local package trees are all as the lock
 * recorded them, so the recorded packages are kept. Returns the lock path,
 * or undefined, writing nothing, when any of those changed or an older
 * PiShip wrote the lock.
 */
export function relockKeepingPackages(
  manifestPath: string,
): string | undefined {
  checkLockOwner(manifestPath);
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  let recorded: Partial<DistributionLock>;
  try {
    recorded = JSON.parse(readFileSync(path, "utf8")) as DistributionLock;
  } catch {
    return undefined;
  }
  // An older PiShip resolved these packages under other lock-time gates; a
  // kept relock would stamp this version on them without a full resolve.
  if (recorded.runtime?.pishipVersion !== PISHIP_VERSION) return undefined;
  const lock = resolveLock(manifestPath, { packages: "keep" });
  const inputs = (item: Partial<DistributionLock>) =>
    canonicalJson([
      item.deployment ?? null,
      item.release ?? null,
      item.governance?.manifest.resources.packages ?? null,
      item.governance?.manifest.packageTrust ?? null,
      item.packages ?? null,
      item.digests?.packages ?? null,
    ]);
  if (inputs(recorded) !== inputs(lock)) return undefined;
  writeFileSync(path, `${JSON.stringify(lock, null, 2)}\n`);
  return path;
}
/**
 * Ids of `source: local` Pi packages whose files changed since the lock was
 * written. Relocking them can run npm for their dependencies, so `dev` and
 * `test` name them instead of relocking on their own.
 */
export function changedLocalPackages(manifestPath: string): string[] {
  const base = dirname(resolve(manifestPath));
  const manifest = readManifest(manifestPath);
  let recorded: readonly LockedPiPackage[] = [];
  try {
    recorded =
      (
        JSON.parse(
          readFileSync(join(base, "piship.lock"), "utf8"),
        ) as Partial<DistributionLock>
      ).packages ?? [];
  } catch {
    return [];
  }
  const current = currentPiPackages(manifest, base);
  return current
    .filter((item) => {
      const old = recorded.find((entry) => entry.id === item.id);
      return item.source === "local" && old && old.tree !== item.tree;
    })
    .map((item) => item.id);
}
/** An exact npm version, which names one immutable tarball. */
const EXACT_VERSION =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Whether resolving the declared Pi packages again could only reproduce what
 * the lock records: every package is an exact npm version or local content
 * (recomputed offline), and the lock was written by this PiShip version, so
 * its entries follow the same rules. A git ref or a semver range can move,
 * and is resolved again.
 */
function recordedPackagesReusable(manifestPath: string): boolean {
  const declared = declaredPackages(readManifest(manifestPath));
  if (!declared.length) return false;
  if (
    !declared.every(
      (item) =>
        item.source === "local" ||
        (item.source === "npm" && EXACT_VERSION.test(item.version)),
    )
  )
    return false;
  try {
    const recorded = JSON.parse(
      readFileSync(join(dirname(resolve(manifestPath)), "piship.lock"), "utf8"),
    ) as Partial<DistributionLock>;
    return recorded.runtime?.pishipVersion === PISHIP_VERSION;
  } catch {
    return false;
  }
}

/** Whether `piship.lock` beside a manifest matches what the manifest locks to. */
export type LockStatus = "current" | "missing" | "stale";
export function lockStatus(manifestPath: string): LockStatus {
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  if (!existsSync(path)) return "missing";
  const expected = `${JSON.stringify(resolveLock(manifestPath), null, 2)}\n`;
  return readFileSync(path, "utf8") === expected ? "current" : "stale";
}
/**
 * Whether relocking resolves new content over the network: Pi packages are
 * resolved over a registry and the lock pins what came back, so a person
 * decides when they are locked again. Bundled search tools are not counted:
 * they come from the download cache when the lock beside the manifest
 * already pins them, so an edit to a resource relocks without the network.
 */
export function lockNeedsNetwork(manifest: Manifest): boolean {
  return declaredPackages(manifest).length > 0;
}
export function requireCurrentLock(manifestPath: string): DistributionLock {
  const path = join(dirname(resolve(manifestPath)), "piship.lock");
  const expected = `${JSON.stringify(resolveLock(manifestPath), null, 2)}\n`;
  if (!existsSync(path))
    throw new Error(
      `Lockfile missing: ${path}. Run ${pishipCommand()} lock ${shellArg(manifestPath)}`,
    );
  const recorded = readFileSync(path, "utf8");
  if (recorded !== expected) {
    let pi: unknown;
    try {
      pi = (JSON.parse(recorded) as Partial<DistributionLock>).runtime?.version;
    } catch {
      // An unreadable lock is just stale.
    }
    const previous = join(dirname(manifestPath), "previous.lock");
    if (typeof pi === "string" && pi !== PI_VERSION)
      throw new Error(
        `Lockfile is stale: ${path} was made for Pi ${pi} and this PiShip uses Pi ${PI_VERSION}. Copy it to ${previous}, run ${pishipCommand()} lock ${shellArg(manifestPath)}, then ${pishipCommand()} diff ${shellArg(previous)} ${shellArg(path)} to review the Pi upgrade`,
      );
    const local = changedLocalPackages(manifestPath);
    throw new Error(
      `Lockfile is stale: ${path}${local.length ? `: the files of the local Pi package ${local.join(", ")} changed since it was written` : ""}. Run ${pishipCommand()} lock ${shellArg(manifestPath)}`,
    );
  }
  return JSON.parse(expected) as DistributionLock;
}
