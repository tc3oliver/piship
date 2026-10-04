// Static release gates: lock, schema, update trust, target, Pi compatibility
// surfaces, package sources and install scripts, policy, certification, and
// sandbox.
import { PiShipError } from "@piship/contracts";
import { manifestContainment, unenforcedRules } from "@piship/policy";
import { type ReleaseManifest, sharedRoleKeyIds } from "@piship/schema";
import {
  currentTarget,
  type DistributionLock,
  EVIDENCED_TARGETS,
  LOCK_SCHEMA_V1ALPHA5,
  LOCK_SCHEMA_V1ALPHA6,
  PI_COMPATIBILITY,
  REVIEWED_INSTALL_SCRIPTS,
  requireCurrentLock,
} from "../index.js";
import { gate } from "./shared.js";

/** The release name `<id>-<version>-<target>`. */
export function releaseName(lock: DistributionLock, target: string): string {
  return `${lock.app.id}-${lock.app.version}-${target}`;
}

const COMPATIBILITY_ORDER = ["unsupported", "candidate", "supported"];

/**
 * Status of each surface a release depends on: its deployment surface
 * (`personal` or `managed`), the `governance` surface when the distribution
 * declares governance (every piship/v1alpha3 or later manifest does), and
 * the `lifecycle` surface every release uses.
 */
export function piCompatibilitySurfaces(
  lock: Pick<DistributionLock, "deployment" | "runtime" | "governance">,
): Readonly<Record<string, string>> {
  const surface = lock.deployment.mode === "managed" ? "managed" : "personal";
  const known = PI_COMPATIBILITY[lock.runtime.version];
  return {
    [surface]: known?.[surface] ?? "unsupported",
    ...(lock.governance
      ? { governance: known?.governance ?? "unsupported" }
      : {}),
    lifecycle: known?.lifecycle ?? "unsupported",
  };
}

/**
 * The weakest status among the surfaces a release depends on
 * (unsupported < candidate < supported); an unknown status counts as
 * unsupported.
 */
export function piCompatibility(
  lock: Pick<DistributionLock, "deployment" | "runtime" | "governance">,
): string {
  const ranks = Object.values(piCompatibilitySurfaces(lock)).map((status) =>
    Math.max(0, COMPATIBILITY_ORDER.indexOf(status)),
  );
  return COMPATIBILITY_ORDER[Math.min(...ranks)] as string;
}

/** Enforced rules that contradict each other or a declared trust class. */
function policyConflicts(lock: DistributionLock): string[] {
  const governance = lock.governance?.manifest;
  if (!governance) return [];
  const conflicts: string[] = [];
  const { policy } = governance;
  const ids = new Map<string, string>();
  for (const [tier, rules] of [
    ["enforced", policy.enforced],
    ["defaults", policy.defaults],
  ] as const)
    for (const rule of rules) {
      const seen = ids.get(rule.id);
      if (seen)
        conflicts.push(
          `rule id ${rule.id} appears in both ${seen} and ${tier}`,
        );
      ids.set(rule.id, tier);
    }
  const enforced = new Map<string, string>();
  for (const rule of policy.enforced) {
    const key = `${rule.action} ${rule.resource}`;
    const effect = enforced.get(key);
    if (effect && effect !== rule.effect)
      conflicts.push(
        `enforced rules for ${key} disagree (${effect} and ${rule.effect})`,
      );
    enforced.set(key, rule.effect);
  }
  const resourceTrust = policy.resourceTrust as Record<string, string>;
  for (const item of governance.resources.declared)
    if (resourceTrust[item.class] === "deny")
      conflicts.push(
        `${item.kind} ${item.path} is declared ${item.class}, which policy.resourceTrust denies`,
      );
  const providerTrust = policy.providerTrust as Record<string, string>;
  for (const capability of governance.capabilities)
    if (
      capability.enabled &&
      capability.provider &&
      providerTrust[capability.provider.class] === "deny"
    )
      conflicts.push(
        `capability ${capability.name} is enabled with a ${capability.provider.class} provider, which policy.providerTrust denies`,
      );
  return conflicts;
}

/**
 * The `source` and `install-script` gates over the locked npm closure: every
 * package has sha512 integrity and a source in `release.sources`, and every
 * npm lifecycle script was reviewed for this PiShip version. `piship release`
 * and `piship build` both run them; only piship/v1alpha4 locks record
 * sources and install scripts.
 */
export function checkPackageSources(
  lock: DistributionLock,
  stage: "Release" | "Build" = "Release",
): void {
  const release = lock.release;
  if (!release) return;
  for (const item of lock.runtime.packages) {
    // The lock keeps every registry entry, so one the npm lock records
    // without integrity is refused here instead of going unchecked.
    if (!item.integrity)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} is missing integrity in the npm lock`,
        "Record the registry dist.integrity for this package in package-lock.json and lock again",
        stage,
      );
    if (!item.resolved)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no recorded source`,
        undefined,
        stage,
      );
    let origin: string;
    try {
      origin = new URL(item.resolved).origin;
    } catch {
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has an unparsable source`,
        undefined,
        stage,
      );
    }
    if (!release.sources.includes(origin))
      throw gate(
        "POLICY_DENIED",
        "source",
        `${item.path}@${item.version} comes from ${origin}, which is not in release.sources (${release.sources.join(", ")})`,
        undefined,
        stage,
      );
    if (!/^sha512-[A-Za-z0-9+/]+=*$/.test(item.integrity))
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no sha512 integrity`,
        undefined,
        stage,
      );
    if (
      item.installScript &&
      !REVIEWED_INSTALL_SCRIPTS.includes(`${item.path}@${item.version}`)
    )
      throw gate(
        "POLICY_DENIED",
        "install-script",
        `${item.path}@${item.version} runs npm lifecycle scripts that were not reviewed for this PiShip version`,
        undefined,
        stage,
      );
  }
}

/**
 * The `trust` gate over the locked update bootstrap: a managed distribution
 * needs distinct root and channel keys. A migrated v1alpha4 key set shares
 * its keys between both roles, so a managed release waits for the owner's
 * explicit root / channel split. An update source without bootstrap trust is
 * not refused here: such a release is update-disabled, `update` fails closed
 * on it, and `piship validate` warns.
 */
function checkUpdateTrust(lock: DistributionLock): void {
  const updates = lock.updates;
  if (!updates || "keys" in updates.trust) return;
  const bootstrap = updates.trust.bootstrap;
  if (!bootstrap) return;
  const shared = sharedRoleKeyIds(bootstrap);
  if (lock.deployment.mode === "managed" && shared.length)
    throw gate(
      "POLICY_DENIED",
      "trust",
      `the update root and channel roles share ${shared.join(", ")}; a managed distribution needs distinct root and channel keys`,
      "Add an offline root key to updates.trust.bootstrap.roles.root, keep the release key only in roles.channel, and lock again",
    );
}

/**
 * Static release gates, checked before anything is assembled. The policy gate
 * also refuses a managed POLICY_UNENFORCEABLE rule. Each failure
 * names its gate: lock, schema, trust, target, pi, source, install-script,
 * policy, certification, or sandbox.
 */
export function checkReleaseInputs(
  manifestPath: string,
  target = currentTarget(),
): DistributionLock {
  let lock: DistributionLock;
  try {
    lock = requireCurrentLock(manifestPath);
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    throw gate(
      "LOCK_INVALID",
      "lock",
      (error as Error).message,
      "Review the manifest and resource changes, then run piship lock",
    );
  }
  if (
    (lock.schema !== LOCK_SCHEMA_V1ALPHA5 &&
      lock.schema !== LOCK_SCHEMA_V1ALPHA6) ||
    !lock.release ||
    !lock.updates
  )
    throw gate(
      "CONFIG_INVALID",
      "schema",
      `production releases need a piship/v1alpha5 or piship/v1alpha6 manifest (found ${lock.manifest.schema})`,
      "Run piship migrate --write, review updates.trust.bootstrap, and lock again",
    );
  checkUpdateTrust(lock);
  const release: ReleaseManifest = lock.release;
  if (!release.targets.includes(target as never))
    throw gate(
      "CONFIG_INVALID",
      "target",
      `${target} is not in release.targets (${release.targets.join(", ")})`,
    );
  if (!EVIDENCED_TARGETS.includes(target))
    throw gate(
      "CONFIG_INVALID",
      "target",
      `${target} has no installed lifecycle evidence in this PiShip version (supported: ${EVIDENCED_TARGETS.join(", ")})`,
    );
  if (target !== currentTarget())
    throw gate(
      "CONFIG_INVALID",
      "target",
      `releases are built on their target; this machine is ${currentTarget()}`,
    );
  if (piCompatibility(lock) === "unsupported")
    throw gate(
      "CONFIG_INVALID",
      "pi",
      `Pi ${lock.runtime.version} is not in this PiShip build's compatibility matrix`,
    );
  checkPackageSources(lock);
  const conflicts = policyConflicts(lock);
  if (conflicts.length)
    throw gate("POLICY_DENIED", "policy", conflicts.join("; "));
  const governance = lock.governance?.manifest;
  const unenforced = governance
    ? unenforcedRules(
        lock.deployment.mode,
        governance.policy,
        manifestContainment(governance),
      ).filter((item) => item.level === "error")
    : [];
  if (unenforced.length)
    throw gate(
      "POLICY_UNENFORCEABLE",
      "policy",
      unenforced.map((item) => item.message).join("; "),
    );
  for (const provider of lock.governance?.providers ?? [])
    if (provider.class === "certified" && !provider.certified)
      throw gate(
        "POLICY_DENIED",
        "certification",
        `capability ${provider.capability} uses certified provider ${provider.id} without certification evidence`,
      );
  for (const item of lock.governance?.manifest.resources.declared ?? [])
    if (item.class === "certified" && !item.certified)
      throw gate(
        "POLICY_DENIED",
        "certification",
        `${item.kind} ${item.path} is certified without certification evidence`,
      );
  // Only the native backend depends on the target's OS sandbox.
  const sandbox = lock.governance?.manifest.sandbox;
  if (
    sandbox?.required &&
    sandbox.provider === undefined &&
    !["linux", "darwin"].includes(target.split("-")[0] ?? "")
  )
    throw gate(
      "SANDBOX_UNAVAILABLE",
      "sandbox",
      `the distribution requires an OS sandbox and PiShip has no sandbox adapter for ${target}`,
      "Remove the target from release.targets or make the sandbox optional after a security review",
    );
  return lock;
}
