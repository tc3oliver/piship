import { dirname, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  manifestContainment,
  type UnenforcedFinding,
  unenforcedRules,
} from "@piship/policy";
import type { Manifest } from "@piship/schema";
import type { LockedResource } from "./lock-schema.js";
import { resolveResources } from "./resources.js";
import {
  assertIntegrity,
  assertNoInstallScripts,
  filesUnder,
  type GovernanceLock,
  treeDigest,
} from "./trust.js";

/** Certified digests and provider versions; any tampering or install script fails. */
export function governanceLock(
  manifest: Manifest,
  base: string,
  resources: readonly LockedResource[],
): GovernanceLock | undefined {
  const governance = manifest.governance;
  if (!governance) return undefined;
  const certified = governance.resources.declared
    .filter((item) => item.class === "certified" && item.certified)
    .map((item) => {
      const field = `resources.${item.kind}.certified`;
      const files = filesUnder(
        resources.filter((entry) => entry.kind === item.kind),
        item.path,
      );
      assertNoInstallScripts(resolve(base, item.path), files, field);
      const integrity = treeDigest(files);
      const evidence = item.certified as NonNullable<typeof item.certified>;
      assertIntegrity(integrity, evidence.integrity, field);
      return { kind: item.kind, path: item.path, evidence, integrity };
    });
  const providers = governance.capabilities.flatMap((capability) => {
    const provider = capability.provider;
    if (!provider) return [];
    const field = `capabilities.${capability.name}.provider`;
    let integrity: string | undefined;
    if (provider.path) {
      const files = filesUnder(
        resources.filter((entry) => entry.kind === "providers"),
        provider.path,
      );
      assertNoInstallScripts(resolve(base, provider.path), files, field);
      integrity = treeDigest(files);
      if (provider.certified)
        assertIntegrity(integrity, provider.certified.integrity, field);
    }
    return [
      {
        capability: capability.name,
        id: provider.id,
        class: provider.class,
        version: provider.version,
        implements: provider.implements,
        ...(provider.path ? { path: provider.path } : {}),
        ...(integrity ? { integrity } : {}),
        ...(provider.certified ? { certified: provider.certified } : {}),
      },
    ];
  });
  return { manifest: governance, certified, providers };
}
/**
 * Check-only form of the lock-time governance checks: certified resource and
 * capability-provider tree integrity and install-script rejection. Throws the
 * same errors as `piship lock` and writes nothing.
 */
export function checkGovernance(
  manifest: Manifest,
  manifestPath: string,
  resources: readonly LockedResource[] = resolveResources(
    manifest,
    manifestPath,
  ),
): void {
  governanceLock(manifest, dirname(resolve(manifestPath)), resources);
}

/**
 * Rules that deny or ask for an action no runtime seam enforces. A managed
 * finding that is neither acknowledged nor audit-only throws
 * POLICY_UNENFORCEABLE; the rest are returned for display.
 */
export function checkEnforceability(manifest: Manifest): UnenforcedFinding[] {
  const governance = manifest.governance;
  if (!governance) return [];
  const findings = unenforcedRules(
    manifest.deployment.mode,
    governance.policy,
    manifestContainment(governance),
  );
  const errors = findings.filter((item) => item.level === "error");
  if (errors.length)
    throw new PiShipError(
      "POLICY_UNENFORCEABLE",
      errors.map((item) => item.message).join("\n"),
      { component: "policy" },
    );
  return findings;
}
