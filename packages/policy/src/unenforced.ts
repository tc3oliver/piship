// POLICY_UNENFORCEABLE: manifest rules that deny or ask for an action no
// runtime seam enforces. Only rules naming such an action exactly count;
// `policy.default`, `*`, and `<prefix>.*` rules never do, or the managed
// `ask` default would fail every manifest.
import type { EnforcementStatus } from "@piship/contracts";
import type {
  DeploymentMode,
  GovernanceManifest,
  PolicyConfig,
} from "@piship/schema";
import type { PolicyContainment } from "./engine.js";
import { isPolicyAction, ruleStatus } from "./seams.js";

/** The policy fields the check reads. */
export type UnenforcedPolicy = Pick<
  PolicyConfig,
  "enforced" | "defaults" | "acknowledgeUnenforced"
>;

export interface UnenforcedFinding {
  /**
   * `error` (POLICY_UNENFORCEABLE) fails validate and the release gate;
   * `info` is acknowledged.
   */
  readonly level: "error" | "warning" | "info";
  readonly status: Exclude<EnforcementStatus, "enforced">;
  readonly tier: "enforced" | "defaults";
  readonly ruleId: string;
  readonly action: string;
  readonly resource: string;
  readonly effect: string;
  /** The `policy.acknowledgeUnenforced` key for this rule. */
  readonly key: string;
  readonly message: string;
}

/**
 * Containment as the manifest declares it: a required sandbox contains the
 * filesystem, shell, and network planes, and a managed launch runs Pi offline
 * (`PI_OFFLINE=1`). Nothing optional is assumed.
 */
export function manifestContainment(
  governance: Partial<Pick<GovernanceManifest, "sandbox">>,
  mode: DeploymentMode,
): PolicyContainment {
  const required = governance.sandbox?.required === true;
  return {
    filesystem: required,
    network: required,
    shell: required,
    piOffline: mode === "managed",
  };
}

/**
 * Deny and ask rules the runtime cannot honor. Managed: an unsupported rule
 * is an error unless acknowledged, and an audit-only rule a warning naming
 * the plane. Personal: an unsupported rule is a warning.
 */
export function unenforcedRules(
  mode: DeploymentMode,
  policy: UnenforcedPolicy,
  containment: PolicyContainment,
): UnenforcedFinding[] {
  const acknowledged = new Set(policy.acknowledgeUnenforced ?? []);
  const findings: UnenforcedFinding[] = [];
  for (const [tier, rules] of [
    ["enforced", policy.enforced],
    ["defaults", policy.defaults],
  ] as const)
    for (const rule of rules) {
      if (rule.effect !== "deny" && rule.effect !== "ask") continue;
      if (!isPolicyAction(rule.action)) continue;
      const status = ruleStatus(rule.action, rule.resource, containment);
      if (status === "enforced") continue;
      const key = `${rule.action}:${rule.resource}`;
      const base = {
        status,
        tier,
        ruleId: rule.id,
        action: rule.action,
        resource: rule.resource,
        effect: rule.effect,
        key,
      };
      const where = `policy.${tier} rule ${rule.id} (${rule.effect} ${key})`;
      if (status === "audit-only") {
        if (mode === "managed")
          findings.push({
            ...base,
            level: "warning",
            message: `${where}: ${rule.action} is on the audit-only plane (observed and recorded, not prevented)`,
          });
        continue;
      }
      const unsupported = `${where}: ${rule.action} has no runtime seam in this Pi version, so the rule is neither prevented nor recorded`;
      if (mode === "personal")
        findings.push({ ...base, level: "warning", message: unsupported });
      else if (acknowledged.has(key))
        findings.push({
          ...base,
          level: "info",
          message: `${unsupported} (acknowledged in policy.acknowledgeUnenforced)`,
        });
      else
        findings.push({
          ...base,
          level: "error",
          message: `${unsupported}; remove it or add "${key}" to policy.acknowledgeUnenforced`,
        });
    }
  return findings;
}
