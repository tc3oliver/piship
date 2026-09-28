import type { DeploymentMode, PolicyConfig, PolicyRule } from "@piship/schema";
import {
  defaultProjectTrust,
  defaultProviderTrust,
  defaultResourceTrust,
} from "./trust.js";

export function makePolicy(
  overrides: Partial<PolicyConfig> = {},
  mode: DeploymentMode = "managed",
): PolicyConfig {
  return {
    id: "acme-engineering",
    version: 3,
    default: mode === "managed" ? "ask" : "allow",
    enforced: [],
    defaults: [],
    resourceTrust: defaultResourceTrust(mode),
    providerTrust: defaultProviderTrust(mode),
    projectTrust: defaultProjectTrust(mode),
    ...overrides,
  };
}

export function rule(
  id: string,
  action: PolicyRule["action"],
  resource: string,
  effect: PolicyRule["effect"],
  reason?: string,
): PolicyRule {
  return { id, action, resource, effect, ...(reason ? { reason } : {}) };
}
