// Parser for the piship/v1alpha3 governance sections: trust-classed
// resources, capabilities, policy, MCP, sandbox, and audit. Every field is
// validated strictly; unknown and secret-looking fields are rejected. Each
// section's parser lives in ./governance/; this module composes them.
import type { DeploymentMode } from "./access.js";
import type { GovernanceManifest } from "./governance.js";
import { parseAudit } from "./governance/audit.js";
import { parseCapabilities } from "./governance/capabilities.js";
import { parseMcp } from "./governance/mcp.js";
import { parsePolicy } from "./governance/policy.js";
import { parseGovernanceResources } from "./governance/resources.js";
import { parseSandbox } from "./governance/sandbox.js";
import { referencedVariables } from "./variables.js";

export { parseAudit } from "./governance/audit.js";
export {
  BUILTIN_PROVIDER_VERSION,
  parseCapabilities,
} from "./governance/capabilities.js";
export { parseMcp } from "./governance/mcp.js";
export { defaultProjectDimensions, parsePolicy } from "./governance/policy.js";
export { parseGovernanceResources } from "./governance/resources.js";
export {
  DEFAULT_SANDBOX_ENVIRONMENT,
  DEFAULT_SANDBOX_READ_DENY,
  DEFAULT_SANDBOX_WRITE_ALLOW,
  parseSandbox,
} from "./governance/sandbox.js";

/** Top-level manifest sections added by piship/v1alpha3. */
export const GOVERNANCE_KEYS = [
  "capabilities",
  "policy",
  "mcp",
  "sandbox",
  "audit",
] as const;

/** Governance fields that accept `${NAME}` runtime references. */
export const GOVERNANCE_RUNTIME_REFERENCE_FIELDS = [
  "mcp.servers.<id>.url",
  "audit.sinks[<index>].url",
] as const;

/**
 * Parse the piship/v1alpha3 governance sections of a manifest root.
 * `variables` are the declared runtime variable names; `app` supplies the
 * default policy ID. Throws AccessFieldError with the offending field path.
 */
export function parseGovernance(
  root: Readonly<Record<string, unknown>>,
  mode: DeploymentMode,
  variables: readonly string[],
  app: { readonly id: string },
): GovernanceManifest {
  return {
    resources: parseGovernanceResources(root.resources),
    capabilities: parseCapabilities(root.capabilities),
    policy: parsePolicy(root.policy, mode, app),
    mcp: parseMcp(root.mcp, mode, variables),
    sandbox: parseSandbox(root.sandbox),
    audit: parseAudit(root.audit, mode, variables),
  };
}

/** Runtime variables referenced by governance fields. */
export function governanceReferences(governance: GovernanceManifest): string[] {
  const names = new Set<string>();
  for (const server of governance.mcp.servers)
    if (server.url)
      for (const name of referencedVariables(server.url)) names.add(name);
  for (const sink of governance.audit.sinks)
    if (sink.url)
      for (const name of referencedVariables(sink.url)) names.add(name);
  return [...names];
}
