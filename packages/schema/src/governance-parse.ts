// Parser for the piship/v1alpha3 governance sections: trust-classed
// resources, capabilities, policy, MCP, sandbox, and audit. Every field is
// validated strictly; unknown and secret-looking fields are rejected. Each
// section's parser lives in ./governance/; this module composes them.
import type { DeploymentMode } from "./access.js";
import type { GovernanceManifest } from "./governance.js";
import { parseAudit } from "./governance/audit.js";
import { parseCapabilities } from "./governance/capabilities.js";
import { parseMcp } from "./governance/mcp.js";
import { parsePackageTrust } from "./governance/packages.js";
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
export { parsePackages, parsePackageTrust } from "./governance/packages.js";
export {
  parseCacheWarming,
  parseRuntimeTools,
  parseSearchTools,
} from "./governance/runtime.js";
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

/** Top-level manifest sections added by piship/v1alpha6 to governance. */
export const V1ALPHA6_GOVERNANCE_KEYS = ["packageTrust"] as const;

/** Governance fields that accept `${NAME}` runtime references. */
export const GOVERNANCE_RUNTIME_REFERENCE_FIELDS = [
  "mcp.servers.<id>.url",
  "audit.sinks[<index>].url",
  "sandbox.endpoint",
  "sandbox.router",
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
  /** piship/v1alpha5 and later: accepts `policy.userAuto`. */
  v5 = false,
  /**
   * piship/v1alpha6 and later: `resources.packages`, `packageTrust`, MCP
   * server class and exposure, `policy.acknowledgeUnenforced`, and the
   * `httpTransport` of the audit sinks and the sandbox.
   */
  v6 = false,
): GovernanceManifest {
  return {
    resources: parseGovernanceResources(root.resources, { packages: v6 }),
    capabilities: parseCapabilities(root.capabilities),
    policy: parsePolicy(root.policy, mode, app, {
      userAuto: v5,
      acknowledgeUnenforced: v6,
    }),
    mcp: parseMcp(root.mcp, mode, variables, v6),
    sandbox: parseSandbox(root.sandbox, variables, v6),
    audit: parseAudit(root.audit, mode, variables, v6),
    ...(v6 ? { packageTrust: parsePackageTrust(root.packageTrust, mode) } : {}),
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
  for (const url of [governance.sandbox.endpoint, governance.sandbox.router])
    if (url) for (const name of referencedVariables(url)) names.add(name);
  return [...names];
}
