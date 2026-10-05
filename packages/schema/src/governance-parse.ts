// Parser for the piship/v1alpha3 governance sections: trust-classed
// resources, capabilities, policy, MCP, sandbox, and audit. Every field is
// validated strictly; unknown and secret-looking fields are rejected. Each
// section's parser lives in ./governance/; this module composes them.
import { AccessFieldError, type DeploymentMode } from "./access.js";
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
 * A capability provider that names a package must name a declared one of the
 * same trust class, and no two capabilities may share a package: its
 * extensions load once, for the one provider that owns them.
 */
function checkPackageProviders(
  resources: GovernanceManifest["resources"],
  capabilities: GovernanceManifest["capabilities"],
): void {
  const owners = new Map<string, string>();
  for (const capability of capabilities) {
    const provider = capability.provider;
    if (!provider?.package) {
      if (
        capability.settings.autoApproveFile !== undefined ||
        capability.settings.autoApproveKey !== undefined
      )
        throw new AccessFieldError(
          "conflict",
          `capabilities.${capability.name}.settings`,
          "autoApproveFile and autoApproveKey need a provider that is a declared Pi package",
        );
      continue;
    }
    const at = `capabilities.${capability.name}.provider.package`;
    const declared = resources.packages?.find(
      (item) => item.id === provider.package,
    );
    if (!declared)
      throw new AccessFieldError(
        "conflict",
        at,
        `${provider.package} is not declared under resources.packages`,
      );
    if (declared.class !== provider.class)
      throw new AccessFieldError(
        "conflict",
        at,
        `Provider ${provider.id} is ${provider.class}, but package ${declared.id} is ${declared.class}; the classes must match`,
      );
    const other = owners.get(declared.id);
    if (other)
      throw new AccessFieldError(
        "conflict",
        at,
        `Package ${declared.id} already provides the ${other} capability`,
      );
    owners.set(declared.id, capability.name);
    checkAutoApprove(capability, declared.agentFiles ?? []);
  }
}

/**
 * The permissions capability's `autoApproveFile` and `autoApproveKey` name
 * where the provider reads a session-wide auto-approval from: a top-level
 * key of one of the provider package's own `agentFiles`. Neither without the
 * other, and neither on another capability.
 */
function checkAutoApprove(
  capability: GovernanceManifest["capabilities"][number],
  files: readonly { readonly path: string }[],
): void {
  const at = `capabilities.${capability.name}.settings`;
  const file = capability.settings.autoApproveFile;
  const key = capability.settings.autoApproveKey;
  if (file === undefined && key === undefined) return;
  if (capability.name !== "permissions")
    throw new AccessFieldError(
      "conflict",
      at,
      "autoApproveFile and autoApproveKey belong to the permissions capability",
    );
  if (file === undefined || key === undefined)
    throw new AccessFieldError(
      "invalid field",
      at,
      "autoApproveFile and autoApproveKey go together",
    );
  if (!files.some((item) => item.path === file))
    throw new AccessFieldError(
      "conflict",
      `${at}.autoApproveFile`,
      `${file} is not one of the provider package's agentFiles`,
    );
  if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(key))
    throw new AccessFieldError(
      "invalid field",
      `${at}.autoApproveKey`,
      "Expected a top-level key name of letters and digits",
    );
}

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
  const resources = parseGovernanceResources(root.resources, { packages: v6 });
  const capabilities = parseCapabilities(root.capabilities, v6);
  checkPackageProviders(resources, capabilities);
  return {
    resources,
    capabilities,
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
