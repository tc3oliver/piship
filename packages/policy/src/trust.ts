// Resource trust (§11) and capability-provider trust (§12) decisions. The two
// tables are independent: allowing a class for resources says nothing about
// the same class for providers.
import type {
  DeploymentMode,
  PolicyConfig,
  ProjectDimensionEffect,
  ProjectDimensions,
  ProjectTrustDimension,
  ProjectTrustPolicy,
  ProviderTrustClass,
  ResourceKind,
  ResourceTrustClass,
  TrustSetting,
} from "@piship/schema";

export type ResourceTrustTable = PolicyConfig["resourceTrust"];
export type ProviderTrustTable = PolicyConfig["providerTrust"];
export type ProjectOrigin = "company" | "external" | "unknown";

export function defaultResourceTrust(mode: DeploymentMode): ResourceTrustTable {
  const user: TrustSetting = mode === "managed" ? "deny" : "allow";
  return {
    upstream: "allow",
    builtin: "allow",
    certified: "allow",
    company: "allow",
    user,
    project: "policy",
  };
}

export function defaultProviderTrust(mode: DeploymentMode): ProviderTrustTable {
  const user: TrustSetting = mode === "managed" ? "deny" : "allow";
  return {
    upstream: "allow",
    builtin: "allow",
    certified: "allow",
    company: "allow",
    user,
  };
}

function dimensions(
  base: ProjectDimensionEffect,
  overrides: Partial<ProjectDimensions>,
): ProjectDimensions {
  return {
    passiveContext: base,
    instructions: base,
    skills: base,
    agents: base,
    hooks: base,
    extensions: base,
    mcp: base,
    providers: base,
    ...overrides,
  };
}

/** Per-origin project dimension defaults for a mode, without matchers. */
export function defaultProjectDimensions(
  mode: DeploymentMode,
): Readonly<Record<ProjectOrigin, ProjectDimensions>> {
  if (mode === "managed")
    return {
      company: dimensions("deny", {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        extensions: "company-approved",
        mcp: "company-approved",
      }),
      external: dimensions("deny", {
        passiveContext: "allow",
        instructions: "ask",
      }),
      unknown: dimensions("deny", { passiveContext: "allow" }),
    };
  return {
    company: dimensions("allow", { hooks: "deny" }),
    external: dimensions("allow", { hooks: "deny" }),
    unknown: dimensions("ask", { passiveContext: "allow", hooks: "deny" }),
  };
}

/** The full project trust default for a mode (no matchers declared). */
export function defaultProjectTrust(mode: DeploymentMode): ProjectTrustPolicy {
  const defaults = defaultProjectDimensions(mode);
  return {
    company: { match: [], dimensions: defaults.company },
    external: { match: [], dimensions: defaults.external },
    unknown: { dimensions: defaults.unknown },
  };
}

/** The project trust dimension that governs a Pi resource kind. */
export const RESOURCE_KIND_DIMENSION: Readonly<
  Record<ResourceKind, ProjectTrustDimension>
> = {
  instructions: "instructions",
  prompts: "instructions",
  skills: "skills",
  extensions: "extensions",
  themes: "passiveContext",
};

export interface TrustDecision<C extends string> {
  readonly allowed: boolean;
  readonly class: C;
  /** The table entry that decided; for projects, the dimension effect. */
  readonly setting: TrustSetting | "policy" | ProjectDimensionEffect;
  readonly reason: string;
}

export type ResourceTrustDecision = TrustDecision<ResourceTrustClass> & {
  /** For `project`: the resolved project dimension effect. */
  readonly effect?: ProjectDimensionEffect;
  readonly dimension?: ProjectTrustDimension;
};
export type ProviderTrustDecision = TrustDecision<ProviderTrustClass>;

function tableDecision<C extends string>(
  cls: C,
  setting: TrustSetting,
  subject: string,
): TrustDecision<C> {
  return {
    allowed: setting === "allow",
    class: cls,
    setting,
    reason:
      setting === "allow"
        ? `${subject} trust allows class ${cls}`
        : `${subject} trust denies class ${cls}`,
  };
}

/**
 * Decide whether a resource of `kind` and trust class `cls` may load. The
 * `project` class resolves through `projectTrust` for the given origin
 * (default `unknown`); `ask` and `company-approved` are reported as not
 * allowed with the effect so the caller can ask or apply an allowlist.
 */
export function resourceTrustDecision(
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  cls: ResourceTrustClass,
  kind: ResourceKind,
  origin: ProjectOrigin = "unknown",
): ResourceTrustDecision {
  if (cls !== "project")
    return tableDecision(cls, policy.resourceTrust[cls], "Resource");
  const setting = policy.resourceTrust.project;
  const dimension = RESOURCE_KIND_DIMENSION[kind];
  if (setting === "deny")
    return {
      allowed: false,
      class: cls,
      setting,
      dimension,
      effect: "deny",
      reason: "Resource trust denies project resources",
    };
  if (setting === "allow")
    return {
      allowed: true,
      class: cls,
      setting,
      dimension,
      effect: "allow",
      reason: "Resource trust allows project resources",
    };
  const effect = policy.projectTrust[origin].dimensions[dimension];
  return {
    allowed: effect === "allow",
    class: cls,
    setting: effect,
    dimension,
    effect,
    reason: projectEffectReason(origin, dimension, effect),
  };
}

export function projectEffectReason(
  origin: ProjectOrigin,
  dimension: ProjectTrustDimension,
  effect: ProjectDimensionEffect,
): string {
  switch (effect) {
    case "allow":
      return `Project trust for ${origin} projects allows ${dimension}`;
    case "deny":
      return `Project trust for ${origin} projects denies ${dimension}`;
    case "ask":
      return `Project trust for ${origin} projects requires approval for ${dimension}`;
    default:
      return "company-approved admits only distribution-approved items";
  }
}

export function providerTrustDecision(
  policy: Pick<PolicyConfig, "providerTrust">,
  cls: ProviderTrustClass,
): ProviderTrustDecision {
  return tableDecision(cls, policy.providerTrust[cls], "Provider");
}
