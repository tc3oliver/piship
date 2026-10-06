// Resource trust and capability-provider trust decisions. The two
// tables are independent: allowing a class for resources says nothing about
// the same class for providers.
import {
  CLAUDE_TRUST_DIMENSIONS,
  type ClaudeTrustDimension,
  type DeploymentMode,
  type PolicyConfig,
  type ProjectDimensionEffect,
  type ProjectDimensions,
  type ProjectTrustDimension,
  type ProjectTrustPolicy,
  type ProviderTrustClass,
  type ResourceKind,
  type ResourceTrustClass,
  type TrustClass,
  type TrustSetting,
  type TrustSubject,
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

/** Any project trust dimension: the eight always present, and the optional Claude ones. */
export type AnyProjectDimension = ProjectTrustDimension | ClaudeTrustDimension;

function claudeDimensions(
  base: ProjectDimensionEffect,
  overrides: Partial<Record<ClaudeTrustDimension, ProjectDimensionEffect>> = {},
): Readonly<Record<ClaudeTrustDimension, ProjectDimensionEffect>> {
  const output = {} as Record<ClaudeTrustDimension, ProjectDimensionEffect>;
  for (const dimension of CLAUDE_TRUST_DIMENSIONS)
    output[dimension] = overrides[dimension] ?? base;
  return output;
}

/**
 * Per-origin defaults of the Claude Code dimensions (`.claude/rules`,
 * `commands`, `skills`, `agents`, `hooks`). The manifest leaves them absent
 * unless declared (so existing locks do not change); this is what applies
 * then. Personal mode loads them like the other project items: company and
 * external projects without a prompt, an unknown one after the person says
 * yes. Managed mode follows the agents and hooks pattern: `hooks` are denied
 * and the rest are `company-approved`, which admits no project content, so a
 * company opts in by declaring `allow`.
 */
export function defaultClaudeDimensions(
  mode: DeploymentMode,
): Readonly<
  Record<
    ProjectOrigin,
    Readonly<Record<ClaudeTrustDimension, ProjectDimensionEffect>>
  >
> {
  if (mode === "managed")
    return {
      company: claudeDimensions("company-approved", { claudeHooks: "deny" }),
      external: claudeDimensions("deny"),
      unknown: claudeDimensions("deny"),
    };
  return {
    company: claudeDimensions("allow"),
    external: claudeDimensions("allow"),
    unknown: claudeDimensions("ask"),
  };
}

/** The effect of a Claude dimension: the declared one, else the mode default. */
export function claudeDimensionEffect(
  policy: Pick<PolicyConfig, "projectTrust">,
  mode: DeploymentMode,
  origin: ProjectOrigin,
  dimension: ClaudeTrustDimension,
): ProjectDimensionEffect {
  return (
    policy.projectTrust[origin].dimensions[dimension] ??
    defaultClaudeDimensions(mode)[origin][dimension]
  );
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

/**
 * The project trust dimension that governs each kind of governed object
 * when it comes from a project. Providers are never project objects.
 */
export const TRUST_SUBJECT_DIMENSION: Readonly<
  Record<Exclude<TrustSubject, "providers">, ProjectTrustDimension>
> = {
  ...RESOURCE_KIND_DIMENSION,
  packages: "extensions",
  "mcp-servers": "mcp",
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
  return resourceTableDecision(
    policy,
    cls,
    RESOURCE_KIND_DIMENSION[kind],
    origin,
  );
}

/**
 * The one trust evaluation for every governed object: capability providers
 * are decided by `policy.providerTrust` (and can never be `project`); every
 * other subject, Pi packages and MCP servers included, by
 * `policy.resourceTrust`, with `project` resolved through project trust.
 */
export function trustDecision(
  policy: Pick<
    PolicyConfig,
    "resourceTrust" | "providerTrust" | "projectTrust"
  >,
  subject: TrustSubject,
  cls: TrustClass,
  origin: ProjectOrigin = "unknown",
): ResourceTrustDecision {
  if (subject === "providers")
    return cls === "project"
      ? {
          allowed: false,
          class: cls,
          setting: "deny",
          reason: "Capability providers are never trusted from a project",
        }
      : providerTrustDecision(policy, cls);
  return resourceTableDecision(
    policy,
    cls,
    TRUST_SUBJECT_DIMENSION[subject],
    origin,
  );
}

function resourceTableDecision(
  policy: Pick<PolicyConfig, "resourceTrust" | "projectTrust">,
  cls: ResourceTrustClass,
  dimension: ProjectTrustDimension,
  origin: ProjectOrigin,
): ResourceTrustDecision {
  if (cls !== "project")
    return tableDecision(cls, policy.resourceTrust[cls], "Resource");
  const setting = policy.resourceTrust.project;
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
  dimension: AnyProjectDimension,
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
