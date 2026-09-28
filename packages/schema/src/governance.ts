// piship/v1alpha3 governance intent: policy, resource and provider trust,
// project trust, capabilities, MCP, sandbox, and audit. These are static,
// secret-free declarations; enforcement lives in the runtime packages.
import type {
  AuditCapture,
  PolicyAction,
  PolicyEffect,
} from "@piship/contracts";

export const RESOURCE_KINDS = [
  "instructions",
  "skills",
  "extensions",
  "prompts",
  "themes",
] as const;
export type ResourceKind = (typeof RESOURCE_KINDS)[number];

/** Pi resource trust classes. `project` is discovered, never declared. */
export const RESOURCE_TRUST_CLASSES = [
  "upstream",
  "builtin",
  "certified",
  "company",
  "user",
  "project",
] as const;
export type ResourceTrustClass = (typeof RESOURCE_TRUST_CLASSES)[number];

/** Capability-provider trust classes; deliberately separate from resource trust. */
export const PROVIDER_TRUST_CLASSES = [
  "upstream",
  "builtin",
  "certified",
  "company",
  "user",
] as const;
export type ProviderTrustClass = (typeof PROVIDER_TRUST_CLASSES)[number];

/** Classes a manifest may declare by path. */
export const DECLARABLE_RESOURCE_CLASSES = [
  "certified",
  "company",
  "user",
] as const;
export type DeclarableResourceClass =
  (typeof DECLARABLE_RESOURCE_CLASSES)[number];

/** PiShip-maintained extensions, referenced by name under `builtin`. */
export const BUILTIN_EXTENSIONS = [
  "piship-ask-user",
  "piship-workflow",
] as const;
export type BuiltinExtension = (typeof BUILTIN_EXTENSIONS)[number];

/** Review evidence a certified resource or provider must carry. */
export interface CertifiedEvidence {
  readonly id: string;
  readonly version: string;
  /** Where the reviewed content came from (URL or package coordinate); informative. */
  readonly source: string;
  /** `sha256-<hex>` digest over the resource tree, checked at lock and launch. */
  readonly integrity: string;
  readonly license: string;
  /** Exact Pi versions the resource was reviewed against. */
  readonly pi: readonly string[];
  /** Node platforms (`linux`, `darwin`, `win32`); empty means any. */
  readonly platforms: readonly string[];
}

export interface DeclaredResource {
  readonly kind: ResourceKind;
  readonly class: DeclarableResourceClass;
  /** `./` relative path inside the distribution repository. */
  readonly path: string;
  /** Present exactly when `class` is `certified`. */
  readonly certified?: CertifiedEvidence;
}

export interface GovernanceResources {
  readonly declared: readonly DeclaredResource[];
  readonly builtin: readonly BuiltinExtension[];
}

// ------------------------------------------------------------ capabilities

export const CAPABILITY_CONTRACTS = {
  permissions: "piship.capability/permissions/v1",
  workflow: "piship.capability/workflow/v1",
  checkpoint: "piship.capability/checkpoint/v1",
  subagents: "piship.capability/agents/v1",
  "code-intel": "piship.capability/code-intel/v1",
  acp: "piship.capability/acp/v1",
} as const;
export type CapabilityName = keyof typeof CAPABILITY_CONTRACTS;

/** Contracts PiShip implements in this release; others are known but unsupported. */
export const SUPPORTED_CAPABILITY_CONTRACTS: readonly string[] = [
  CAPABILITY_CONTRACTS.permissions,
  CAPABILITY_CONTRACTS.workflow,
];

/** Builtin providers and the contracts they implement. */
export const BUILTIN_PROVIDERS: Readonly<Record<string, readonly string[]>> = {
  "builtin/permissions": [CAPABILITY_CONTRACTS.permissions],
  "builtin/workflow": [CAPABILITY_CONTRACTS.workflow],
};

export interface CapabilityProviderRef {
  /** `<class>/<name>`; the prefix is the provider trust class. */
  readonly id: string;
  readonly class: ProviderTrustClass;
  /** Provider SemVer, independent from the contract version. */
  readonly version: string;
  readonly implements: readonly string[];
  /** `./` path to the provider's Pi extension entry (non-builtin providers). */
  readonly path?: string;
  /** Required for certified providers. */
  readonly certified?: CertifiedEvidence;
}

/**
 * Model capabilities an enabled capability needs. At launch they are compared
 * with the selected model's verified catalog metadata; unknown metadata does
 * not satisfy a requirement.
 */
export interface CapabilityModelRequirements {
  /** The model must support tool calls. */
  readonly tools?: boolean;
  /** The model must accept structured (JSON schema) output. */
  readonly structuredOutput?: boolean;
  /** Smallest acceptable context window, in tokens. */
  readonly minContextWindow?: number;
  /** Input modalities the model must accept. */
  readonly input?: readonly ("text" | "image")[];
}

export interface CapabilityConfig {
  readonly name: CapabilityName;
  readonly enabled: boolean;
  readonly provider?: CapabilityProviderRef;
  /** Non-secret provider settings, such as workflow prompts. */
  readonly settings: Readonly<Record<string, string>>;
  /** Present only when declared. */
  readonly requirements?: CapabilityModelRequirements;
}

// ------------------------------------------------------------------ policy

export interface PolicyRule {
  readonly id: string;
  /** A policy action, `<prefix>.*`, or `*`. */
  readonly action: PolicyAction | `${string}.*` | "*";
  /** Glob over the action's resource; `*` matches one segment, `**` any. */
  readonly resource: string;
  readonly effect: PolicyEffect;
  readonly reason?: string;
}

export type TrustSetting = "allow" | "deny";
export type ProjectResourceTrust = TrustSetting | "policy";

export const PROJECT_TRUST_DIMENSIONS = [
  "passiveContext",
  "instructions",
  "skills",
  "agents",
  "hooks",
  "extensions",
  "mcp",
  "providers",
] as const;
export type ProjectTrustDimension = (typeof PROJECT_TRUST_DIMENSIONS)[number];
/**
 * `company-approved` admits only distribution-approved items (for example an
 * allowlisted MCP server); project-supplied executable code is never admitted.
 */
export type ProjectDimensionEffect = PolicyEffect | "company-approved";
export type ProjectDimensions = Readonly<
  Record<ProjectTrustDimension, ProjectDimensionEffect>
>;

export interface ProjectMatcher {
  /** Glob over the normalized origin remote, such as `git.example.com/team/**`. */
  readonly remote?: string;
  /** Glob over the resolved absolute project root. */
  readonly path?: string;
}

export interface ProjectTrustPolicy {
  readonly company: {
    readonly match: readonly ProjectMatcher[];
    readonly dimensions: ProjectDimensions;
  };
  readonly external: {
    readonly match: readonly ProjectMatcher[];
    readonly dimensions: ProjectDimensions;
  };
  readonly unknown: { readonly dimensions: ProjectDimensions };
}

export interface PolicyConfig {
  readonly id: string;
  readonly version: number;
  /** Effect when no rule matches. Headless `ask` resolves to deny. */
  readonly default: PolicyEffect;
  readonly enforced: readonly PolicyRule[];
  readonly defaults: readonly PolicyRule[];
  /** Optional downstream team rules module (`./x.mjs`); narrowing only. */
  readonly adapter?: string;
  readonly resourceTrust: Readonly<
    Record<Exclude<ResourceTrustClass, "project">, TrustSetting> & {
      readonly project: ProjectResourceTrust;
    }
  >;
  readonly providerTrust: Readonly<Record<ProviderTrustClass, TrustSetting>>;
  readonly projectTrust: ProjectTrustPolicy;
}

// --------------------------------------------------------------------- MCP

export interface McpServerConfig {
  readonly id: string;
  readonly transport: "stdio" | "streamable-http";
  /** stdio: `./` module run with the distribution's Node, or an executable name. */
  readonly module?: string;
  readonly command?: string;
  readonly args: readonly string[];
  /** Streamable HTTP endpoint; may be a `${NAME}` runtime reference. */
  readonly url?: string;
  readonly env: {
    readonly allow: readonly string[];
    readonly set: Readonly<Record<string, string>>;
  };
  /** `runtime` binds the distribution's runtime credential as a bearer (HTTP only). */
  readonly credential: "none" | "runtime";
  /** Expected `serverInfo.name` from initialize; a mismatch fails the start. */
  readonly expectedServerName?: string;
  readonly timeoutMs: number;
  readonly startupTimeoutMs: number;
  readonly retry: { readonly attempts: number };
  readonly required: boolean;
  readonly tools: {
    readonly allow: readonly string[];
    readonly deny: readonly string[];
  };
}

export interface McpConfig {
  /** `off`: no MCP; `allowlist`: only declared servers; `explicit`: declared plus trusted user/project definitions. */
  readonly mode: "off" | "allowlist" | "explicit";
  readonly servers: readonly McpServerConfig[];
  readonly project: TrustSetting;
  readonly user: TrustSetting;
}

// ----------------------------------------------------------------- sandbox

export interface SandboxConfig {
  /** A required sandbox that cannot be activated fails closed. */
  readonly required: boolean;
  readonly filesystem: {
    /** Path tokens: `workspace`, `tmp`, `~/...`, or absolute paths. */
    readonly read: { readonly deny: readonly string[] };
    readonly write: { readonly allow: readonly string[] };
  };
  /** Enforced at the OS boundary; hostname allowlists are not claimed. */
  readonly network: { readonly mode: "deny" | "allow" };
  /** Environment variable names passed into sandboxed processes. */
  readonly environment: { readonly allow: readonly string[] };
}

// ------------------------------------------------------------------- audit

export interface AuditSinkConfig {
  readonly id: string;
  readonly type: "file" | "http";
  /** HTTP sinks: endpoint URL or `${NAME}` runtime reference. */
  readonly url?: string;
  readonly required: boolean;
}

export interface AuditConfig {
  readonly enabled: boolean;
  readonly sinks: readonly AuditSinkConfig[];
  readonly buffer: {
    readonly maxEvents: number;
    readonly flushIntervalMs: number;
  };
  readonly capture: AuditCapture;
}

export interface GovernanceManifest {
  readonly policy: PolicyConfig;
  readonly resources: GovernanceResources;
  readonly capabilities: readonly CapabilityConfig[];
  readonly mcp: McpConfig;
  readonly sandbox: SandboxConfig;
  readonly audit: AuditConfig;
}
