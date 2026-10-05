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

/**
 * The one trust vocabulary for every governed object: extensions, skills,
 * prompts, themes, instructions, Pi packages, MCP servers, and capability
 * providers. Each object is evaluated as source trust (this class) plus
 * integrity (the lock digest), policy (its load, start, or call action), and,
 * for tools, exposure.
 */
export const TRUST_CLASSES = [
  "upstream",
  "builtin",
  "certified",
  "company",
  "user",
  "project",
] as const;
export type TrustClass = (typeof TRUST_CLASSES)[number];

/** Kinds of governed object that carry a trust class. */
export const TRUST_SUBJECTS = [
  "instructions",
  "skills",
  "extensions",
  "prompts",
  "themes",
  "packages",
  "mcp-servers",
  "providers",
] as const;
export type TrustSubject = (typeof TRUST_SUBJECTS)[number];

/** Pi resource trust classes. `project` is discovered, never declared. */
export const RESOURCE_TRUST_CLASSES = TRUST_CLASSES;
export type ResourceTrustClass = TrustClass;

/**
 * Capability-provider trust classes: the shared vocabulary without
 * `project` (a provider is never discovered in a project), evaluated
 * against `policy.providerTrust` rather than `policy.resourceTrust`.
 */
export const PROVIDER_TRUST_CLASSES = [
  "upstream",
  "builtin",
  "certified",
  "company",
  "user",
] as const satisfies readonly TrustClass[];
export type ProviderTrustClass = Exclude<TrustClass, "project">;

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
  /** piship/v1alpha6: Pi packages that PiShip resolves and vendors. */
  readonly packages?: readonly DeclaredPackage[];
}

// ---------------------------------------------------------- Pi packages

/** Where a Pi package comes from. PiShip resolves it; Pi never installs it. */
export const PACKAGE_SOURCE_KINDS = ["npm", "git", "local"] as const;
export type PackageSourceKind = (typeof PACKAGE_SOURCE_KINDS)[number];

/** Pi resource kinds a package filter selects, in Pi's package manifest. */
export const PACKAGE_RESOURCE_KINDS = [
  "extensions",
  "skills",
  "prompts",
  "themes",
] as const;
export type PackageResourceKind = (typeof PACKAGE_RESOURCE_KINDS)[number];

/**
 * Pi's object-form filter grammar per resource kind, unchanged: glob
 * patterns with `!`, `+`, and `-` prefixes. An absent kind selects all of
 * that kind; an empty list selects none.
 */
export type PackageFilters = Readonly<
  Partial<Record<PackageResourceKind, readonly string[]>>
>;

interface DeclaredPackageBase {
  readonly id: string;
  readonly class: DeclarableResourceClass;
  /** Present exactly when `class` is `certified`. */
  readonly certified?: CertifiedEvidence;
  readonly filters: PackageFilters;
}
export interface NpmPackage extends DeclaredPackageBase {
  readonly source: "npm";
  /** The npm package name, such as `@company/pi-platform`. */
  readonly package: string;
  /** As declared: an exact version, or (personal only) a range the lock resolves. */
  readonly version: string;
  /** Registry URL; absent uses the build environment's npm configuration. */
  readonly registry?: string;
}
export interface GitPackage extends DeclaredPackageBase {
  readonly source: "git";
  /** https repository URL without credentials. */
  readonly repository: string;
  /** As declared: a full commit SHA, or (personal only) a ref the lock resolves. */
  readonly ref: string;
}
export interface LocalPackage extends DeclaredPackageBase {
  readonly source: "local";
  /** `./` relative path inside the distribution directory. */
  readonly path: string;
}
export type DeclaredPackage = NpmPackage | GitPackage | LocalPackage;

/**
 * `packageTrust`: constraints on package *sources* (not trust classes).
 * An absent `git.hosts` or `local.paths` places no constraint beyond the
 * other rules.
 */
export interface PackageTrustConfig {
  readonly npm: { readonly requireIntegrity: boolean };
  readonly git: {
    readonly hosts?: readonly string[];
    readonly requireCommitSha: boolean;
  };
  readonly local: { readonly paths?: readonly string[] };
}

// ------------------------------------------------------------ tool exposure

/**
 * Pi's `ToolDefinition.exposure`, used for PiShip-registered tools and
 * PiShip-governed MCP tools. Exposure decides what the model can see or
 * discover; policy still decides what can run. `hidden` is excluded from
 * the session.
 */
export const TOOL_EXPOSURES = [
  "direct",
  "model-only",
  "codemode",
  "deferred",
  "hidden",
] as const;
export type ToolExposure = (typeof TOOL_EXPOSURES)[number];

/**
 * One `<glob>: <exposure>` entry, in declaration order. Precedence (the most
 * specific glob wins; a tie is invalid) is resolved where tools are
 * registered, not by the parser.
 */
export interface ToolExposureRule {
  readonly pattern: string;
  readonly exposure: ToolExposure;
}

/** `runtime.tools.codemode`: Pi's Codemode factory `mode`. */
export const CODEMODE_MODES = ["off", "on", "only"] as const;
export type CodemodeMode = (typeof CODEMODE_MODES)[number];

/** `runtime.tools.toolSearch`. */
export const TOOL_SEARCH_MODES = ["off", "on"] as const;
export type ToolSearchMode = (typeof TOOL_SEARCH_MODES)[number];

/** `runtime.tools` (piship/v1alpha6). */
export interface RuntimeToolsConfig {
  readonly codemode: CodemodeMode;
  readonly toolSearch: ToolSearchMode;
  readonly exposure: readonly ToolExposureRule[];
}

/** `runtime.cacheWarming.mode`: Pi's `cacheWarming` setting. */
export const CACHE_WARMING_MODES = ["off", "streaming", "idle"] as const;
export type CacheWarmingMode = (typeof CACHE_WARMING_MODES)[number];

/** `runtime.cacheWarming` (piship/v1alpha6); an omitted mode is `off`. */
export interface CacheWarmingConfig {
  readonly mode: CacheWarmingMode;
  /** Whether a user preference may override the distribution's mode. */
  readonly userOverride: boolean;
}

// -------------------------------------------------- runtime mutability

/**
 * Who may change a resource at runtime: `enforced` nobody (PiShip restores
 * it every turn), `mutable` any extension or command. There is no
 * "distribution extensions only" class: Pi does not record which extension
 * made a change, so it could not be enforced.
 */
export const MUTABILITY_CLASSES = ["enforced", "mutable"] as const;
export type MutabilityClass = (typeof MUTABILITY_CLASSES)[number];

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

export const USER_AUTO_SETTINGS = ["off", "allowed"] as const;
export type UserAutoSetting = (typeof USER_AUTO_SETTINGS)[number];

export interface PolicyConfig {
  readonly id: string;
  readonly version: number;
  /** Effect when no rule matches. Headless `ask` resolves to deny. */
  readonly default: PolicyEffect;
  readonly enforced: readonly PolicyRule[];
  readonly defaults: readonly PolicyRule[];
  /** Optional downstream team rules module (`./x.mjs`); narrowing only. */
  readonly adapter?: string;
  /**
   * Whether a managed user may switch on auto mode, which resolves `ask` to
   * allow for that user (never `deny` or an enforced rule). Present only when
   * the manifest declares it (piship/v1alpha5, managed mode); absent is `off`.
   */
  readonly userAuto?: UserAutoSetting;
  /**
   * piship/v1alpha6: `<action>:<resource>` pairs whose `deny` or `ask` rule
   * names an action PiShip cannot enforce, acknowledged by the owner.
   */
  readonly acknowledgeUnenforced?: readonly string[];
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
  /**
   * The piship/v1alpha5 tool filter: deny wins; an empty allow admits every
   * tool not denied. Empty for piship/v1alpha6, where `exposure` and
   * `toolExposure` decide which tools are visible.
   */
  readonly tools: {
    readonly allow: readonly string[];
    readonly deny: readonly string[];
  };
  /** piship/v1alpha6: trust class, governed by `policy.resourceTrust`. */
  readonly class?: McpServerClass;
  /** piship/v1alpha6: the server's default tool exposure (default `direct`). */
  readonly exposure?: ToolExposure;
  /** piship/v1alpha6: per-tool exposure globs (`tools:` in the manifest). */
  readonly toolExposure?: readonly ToolExposureRule[];
  /**
   * piship/v1alpha6, streamable-http only: `http-allowed` also permits plain
   * HTTP to a private or internal host (`isPrivateNetworkHost`). Absent
   * means `https` (plain HTTP only on loopback).
   */
  readonly httpTransport?: McpHttpTransport;
  /**
   * piship/v1alpha6, streamable-http only: request headers whose value is a
   * claim of the signed-in OIDC identity, keyed by header name. Only the
   * header and claim names are declared and locked, never a value.
   */
  readonly headers?: Readonly<Record<string, McpIdentityHeader>>;
}

/** `mcp.servers.<id>.httpTransport`: `https` (default) or `http-allowed`. */
export const MCP_HTTP_TRANSPORTS = ["https", "http-allowed"] as const;
export type McpHttpTransport = (typeof MCP_HTTP_TRANSPORTS)[number];

/**
 * The identity claims an MCP header may carry: string claims of the signed-in
 * OIDC identity that PiShip keeps (`RETAINED_CLAIMS`).
 */
export const MCP_IDENTITY_HEADER_CLAIMS = [
  "sub",
  "preferred_username",
  "email",
  "name",
] as const;
export type McpIdentityHeaderClaim =
  (typeof MCP_IDENTITY_HEADER_CLAIMS)[number];

export interface McpIdentityHeader {
  readonly identityClaim: McpIdentityHeaderClaim;
}

/**
 * Trust classes an MCP server may declare. `certified` needs review evidence
 * that has no MCP form yet, and the rest of the vocabulary is never declared.
 */
export const MCP_SERVER_CLASSES = ["company", "user"] as const;
export type McpServerClass = (typeof MCP_SERVER_CLASSES)[number];

/** The exposure of an MCP server without `exposure` (v0.8 behavior). */
export const DEFAULT_MCP_EXPOSURE: ToolExposure = "direct";

/**
 * The trust class of an MCP server that declares none: `company` in a
 * managed distribution and `user` in a personal one. piship/v1alpha5
 * servers migrate to it.
 */
export function defaultMcpServerClass(
  mode: "personal" | "managed",
): McpServerClass {
  return mode === "managed" ? "company" : "user";
}

export interface McpConfig {
  /** `off`: no MCP; `allowlist`: only declared servers; `explicit`: declared plus trusted user/project definitions. */
  readonly mode: "off" | "allowlist" | "explicit";
  readonly servers: readonly McpServerConfig[];
  readonly project: TrustSetting;
  readonly user: TrustSetting;
}

// ----------------------------------------------------------------- sandbox

/** Where sandboxed commands run; `native` is the platform OS sandbox. */
export const SANDBOX_PROVIDERS = [
  "native",
  "custom",
  "e2b-compatible",
  "kubernetes-agent-sandbox",
] as const;
export type SandboxProvider = (typeof SANDBOX_PROVIDERS)[number];

export interface SandboxConfig {
  /** A required sandbox that cannot be activated fails closed. */
  readonly required: boolean;
  /** The backend; omitted for `native`, the default. */
  readonly provider?: Exclude<SandboxProvider, "native">;
  /** `custom`: the adapter module (`./...`, packaged and locked). */
  readonly adapter?: string;
  /** Remote providers: control endpoint URL or `${NAME}` reference. */
  readonly endpoint?: string;
  /** `kubernetes-agent-sandbox`: sandbox router URL or `${NAME}` reference. */
  readonly router?: string;
  /** `kubernetes-agent-sandbox`: namespace of the SandboxClaims. */
  readonly namespace?: string;
  /** `e2b-compatible`: template ID; `kubernetes-agent-sandbox`: warm pool. */
  readonly template?: string;
  /** Remote providers: the remote directory that maps to the workspace. */
  readonly workdir?: string;
  /** `e2b-compatible`: the sandbox user commands run as (default `user`). */
  readonly user?: string;
  /**
   * Sent to the endpoint (and, for Kubernetes, the router): `runtime` sends
   * the runtime credential when the endpoint is on its origin; `stored`
   * sends the sandbox credential a person stored with `sandbox login`,
   * bound to the principal and the endpoint origins. Omitted is `none`.
   */
  readonly credential?: "runtime" | "stored";
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
  /** piship/v1alpha6: package source constraints, mode defaults applied. */
  readonly packageTrust?: PackageTrustConfig;
}
