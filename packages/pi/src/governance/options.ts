import type { LocalMetrics } from "@piship/audit";
import type {
  ApprovalChannel,
  AuditEventType,
  ManagedFetch,
  PolicyAction,
} from "@piship/contracts";
import type { DistributionLock, GovernanceLock } from "@piship/core";
import type { ModelEvidence } from "@piship/policy";
import type { BuiltinExtension, ResourceKind } from "@piship/schema";

export interface GovernanceOptions {
  readonly lock: DistributionLock & { readonly governance: GovernanceLock };
  readonly distributionDir: string;
  readonly stateDir: string;
  readonly cwd: string;
  readonly piVersion: string;
  /** Whether a person can answer startup approvals on this terminal. */
  readonly interactive: boolean;
  readonly fetch: ManagedFetch;
  readonly resolveTemplate: (key: string, template: string) => string;
  /** Identity subject for audit events; never a token. */
  readonly user?: string | null;
  /** Bearer for `credential: runtime` MCP servers. */
  readonly credential?: () => Promise<string | undefined>;
  /** Origins the runtime credential is issued for (the inference gateway). */
  readonly credentialOrigins?: readonly string[];
  readonly homeDir?: string;
  /** Override the startup approval channel (tests). */
  readonly startupApproval?: ApprovalChannel;
  /**
   * The selected model, which the `compatible` axis checks capability
   * requirements against; absent means unknown and meets no requirement.
   */
  readonly model?: ModelEvidence;
  /**
   * The launch's local metrics, shared with access so one save holds both;
   * loaded from the state directory when absent.
   */
  readonly metrics?: LocalMetrics;
}

export interface DecisionEvents {
  readonly allowed?: AuditEventType;
  readonly denied: AuditEventType;
  /** Metadata-only resource for the audit record (defaults to the redacted resource). */
  readonly resource?: string;
  /**
   * What the approval prompt shows the person, such as the tool and its
   * path or command. It is redacted and never written to audit.
   */
  readonly prompt?: string;
  readonly detail?: Readonly<Record<string, string | number | boolean | null>>;
  /** Content kept only for classes the distribution opted in to capture. */
  readonly content?: Readonly<Record<string, string>>;
}

/** Evidence for one declared, builtin, or project resource. */
export interface ResourceEvidence {
  readonly kind: ResourceKind | "mcp" | "settings" | "agents" | "providers";
  readonly class: string;
  readonly path: string;
  readonly loaded: boolean;
  readonly reason: string;
  readonly integrity?: "verified" | "not-applicable";
  readonly compatible?: boolean;
  readonly origin?: string;
}

export interface LoaderInputs {
  readonly instructions: readonly { path: string; content: string }[];
  readonly skills: readonly string[];
  readonly extensions: readonly string[];
  readonly prompts: readonly string[];
  readonly themes: readonly string[];
  readonly builtin: ReadonlySet<BuiltinExtension>;
}

export const KIND_ACTION: Readonly<Record<string, PolicyAction>> = {
  instructions: "instruction.load",
  skills: "skill.load",
  extensions: "extension.load",
  prompts: "resource.load",
  themes: "resource.load",
};
