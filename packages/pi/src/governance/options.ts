import type { LocalMetrics } from "@piship/audit";
import type {
  ApprovalChannel,
  AuditEventType,
  IdentitySession,
  ManagedFetch,
  PolicyAction,
  PrincipalKey,
  SandboxCredentialAccess,
} from "@piship/contracts";
import type {
  AccessEvent,
  DistributionLock,
  GovernanceLock,
} from "@piship/core";
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
  /**
   * How long the final audit flush may retry a required sink before the loss
   * is reported (default 5 s). A test seam: fault-injection tests shorten it.
   */
  readonly auditCloseDeadlineMs?: number;
  /**
   * How long one call into a custom sandbox adapter may take: its factory,
   * `available()`, `prepare()`, `dispose()`, and its `sandboxCredential`.
   * A test seam; production uses PiShip's defaults for each call.
   */
  readonly adapterTimeoutMs?: number;
  /** Bearer for `credential: runtime` MCP servers. */
  readonly credential?: () => Promise<string | undefined>;
  /** Origins the runtime credential is issued for (the inference gateway). */
  readonly credentialOrigins?: readonly string[];
  /**
   * `sandbox.credential: stored`: the stored sandbox credential of the
   * launch's principal, for the resolved endpoint (and router) URLs it
   * would be sent to. Fails closed (SANDBOX_UNAVAILABLE) before the secret
   * is read when it belongs to another principal, was rejected, or was
   * stored for other origins. Absent when the launch has no principal to
   * check it against.
   */
  readonly sandboxCredential?: (
    targets: readonly string[],
  ) => Promise<SandboxCredentialAccess>;
  /**
   * The launch's identity for a custom sandbox adapter's `sandboxCredential`
   * export, which must stay the launch's principal. Absent when the launch
   * has none to offer.
   */
  readonly sandboxIdentity?: {
    readonly principal: PrincipalKey | null;
    readonly current: () => Promise<IdentitySession | null>;
  };
  /** Receives sandbox credential lifecycle events (purpose sandbox). */
  readonly onSandboxCredentialEvent?: (event: AccessEvent) => void;
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
