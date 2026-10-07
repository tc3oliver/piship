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
  /**
   * The governance fetch that also permits plain HTTP to the origins of the
   * resolved urls of MCP servers with `httpTransport: http-allowed` on a
   * private or internal host; only those servers use it. Absent when none
   * resolves to such a url.
   */
  readonly mcpPlainHttpFetch?: ManagedFetch;
  /**
   * The governance fetch that also admits plain HTTP where `plainHttp`
   * accepts (usually `plainHttpOrigins` of one endpoint): for the audit
   * sinks and the sandbox with `httpTransport: http-allowed`. Absent, such
   * an endpoint over plain HTTP is refused.
   */
  readonly plainHttpFetch?: (
    plainHttp: (target: URL) => boolean,
  ) => ManagedFetch;
  /**
   * The claims of the identity this launch activated, for MCP identity
   * headers. Each call checks only the stored identity metadata and fails
   * when the launch's principal is signed out or replaced. Absent without an
   * OIDC identity.
   */
  readonly identityClaims?: () => Promise<Readonly<
    Record<string, unknown>
  > | null>;
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
  /**
   * `--yolo`: approve asks for this session only, without storing anything.
   * A managed distribution must allow auto-approval (`policy.userAuto`);
   * `GovernanceSession.open` refuses it otherwise.
   */
  readonly yolo?: boolean;
  /**
   * Called when `/auto off` ends `--yolo` for the rest of the session: the
   * permission provider's own auto-approval, switched on with it, goes off
   * too.
   */
  readonly onYoloEnd?: () => string | undefined | void;
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
  readonly kind:
    | ResourceKind
    | "mcp"
    | "extension-config"
    | "settings"
    | "agents"
    | "providers"
    | "claude";
  readonly class: string;
  readonly path: string;
  readonly loaded: boolean;
  readonly reason: string;
  readonly integrity?: "verified" | "not-applicable";
  readonly compatible?: boolean;
  readonly origin?: string;
}

/**
 * PiShip's decision on the project configuration that extensions load by
 * themselves (the Claude Code files pi-code reads). `trusted` is what Pi's
 * `isProjectTrusted()` reports; `surfaces` is how many items were found.
 */
export interface ProjectTrustResult {
  readonly trusted: boolean;
  readonly surfaces: number;
  readonly reason: string;
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
