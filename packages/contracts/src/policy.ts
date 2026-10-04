// The canonical policy decision contract shared by the policy engine, the Pi
// runtime integration, MCP governance, the sandbox, and audit.

export type PolicyEffect = "allow" | "ask" | "deny";

/**
 * Where a decision is enforced. `control-plane` is prevented by PiShip before
 * the action runs; `sandbox` needs an OS/process boundary; `gateway` is
 * prevented by the managed LLM gateway or credential broker; `audit-only` is
 * observed but cannot be reliably prevented and is never reported as deny.
 */
export const ENFORCEMENT_PLANES = [
  "control-plane",
  "sandbox",
  "gateway",
  "audit-only",
] as const;
export type EnforcementPlane = (typeof ENFORCEMENT_PLANES)[number];

/**
 * The status reported for an action. `control-plane`, `sandbox`, and
 * `gateway` are `enforced`; `audit-only` is observed and recorded but not
 * prevented; `unsupported` has no runtime hook at all: it is neither
 * prevented nor recorded, and is never emitted in an audit event.
 */
export const ENFORCEMENT_STATUSES = [
  "enforced",
  "audit-only",
  "unsupported",
] as const;
export type EnforcementStatus = (typeof ENFORCEMENT_STATUSES)[number];

/**
 * What the Pi runtime offers PiShip for an action: `hook` can prevent it,
 * `observe` only reports it, `none` has no public seam.
 */
export const RUNTIME_SEAM_KINDS = ["hook", "observe", "none"] as const;
export type RuntimeSeamKind = (typeof RUNTIME_SEAM_KINDS)[number];

/**
 * Resources of the `session.export` action: `public` is `/share` and any
 * upload that leaves the machine, `local` is `/export` to a local file, and
 * `support` is a support bundle or bug attachment.
 */
export const SESSION_EXPORT_RESOURCES = ["public", "local", "support"] as const;
export type SessionExportResource = (typeof SESSION_EXPORT_RESOURCES)[number];

export const POLICY_ACTIONS = [
  "model.select",
  "model.dispatch",
  "session.export",
  "resource.load",
  "extension.load",
  "skill.load",
  "instruction.load",
  "provider.load",
  "agent.invoke",
  "mcp.server.start",
  "mcp.tool.call",
  "tool.execute",
  "shell.execute",
  "filesystem.read",
  "filesystem.write",
  "network.connect",
  "memory.read",
  "memory.write",
  "web.request",
  "browser.execute",
] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

/**
 * Former action names that are still accepted in rules and normalized to
 * the current name when the rule is parsed. `model.use` (piship/v1alpha5 and
 * earlier) is `model.select`.
 */
export const POLICY_ACTION_ALIASES = {
  "model.use": "model.select",
} as const satisfies Readonly<Record<string, PolicyAction>>;
export type PolicyActionAlias = keyof typeof POLICY_ACTION_ALIASES;

/**
 * The current name of a rule action: an alias becomes its action, and
 * anything else (an action, a `<prefix>.*`, `*`, or an unknown name) is
 * returned unchanged.
 */
export function normalizePolicyAction(action: string): string {
  return Object.hasOwn(POLICY_ACTION_ALIASES, action)
    ? POLICY_ACTION_ALIASES[action as PolicyActionAlias]
    : action;
}

/** The configuration layer a rule came from, highest precedence first. */
export const POLICY_LAYERS = [
  "distribution-enforced",
  "team-project",
  "distribution-default",
  "user-preference",
] as const;
export type PolicyLayer = (typeof POLICY_LAYERS)[number];

export interface PolicyDecision {
  readonly effect: PolicyEffect;
  /** `<policy id>@<version>` of the evaluated policy. */
  readonly policyId: string;
  /** The rule that produced the effect, or a `builtin:` fallback rule ID. */
  readonly ruleId: string;
  readonly reason?: string;
  readonly enforcement: EnforcementPlane;
  readonly action: PolicyAction;
  readonly resource: string;
  /** Layer of the deciding rule; `builtin` for the documented fallback. */
  readonly layer: PolicyLayer | "builtin";
}

/** The outcome after `ask` is resolved through an approval channel. */
export interface ResolvedDecision extends PolicyDecision {
  /** Final effect: `ask` never survives resolution. */
  readonly outcome: "allow" | "deny";
  /**
   * How an `ask` was resolved. `auto`: the user's auto mode, which the
   * distribution allows (`policy.userAuto`), approved it without a prompt.
   */
  readonly approval?:
    | "approved"
    | "denied"
    | "cancelled"
    | "unavailable"
    | "auto";
}

export interface PolicyRequest {
  readonly action: PolicyAction;
  /** Action-specific resource: model key, `server:tool`, path, host, tool name. */
  readonly resource: string;
  /** Headless flows have no approval channel; `ask` then resolves to deny. */
  readonly interactive?: boolean;
}

/** Evaluates a request. Implementations must be deterministic and side-effect free. */
export type PolicyEvaluator = (request: PolicyRequest) => PolicyDecision;

/**
 * An approval channel for `ask`. It returns the user's answer; a missing
 * channel (headless) is treated as unavailable and resolves to deny.
 */
export type ApprovalChannel = (
  decision: PolicyDecision,
  detail: { readonly title: string; readonly message: string },
) => Promise<"approved" | "denied" | "cancelled">;

export function resolveWithoutChannel(
  decision: PolicyDecision,
): ResolvedDecision {
  if (decision.effect === "ask")
    return { ...decision, outcome: "deny", approval: "unavailable" };
  return { ...decision, outcome: decision.effect };
}

export async function resolveDecision(
  decision: PolicyDecision,
  channel: ApprovalChannel | undefined,
  detail: { readonly title: string; readonly message: string },
): Promise<ResolvedDecision> {
  if (decision.effect !== "ask") return resolveWithoutChannel(decision);
  if (!channel) return resolveWithoutChannel(decision);
  let answer: "approved" | "denied" | "cancelled";
  try {
    answer = await channel(decision, detail);
  } catch {
    answer = "cancelled";
  }
  return {
    ...decision,
    outcome: answer === "approved" ? "allow" : "deny",
    approval: answer,
  };
}
