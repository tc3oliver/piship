// Human and JSON renderings of a policy explanation. All free text passes
// through redact() so rule reasons can never leak secret values.
import {
  type PolicyDecision,
  type PolicyEffect,
  type PolicyRequest,
  type ResolvedDecision,
  redact,
} from "@piship/contracts";
import {
  BUILTIN_DEFAULT_RULE,
  BUILTIN_UNKNOWN_ACTION_RULE,
  type PolicyEngine,
  type PolicyExplanation,
} from "./engine.js";
import { gitPushResources } from "./git-push.js";
import { grantShellPrograms, programRefusal } from "./grant.js";
import { decisionStatus } from "./seams.js";

const HEADINGS: Readonly<Record<PolicyEffect, string>> = {
  allow: "ALLOWED",
  ask: "APPROVAL REQUIRED",
  deny: "DENIED",
};

const STRICTNESS: Readonly<Record<PolicyEffect, number>> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

// shortcut: a name whose server id holds `__` reads as the first split, as
// the governor's first-claim rule usually resolves it; use the lock's server
// list if explain ever needs the exact owner.
const MCP_TOOL_NAME = /^mcp__([^_]+(?:_[^_]+)*)__(.+)$/;

/**
 * The other requests a session decides along with `request`: an MCP tool
 * call is decided as `tool.execute` on its model-facing name and as
 * `mcp.tool.call` on `<server>:<tool>`; a command `shell.execute` does not
 * deny is also decided as `git.push` for each push target a rule names.
 */
export function companionRequests(
  engine: Pick<PolicyEngine, "evaluate">,
  request: PolicyRequest,
): PolicyRequest[] {
  switch (request.action) {
    case "tool.execute": {
      const tool = MCP_TOOL_NAME.exec(request.resource);
      return tool
        ? [{ action: "mcp.tool.call", resource: `${tool[1]}:${tool[2]}` }]
        : [];
    }
    case "mcp.tool.call": {
      const colon = request.resource.indexOf(":");
      return colon > 0
        ? [
            {
              action: "tool.execute",
              resource: `mcp__${request.resource.slice(0, colon)}__${request.resource.slice(colon + 1)}`,
            },
          ]
        : [];
    }
    case "shell.execute": {
      // A push no rule covers is left to shell.execute; a denied command is
      // refused before any push prompt.
      const pushes = gitPushResources(request.resource).filter(
        (resource) =>
          engine.evaluate({ action: "git.push", resource }).ruleId !==
          BUILTIN_DEFAULT_RULE,
      );
      return pushes.length && engine.evaluate(request).effect !== "deny"
        ? pushes.map((resource) => ({ action: "git.push", resource }))
        : [];
    }
    default:
      return [];
  }
}

/** The strictest effect of a decision and its companions, as a session applies them. */
function overallEffect(
  decision: PolicyDecision,
  also: readonly PolicyDecision[] = [],
): PolicyEffect {
  return [decision, ...also].reduce<PolicyEffect>(
    (worst, item) =>
      STRICTNESS[item.effect] > STRICTNESS[worst] ? item.effect : worst,
    "allow",
  );
}

/**
 * The rule behind a decision, for a one-line reason. A decision no rule made
 * says so in words: `builtin:default` alone reads like a rule someone wrote.
 */
export function decisionRule(
  decision: Pick<PolicyDecision, "ruleId" | "reason">,
): string {
  return decision.ruleId === BUILTIN_DEFAULT_RULE
    ? (decision.reason ?? "No rule matched; the policy default decides")
    : `policy ${decision.ruleId}`;
}

function section(title: string, ...lines: readonly string[]): string {
  return `${title}:\n${lines.map((line) => `  ${redact(line)}`).join("\n")}`;
}

function enforcementLine(explanation: PolicyExplanation): string {
  const { decision } = explanation;
  switch (decisionStatus(decision)) {
    case "enforced":
      return decision.action === "git.push"
        ? `enforced (${decision.enforcement}, command text only: a push from a script, alias, or wrapper is not recognized)`
        : `enforced (${decision.enforcement})`;
    case "audit-only":
      return "audit-only (observed and recorded, not prevented)";
    default:
      return "unsupported (no runtime seam: neither prevented nor recorded)";
  }
}

/**
 * Rendering options. `autoApproved`: the user's auto mode is on and no
 * explicit `ask` keeps the prompt (`PolicyEngine.keepsPrompt`), so an `ask`
 * decision is approved without one. It changes nothing else.
 */
export interface DecisionFormatOptions {
  readonly autoApproved?: boolean;
  /** The task grant that approves an `ask` without a prompt (in-session only). */
  readonly grantId?: string;
  /** The companion decisions (`companionRequests`); the heading is the strictest. */
  readonly also?: readonly PolicyDecision[];
}

const AUTO_APPROVED = "ask (auto-approved by user)";

export function formatDecision(
  explanation: PolicyExplanation,
  options: DecisionFormatOptions = {},
): string {
  const { decision } = explanation;
  const effect = overallEffect(decision, options.also);
  const auto = !!options.autoApproved && effect === "ask";
  const grant = !auto && effect === "ask" ? options.grantId : undefined;
  const blocks = [
    auto ? "AUTO-APPROVED" : grant ? "GRANT-APPROVED" : HEADINGS[effect],
    ...(auto ? [section("Effect", AUTO_APPROVED)] : []),
    ...(grant
      ? [section("Effect", `ask (approved by task grant ${grant})`)]
      : []),
    section("Action", decision.action),
    section("Resource", decision.resource),
    section(
      "Rule",
      decision.ruleId === BUILTIN_DEFAULT_RULE
        ? `${decision.ruleId} (no rule matched; policy.default decides)`
        : decision.ruleId,
    ),
    section("Policy", decision.policyId),
    section("Enforcement", enforcementLine(explanation)),
    section("Layer", decision.layer),
  ];
  if (decision.reason) blocks.push(section("Reason", decision.reason));
  if (options.also?.length)
    blocks.push(
      section(
        "Also decided as",
        ...options.also.map(
          (item) =>
            `${item.action} ${item.resource}: ${HEADINGS[item.effect]} (${decisionRule(item)})`,
        ),
      ),
    );
  const tool =
    decision.action === "mcp.tool.call"
      ? MCP_TOOL_NAME.exec(decision.resource)
      : null;
  if (tool)
    blocks.push(
      section(
        "Hint",
        `${decision.resource} is the model-facing tool name; an mcp.tool.call resource is <server>:<tool>, so ask for ${tool[1]}:${tool[2]} (the model-facing name is the tool.execute resource)`,
      ),
    );
  const others = explanation.matches.filter(
    (match) =>
      !(match.ruleId === decision.ruleId && match.layer === decision.layer),
  );
  if (others.length > 0)
    blocks.push(
      section(
        "Other matching rules",
        ...others.map(
          (match) =>
            `${match.ruleId} (${match.layer}, ${match.effect}${match.replaced ? ", replaced by a matching user rule" : !match.first ? ", shadowed by an earlier rule in its layer" : match.layer === "user-preference" && decision.layer !== "user-preference" ? `, overridden by ${decision.ruleId}` : ""})`,
        ),
      ),
    );
  if (explanation.inactive.length > 0)
    blocks.push(
      section(
        "Inactive rules (would match, but apply only under an enforced sandbox; set sandbox.required: true in piship.yaml to activate them)",
        ...explanation.inactive.map(
          (match) => `${match.ruleId} (${match.layer}, ${match.effect})`,
        ),
      ),
    );
  const ignored = explanation.ignored.filter((item) => item.matches);
  if (ignored.length > 0)
    blocks.push(
      section(
        "Ignored rules",
        ...ignored.map(
          (item) => `${item.rule.id} (${item.source}): ${item.why}`,
        ),
      ),
    );
  return blocks.join("\n\n");
}

/** A JSON-safe explanation object (stable field names, redacted text). */
export function decisionToJSON(
  explanation: PolicyExplanation,
  options: DecisionFormatOptions = {},
): Record<string, unknown> {
  const { decision } = explanation;
  const effect = overallEffect(decision, options.also);
  return {
    effect: decision.effect,
    ...(options.also?.length
      ? {
          overallEffect: effect,
          also: options.also.map((item) => ({
            action: item.action,
            resource: redact(item.resource),
            effect: item.effect,
            ruleId: item.ruleId,
            layer: item.layer,
          })),
        }
      : {}),
    ...(options.autoApproved && effect === "ask" ? { autoApproved: true } : {}),
    ...(!options.autoApproved && options.grantId && effect === "ask"
      ? { grantId: options.grantId }
      : {}),
    action: decision.action,
    resource: redact(decision.resource),
    ruleId: decision.ruleId,
    layer: decision.layer,
    policyId: decision.policyId,
    enforcement: decision.enforcement,
    enforcementStatus: decisionStatus(decision),
    ...(decision.reason ? { reason: redact(decision.reason) } : {}),
    matches: explanation.matches.map((match) => ({
      layer: match.layer,
      source: match.source,
      ruleId: match.ruleId,
      effect: match.effect,
      resource: redact(match.resource),
      first: match.first,
      ...(match.reason ? { reason: redact(match.reason) } : {}),
    })),
    ...(explanation.inactive.length
      ? { inactive: explanation.inactive.map((match) => match.ruleId) }
      : {}),
    ignored: explanation.ignored.map((item) => ({
      source: item.source,
      layer: item.layer,
      ruleId: item.rule.id,
      effect: item.rule.effect,
      matches: item.matches,
      why: redact(item.why),
    })),
    diagnostics: explanation.diagnostics.map((item) => ({
      ...item,
      message: redact(item.message),
    })),
  };
}

/**
 * One sentence on how to change a blocking decision, chosen by the layer of
 * the deciding rule. A personal hint may name the user's own policy file (an
 * absolute path under their state directory), never a resource beyond what
 * the denial text carries, and a distribution-enforced or team rule never
 * gets a workaround.
 */
export function denialHint(
  decision: Pick<PolicyDecision, "layer" | "action" | "ruleId" | "effect"> & {
    readonly approval?: ResolvedDecision["approval"];
    readonly resource?: string;
  },
  deployment: "personal" | "managed",
  where: {
    readonly policyFile?: string;
    /** The distribution's command, which runs `policy explain`. */
    readonly command?: string;
    /**
     * Task grants are on; `actions` limits which actions a grant covers, and
     * `commands` are the programs a grant covers unless `--run` names others.
     */
    readonly grants?: {
      readonly actions?: readonly string[] | undefined;
      readonly commands?: readonly string[];
    };
  } = {},
): string {
  const file = where.policyFile ?? "config/policy.json";
  // A grant covers only an interactive ask for a file or shell action.
  const grantable =
    deployment === "personal" &&
    where.grants !== undefined &&
    decision.effect === "ask" &&
    decision.approval !== "unavailable" &&
    (decision.action.startsWith("filesystem.") ||
      decision.action === "shell.execute") &&
    (where.grants.actions?.includes(decision.action) ?? true);
  let grant = grantable
    ? " Or type `/grant <folder>` to approve that folder's prompts for a limited time (`--for` sets how long)."
    : "";
  // A grant covers a command only when it lists every program of the chain.
  const commands = where.grants?.commands;
  if (
    grant &&
    decision.action === "shell.execute" &&
    decision.resource !== undefined &&
    commands
  ) {
    const programs = [...new Set(grantShellPrograms(decision.resource))];
    if (!programs.length || programs.some(programRefusal)) grant = "";
    else if (programs.some((program) => !commands.includes(program)))
      grant = ` Or type \`/grant <folder> --run ${programs.join(",")}\` to approve that folder's prompts and these commands for a limited time; a plain \`/grant\` covers only ${commands.join(", ")}.`;
  }
  // The person's own refusal of a prompt needs no way to change a rule.
  if (decision.approval === "denied" || decision.approval === "cancelled")
    return "";
  const explain = `\`${where.command ?? "piship"} policy explain ${decision.action} <resource>\` shows how it was decided`;
  switch (decision.layer) {
    case "distribution-enforced":
      return deployment === "managed"
        ? "This rule is distribution-owned and cannot be changed here; ask your administrator to change it."
        : `This rule is distribution-owned and cannot be changed here; it lives in the distribution's piship.yaml, which you own in personal mode (${explain}).`;
    case "team-project":
      return "This rule comes from the project or team policy; ask its owner to change it.";
    case "user-preference":
      return `This is your own rule ${decision.ruleId}; edit it in ${file} (${explain}).${grant}`;
    case "builtin":
      // No rule decided: only the person's own grant or rule can change it.
      return deployment === "personal" &&
        where.policyFile &&
        decision.ruleId !== BUILTIN_UNKNOWN_ACTION_RULE
        ? `Nothing allows this yet; add a rule to ${file} (${explain}).${grant}`
        : deployment === "personal" &&
            decision.ruleId === BUILTIN_UNKNOWN_ACTION_RULE
          ? "This action is not known to this release; check its spelling in the rule."
          : "";
    default:
      return deployment === "managed"
        ? "This is a distribution default; ask your administrator to change it."
        : `This is a distribution default; add a rule to ${file} to change it (${explain}).${grant}`;
  }
}
