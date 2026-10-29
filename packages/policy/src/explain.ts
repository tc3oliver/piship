// Human and JSON renderings of a policy explanation. All free text passes
// through redact() so rule reasons can never leak secret values.
import {
  type PolicyDecision,
  type PolicyEffect,
  type ResolvedDecision,
  redact,
} from "@piship/contracts";
import {
  BUILTIN_UNKNOWN_ACTION_RULE,
  type PolicyExplanation,
} from "./engine.js";
import { decisionStatus } from "./seams.js";

const HEADINGS: Readonly<Record<PolicyEffect, string>> = {
  allow: "ALLOWED",
  ask: "APPROVAL REQUIRED",
  deny: "DENIED",
};

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
}

const AUTO_APPROVED = "ask (auto-approved by user)";

export function formatDecision(
  explanation: PolicyExplanation,
  options: DecisionFormatOptions = {},
): string {
  const { decision } = explanation;
  const auto = !!options.autoApproved && decision.effect === "ask";
  const grant =
    !auto && decision.effect === "ask" ? options.grantId : undefined;
  const blocks = [
    auto
      ? "AUTO-APPROVED"
      : grant
        ? "GRANT-APPROVED"
        : HEADINGS[decision.effect],
    ...(auto ? [section("Effect", AUTO_APPROVED)] : []),
    ...(grant
      ? [section("Effect", `ask (approved by task grant ${grant})`)]
      : []),
    section("Action", decision.action),
    section("Resource", decision.resource),
    section("Rule", decision.ruleId),
    section("Policy", decision.policyId),
    section("Enforcement", enforcementLine(explanation)),
    section("Layer", decision.layer),
  ];
  if (decision.reason) blocks.push(section("Reason", decision.reason));
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
            `${match.ruleId} (${match.layer}, ${match.effect}${match.first ? "" : ", shadowed by an earlier rule in its layer"})`,
        ),
      ),
    );
  if (explanation.inactive.length > 0)
    blocks.push(
      section(
        "Inactive rules (no enforced sandbox contains them)",
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
  return {
    effect: decision.effect,
    ...(options.autoApproved && decision.effect === "ask"
      ? { autoApproved: true }
      : {}),
    ...(!options.autoApproved && options.grantId && decision.effect === "ask"
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

export function formatDecisionJSON(
  explanation: PolicyExplanation,
  options: DecisionFormatOptions = {},
): string {
  return JSON.stringify(decisionToJSON(explanation, options), null, 2);
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
  },
  deployment: "personal" | "managed",
  where: {
    readonly policyFile?: string;
    /** Task grants are on; `actions` limits which actions a grant covers. */
    readonly grants?: { readonly actions?: readonly string[] | undefined };
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
  const grant = grantable
    ? " Or type `/grant <folder>` to approve that folder's prompts for this session."
    : "";
  // The person's own refusal of a prompt needs no way to change a rule.
  if (decision.approval === "denied" || decision.approval === "cancelled")
    return "";
  const explain = `\`piship policy explain ${decision.action} <resource>\` shows how it was decided`;
  switch (decision.layer) {
    case "distribution-enforced":
      return deployment === "managed"
        ? "This rule is distribution-owned and cannot be changed here; contact the distribution owner."
        : "This rule is distribution-owned and cannot be changed here.";
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
        : "";
    default:
      return deployment === "managed"
        ? "This is a distribution default; contact the distribution owner."
        : `This is a distribution default; add a rule to ${file} to change it (${explain}).${grant}`;
  }
}
