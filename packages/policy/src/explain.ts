// Human and JSON renderings of a policy explanation. All free text passes
// through redact() so rule reasons can never leak secret values.
import { redact, type PolicyEffect } from "@piship/contracts";
import type { PolicyExplanation } from "./engine.js";
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
      return `enforced (${decision.enforcement})`;
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
}

const AUTO_APPROVED = "ask (auto-approved by user)";

export function formatDecision(
  explanation: PolicyExplanation,
  options: DecisionFormatOptions = {},
): string {
  const { decision } = explanation;
  const auto = !!options.autoApproved && decision.effect === "ask";
  const blocks = [
    auto ? "AUTO-APPROVED" : HEADINGS[decision.effect],
    ...(auto ? [section("Effect", AUTO_APPROVED)] : []),
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
