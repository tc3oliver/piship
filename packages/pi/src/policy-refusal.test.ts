import type { ResolvedDecision } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import type { GovernanceSession } from "./governance-session.js";
import { policyRefusal } from "./governed-tools.js";

const gov = {
  denialHint: () => " Ask the distribution owner.",
} as unknown as GovernanceSession;
const decision = (extra: Partial<ResolvedDecision> = {}) =>
  ({
    outcome: "deny",
    effect: "deny",
    policyId: "acme",
    ruleId: "no-curl",
    reason: "network tools are blocked",
    ...extra,
  }) as ResolvedDecision;

describe("a policy refusal", () => {
  it("names the policy, rule, reason and remedy, and tells the model not to retry", () => {
    expect(policyRefusal(gov, decision(), "curl")).toBe(
      "curl is not allowed by acme rule no-curl: network tools are blocked. Ask the distribution owner. Do not retry it or work around the rule; tell the user what was blocked.",
    );
  });

  it("says the user declined, not that a rule did", () => {
    const text = policyRefusal(
      gov,
      decision({ effect: "ask", approval: "denied" }),
      "This command",
    );
    expect(text).toBe(
      "This command was declined by the user (acme rule no-curl asks for approval). Do not retry it unless the user asks; ask how they want to proceed.",
    );
  });

  it("says a dismissed prompt did not run", () => {
    expect(
      policyRefusal(
        gov,
        decision({ effect: "ask", approval: "cancelled" }),
        "Writing /w/a",
      ),
    ).toBe(
      "Writing /w/a did not run: the approval prompt was dismissed (acme rule no-curl asks for approval). Do not retry it unless the user asks; ask how they want to proceed.",
    );
  });

  it("speaks to the user, not the model, for the user's own ! command", () => {
    expect(policyRefusal(gov, decision(), "This command", false)).toBe(
      "This command is not allowed by acme rule no-curl: network tools are blocked. Ask the distribution owner.",
    );
    expect(
      policyRefusal(
        gov,
        decision({ effect: "ask", approval: "denied" }),
        "This command",
        false,
      ),
    ).toBe("This command was declined (acme rule no-curl asks for approval).");
  });
});
