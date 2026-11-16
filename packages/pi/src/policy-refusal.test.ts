import type { ResolvedDecision } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import type { GovernanceSession } from "./governance-session.js";
import { whyAsked } from "./governance/approval.js";
import { policyRefusal, userText } from "./governed-tools.js";

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

describe("what the user reads of a refusal", () => {
  it("leaves out the instructions to the model, and says what the user does", () => {
    expect(userText(policyRefusal(gov, decision(), "curl"))).toBe(
      "curl is not allowed by acme rule no-curl: network tools are blocked. Ask the distribution owner.",
    );
    expect(
      userText(
        policyRefusal(gov, decision({ approval: "denied" }), "This command"),
      ),
    ).toBe("This command was declined (acme rule no-curl asks for approval).");
    expect(
      userText(
        "Plan mode does not allow write. The user can switch to Build mode with /build. Do not retry it or work around Plan mode with another tool; finish the plan and tell the user it needs Build mode.",
      ),
    ).toBe("Plan mode does not allow write. Switch to Build mode with /build.");
    expect(
      userText(
        "[PiShip sandbox: shell commands have no network access. Change sandbox.network.mode in your piship.yaml. Do not retry it or work around the sandbox; tell the user what failed.]",
      ),
    ).toBe(
      "[PiShip sandbox: shell commands have no network access. Change sandbox.network.mode in your piship.yaml.]",
    );
    expect(userText("Successfully wrote to notes.txt")).toBe(
      "Successfully wrote to notes.txt",
    );
  });
});

describe("why a prompt asks", () => {
  it("names a rule and its reason, and says plainly when only the policy default asks", () => {
    expect(whyAsked("acme.curl", "network tools ask")).toEqual([
      "network tools ask",
      "Rule: acme.curl",
    ]);
    expect(
      whyAsked("builtin:default", "No rule matched; the policy default is ask"),
    ).toEqual([
      "No rule covers it, and this distribution asks by default (policy.default).",
    ]);
  });
});
