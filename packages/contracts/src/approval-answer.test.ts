// A kept answer ("always", "never") is honoured only where the prompt offered
// it; anywhere else it is a refusal, so a channel can never keep an answer a
// caller did not ask to keep.
import { describe, expect, it } from "vitest";
import {
  type ApprovalAnswer,
  type PolicyDecision,
  resolveDecision,
} from "./policy.js";

const ask: PolicyDecision = {
  effect: "ask",
  policyId: "p@1",
  ruleId: "r",
  enforcement: "control-plane",
  action: "resource.load",
  resource: "project:.claude",
  layer: "distribution-enforced",
};
const detail = { title: "t", message: "m" };
const channel = (answer: ApprovalAnswer) => async () => answer;

describe("resolveDecision with a kept answer", () => {
  it("keeps an answer only when the prompt offered it", async () => {
    expect(
      await resolveDecision(ask, channel("approved-always"), {
        ...detail,
        offerRemember: true,
      }),
    ).toMatchObject({
      outcome: "allow",
      approval: "approved",
      remember: "allow",
    });
    expect(
      await resolveDecision(ask, channel("denied-always"), {
        ...detail,
        offerRemember: true,
      }),
    ).toMatchObject({ outcome: "deny", approval: "denied", remember: "deny" });
  });

  it("treats an unoffered kept answer as a refusal that keeps nothing", async () => {
    const resolved = await resolveDecision(
      ask,
      channel("approved-always"),
      detail,
    );
    expect(resolved).toMatchObject({ outcome: "deny", approval: "denied" });
    expect(resolved.remember).toBeUndefined();
  });

  it("leaves a plain yes and no as they were", async () => {
    expect(
      await resolveDecision(ask, channel("approved"), detail),
    ).toMatchObject({ outcome: "allow", approval: "approved" });
    expect(
      await resolveDecision(ask, channel("denied"), {
        ...detail,
        offerRemember: true,
      }),
    ).toMatchObject({ outcome: "deny", approval: "denied" });
  });
});
