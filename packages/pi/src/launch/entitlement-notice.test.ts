import { describe, expect, it } from "vitest";
import { entitlementNotice } from "./entitlement-notice.js";

describe("entitlementNotice", () => {
  const command = "acme";

  it("says which models were added or removed, and to restart", () => {
    expect(
      entitlementNotice({
        before: ["coder"],
        after: ["coder", "general"],
        refused: "general",
        command,
      }),
    ).toBe(
      "Your models changed (added: general). Restart acme to pick them up.",
    );
    expect(
      entitlementNotice({
        before: ["coder", "general"],
        after: ["general", "fast"],
        refused: "coder",
        command,
      }),
    ).toBe(
      "Your models changed (added: fast; removed: coder). Restart acme to pick them up.",
    );
  });

  it("names the refused model and the next action when nothing changed", () => {
    const unchanged = entitlementNotice({
      before: ["coder"],
      after: ["coder"],
      refused: "general",
      command,
    });
    expect(unchanged).toBe(
      "The gateway refused general, and your model access has not changed. Choose another model with /model.",
    );
    // A credential that carries no entitlement cannot show a change.
    expect(
      entitlementNotice({
        before: undefined,
        after: ["coder"],
        refused: undefined,
        command,
      }),
    ).toContain("refused that model");
  });
});
