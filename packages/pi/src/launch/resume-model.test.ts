import { describe, expect, it } from "vitest";
import { replacementModel } from "./runtime.js";

describe("replacementModel", () => {
  it("keeps the model the launch chose", () => {
    expect(replacementModel("chosen", ["first"], "old/model", "acme")).toBe(
      "chosen",
    );
  });

  it("switches to the first allowed model when the launch chose none", () => {
    expect(
      replacementModel(undefined, ["first", "second"], "old/model", "acme"),
    ).toBe("first");
  });

  it("fails with the next action only when no model is allowed", () => {
    expect(() => replacementModel(undefined, [], "old/model", "acme")).toThrow(
      expect.objectContaining({
        code: "MODEL_DENIED",
        userAction: expect.stringContaining("allow a model"),
      }),
    );
  });
});
