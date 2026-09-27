import { describe, expect, it } from "vitest";
import { distributionStateDirectory } from "./index.js";

describe("distribution state path", () => {
  it("uses a contained path for valid ids", () => {
    expect(distributionStateDirectory({ value: "my-agent" })).toBe(
      ".piship/my-agent",
    );
  });

  it("rejects traversal and invalid ids", () => {
    expect(() => distributionStateDirectory({ value: "../outside" })).toThrow();
  });
});
