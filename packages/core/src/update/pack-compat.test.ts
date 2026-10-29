import { describe, expect, it } from "vitest";
import { assertSupportedPi } from "./update.js";

describe("the Pi compatibility an update refuses", () => {
  it("refuses a release or a pack whose Pi version is recorded as unsupported", () => {
    for (const kind of ["release", "pack"] as const)
      expect(() =>
        assertSupportedPi(kind, "1.1.0", "1.1.0", "unsupported"),
      ).toThrow(
        new RegExp(
          `The 1.1.0 ${kind} runs Pi 1.1.0, which it records as unsupported`,
        ),
      );
  });

  it("accepts the other statuses", () => {
    for (const status of ["supported", "candidate"])
      expect(() =>
        assertSupportedPi("pack", "1.1.0", "1.1.0", status),
      ).not.toThrow();
  });
});
