import { describe, expect, it } from "vitest";
import { PISHIP_SCHEMA_VERSION, parseManifestHeader } from "./index.js";

describe("experimental schema marker", () => {
  it("accepts only the alpha marker", () => {
    expect(PISHIP_SCHEMA_VERSION).toBe("piship/v1alpha1");
    expect(parseManifestHeader({ schema: PISHIP_SCHEMA_VERSION })).toEqual({
      schema: PISHIP_SCHEMA_VERSION,
    });
    expect(parseManifestHeader({ schema: "piship/v1" })).toEqual({
      path: "schema",
      message: "Expected piship/v1alpha1",
    });
  });
});
