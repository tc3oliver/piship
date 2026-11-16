import { describe, expect, it } from "vitest";
import { join } from "node:path";
import {
  replacementModel,
  sourcePaths,
  unavailableModelAction,
} from "./runtime.js";

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

describe("unavailableModelAction", () => {
  const flag = "--model <provider/model>";
  it("points a manifest default at models.default, not a flag", () => {
    for (const source of ["distribution-default", "distribution-enforced"])
      expect(unavailableModelAction("acme", flag, source)).toContain(
        "set models.default (and models.allowed, if it lists models) in piship.yaml to one acme models lists",
      );
  });

  it("keeps the preference and flag actions", () => {
    expect(unavailableModelAction("acme", flag, "user-preference")).toContain(
      "acme config unset model",
    );
    expect(unavailableModelAction("acme", flag, undefined)).toBe(
      "Start acme --model <provider/model> with a model Pi offers",
    );
  });
});

describe("sourcePaths", () => {
  it("names the manifest-relative source of a built resource", () => {
    const dir = join("/work", "dist", "myagent");
    const built = join(dir, "resources", "resources", "extensions", "bad.ts");
    expect(sourcePaths(`Failed to load ${built}:2:0: oops`, dir)).toBe(
      `Failed to load ./${join("resources", "extensions", "bad.ts")}:2:0: oops`,
    );
    expect(sourcePaths("/elsewhere/x.ts: oops", dir)).toBe(
      "/elsewhere/x.ts: oops",
    );
  });
});
