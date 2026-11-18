import { describe, expect, it } from "vitest";
import { join } from "node:path";
import {
  replacementModel,
  sourcePaths,
  unavailableModelAction,
} from "./runtime.js";

describe("replacementModel", () => {
  const cause = {
    resumed: true,
    userNarrowed: false,
    mode: "managed",
  } as const;
  it("keeps the model the launch chose", () => {
    expect(
      replacementModel("chosen", ["first"], "old/model", "acme", cause),
    ).toBe("chosen");
  });

  it("switches to the first allowed model when the launch chose none", () => {
    expect(
      replacementModel(
        undefined,
        ["first", "second"],
        "old/model",
        "acme",
        cause,
      ),
    ).toBe("first");
  });

  it("names the resumed session and the administrator when no model is allowed", () => {
    expect(() =>
      replacementModel(undefined, [], "old/model", "acme", cause),
    ).toThrow(
      expect.objectContaining({
        code: "MODEL_DENIED",
        message: expect.stringContaining(
          "The resumed session uses old/model, which is not allowed",
        ),
        userAction: expect.stringContaining("Ask your administrator"),
      }),
    );
  });

  it("blames the user's models.allowed preference, not a resumed session, in a new one", () => {
    let error: unknown;
    try {
      replacementModel(undefined, [], "unknown/unknown", "acme", {
        resumed: false,
        userNarrowed: true,
        mode: "personal",
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      code: "MODEL_DENIED",
      message:
        "No allowed model is available: no model Pi offers matches your models.allowed preference",
      userAction:
        "Run acme config unset models.allowed, or set it to a model acme models lists, then start acme again",
    });
    expect(String((error as Error).message)).not.toContain("resumed");
  });

  it("points a personal owner at piship.yaml when the distribution allows nothing", () => {
    expect(() =>
      replacementModel(undefined, [], "a/b", "acme", {
        resumed: false,
        userNarrowed: false,
        mode: "personal",
      }),
    ).toThrow(
      expect.objectContaining({
        userAction: expect.stringContaining(
          "Set models.allowed in piship.yaml",
        ),
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
