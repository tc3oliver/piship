import { describe, expect, it } from "vitest";
import {
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

function personal(
  runtime: Json = {},
  schema: string = PISHIP_SCHEMA_V1ALPHA6,
): Json {
  return {
    schema,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.0.2", ...runtime },
    deployment: { mode: "personal" },
    updates: { channel: "stable", channels: ["stable"] },
  };
}

function rejects(input: Json, field: string, message: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  expect((error as ManifestError).message).toContain(message);
}

describe("runtime.searchTools (piship/v1alpha6)", () => {
  it("is absent unless declared, so existing manifests parse as before", () => {
    expect(parseManifest(personal()).runtime).not.toHaveProperty("searchTools");
  });

  it("opts in with mode: bundled and keeps only the versions it pins", () => {
    expect(
      parseManifest(personal({ searchTools: { mode: "bundled" } })).runtime
        .searchTools,
    ).toEqual({ mode: "bundled" });
    expect(
      parseManifest(
        personal({
          searchTools: { mode: "bundled", fd: "10.4.2", rg: "15.1.0" },
        }),
      ).runtime.searchTools,
    ).toEqual({ mode: "bundled", fd: "10.4.2", rg: "15.1.0" });
  });

  it.each([
    [{ searchTools: "bundled" }, "runtime.searchTools", "Expected an object"],
    [{ searchTools: {} }, "runtime.searchTools.mode", "Expected bundled"],
    [
      { searchTools: { mode: "system" } },
      "runtime.searchTools.mode",
      "Expected bundled",
    ],
    [
      { searchTools: { mode: "bundled", fd: "latest" } },
      "runtime.searchTools.fd",
      "exact upstream release version",
    ],
    [
      { searchTools: { mode: "bundled", rg: 15 } },
      "runtime.searchTools.rg",
      "exact upstream release version",
    ],
    [
      { searchTools: { mode: "bundled", rg: "v15.2.0" } },
      "runtime.searchTools.rg",
      "exact upstream release version",
    ],
    [
      { searchTools: { mode: "bundled", ag: "2.2.0" } },
      "runtime.searchTools.ag",
      "Unknown field",
    ],
  ])("rejects %j at %s", (runtime, field, message) => {
    rejects(personal(runtime), field, message);
  });

  it.each([PISHIP_SCHEMA_V1ALPHA5, PISHIP_SCHEMA_V1ALPHA4])(
    "is rejected by %s",
    (schema) => {
      rejects(
        personal({ searchTools: { mode: "bundled" } }, schema),
        "runtime.searchTools",
        "Unknown field",
      );
    },
  );
});
