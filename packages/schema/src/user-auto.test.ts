// `policy.userAuto` (piship/v1alpha5): accepted in managed manifests,
// absent by default, rejected in personal mode and in older schemas.
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseManifest, readManifestDocument } from "./index.js";

type Json = Record<string, unknown>;
const example = (path: string) =>
  readManifestDocument(
    fileURLToPath(new URL(`../../../examples/${path}`, import.meta.url)),
  ) as Json;
const MANAGED = example("demo-company/piship.yaml");
const PERSONAL = example("personal/piship.yaml");

function withUserAuto(manifest: Json, value: unknown, schema?: string): Json {
  const copy = structuredClone(manifest);
  copy.policy = { ...((copy.policy as Json) ?? {}), userAuto: value };
  if (schema) copy.schema = schema;
  return copy;
}

const fieldError = (input: Json) => {
  try {
    parseManifest(input);
  } catch (error) {
    return error as { field?: string; message: string };
  }
  throw new Error("the manifest was accepted");
};

describe("policy.userAuto", () => {
  it("is absent unless declared, which keeps existing locks unchanged", () => {
    const policy = parseManifest(MANAGED).governance?.policy;
    expect(policy).toBeDefined();
    expect(policy).not.toHaveProperty("userAuto");
  });

  it("accepts off and allowed in a managed v1alpha5 manifest", () => {
    for (const value of ["off", "allowed"])
      expect(
        parseManifest(withUserAuto(MANAGED, value)).governance?.policy.userAuto,
      ).toBe(value);
  });

  it("rejects any other value", () => {
    for (const value of ["on", true, "ALLOWED", null])
      expect(fieldError(withUserAuto(MANAGED, value))).toMatchObject({
        field: "policy.userAuto",
        message: expect.stringContaining("Expected off, allowed"),
      });
  });

  it("is rejected in personal mode, where the user owns the policy", () => {
    expect(fieldError(withUserAuto(PERSONAL, "allowed"))).toMatchObject({
      field: "policy.userAuto",
      message: expect.stringContaining(
        "userAuto applies to managed distributions only",
      ),
    });
  });

  it("is an unknown field before piship/v1alpha5", () => {
    const v1alpha3 = withUserAuto(MANAGED, "allowed", "piship/v1alpha3");
    for (const key of ["updates", "release"]) delete v1alpha3[key];
    expect(fieldError(v1alpha3)).toMatchObject({
      field: "policy.userAuto",
      message: expect.stringContaining("Unknown field"),
    });
  });
});
