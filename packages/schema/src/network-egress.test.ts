// piship/v1alpha6 `sandbox.network.egress: it`: a declaration that IT owns
// egress, which makes network allow the default of a required sandbox.
import { describe, expect, it } from "vitest";
import {
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

function manifest(
  sandbox: Json,
  schema: string = PISHIP_SCHEMA_V1ALPHA6,
): Json {
  return {
    schema,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.1.0" },
    deployment: { mode: "personal" },
    updates: { channel: "stable", channels: ["stable"] },
    sandbox,
  };
}

function network(sandbox: Json, schema: string = PISHIP_SCHEMA_V1ALPHA6) {
  const governance = parseManifest(manifest(sandbox, schema)).governance;
  if (!governance) throw new Error("governance missing");
  return governance.sandbox.network;
}

function field(
  sandbox: Json,
  schema: string = PISHIP_SCHEMA_V1ALPHA6,
): unknown {
  try {
    parseManifest(manifest(sandbox, schema));
  } catch (error) {
    expect(error).toBeInstanceOf(ManifestError);
    return (error as ManifestError).field;
  }
  return undefined;
}

describe("sandbox.network.egress", () => {
  it("makes network allow the default of a required sandbox and is recorded", () => {
    expect(network({ required: true, network: { egress: "it" } })).toEqual({
      mode: "allow",
      egress: "it",
    });
  });

  it("leaves a required sandbox without it on deny, with no new key", () => {
    expect(network({ required: true })).toEqual({ mode: "deny" });
  });

  it("is rejected without required, with mode deny, with another value, and before v1alpha6", () => {
    expect(field({ network: { egress: "it" } })).toBe("sandbox.network.egress");
    expect(
      field({ required: true, network: { mode: "deny", egress: "it" } }),
    ).toBe("sandbox.network.egress");
    expect(field({ required: true, network: { egress: "proxy" } })).toBe(
      "sandbox.network.egress",
    );
    expect(
      field(
        { required: true, network: { egress: "it" } },
        PISHIP_SCHEMA_V1ALPHA5,
      ),
    ).toBe("sandbox.network.egress");
  });

  it("accepts an explicit allow", () => {
    expect(
      network({ required: true, network: { mode: "allow", egress: "it" } }),
    ).toEqual({ mode: "allow", egress: "it" });
  });
});
