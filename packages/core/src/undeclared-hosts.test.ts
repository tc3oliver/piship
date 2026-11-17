import { describe, expect, it } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { undeclaredGovernanceHosts } from "./branded/doctor.js";

const ctx = (required: boolean) =>
  ({
    metadata: {
      governance: {
        manifest: {
          mcp: { servers: [] },
          audit: { sinks: [] },
          sandbox: { required, endpoint: "https://sandbox.acme.example" },
        },
      },
    },
  }) as unknown as BrandedContext;

describe("undeclaredGovernanceHosts", () => {
  it("names a required sandbox's endpoint host that is not allowed", () => {
    expect(undeclaredGovernanceHosts(ctx(true), [])).toEqual([
      { label: "sandbox endpoint", host: "sandbox.acme.example" },
    ]);
    expect(
      undeclaredGovernanceHosts(ctx(true), ["sandbox.acme.example"]),
    ).toEqual([]);
  });

  it("ignores the endpoint of a sandbox that is never activated", () => {
    expect(undeclaredGovernanceHosts(ctx(false), [])).toEqual([]);
  });
});
