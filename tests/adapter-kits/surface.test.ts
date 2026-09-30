// What the kits and the SDK take from PiShip is PiShip's own: one claim
// allowlist, one principal comparison, whichever package a caller imports
// it from.
import { IDENTITY_ALLOWED_CLAIMS } from "@piship/adapter-conformance";
import * as sdk from "@piship/adapter-sdk";
import * as contracts from "@piship/contracts";
import * as identity from "@piship/identity";
import { describe, expect, it } from "vitest";

describe("the identity surface the SDK and the kits share with PiShip", () => {
  it("has one claim allowlist", () => {
    expect(identity.RETAINED_CLAIMS).toBe(contracts.RETAINED_CLAIMS);
    expect(sdk.RETAINED_CLAIMS).toBe(contracts.RETAINED_CLAIMS);
    expect(IDENTITY_ALLOWED_CLAIMS).toBe(contracts.RETAINED_CLAIMS);
    // The claims PiShip's own filter keeps are exactly that list.
    const all = Object.fromEntries(
      [...contracts.RETAINED_CLAIMS, "employee_id", "refresh_token"].map(
        (name) => [name, "x"],
      ),
    );
    expect(Object.keys(identity.retainClaims(all))).toEqual([
      ...contracts.RETAINED_CLAIMS,
    ]);
  });

  it("has one principal comparison", () => {
    expect(sdk.principalKey).toBe(contracts.principalKey);
    expect(sdk.samePrincipal).toBe(contracts.samePrincipal);
    const session = { issuer: "https://issuer.invalid", subject: "alice" };
    expect(
      sdk.samePrincipal(sdk.principalKey(session), {
        issuer: "https://issuer.invalid",
        subject: "alice",
      }),
    ).toBe(true);
  });

  it("types a workload identity adapter from the SDK as @piship/identity recognizes it", () => {
    const workload: sdk.WorkloadIdentityProvider = {
      kind: "ci",
      interactive: false,
      login: async () => ({ subject: "job", issuer: "https://ci.invalid" }),
    };
    expect(identity.isWorkloadIdentityProvider(workload)).toBe(true);
  });
});
