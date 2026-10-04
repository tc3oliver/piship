import {
  PROVIDER_TRUST_CLASSES,
  RESOURCE_KINDS,
  RESOURCE_TRUST_CLASSES,
  type DeploymentMode,
  type ProviderTrustClass,
  type ResourceTrustClass,
  TRUST_CLASSES,
  TRUST_SUBJECTS,
} from "@piship/schema";
import { describe, expect, it } from "vitest";
import { makePolicy } from "./fixtures.test-helpers.js";
import {
  defaultProjectDimensions,
  defaultProviderTrust,
  defaultResourceTrust,
  providerTrustDecision,
  resourceTrustDecision,
  TRUST_SUBJECT_DIMENSION,
  trustDecision,
} from "./trust.js";

const RESOURCE_EXPECTED: Record<
  DeploymentMode,
  Record<Exclude<ResourceTrustClass, "project">, boolean>
> = {
  managed: {
    upstream: true,
    builtin: true,
    certified: true,
    company: true,
    user: false,
  },
  personal: {
    upstream: true,
    builtin: true,
    certified: true,
    company: true,
    user: true,
  },
};

const PROVIDER_EXPECTED: Record<
  DeploymentMode,
  Record<ProviderTrustClass, boolean>
> = {
  managed: {
    upstream: true,
    builtin: true,
    certified: true,
    company: true,
    user: false,
  },
  personal: {
    upstream: true,
    builtin: true,
    certified: true,
    company: true,
    user: true,
  },
};

describe("resource trust defaults", () => {
  for (const mode of ["managed", "personal"] as const) {
    const policy = makePolicy({}, mode);
    for (const cls of RESOURCE_TRUST_CLASSES) {
      if (cls === "project") continue;
      for (const kind of RESOURCE_KINDS)
        it(`${mode} ${cls} ${kind}`, () => {
          const decision = resourceTrustDecision(policy, cls, kind);
          expect(decision.allowed).toBe(RESOURCE_EXPECTED[mode][cls]);
          expect(decision.class).toBe(cls);
          expect(decision.setting).toBe(
            RESOURCE_EXPECTED[mode][cls] ? "allow" : "deny",
          );
          expect(decision.reason).toContain(cls);
        });
    }
    it(`${mode} project resources resolve through project trust`, () => {
      expect(defaultResourceTrust(mode).project).toBe("policy");
      const dims = defaultProjectDimensions(mode);
      for (const origin of ["company", "external", "unknown"] as const)
        for (const kind of RESOURCE_KINDS) {
          const decision = resourceTrustDecision(
            policy,
            "project",
            kind,
            origin,
          );
          expect(decision.effect).toBe(
            dims[origin][decision.dimension ?? "instructions"],
          );
          expect(decision.allowed).toBe(decision.effect === "allow");
        }
    });
  }
  it("maps kinds onto dimensions", () => {
    const policy = makePolicy({}, "managed");
    expect(
      resourceTrustDecision(policy, "project", "themes", "unknown"),
    ).toMatchObject({
      dimension: "passiveContext",
      allowed: true,
    });
    expect(
      resourceTrustDecision(policy, "project", "prompts", "external"),
    ).toMatchObject({
      dimension: "instructions",
      effect: "ask",
      allowed: false,
    });
    expect(
      resourceTrustDecision(policy, "project", "extensions", "company"),
    ).toMatchObject({
      effect: "company-approved",
      allowed: false,
      reason: "company-approved admits only distribution-approved items",
    });
  });
  it("honors explicit project allow and deny", () => {
    const base = makePolicy({}, "managed");
    const deny = makePolicy({
      resourceTrust: { ...base.resourceTrust, project: "deny" },
    });
    const allow = makePolicy({
      resourceTrust: { ...base.resourceTrust, project: "allow" },
    });
    expect(
      resourceTrustDecision(deny, "project", "themes", "company").allowed,
    ).toBe(false);
    expect(
      resourceTrustDecision(allow, "project", "skills", "unknown").allowed,
    ).toBe(true);
  });
  it("keeps resource and provider tables independent", () => {
    const base = makePolicy({}, "managed");
    const policy = makePolicy({
      resourceTrust: { ...base.resourceTrust, user: "allow" },
      providerTrust: { ...base.providerTrust, company: "deny" },
    });
    expect(resourceTrustDecision(policy, "user", "skills").allowed).toBe(true);
    expect(providerTrustDecision(policy, "user").allowed).toBe(false);
    expect(resourceTrustDecision(policy, "company", "skills").allowed).toBe(
      true,
    );
    expect(providerTrustDecision(policy, "company").allowed).toBe(false);
  });
});

describe("provider trust defaults", () => {
  for (const mode of ["managed", "personal"] as const)
    for (const cls of PROVIDER_TRUST_CLASSES)
      it(`${mode} ${cls}`, () => {
        const decision = providerTrustDecision(
          { providerTrust: defaultProviderTrust(mode) },
          cls,
        );
        expect(decision.allowed).toBe(PROVIDER_EXPECTED[mode][cls]);
        expect(decision.reason).toMatch(
          /^Provider trust (allows|denies) class /,
        );
      });
});

describe("project dimension defaults", () => {
  it("match the documented managed table", () => {
    const managed = defaultProjectDimensions("managed");
    expect(managed.company).toEqual({
      passiveContext: "allow",
      instructions: "allow",
      skills: "allow",
      agents: "deny",
      hooks: "deny",
      extensions: "company-approved",
      mcp: "company-approved",
      providers: "deny",
    });
    expect(managed.external.instructions).toBe("ask");
    expect(managed.external.skills).toBe("deny");
    expect(Object.values(managed.unknown).filter((v) => v !== "deny")).toEqual([
      "allow",
    ]);
  });
  it("match the documented personal table", () => {
    const personal = defaultProjectDimensions("personal");
    expect(personal.company.hooks).toBe("deny");
    expect(personal.external.extensions).toBe("allow");
    expect(personal.unknown).toEqual({
      passiveContext: "allow",
      instructions: "ask",
      skills: "ask",
      agents: "ask",
      hooks: "deny",
      extensions: "ask",
      mcp: "ask",
      providers: "ask",
    });
  });
});

describe("trustDecision (one evaluation for every governed object)", () => {
  const policy = makePolicy({
    resourceTrust: { ...defaultResourceTrust("managed"), company: "deny" },
    providerTrust: defaultProviderTrust("managed"),
  });

  it("decides resources, packages, and MCP servers by resource trust", () => {
    for (const subject of TRUST_SUBJECTS) {
      if (subject === "providers") continue;
      for (const cls of TRUST_CLASSES) {
        if (cls === "project") continue;
        const decision = trustDecision(policy, subject, cls);
        expect(decision.allowed).toBe(policy.resourceTrust[cls] === "allow");
        expect(decision.class).toBe(cls);
      }
    }
    // Same result as the resource function for a resource kind.
    for (const kind of RESOURCE_KINDS)
      expect(trustDecision(policy, kind, "user")).toEqual(
        resourceTrustDecision(policy, "user", kind),
      );
  });

  it("decides capability providers by provider trust, never from a project", () => {
    expect(trustDecision(policy, "providers", "company")).toEqual(
      providerTrustDecision(policy, "company"),
    );
    expect(trustDecision(policy, "providers", "company").allowed).toBe(true);
    expect(trustDecision(policy, "providers", "project")).toMatchObject({
      allowed: false,
      setting: "deny",
    });
  });

  it("resolves project packages and MCP servers through their project dimension", () => {
    expect(TRUST_SUBJECT_DIMENSION.packages).toBe("extensions");
    expect(TRUST_SUBJECT_DIMENSION["mcp-servers"]).toBe("mcp");
    const decision = trustDecision(policy, "mcp-servers", "project", "company");
    expect(decision.dimension).toBe("mcp");
    expect(decision.effect).toBe(policy.projectTrust.company.dimensions.mcp);
  });
});
