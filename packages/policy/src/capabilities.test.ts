import type { ModelDefinition } from "@piship/contracts";
import type { CapabilityConfig, CapabilityProviderRef } from "@piship/schema";
import { describe, expect, it } from "vitest";
import {
  computeCapabilityStates,
  contractsCompatible,
  formatCapabilities,
  type CapabilityState,
  type CapabilityStateInput,
} from "./capabilities.js";
import { makePolicy } from "./fixtures.test-helpers.js";
import { incompatibleCapabilities } from "./model-requirements.js";
import { providerTrustDecision } from "./trust.js";

const builtinPermissions: CapabilityProviderRef = {
  id: "builtin/permissions",
  class: "builtin",
  version: "1.0.0",
  implements: ["piship.capability/permissions/v1"],
};

function certified(
  overrides: Partial<CapabilityProviderRef> = {},
): CapabilityProviderRef {
  return {
    id: "certified/workflow-plus",
    class: "certified",
    version: "2.3.1",
    implements: ["piship.capability/workflow/v1"],
    path: "./providers/workflow-plus",
    certified: {
      id: "workflow-plus",
      version: "2.3.1",
      source: "https://example.org/workflow-plus",
      integrity: `sha256-${"a".repeat(64)}`,
      license: "MIT",
      pi: ["1.1.0"],
      platforms: ["linux", "darwin"],
    },
    ...overrides,
  };
}

function capability(
  name: CapabilityConfig["name"],
  enabled: boolean,
  provider?: CapabilityProviderRef,
): CapabilityConfig {
  return { name, enabled, settings: {}, ...(provider ? { provider } : {}) };
}

function input(
  overrides: Partial<CapabilityStateInput> = {},
): CapabilityStateInput {
  return {
    capabilities: [capability("permissions", true, builtinPermissions)],
    policy: makePolicy(),
    piVersion: "1.1.0",
    platform: "linux",
    ...overrides,
  };
}

function state(
  states: readonly CapabilityState[],
  name: string,
): CapabilityState {
  const found = states.find((item) => item.name === name);
  if (!found) throw new Error(`missing ${name}`);
  return found;
}

function values(item: CapabilityState): string {
  return Object.values(item.axes)
    .map((axis) => axis.value)
    .join(" ");
}

describe("computeCapabilityStates", () => {
  it("lists every known contract", () => {
    const states = computeCapabilityStates(input());
    expect(states.map((item) => item.name)).toEqual([
      "permissions",
      "workflow",
      "checkpoint",
      "subagents",
      "code-intel",
      "acp",
    ]);
  });
  it("reports an effective builtin capability", () => {
    const item = state(
      computeCapabilityStates(input({ health: { permissions: { ok: true } } })),
      "permissions",
    );
    expect(values(item)).toBe("yes yes yes yes yes yes");
    expect(item.provider).toBe("builtin/permissions");
  });
  it("treats an unchecked health axis as n/a without blocking", () => {
    const item = state(computeCapabilityStates(input()), "permissions");
    expect(item.axes.healthy.value).toBe("n/a");
    expect(item.axes.effective.value).toBe("yes");
  });
  it("reports an unsupported contract", () => {
    const item = state(
      computeCapabilityStates(
        input({
          capabilities: [
            capability("checkpoint", true, {
              ...builtinPermissions,
              id: "company/cp",
              class: "company",
              implements: ["piship.capability/checkpoint/v1"],
            }),
          ],
          verification: { "company/cp": { ok: true } },
        }),
      ),
      "checkpoint",
    );
    expect(item.axes.supported).toEqual({
      value: "no",
      reason:
        "Contract piship.capability/checkpoint/v1 is not implemented in this release",
    });
    expect(item.axes.resolved.value).toBe("yes");
    expect(item.axes.effective.value).toBe("no");
  });
  it("reports an unresolved provider for untrusted, unverified, or missing providers", () => {
    const userProvider = {
      ...certified(),
      id: "user/wf",
      class: "user" as const,
      certified: undefined,
    };
    const { certified: _drop, ...plainUser } = userProvider;
    const untrusted = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, plainUser)],
          verification: { "user/wf": { ok: true } },
        }),
      ),
      "workflow",
    );
    expect(untrusted.axes.resolved).toEqual({
      value: "no",
      reason: "Provider trust denies class user",
    });
    const unverified = state(
      computeCapabilityStates(
        input({ capabilities: [capability("workflow", true, certified())] }),
      ),
      "workflow",
    );
    expect(unverified.axes.resolved.reason).toContain("not verified");
    const failed = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, certified())],
          verification: {
            "certified/workflow-plus": {
              ok: false,
              reason: "Integrity mismatch",
            },
          },
        }),
      ),
      "workflow",
    );
    expect(failed.axes.resolved).toEqual({
      value: "no",
      reason: "Integrity mismatch",
    });
    const missing = state(
      computeCapabilityStates(
        input({ capabilities: [capability("workflow", true)] }),
      ),
      "workflow",
    );
    expect(missing.axes.resolved).toEqual({
      value: "no",
      reason: "No provider is selected",
    });
    expect(missing.axes.compatible.value).toBe("n/a");
    const unknownBuiltin = state(
      computeCapabilityStates(
        input({
          capabilities: [
            capability("workflow", true, {
              ...builtinPermissions,
              id: "builtin/nope",
            }),
          ],
        }),
      ),
      "workflow",
    );
    expect(unknownBuiltin.axes.resolved.reason).toContain(
      "Unknown builtin provider",
    );
    const wrong = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, builtinPermissions)],
        }),
      ),
      "workflow",
    );
    expect(wrong.axes.resolved.reason).toContain("does not implement");
  });
  it("uses explicit provider trust decisions over the policy", () => {
    const policy = makePolicy();
    const denied = {
      ...providerTrustDecision(policy, "builtin"),
      allowed: false,
      reason: "Blocked by the operator",
    };
    const item = state(
      computeCapabilityStates(
        input({ providerTrust: { "builtin/permissions": denied } }),
      ),
      "permissions",
    );
    expect(item.axes.resolved).toEqual({
      value: "no",
      reason: "Blocked by the operator",
    });
  });
  it("reports a disabled capability independently", () => {
    const item = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("permissions", false, builtinPermissions)],
        }),
      ),
      "permissions",
    );
    expect(values(item)).toBe("yes yes no yes n/a no");
    expect(item.axes.enabled.reason).toBe("Disabled in the manifest");
    const undeclared = state(computeCapabilityStates(input()), "workflow");
    expect(undeclared.axes.enabled.reason).toBe("Not declared in the manifest");
    expect(undeclared.axes.resolved.value).toBe("n/a");
  });
  it("reports incompatible Pi version, platform, and contract major", () => {
    const verified = { "certified/workflow-plus": { ok: true } };
    const pi = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, certified())],
          verification: verified,
          piVersion: "0.88.0",
          health: { workflow: { ok: true } },
        }),
      ),
      "workflow",
    );
    expect(pi.axes.compatible.reason).toContain(
      "reviewed for Pi 1.1.0, not 0.88.0",
    );
    expect(pi.axes.healthy.value).toBe("yes");
    expect(pi.axes.effective.value).toBe("no");
    const platform = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, certified())],
          verification: verified,
          platform: "win32",
        }),
      ),
      "workflow",
    );
    expect(platform.axes.compatible.reason).toContain("platform win32");
    const major = state(
      computeCapabilityStates(
        input({
          capabilities: [
            capability(
              "workflow",
              true,
              certified({ implements: ["piship.capability/workflow/v2"] }),
            ),
          ],
          verification: verified,
        }),
      ),
      "workflow",
    );
    expect(major.axes.resolved.value).toBe("yes");
    expect(major.axes.compatible.value).toBe("no");
    expect(major.axes.compatible.reason).toContain("workflow/v2");
    const effective = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, certified())],
          verification: verified,
        }),
      ),
      "workflow",
    );
    expect(effective.axes.effective.value).toBe("yes");
  });
  it("reports a contract major this release does not implement as unsupported", () => {
    const states = computeCapabilityStates(
      input({ supportedContracts: ["piship.capability/permissions/v2"] }),
    );
    expect(state(states, "permissions").axes.supported.reason).toContain(
      "unsupported major version",
    );
  });
  describe("checks model requirements as launch does", () => {
    const requiring = (enabled = true): CapabilityConfig => ({
      ...capability("permissions", enabled, builtinPermissions),
      requirements: { tools: true, minContextWindow: 100000 },
    });
    const model = (capabilities: ModelDefinition["capabilities"]) => ({
      id: "acme/coder",
      metadata: {
        id: "coder",
        name: "Coder",
        provider: "acme",
        capabilities,
        policyTags: [],
        availability: { available: true },
      },
    });
    const compatible = (overrides: Partial<CapabilityStateInput>) =>
      state(
        computeCapabilityStates(
          input({ capabilities: [requiring()], ...overrides }),
        ),
        "permissions",
      ).axes.compatible;

    it.each([
      [
        "a model that meets them",
        model({ tools: true, contextWindow: 200000 }),
        { value: "yes" },
      ],
      [
        "a model without tool calls",
        model({ tools: false, contextWindow: 200000 }),
        {
          value: "no",
          reason:
            "Model acme/coder does not meet the model requirements: tool calling is not supported",
        },
      ],
      [
        "a model without verified metadata",
        { id: "(selected by Pi)" },
        {
          value: "no",
          reason:
            "Model (selected by Pi) does not meet the model requirements: tool calling support is unknown; the context window is unknown",
        },
      ],
      [
        "no known model",
        undefined,
        {
          value: "no",
          reason:
            "Model (unknown) does not meet the model requirements: tool calling support is unknown; the context window is unknown",
        },
      ],
    ])("%s", (_label, evidence, expected) => {
      expect(compatible(evidence ? { model: evidence } : {})).toEqual(expected);
    });

    it("gives the same reasons as the launch comparison", () => {
      const evidence = model({ tools: false, contextWindow: 500 });
      const gaps = incompatibleCapabilities(evidence.metadata, [requiring()]);
      expect(compatible({ model: evidence }).reason).toBe(
        `Model acme/coder does not meet the model requirements: ${gaps[0]?.reasons.join("; ")}`,
      );
    });

    it("ignores the requirements of a disabled capability", () => {
      expect(
        state(
          computeCapabilityStates(input({ capabilities: [requiring(false)] })),
          "permissions",
        ).axes.compatible,
      ).toEqual({ value: "yes" });
    });
  });
  it("reports a provider the policy refused as not enabled, not unhealthy", () => {
    const item = state(
      computeCapabilityStates(
        input({
          capabilities: [capability("workflow", true, certified())],
          verification: {
            "certified/workflow-plus": { ok: true },
          },
          policyDenied: { workflow: "policy team (provider.load)" },
        }),
      ),
      "workflow",
    );
    expect(values(item)).toBe("yes yes no yes n/a no");
    expect(item.axes.enabled.reason).toBe(
      "The policy does not allow its provider: policy team (provider.load)",
    );
    expect(item.axes.effective.reason).toBe(
      "enabled: The policy does not allow its provider: policy team (provider.load)",
    );
  });
  it("reports an unhealthy provider", () => {
    const item = state(
      computeCapabilityStates(
        input({
          health: { permissions: { ok: false, reason: "Hook failed" } },
        }),
      ),
      "permissions",
    );
    expect(values(item)).toBe("yes yes yes yes no no");
    expect(item.axes.effective.reason).toBe("healthy: Hook failed");
  });
});

describe("contractsCompatible", () => {
  it("compares name and major", () => {
    expect(contractsCompatible("a/b/v1", "a/b/v1")).toBe(true);
    expect(contractsCompatible("a/b/v1", "a/b/v2")).toBe(false);
    expect(contractsCompatible("a/b/v1", "a/c/v1")).toBe(false);
    expect(contractsCompatible("nope", "nope")).toBe(false);
  });
});

describe("formatCapabilities", () => {
  it("renders a table with reasons", () => {
    const text = formatCapabilities(
      computeCapabilityStates(
        input({
          health: {
            permissions: {
              ok: false,
              reason: "access_token=abcdef123456 failed",
            },
          },
        }),
      ),
    );
    const lines = text.split("\n");
    expect(lines[0]).toMatch(
      /^CAPABILITY\s+PROVIDER\s+SUPPORTED\s+RESOLVED\s+ENABLED\s+COMPATIBLE\s+HEALTHY\s+EFFECTIVE$/,
    );
    expect(lines[1]).toMatch(
      /^permissions\s+builtin\/permissions\s+yes\s+yes\s+yes\s+yes\s+no\s+no$/,
    );
    expect(lines[2]).toMatch(
      /^workflow\s+-\s+yes\s+n\/a\s+no\s+n\/a\s+n\/a\s+no$/,
    );
    expect(text).toContain("Reasons:");
    expect(text).toContain("  workflow enabled: Not declared in the manifest");
    expect(text).not.toContain("abcdef123456");
  });
});
