import { NO_CONTAINMENT, unenforcedRules } from "@piship/policy";
import type {
  AccessManifest,
  DataManifest,
  PolicyConfig,
} from "@piship/schema";
import { describe, expect, it } from "vitest";
import {
  assertRadiusClosed,
  exportModelGovernance,
  radiusShareReachable,
  sessionExportRules,
  sessionExportStatus,
  withSessionExportRules,
} from "./session-export.js";

const access = (
  provider: "openai-compatible" | "pi-native",
  allowed: string[],
) =>
  ({
    inference: { provider },
    models: { allowed },
  }) as unknown as AccessManifest;

describe("radiusShareReachable", () => {
  it("is closed for a gateway distribution unless its provider is named radius", () => {
    expect(
      radiusShareReachable(
        exportModelGovernance("acme", access("openai-compatible", ["coder"])),
      ),
    ).toBe(false);
    expect(
      radiusShareReachable(
        exportModelGovernance("radius", access("openai-compatible", ["c"])),
      ),
    ).toBe(true);
  });

  it("follows the pi-native model allowlist", () => {
    const reachable = (allowed: string[]) =>
      radiusShareReachable(
        exportModelGovernance("acme", access("pi-native", allowed)),
      );
    expect(reachable([])).toBe(true);
    expect(reachable(["anthropic/claude-x"])).toBe(false);
    expect(reachable(["radius/some-model"])).toBe(true);
    // No access manifest: Pi's own providers, unrestricted.
    expect(radiusShareReachable(exportModelGovernance("acme", undefined))).toBe(
      true,
    );
    // Restricted to nothing admits no provider.
    expect(
      radiusShareReachable({
        kind: "pi-native",
        allowedModelKeys: [],
        restricted: true,
      }),
    ).toBe(false);
  });
});

describe("assertRadiusClosed", () => {
  it("refuses a gateway distribution with the id radius, in any mode", () => {
    expect(() =>
      assertRadiusClosed("radius", access("openai-compatible", ["coder"])),
    ).toThrow(expect.objectContaining({ code: "RADIUS_PROVIDER_RESERVED" }));
    expect(() =>
      assertRadiusClosed("acme", access("openai-compatible", ["coder"])),
    ).not.toThrow();
    // A pi-native distribution has no provider of its own.
    expect(() =>
      assertRadiusClosed("radius", access("pi-native", [])),
    ).not.toThrow();
  });
});

describe("sessionExportStatus", () => {
  it("reports every resource from the seam table", () => {
    expect(sessionExportStatus({ ...NO_CONTAINMENT, piOffline: true })).toEqual(
      {
        public: "unsupported",
        local: "unsupported",
        support: "enforced",
      },
    );
  });

  it("reports support unsupported while Pi is online (personal)", () => {
    expect(sessionExportStatus(NO_CONTAINMENT).support).toBe("unsupported");
  });
});

describe("data.export sugar", () => {
  it("expands into distribution-enforced session.export rules", () => {
    expect(sessionExportRules(undefined)).toEqual([]);
    expect(sessionExportRules({ public: "deny", local: "allow" })).toEqual([
      {
        id: "data.export.public",
        action: "session.export",
        resource: "public",
        effect: "deny",
        reason: "data.export.public",
      },
      {
        id: "data.export.local",
        action: "session.export",
        resource: "local",
        effect: "allow",
        reason: "data.export.local",
      },
    ]);
  });

  it("is checked by the seam table like any enforced rule", () => {
    const policy = {
      enforced: [],
      defaults: [],
      acknowledgeUnenforced: [],
    } as unknown as PolicyConfig;
    const data = {
      retention: {},
      purge: { onLogout: [], onUninstall: "none" },
      export: { public: "deny", support: "deny" },
    } as DataManifest;
    expect(withSessionExportRules(policy, undefined)).toBe(policy);
    const offline = { ...NO_CONTAINMENT, piOffline: true };
    const managed = unenforcedRules(
      "managed",
      withSessionExportRules(policy, data),
      offline,
    );
    expect(managed.map((item) => [item.level, item.key])).toEqual([
      ["error", "session.export:public"],
    ]);
    const acknowledged = unenforcedRules(
      "managed",
      withSessionExportRules(
        { ...policy, acknowledgeUnenforced: ["session.export:public"] },
        data,
      ),
      offline,
    );
    expect(acknowledged.map((item) => item.level)).toEqual(["info"]);
    expect(
      unenforcedRules(
        "personal",
        withSessionExportRules(policy, data),
        NO_CONTAINMENT,
      ).map((item) => [item.level, item.key]),
    ).toEqual([
      ["warning", "session.export:public"],
      ["warning", "session.export:support"],
    ]);
  });
});
