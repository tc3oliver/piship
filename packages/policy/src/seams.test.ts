import {
  POLICY_ACTIONS,
  type PolicyAction,
  SESSION_EXPORT_RESOURCES,
} from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  decisionStatus,
  enforcementPlane,
  enforcementStatus,
  NO_CONTAINMENT,
  planeStatus,
  RESOURCE_SEAMS,
  RUNTIME_SEAMS,
  ruleStatus,
  seamEvidence,
} from "./index.js";

const contained = {
  filesystem: true,
  network: true,
  shell: true,
  piOffline: true,
};
const offline = { ...NO_CONTAINMENT, piOffline: true };

describe("RUNTIME_SEAMS", () => {
  it("covers every policy action", () => {
    for (const action of POLICY_ACTIONS)
      expect(RUNTIME_SEAMS[action]).toMatch(/^(hook|observe|none)$/);
  });

  it("matches the v0.9 table against Pi 1.1.0", () => {
    const enforced: PolicyAction[] = [
      "tool.execute",
      "mcp.tool.call",
      "mcp.server.start",
      "shell.execute",
      "filesystem.read",
      "filesystem.write",
      "resource.load",
      "extension.load",
      "skill.load",
      "instruction.load",
      "provider.load",
      "model.select",
      "model.dispatch",
    ];
    for (const action of enforced) {
      expect(enforcementStatus(action, NO_CONTAINMENT)).toBe("enforced");
      expect(enforcementStatus(action, contained)).toBe("enforced");
    }
    for (const action of [
      "web.request",
      "browser.execute",
      "memory.read",
      "memory.write",
      "agent.invoke",
    ] as const) {
      expect(enforcementStatus(action, NO_CONTAINMENT)).toBe("unsupported");
      expect(enforcementStatus(action, contained)).toBe("unsupported");
    }
    expect(enforcementStatus("network.connect", contained)).toBe("enforced");
    expect(enforcementStatus("network.connect", NO_CONTAINMENT)).toBe(
      "unsupported",
    );
  });

  it("narrows session.export per resource", () => {
    expect(Object.keys(RESOURCE_SEAMS["session.export"]).sort()).toEqual(
      [...SESSION_EXPORT_RESOURCES].sort(),
    );
    expect(enforcementStatus("session.export", offline, "support")).toBe(
      "enforced",
    );
    for (const resource of ["public", "local"])
      expect(enforcementStatus("session.export", contained, resource)).toBe(
        "unsupported",
      );
    expect(ruleStatus("session.export", "support", offline)).toBe("enforced");
    expect(ruleStatus("session.export", "**", NO_CONTAINMENT)).toBe(
      "unsupported",
    );
    expect(ruleStatus("session.export", "pub*", NO_CONTAINMENT)).toBe(
      "unsupported",
    );
    // Only the per-resource table raises support: an unknown resource, or
    // none, has no seam.
    expect(RUNTIME_SEAMS["session.export"]).toBe("none");
    for (const resource of ["secret", undefined])
      expect(enforcementStatus("session.export", offline, resource)).toBe(
        "unsupported",
      );
    expect(ruleStatus("session.export", "secret", offline)).toBe("unsupported");
  });
});

describe("support export needs Pi offline", () => {
  it("reports support unsupported while Pi's /bug upload is open", () => {
    // Personal launches leave Pi online; only PI_OFFLINE closes /bug.
    expect(enforcementStatus("session.export", NO_CONTAINMENT, "support")).toBe(
      "unsupported",
    );
    expect(
      enforcementStatus(
        "session.export",
        { ...contained, piOffline: false },
        "support",
      ),
    ).toBe("unsupported");
    expect(ruleStatus("session.export", "support", NO_CONTAINMENT)).toBe(
      "unsupported",
    );
    expect(enforcementStatus("session.export", offline, "support")).toBe(
      "enforced",
    );
    // Other actions do not depend on Pi being offline.
    expect(enforcementStatus("tool.execute", NO_CONTAINMENT)).toBe("enforced");
  });
});

describe("status derivation", () => {
  it("maps planes to statuses", () => {
    expect(planeStatus("control-plane")).toBe("enforced");
    expect(planeStatus("sandbox")).toBe("enforced");
    expect(planeStatus("gateway")).toBe("enforced");
    expect(planeStatus("audit-only")).toBe("audit-only");
    expect(planeStatus(undefined)).toBe("unsupported");
  });

  it("keeps the engine's plane for decisions and reports no seam as unsupported", () => {
    expect(enforcementPlane("web.request", NO_CONTAINMENT)).toBe("audit-only");
    expect(
      decisionStatus({
        action: "web.request",
        resource: "https://example.com",
        enforcement: "audit-only",
      }),
    ).toBe("unsupported");
    expect(
      decisionStatus({
        action: "tool.execute",
        resource: "bash",
        enforcement: "control-plane",
      }),
    ).toBe("enforced");
    // A personal engine (Pi online) decides support exports audit-only.
    const personal = enforcementPlane(
      "session.export",
      NO_CONTAINMENT,
      "support",
    );
    expect(personal).toBe("audit-only");
    expect(
      decisionStatus({
        action: "session.export",
        resource: "support",
        enforcement: personal,
      }),
    ).toBe("unsupported");
    expect(
      decisionStatus({
        action: "session.export",
        resource: "support",
        enforcement: enforcementPlane("session.export", offline, "support"),
      }),
    ).toBe("enforced");
  });
});

describe("seamEvidence", () => {
  it("records the Pi version, the table, and a stable digest", () => {
    const evidence = seamEvidence("1.0.3");
    expect(evidence.pi).toBe("1.0.3");
    expect(evidence.seams).toEqual(RUNTIME_SEAMS);
    expect(Object.keys(evidence.seams)).toEqual(
      Object.keys(RUNTIME_SEAMS).sort(),
    );
    expect(evidence.digest).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(seamEvidence("1.0.3").digest).toBe(evidence.digest);
    expect(seamEvidence("1.0.2").digest).not.toBe(evidence.digest);
  });
});
