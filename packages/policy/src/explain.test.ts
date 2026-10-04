import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { makePolicy, rule } from "./fixtures.test-helpers.js";
import { POLICY_ACTIONS } from "@piship/contracts";
import {
  NO_CONTAINMENT,
  PolicyEngine,
  RUNTIME_SEAMS,
  decisionToJSON,
  formatDecision,
  formatDecisionJSON,
} from "./index.js";

const base = realpathSync(
  mkdtempSync(join(tmpdir(), "piship-policy-explain-")),
);
afterAll(() => rmSync(base, { recursive: true, force: true }));
const context = {
  workspaceRoot: base,
  homeDir: base,
  tmpDir: base,
  containment: NO_CONTAINMENT,
};

describe("formatDecision", () => {
  const engine = new PolicyEngine({
    policy: makePolicy({
      enforced: [
        rule(
          "acme.docs.destructive",
          "mcp.tool.call",
          "docs:delete_*",
          "deny",
          "Destructive document tools need a change ticket",
        ),
      ],
      defaults: [rule("acme.mcp.default", "mcp.*", "**", "allow")],
    }),
    teamRules: [rule("team.docs.allow", "mcp.tool.call", "docs:*", "allow")],
    context,
    userRules: [rule("me.docs", "mcp.tool.call", "docs:*", "ask")],
  });
  const explanation = engine.explain({
    action: "mcp.tool.call",
    resource: "docs:delete_document",
  });

  it("renders the human form", () => {
    expect(formatDecision(explanation)).toBe(
      [
        "DENIED",
        "Action:\n  mcp.tool.call",
        "Resource:\n  docs:delete_document",
        "Rule:\n  acme.docs.destructive",
        "Policy:\n  acme-engineering@3",
        "Enforcement:\n  enforced (control-plane)",
        "Layer:\n  distribution-enforced",
        "Reason:\n  Destructive document tools need a change ticket",
        "Other matching rules:\n  acme.mcp.default (distribution-default, allow)\n  me.docs (user-preference, ask)",
        "Ignored rules:\n  team.docs.allow (team): team rules are narrowing only; allow is ignored",
      ].join("\n\n"),
    );
  });
  it("renders a JSON form", () => {
    const json = JSON.parse(formatDecisionJSON(explanation));
    expect(json).toMatchObject({
      effect: "deny",
      ruleId: "acme.docs.destructive",
      policyId: "acme-engineering@3",
      enforcement: "control-plane",
      enforcementStatus: "enforced",
      layer: "distribution-enforced",
    });
    expect(json.matches).toHaveLength(3);
    expect(json.ignored[0]).toMatchObject({
      ruleId: "team.docs.allow",
      matches: true,
    });
    expect(json.diagnostics).toHaveLength(1);
  });
  it("labels unsupported denies honestly and redacts secrets", () => {
    const audit = new PolicyEngine({
      policy: makePolicy({
        enforced: [
          rule(
            "no.web",
            "web.request",
            "**",
            "deny",
            "blocked: Authorization: Bearer abcdefghijkl",
          ),
        ],
      }),
      context,
    }).explain({
      action: "web.request",
      resource: "https://example.com/?access_token=zzz123456",
    });
    const text = formatDecision(audit);
    expect(text).toContain(
      "Enforcement:\n  unsupported (no runtime seam: neither prevented nor recorded)",
    );
    expect(decisionToJSON(audit)).toMatchObject({
      enforcement: "audit-only",
      enforcementStatus: "unsupported",
    });
    expect(text).not.toContain("abcdefghijkl");
    expect(text).not.toContain("zzz123456");
    expect(JSON.stringify(decisionToJSON(audit))).not.toContain("zzz123456");
  });
  it("renders ask and allow headings", () => {
    const e = new PolicyEngine({
      policy: makePolicy({ default: "ask" }),
      context,
    });
    expect(
      formatDecision(e.explain({ action: "model.select", resource: "m" })),
    ).toMatch(/^APPROVAL REQUIRED\n/);
    const a = new PolicyEngine({
      policy: makePolicy({ default: "allow" }),
      context,
    });
    const text = formatDecision(
      a.explain({ action: "model.select", resource: "m" }),
    );
    expect(text).toMatch(/^ALLOWED\n/);
    expect(text).toContain("Rule:\n  builtin:default");
  });
});

describe("enforcement status in explain", () => {
  it("never prints enforced for an action without a runtime seam", () => {
    const contained = { filesystem: true, network: true, shell: true };
    for (const containment of [NO_CONTAINMENT, contained])
      for (const action of POLICY_ACTIONS) {
        if (RUNTIME_SEAMS[action] !== "none") continue;
        const engine = new PolicyEngine({
          policy: makePolicy({
            enforced: [rule("no.action", action, "**", "deny")],
          }),
          context: { ...context, containment },
        });
        const explanation = engine.explain({ action, resource: "anything" });
        const sandboxed =
          action === "network.connect" && containment.network === true;
        const line = formatDecision(explanation)
          .split("\n\n")
          .find((block) => block.startsWith("Enforcement:"));
        if (sandboxed) expect(line).toBe("Enforcement:\n  enforced (sandbox)");
        else {
          expect(line).not.toMatch(/\benforced\b/);
          expect(decisionToJSON(explanation).enforcementStatus).toBe(
            "unsupported",
          );
        }
      }
  });
});

describe("managed user rules in explain", () => {
  it("reports an ignored user allow rule in text and JSON", () => {
    const engine = new PolicyEngine({
      policy: makePolicy({
        defaults: [rule("acme.shell", "shell.execute", "**", "ask")],
      }),
      userRules: [rule("me.shell", "shell.execute", "**", "allow")],
      userRuleMode: "narrowing",
      context,
    });
    const explanation = engine.explain({
      action: "shell.execute",
      resource: "ls",
    });
    expect(explanation.decision).toMatchObject({
      effect: "ask",
      ruleId: "acme.shell",
    });
    expect(formatDecision(explanation)).toContain(
      "me.shell (user): user rules are narrowing only in managed mode; allow is ignored",
    );
    expect(JSON.stringify(decisionToJSON(explanation))).toContain("me.shell");
  });
});
