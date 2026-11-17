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
  companionRequests,
  decisionToJSON,
  denialHint,
  formatDecision,
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
        "Other matching rules:\n  acme.mcp.default (distribution-default, allow, replaced by a matching user rule)\n  me.docs (user-preference, ask, overridden by acme.docs.destructive)",
        "Ignored rules:\n  team.docs.allow (team): team rules are narrowing only; allow is ignored",
      ].join("\n\n"),
    );
  });
  it("points a model-facing tool name at <server>:<tool>", () => {
    const text = formatDecision(
      engine.explain({
        action: "mcp.tool.call",
        resource: "mcp__docs__delete_document",
      }),
    );
    expect(text).toContain(
      "Hint:\n  mcp__docs__delete_document is the model-facing tool name; an mcp.tool.call resource is <server>:<tool>, so ask for docs:delete_document",
    );
    expect(formatDecision(explanation)).not.toContain("Hint:");
  });
  it("renders a JSON form", () => {
    const json = JSON.parse(JSON.stringify(decisionToJSON(explanation)));
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
    expect(text).toContain(
      "Rule:\n  builtin:default (no rule matched; policy.default decides)",
    );
  });
});

describe("a request the session also decides as another action", () => {
  const engine = new PolicyEngine({
    policy: makePolicy({
      enforced: [
        rule("no-delete", "mcp.tool.call", "docs:delete_*", "deny"),
        rule("push", "git.push", "**", "ask"),
        rule("no-rm", "shell.execute", "rm **", "deny"),
      ],
      defaults: [
        rule("tools", "tool.execute", "*", "allow"),
        rule("shell", "shell.execute", "**", "allow"),
        rule("mcp", "mcp.tool.call", "**", "allow"),
      ],
    }),
    context,
  });
  const explain = (
    action: "tool.execute" | "shell.execute",
    resource: string,
  ) => {
    const request = { action, resource } as const;
    const also = companionRequests(engine, request).map((item) =>
      engine.evaluate(item),
    );
    return { explanation: engine.explain(request), also };
  };

  it("maps an MCP tool's two names onto each other", () => {
    expect(
      companionRequests(engine, {
        action: "tool.execute",
        resource: "mcp__docs__delete_page",
      }),
    ).toEqual([{ action: "mcp.tool.call", resource: "docs:delete_page" }]);
    expect(
      companionRequests(engine, {
        action: "mcp.tool.call",
        resource: "docs:delete_page",
      }),
    ).toEqual([{ action: "tool.execute", resource: "mcp__docs__delete_page" }]);
    expect(
      companionRequests(engine, { action: "tool.execute", resource: "read" }),
    ).toEqual([]);
  });

  it("reports a hidden MCP tool as denied under its model-facing name", () => {
    const { explanation, also } = explain(
      "tool.execute",
      "mcp__docs__delete_page",
    );
    expect(explanation.decision.effect).toBe("allow");
    const text = formatDecision(explanation, { also });
    expect(text).toMatch(/^DENIED\n/);
    expect(text).toContain(
      "Also decided as:\n  mcp.tool.call docs:delete_page: DENIED (policy no-delete)",
    );
    expect(decisionToJSON(explanation, { also })).toMatchObject({
      effect: "allow",
      overallEffect: "deny",
      also: [{ action: "mcp.tool.call", effect: "deny", ruleId: "no-delete" }],
    });
  });

  it("adds the push prompt to a git push command, as the session does", () => {
    const { explanation, also } = explain(
      "shell.execute",
      "git push --force origin main",
    );
    const text = formatDecision(explanation, { also });
    expect(text).toMatch(/^APPROVAL REQUIRED\n/);
    expect(text).toContain(
      "Also decided as:\n  git.push origin/main: APPROVAL REQUIRED (policy push)",
    );
    // Auto mode then approves the combined ask.
    expect(formatDecision(explanation, { also, autoApproved: true })).toMatch(
      /^AUTO-APPROVED\n/,
    );
    // A command shell.execute denies is refused before any push prompt.
    expect(explain("shell.execute", "rm -rf x; git push").also).toEqual([]);
    // No push, no second decision, and the JSON form is unchanged.
    const plain = explain("shell.execute", "git status");
    expect(plain.also).toEqual([]);
    expect(decisionToJSON(plain.explanation, { also: [] })).not.toHaveProperty(
      "overallEffect",
    );
  });
});

describe("an ask a task grant approves", () => {
  const engine = new PolicyEngine({
    policy: makePolicy({ default: "ask" }),
    context,
  });
  const ask = engine.explain({ action: "model.select", resource: "m" });

  it("names the grant in both forms, and only for an ask", () => {
    const text = formatDecision(ask, { grantId: "a1b2" });
    expect(text).toMatch(/^GRANT-APPROVED\n/);
    expect(text).toContain("Effect:\n  ask (approved by task grant a1b2)");
    expect(
      JSON.parse(JSON.stringify(decisionToJSON(ask, { grantId: "a1b2" }))),
    ).toMatchObject({ effect: "ask", grantId: "a1b2" });
    const allow = new PolicyEngine({
      policy: makePolicy({ default: "allow" }),
      context,
    }).explain({ action: "model.select", resource: "m" });
    expect(formatDecision(allow, { grantId: "a1b2" })).toMatch(/^ALLOWED\n/);
    expect(
      JSON.parse(JSON.stringify(decisionToJSON(allow, { grantId: "a1b2" }))),
    ).not.toHaveProperty("grantId");
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

  it("says git.push is read from the command text, even with a shell sandbox", () => {
    for (const shell of [false, true]) {
      const engine = new PolicyEngine({
        policy: makePolicy({
          enforced: [rule("no.main", "git.push", "origin/main", "deny")],
        }),
        context: {
          ...context,
          containment: { filesystem: true, network: true, shell },
        },
      });
      const explanation = engine.explain({
        action: "git.push",
        resource: "origin/main",
      });
      expect(formatDecision(explanation)).toContain(
        "Enforcement:\n  enforced (control-plane, command text only: a push from a script, alias, or wrapper is not recognized)",
      );
      expect(decisionToJSON(explanation).enforcement).toBe("control-plane");
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

describe("denialHint", () => {
  const at = (layer: Parameters<typeof denialHint>[0]["layer"]) => ({
    layer,
    action: "shell.execute" as const,
    ruleId: "r1",
    effect: "deny" as const,
  });
  const FORBIDDEN = /--yolo|\/auto|config[\\/]policy\.json|add a rule/;

  it("names the owner and the way to change it per layer", () => {
    expect(denialHint(at("user-preference"), "personal")).toMatch(
      /your own rule r1.*config\/policy\.json.*policy explain shell\.execute/,
    );
    expect(denialHint(at("distribution-default"), "personal")).toMatch(
      /add a rule to config\/policy\.json/,
    );
    expect(denialHint(at("distribution-default"), "managed")).toMatch(
      /ask your administrator/,
    );
    expect(denialHint(at("team-project"), "personal")).toMatch(
      /project or team policy; ask its owner/,
    );
    expect(denialHint(at("distribution-enforced"), "managed")).toMatch(
      /distribution-owned.*ask your administrator/,
    );
  });

  it("points a personal user at their own piship.yaml for an enforced rule", () => {
    expect(denialHint(at("distribution-enforced"), "personal")).toMatch(
      /cannot be changed here; it lives in the distribution's piship\.yaml.*policy explain shell\.execute/,
    );
  });

  it("offers no workaround for an enforced or team rule", () => {
    for (const layer of ["distribution-enforced", "team-project"] as const)
      for (const mode of ["personal", "managed"] as const)
        expect(denialHint(at(layer), mode)).not.toMatch(FORBIDDEN);
  });

  it("has nothing to say for the builtin fallback", () => {
    expect(denialHint(at("builtin"), "personal")).toBe("");
  });

  it("names the absolute policy file for a personal user", () => {
    const policyFile = "/state/config/policy.json";
    expect(denialHint(at("builtin"), "personal", { policyFile })).toBe(
      "Nothing allows this yet; add a rule to /state/config/policy.json (`piship policy explain shell.execute <resource>` shows how it was decided).",
    );
    expect(
      denialHint(at("builtin"), "personal", { policyFile, command: "acme" }),
    ).toContain("`acme policy explain shell.execute <resource>`");
    expect(denialHint(at("builtin"), "managed", { policyFile })).toBe("");
    expect(
      denialHint(
        { ...at("builtin"), ruleId: "builtin:unknown-action" },
        "personal",
        { policyFile },
      ),
    ).toBe(
      "This action is not known to this release; check its spelling in the rule.",
    );
    expect(
      denialHint(
        { ...at("builtin"), ruleId: "builtin:unknown-action" },
        "managed",
        { policyFile },
      ),
    ).toBe("");
    const windows = "C:\\Users\\me\\state\\config\\policy.json";
    expect(
      denialHint(at("distribution-default"), "personal", {
        policyFile: windows,
      }),
    ).toContain(`add a rule to ${windows} to change it`);
  });

  it("offers /grant only for an interactive ask on a covered action", () => {
    const where = { policyFile: "/s/policy.json", grants: {} };
    const ask = { ...at("distribution-default"), effect: "ask" as const };
    const grant = /Or type `\/grant <folder>`/;
    expect(denialHint(ask, "personal", where)).toMatch(grant);
    expect(
      denialHint({ ...ask, action: "filesystem.write" }, "personal", where),
    ).toMatch(grant);
    expect(
      denialHint(ask, "personal", {
        ...where,
        grants: { actions: ["shell.execute"] },
      }),
    ).toMatch(grant);
    for (const other of [
      { ...ask, effect: "deny" as const },
      { ...ask, approval: "unavailable" as const },
      { ...ask, action: "model.select" as const },
      { ...ask, action: "tool.execute" as const },
    ])
      expect(denialHint(other, "personal", where)).not.toMatch(/grant/);
    expect(
      denialHint(ask, "personal", {
        ...where,
        grants: { actions: ["filesystem.read"] },
      }),
    ).not.toMatch(/grant/);
    expect(
      denialHint(ask, "personal", { policyFile: "/s/p.json" }),
    ).not.toMatch(/grant/);
    expect(denialHint(ask, "managed", where)).not.toMatch(/grant/);
  });

  it("offers /grant for a command only when a grant could cover it", () => {
    const where = {
      policyFile: "/s/policy.json",
      grants: { commands: ["git", "npm"] },
    };
    const ask = (resource: string) => ({
      ...at("distribution-default"),
      effect: "ask" as const,
      resource,
    });
    expect(
      denialHint(ask("npm test && git status"), "personal", where),
    ).toMatch(/Or type `\/grant <folder>` to approve/);
    // A program outside the default list needs `--run`, naming the whole chain.
    expect(
      denialHint(ask("npm run build && node x.js"), "personal", where),
    ).toMatch(
      /`\/grant <folder> --run npm,node` .*a plain `\/grant` covers only git, npm\./,
    );
    // No grant covers a wrapper, a path, a substitution, or a git push.
    for (const resource of [
      "bash -c 'node x.js'",
      "./run.sh",
      "node $(cat f)",
      "git push origin main",
    ])
      expect(denialHint(ask(resource), "personal", where)).not.toMatch(/grant/);
  });

  it("is empty after the person refused a prompt", () => {
    expect(
      denialHint({ ...at("user-preference"), approval: "denied" }, "personal"),
    ).toBe("");
  });
});
