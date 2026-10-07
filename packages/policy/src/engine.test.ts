import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  POLICY_ACTIONS,
  PiShipError,
  resolveDecision,
  type PolicyAction,
  type PolicyEffect,
} from "@piship/contracts";
import type { PolicyRule } from "@piship/schema";
import { afterAll, describe, expect, it } from "vitest";
import {
  NO_CONTAINMENT,
  PolicyEngine,
  enforcementPlane,
  parseRuleList,
  type PolicyContext,
} from "./index.js";
import { makePolicy, rule } from "./fixtures.test-helpers.js";

const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-policy-engine-")));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const context: PolicyContext = {
  workspaceRoot: join(base, "work"),
  homeDir: join(base, "home"),
  tmpDir: join(base, "tmp"),
  containment: NO_CONTAINMENT,
};

function engine(
  input: Partial<ConstructorParameters<typeof PolicyEngine>[0]> = {},
): PolicyEngine {
  return new PolicyEngine({ policy: makePolicy(), context, ...input });
}

describe("decision tables for every action", () => {
  const cases: readonly (readonly [PolicyAction, string])[] = [
    ["model.select", "acme/general"],
    ["model.dispatch", "anthropic/claude-opus-x"],
    ["session.export", "public"],
    ["resource.load", "company:skills/review"],
    ["extension.load", "piship-workflow"],
    ["skill.load", "review"],
    ["instruction.load", "AGENTS.md"],
    ["provider.load", "builtin/permissions"],
    ["agent.invoke", "planner"],
    ["mcp.server.start", "docs"],
    ["mcp.tool.call", "docs:search"],
    ["tool.execute", "bash"],
    ["shell.execute", "git status"],
    ["filesystem.read", "src/index.ts"],
    ["filesystem.write", "src/index.ts"],
    ["network.connect", "registry.example.com:443"],
    ["memory.read", "notes"],
    ["memory.write", "notes"],
    ["web.request", "https://example.com/"],
    ["browser.execute", "https://example.com/"],
  ];
  it("covers every declared action", () => {
    expect(cases.map(([action]) => action).sort()).toEqual(
      [...POLICY_ACTIONS].sort(),
    );
  });
  for (const [action, resource] of cases)
    for (const effect of ["allow", "ask", "deny"] as const) {
      it(`${action} with an exact ${effect} rule`, () => {
        const decision = engine({
          policy: makePolicy({
            default: effect === "allow" ? "deny" : "allow",
            defaults: [rule(`r.${effect}`, action, "**", effect)],
          }),
        }).evaluate({ action, resource });
        expect(decision.effect).toBe(effect);
        expect(decision.ruleId).toBe(`r.${effect}`);
        expect(decision.layer).toBe("distribution-default");
        expect(decision.action).toBe(action);
        expect(decision.policyId).toBe("acme-engineering@3");
      });
    }
  it("falls back to the policy default with a builtin rule", () => {
    for (const effect of ["allow", "ask", "deny"] as PolicyEffect[]) {
      const decision = engine({
        policy: makePolicy({ default: effect }),
      }).evaluate({ action: "model.select", resource: "x" });
      expect(decision).toMatchObject({
        effect,
        ruleId: "builtin:default",
        layer: "builtin",
      });
    }
  });
  it("matches prefix and wildcard actions", () => {
    const e = engine({
      policy: makePolicy({
        default: "allow",
        defaults: [
          rule("mcp.all", "mcp.*", "docs*", "deny"),
          rule("all", "*", "secret", "ask"),
        ],
      }),
    });
    expect(
      e.evaluate({ action: "mcp.tool.call", resource: "docs:x" }).effect,
    ).toBe("allow");
    expect(
      e.evaluate({ action: "mcp.server.start", resource: "docs" }).ruleId,
    ).toBe("mcp.all");
    expect(
      e.evaluate({ action: "memory.read", resource: "secret" }).ruleId,
    ).toBe("all");
    expect(e.evaluate({ action: "model.select", resource: "mcp" }).effect).toBe(
      "allow",
    );
  });
  it("uses first match within a layer", () => {
    const decision = engine({
      policy: makePolicy({
        defaults: [
          rule("first", "tool.execute", "b*", "allow"),
          rule("second", "tool.execute", "bash", "deny"),
        ],
      }),
    }).evaluate({ action: "tool.execute", resource: "bash" });
    expect(decision.ruleId).toBe("first");
    expect(decision.effect).toBe("allow");
  });
});

describe("precedence", () => {
  it("an enforced deny beats a user allow", () => {
    const e = engine({
      policy: makePolicy({
        enforced: [
          rule(
            "acme.secrets.read",
            "filesystem.read",
            "~/.ssh/**",
            "deny",
            "Credentials stay outside the agent",
          ),
        ],
      }),
      userRules: [rule("me.ssh", "filesystem.read", "**", "allow")],
    });
    const decision = e.evaluate({
      action: "filesystem.read",
      resource: join(context.homeDir, ".ssh", "id_ed25519"),
    });
    expect(decision).toMatchObject({
      effect: "deny",
      ruleId: "acme.secrets.read",
      layer: "distribution-enforced",
      reason: "Credentials stay outside the agent",
    });
  });
  it("a restriction ask beats a default allow", () => {
    const decision = engine({
      policy: makePolicy({
        defaults: [rule("d.allow", "shell.execute", "**", "allow")],
      }),
      projectRules: [rule("p.ask", "shell.execute", "rm *", "ask")],
    }).evaluate({ action: "shell.execute", resource: "rm build" });
    expect(decision).toMatchObject({
      effect: "ask",
      ruleId: "p.ask",
      layer: "team-project",
    });
  });
  it("a user rule relaxes a default", () => {
    const decision = engine({
      policy: makePolicy({
        defaults: [rule("acme.shell.ask", "shell.execute", "**", "ask")],
      }),
      userRules: [rule("me.git", "shell.execute", "git *", "allow")],
    }).evaluate({ action: "shell.execute", resource: "git status" });
    expect(decision).toMatchObject({
      effect: "allow",
      ruleId: "me.git",
      layer: "user-preference",
    });
  });
  it("a user rule relaxes the policy default", () => {
    const decision = engine({
      userRules: [rule("me.model", "model.select", "acme/*", "allow")],
    }).evaluate({ action: "model.select", resource: "acme/general" });
    expect(decision.effect).toBe("allow");
  });
  it("a user rule cannot relax an enforced ask", () => {
    const decision = engine({
      policy: makePolicy({
        enforced: [rule("e.ask", "shell.execute", "**", "ask")],
      }),
      userRules: [rule("me.all", "shell.execute", "**", "allow")],
    }).evaluate({ action: "shell.execute", resource: "ls" });
    expect(decision).toMatchObject({ effect: "ask", ruleId: "e.ask" });
  });
  it("a user rule may narrow further", () => {
    const decision = engine({
      policy: makePolicy({
        enforced: [rule("e.ask", "shell.execute", "**", "ask")],
      }),
      userRules: [rule("me.deny", "shell.execute", "curl *", "deny")],
    }).evaluate({ action: "shell.execute", resource: "curl x" });
    expect(decision).toMatchObject({
      effect: "deny",
      ruleId: "me.deny",
      layer: "user-preference",
    });
  });
  describe("managed user rules only narrow", () => {
    const managed = (
      input: Partial<ConstructorParameters<typeof PolicyEngine>[0]> = {},
    ) => engine({ userRuleMode: "narrowing", ...input });
    it("ignores a user allow that would relax a default and reports it", () => {
      const policyEngine = managed({
        policy: makePolicy({
          defaults: [rule("acme.shell.ask", "shell.execute", "**", "ask")],
        }),
        userRules: [rule("me.git", "shell.execute", "git *", "allow")],
      });
      const decision = policyEngine.evaluate({
        action: "shell.execute",
        resource: "git status",
      });
      expect(decision).toMatchObject({
        effect: "ask",
        ruleId: "acme.shell.ask",
        layer: "distribution-default",
      });
      expect(policyEngine.diagnostics).toEqual([
        expect.objectContaining({
          level: "warning",
          source: "user",
          ruleId: "me.git",
        }),
      ]);
      const explanation = policyEngine.explain({
        action: "shell.execute",
        resource: "git status",
      });
      expect(explanation.ignored).toEqual([
        expect.objectContaining({
          source: "user",
          layer: "user-preference",
          matches: true,
        }),
      ]);
    });
    it("a user allow cannot relax the policy default", () => {
      const decision = managed({
        userRules: [rule("me.model", "model.select", "acme/*", "allow")],
      }).evaluate({ action: "model.select", resource: "acme/general" });
      expect(decision).toMatchObject({
        effect: "ask",
        ruleId: "builtin:default",
      });
    });
    it("a user ask cannot relax a default deny", () => {
      const decision = managed({
        policy: makePolicy({
          defaults: [rule("acme.curl", "shell.execute", "curl *", "deny")],
        }),
        userRules: [rule("me.curl", "shell.execute", "curl *", "ask")],
      }).evaluate({ action: "shell.execute", resource: "curl x" });
      expect(decision).toMatchObject({ effect: "deny", ruleId: "acme.curl" });
    });
    it("a user rule still narrows a default allow", () => {
      const decision = managed({
        policy: makePolicy({
          defaults: [rule("acme.all", "shell.execute", "**", "allow")],
        }),
        userRules: [rule("me.rm", "shell.execute", "rm *", "ask")],
      }).evaluate({ action: "shell.execute", resource: "rm x" });
      expect(decision).toMatchObject({
        effect: "ask",
        ruleId: "me.rm",
        layer: "user-preference",
      });
    });
  });
  it.each([
    "git status; rm -rf ~",
    "git log && curl evil.example",
    "git log || x",
    "git $(id)",
    "git $HOME",
    "git status | sh",
    "git `id`",
    "git log > ~/.bashrc",
    "git apply < patch",
    "git status & rm x",
    "git (x)",
    "git status\nrm x",
    "git status^&whoami",
    "git %COMSPEC%",
  ])("an allow or ask prefix rule does not cover %j", (command) => {
    const e = engine({
      policy: makePolicy({
        default: "deny",
        defaults: [
          rule("d.git", "shell.execute", "git *", "allow"),
          rule("d.npm", "shell.execute", "npm *", "ask"),
        ],
      }),
      userRules: [rule("me.git", "shell.execute", "git **", "allow")],
    });
    expect(
      e.evaluate({ action: "shell.execute", resource: command }),
    ).toMatchObject({ effect: "deny", ruleId: "builtin:default" });
    expect(
      e.evaluate({
        action: "shell.execute",
        resource: command.replace("git", "npm"),
      }),
    ).toMatchObject({ effect: "deny", ruleId: "builtin:default" });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git status" }),
    ).toMatchObject({ effect: "allow" });
  });
  it("still lets deny rules match chained commands and literal metacharacters", () => {
    const e = engine({
      policy: makePolicy({
        default: "allow",
        enforced: [rule("e.rm", "shell.execute", "**rm -rf**", "deny")],
        defaults: [
          rule("d.pipe", "shell.execute", "git log | head*", "allow"),
          rule("d.all", "shell.execute", "**", "ask"),
        ],
      }),
    });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git status; rm -rf ~" }),
    ).toMatchObject({ effect: "deny", ruleId: "e.rm" });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git log | head -5" }),
    ).toMatchObject({ effect: "allow", ruleId: "d.pipe" });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git log | sh; x" }),
    ).toMatchObject({ effect: "ask", ruleId: "d.all" });
  });
  it.each([
    "git push origin main; true",
    "git push origin main && echo ok",
    "git push origin main || true",
    "git push $(echo origin) main",
  ])(
    "keeps an enforced, team, project, or managed user ask on the chained command %j",
    (command) => {
      const ask = rule("x.push", "shell.execute", "git push**", "ask");
      const layers = [
        { policy: makePolicy({ default: "allow", enforced: [ask] }) },
        { teamRules: [ask] },
        { projectRules: [ask] },
        { userRuleMode: "narrowing" as const, userRules: [ask] },
      ];
      for (const layer of layers) {
        const e = engine({
          policy: makePolicy({
            default: "allow",
            // A wider default allow and a later deny must not be hidden.
            defaults: [rule("d.git", "shell.execute", "git **", "allow")],
          }),
          ...layer,
        });
        const request = { action: "shell.execute" as const, resource: command };
        expect(e.evaluate(request)).toMatchObject({
          effect: "ask",
          ruleId: "x.push",
        });
        expect(e.keepsPrompt(request)).toBe(true);
      }
    },
  );
  it("a chained ask never hides a stricter rule or applies outside its own layers", () => {
    const e = engine({
      policy: makePolicy({
        default: "allow",
        enforced: [
          rule("e.push", "shell.execute", "git push**", "ask"),
          rule("e.rm", "shell.execute", "**rm -rf**", "deny"),
        ],
        defaults: [rule("d.npm", "shell.execute", "npm **", "ask")],
      }),
      // A personal user rule replaces defaults; it is not a narrowing ask.
      userRules: [rule("u.ls", "shell.execute", "ls**", "ask")],
    });
    expect(
      e.evaluate({ action: "shell.execute", resource: "git push; rm -rf ~" }),
    ).toMatchObject({ effect: "deny", ruleId: "e.rm" });
    expect(
      e.keepsPrompt({ action: "shell.execute", resource: "npm test; true" }),
    ).toBe(false);
    expect(
      e.keepsPrompt({ action: "shell.execute", resource: "ls; true" }),
    ).toBe(false);
    // Unchained commands keep first-match semantics.
    expect(
      e.evaluate({ action: "shell.execute", resource: "git status" }),
    ).toMatchObject({ effect: "allow", ruleId: "builtin:default" });
  });
  it("ignores team and project allow rules with diagnostics", () => {
    const e = engine({
      policy: makePolicy({ default: "deny" }),
      teamRules: [rule("t.allow", "model.select", "**", "allow")],
      projectRules: [rule("p.allow", "model.select", "**", "allow")],
    });
    const decision = e.evaluate({ action: "model.select", resource: "any" });
    expect(decision).toMatchObject({
      effect: "deny",
      ruleId: "builtin:default",
    });
    expect(e.diagnostics.map((d) => d.ruleId)).toEqual(["t.allow", "p.allow"]);
    const explanation = e.explain({ action: "model.select", resource: "any" });
    expect(
      explanation.ignored.map((item) => [item.rule.id, item.matches]),
    ).toEqual([
      ["t.allow", true],
      ["p.allow", true],
    ]);
  });
  it("prefers the higher layer when effects tie", () => {
    const decision = engine({
      policy: makePolicy({
        enforced: [rule("e.deny", "tool.execute", "bash", "deny")],
        defaults: [rule("d.deny", "tool.execute", "bash", "deny")],
      }),
      teamRules: [rule("t.deny", "tool.execute", "bash", "deny")],
    }).evaluate({ action: "tool.execute", resource: "bash" });
    expect(decision.ruleId).toBe("e.deny");
  });
  it("reports the diagnostics of reading its inputs first", () => {
    const unreadable = {
      level: "warning" as const,
      source: "/work/.piship/policy.json",
      message: "The project restriction file could not be read",
    };
    const e = engine({
      diagnostics: [unreadable],
      projectRules: [rule("p.allow", "shell.execute", "**", "allow")],
    });
    expect(e.diagnostics[0]).toEqual(unreadable);
    expect(e.diagnostics.map((item) => item.ruleId)).toEqual([
      undefined,
      "p.allow",
    ]);
    expect(
      e.explain({ action: "shell.execute", resource: "ls" }).diagnostics,
    ).toContainEqual(unreadable);
  });
  it("does not let a team ask hide a project deny", () => {
    const decision = engine({
      policy: makePolicy({ default: "allow" }),
      teamRules: [rule("t.ask", "shell.execute", "**", "ask")],
      projectRules: [rule("p.deny", "shell.execute", "rm *", "deny")],
    }).evaluate({ action: "shell.execute", resource: "rm -rf build" });
    expect(decision).toMatchObject({
      effect: "deny",
      ruleId: "p.deny",
      layer: "team-project",
    });
  });
  it("takes the strictest of the first team and the first project rule", () => {
    const e = engine({
      policy: makePolicy({ default: "allow" }),
      teamRules: [
        rule("t.deny", "shell.execute", "curl *", "deny"),
        rule("t.ask", "shell.execute", "**", "ask"),
      ],
      projectRules: [
        rule("p.ask", "shell.execute", "curl *", "ask"),
        rule("p.deny", "shell.execute", "**", "deny"),
      ],
    });
    // Team deny over project ask; a later project rule stays shadowed.
    expect(
      e.evaluate({ action: "shell.execute", resource: "curl x" }),
    ).toMatchObject({ effect: "deny", ruleId: "t.deny" });
    // Project deny over team ask.
    expect(
      e.evaluate({ action: "shell.execute", resource: "ls" }),
    ).toMatchObject({ effect: "deny", ruleId: "p.deny" });
    // Equal effects: the team rule is named, as before.
    const tie = engine({
      teamRules: [rule("t.ask", "shell.execute", "**", "ask")],
      projectRules: [rule("p.ask", "shell.execute", "**", "ask")],
    }).evaluate({ action: "shell.execute", resource: "ls" });
    expect(tie).toMatchObject({ effect: "ask", ruleId: "t.ask" });
    const explanation = e.explain({ action: "shell.execute", resource: "ls" });
    expect(
      explanation.matches.map((m) => [m.ruleId, m.source, m.first]),
    ).toEqual([
      ["t.ask", "team", true],
      ["p.deny", "project", true],
    ]);
  });
  it("a project deny beats an enforced ask when the team rules are silent", () => {
    const decision = engine({
      policy: makePolicy({
        default: "allow",
        enforced: [rule("e.ask", "shell.execute", "**", "ask")],
      }),
      projectRules: [rule("p.deny", "shell.execute", "rm *", "deny")],
    }).evaluate({ action: "shell.execute", resource: "rm x" });
    expect(decision).toMatchObject({ effect: "deny", ruleId: "p.deny" });
  });
  it("explains every matching rule per layer", () => {
    const e = engine({
      policy: makePolicy({
        enforced: [rule("e1", "mcp.tool.call", "docs:*", "ask")],
        defaults: [
          rule("d1", "mcp.tool.call", "docs:delete_*", "deny"),
          rule("d2", "mcp.*", "**", "allow"),
        ],
      }),
      userRules: [rule("u1", "mcp.tool.call", "**", "allow")],
    });
    const explanation = e.explain({
      action: "mcp.tool.call",
      resource: "docs:delete_document",
    });
    expect(explanation.decision.ruleId).toBe("e1");
    expect(explanation.decision.effect).toBe("ask");
    expect(
      explanation.matches.map((m) => [m.ruleId, m.layer, m.first]),
    ).toEqual([
      ["e1", "distribution-enforced", true],
      ["d1", "distribution-default", true],
      ["d2", "distribution-default", false],
      ["u1", "user-preference", true],
    ]);
  });
  it("is deterministic", () => {
    const e = engine({
      policy: makePolicy({ defaults: [rule("d", "*", "**", "ask")] }),
    });
    const request = { action: "tool.execute" as const, resource: "bash" };
    expect(e.evaluate(request)).toEqual(e.evaluate(request));
  });
  it("reports an unknown action as denied", () => {
    const decision = engine().evaluate({
      action: "unknown.thing" as PolicyAction,
      resource: "x",
    });
    expect(decision).toMatchObject({
      effect: "deny",
      ruleId: "builtin:unknown-action",
    });
  });
});

describe("headless ask", () => {
  it("resolves to deny without an approval channel", async () => {
    const decision = engine().evaluate({
      action: "shell.execute",
      resource: "ls",
    });
    expect(decision.effect).toBe("ask");
    const resolved = await resolveDecision(decision, undefined, {
      title: "t",
      message: "m",
    });
    expect(resolved).toMatchObject({
      outcome: "deny",
      approval: "unavailable",
    });
    const approved = await resolveDecision(decision, async () => "approved", {
      title: "t",
      message: "m",
    });
    expect(approved.outcome).toBe("allow");
    // A session scope is remembered only when it was offered; a channel that
    // answers it unasked approves this one action.
    const unasked = await resolveDecision(
      decision,
      async () => "approved-session",
      { title: "t", message: "m" },
    );
    expect(unasked).toMatchObject({ outcome: "allow", approval: "approved" });
    expect(unasked.remember).toBeUndefined();
    const offered = await resolveDecision(
      decision,
      async () => "approved-session",
      { title: "t", message: "m", scopes: ["once", "session"] },
    );
    expect(offered).toMatchObject({
      outcome: "allow",
      approval: "approved",
      remember: "session",
    });
  });
});

describe("enforcement planes", () => {
  const contained = {
    filesystem: true,
    network: true,
    shell: true,
    piOffline: true,
  };
  it("maps control-plane actions", () => {
    for (const action of [
      "model.select",
      "model.dispatch",
      "resource.load",
      "extension.load",
      "skill.load",
      "instruction.load",
      "provider.load",
      "mcp.server.start",
      "mcp.tool.call",
      "tool.execute",
    ] as const) {
      expect(enforcementPlane(action, NO_CONTAINMENT)).toBe("control-plane");
      expect(enforcementPlane(action, contained)).toBe("control-plane");
    }
  });
  it("reports actions without a runtime hook as audit-only", () => {
    for (const action of [
      "agent.invoke",
      "memory.read",
      "memory.write",
    ] as const) {
      expect(enforcementPlane(action, NO_CONTAINMENT)).toBe("audit-only");
      expect(enforcementPlane(action, contained)).toBe("audit-only");
      const decision = engine({
        policy: makePolicy({
          enforced: [rule("no.action", action, "**", "deny")],
        }),
        context: { ...context, containment: contained },
      }).evaluate({ action, resource: "anything" });
      expect(decision.effect).toBe("deny");
      expect(decision.enforcement).toBe("audit-only");
    }
  });
  it("takes session.export's plane from its resource", () => {
    expect(enforcementPlane("session.export", contained, "support")).toBe(
      "control-plane",
    );
    for (const resource of ["public", "local"]) {
      expect(enforcementPlane("session.export", contained, resource)).toBe(
        "audit-only",
      );
      expect(
        engine({ context: { ...context, containment: contained } }).evaluate({
          action: "session.export",
          resource,
        }).enforcement,
      ).toBe("audit-only");
    }
  });
  it("uses the sandbox only when containment is active", () => {
    expect(enforcementPlane("filesystem.read", contained)).toBe("sandbox");
    expect(enforcementPlane("filesystem.write", NO_CONTAINMENT)).toBe(
      "control-plane",
    );
    expect(enforcementPlane("shell.execute", contained)).toBe("sandbox");
    expect(enforcementPlane("shell.execute", NO_CONTAINMENT)).toBe(
      "control-plane",
    );
    expect(enforcementPlane("network.connect", contained)).toBe("sandbox");
    expect(enforcementPlane("network.connect", NO_CONTAINMENT)).toBe(
      "audit-only",
    );
  });
  it("never reports web or browser denies as enforceable", () => {
    for (const action of ["web.request", "browser.execute"] as const) {
      expect(enforcementPlane(action, contained)).toBe("audit-only");
      const decision = engine({
        policy: makePolicy({
          enforced: [rule("no.web", action, "**", "deny")],
        }),
        context: { ...context, containment: contained },
      }).evaluate({ action, resource: "https://x" });
      expect(decision.effect).toBe("deny");
      expect(decision.enforcement).toBe("audit-only");
    }
  });
});

describe("filesystem resources", () => {
  it("expands tokens and matches normalized paths", () => {
    const e = engine({
      policy: makePolicy({
        default: "deny",
        defaults: [
          rule("ws", "filesystem.write", "workspace/**", "allow"),
          rule("tmp", "filesystem.write", "tmp/**", "allow"),
        ],
      }),
    });
    expect(
      e.evaluate({ action: "filesystem.write", resource: "src/a.ts" }).ruleId,
    ).toBe("ws");
    expect(
      e.evaluate({
        action: "filesystem.write",
        resource: join(context.tmpDir, "x"),
      }).ruleId,
    ).toBe("tmp");
    const outside = e.evaluate({
      action: "filesystem.write",
      resource: "../outside.txt",
    });
    expect(outside.effect).toBe("deny");
    expect(outside.resource).toBe(`${base.split("\\").join("/")}/outside.txt`);
  });
  it("does not expand tokens for non-filesystem actions", () => {
    const decision = engine({
      policy: makePolicy({
        defaults: [rule("lit", "model.select", "workspace/**", "deny")],
      }),
    }).evaluate({ action: "model.select", resource: "workspace/x" });
    expect(decision.ruleId).toBe("lit");
  });
});

describe("parseRuleList", () => {
  it("accepts arrays and rules objects", () => {
    const parsed = parseRuleList(
      {
        rules: [
          {
            id: "me.git",
            action: "shell.execute",
            resource: "git *",
            effect: "allow",
          },
        ],
      },
      "config/policy.json",
      { narrowingOnly: false },
    );
    expect(parsed.rules).toHaveLength(1);
    expect(parseRuleList([], "x", { narrowingOnly: false }).rules).toEqual([]);
    expect(
      parseRuleList(
        [{ id: "all", action: "mcp.tool.*", effect: "deny" }],
        "x",
        {
          narrowingOnly: false,
        },
      ).rules[0]?.resource,
    ).toBe("**");
  });
  it("reads a model.use rule from an older state file as model.select", () => {
    const value = [
      {
        id: "me.model",
        action: "model.use",
        resource: "acme/*",
        effect: "deny",
      },
    ];
    const before = JSON.stringify(value);
    const parsed = parseRuleList(value, "config/policy.json", {
      narrowingOnly: false,
    });
    expect(parsed.rules[0]?.action).toBe("model.select");
    // The input is read, never rewritten.
    expect(JSON.stringify(value)).toBe(before);
    const decision = engine({ userRules: parsed.rules }).evaluate({
      action: "model.select",
      resource: "acme/general",
    });
    expect(decision.effect).toBe("deny");
    expect(decision.ruleId).toBe("me.model");
  });
  it("applies a model.use rule from a lock written before the rename", () => {
    const legacy = {
      id: "no.model",
      action: "model.use",
      resource: "acme/*",
      effect: "deny",
    } as unknown as PolicyRule;
    const decision = engine({
      policy: makePolicy({ enforced: [legacy] }),
    }).evaluate({ action: "model.select", resource: "acme/general" });
    expect(decision.effect).toBe("deny");
    expect(decision.ruleId).toBe("no.model");
  });
  it("drops allow rules when narrowing only", () => {
    const parsed = parseRuleList(
      [
        { id: "p.allow", action: "*", resource: "**", effect: "allow" },
        {
          id: "p.deny",
          action: "mcp.*",
          resource: "**",
          effect: "deny",
          reason: "no",
        },
      ],
      ".piship/policy.json",
      { narrowingOnly: true },
    );
    expect(parsed.rules.map((r) => r.id)).toEqual(["p.deny"]);
    expect(parsed.ignored.map((r) => r.rule.id)).toEqual(["p.allow"]);
    expect(parsed.diagnostics[0]?.message).toContain("narrowing only");
  });
  it.each([
    [{ rules: "x" }, "rules must be an array"],
    [{ other: [] }, "unknown field"],
    [
      [{ id: "a", action: "nope", resource: "*", effect: "deny" }],
      "action must be",
    ],
    [
      [{ id: "a", action: "foo.*", resource: "*", effect: "deny" }],
      "action must be",
    ],
    [
      [{ id: "", action: "*", resource: "*", effect: "deny" }],
      "non-empty string",
    ],
    [
      [{ id: "Upper", action: "*", resource: "*", effect: "deny" }],
      "rule ids use",
    ],
    [
      [{ id: "a", action: "*", resource: "", effect: "deny" }],
      "non-empty string",
    ],
    [
      [
        {
          id: "a",
          action: "*",
          resource: ["$", "{HOME}/x"].join(""),
          effect: "deny",
        },
      ],
      "runtime references",
    ],
    [
      [{ id: "a", action: "*", resource: "a\nb", effect: "deny" }],
      "control characters",
    ],
    [
      [
        {
          id: "a",
          action: "*",
          resource: "*",
          effect: "deny",
          reason: "x".repeat(241),
        },
      ],
      "at most 240",
    ],
    [[{ id: "a", action: "*", resource: "*", effect: "maybe" }], "effect must"],
    [
      [{ id: "a", action: "*", resource: "*", effect: "deny", extra: 1 }],
      "unknown field",
    ],
    [
      [{ id: "a", action: "*", resource: "*", effect: "deny", reason: 3 }],
      "non-empty string",
    ],
    [
      [
        { id: "a", action: "*", resource: "*", effect: "deny" },
        { id: "a", action: "*", resource: "*", effect: "ask" },
      ],
      "duplicate rule id",
    ],
    [["x"], "must be an object"],
  ])("rejects %j", (value, message) => {
    try {
      parseRuleList(value, "config/policy.json", { narrowingOnly: false });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(PiShipError);
      expect((error as PiShipError).code).toBe("CONFIG_INVALID");
      expect((error as PiShipError).message).toContain(message);
    }
  });
});
