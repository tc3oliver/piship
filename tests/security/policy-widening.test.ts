import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PolicyAction, PolicyEffect } from "@piship/contracts";
import {
  defaultProjectTrust,
  defaultProviderTrust,
  defaultResourceTrust,
  NO_CONTAINMENT,
  type PolicyContext,
  PolicyEngine,
} from "@piship/policy";
import type { PolicyConfig, PolicyRule } from "@piship/schema";
import { afterAll, describe, expect, it } from "vitest";

// Security case 8 (spec 30.3), policy widening, at the policy engine that
// decides every governed action. A team, project, or user rule can only make a
// decision stricter than the distribution's own (enforced and default) rules;
// in personal mode a user rule may take the place of a default but never of an
// enforced rule. The launcher-level counterpart, with real tool calls that a
// widening team, project, and user rule fail to unlock, is
// tests/e2e/security-controls.test.ts.

const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-widening-")));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const context: PolicyContext = {
  workspaceRoot: join(base, "work"),
  homeDir: join(base, "home"),
  tmpDir: join(base, "tmp"),
  containment: NO_CONTAINMENT,
};

const RANK: Record<PolicyEffect, number> = { allow: 0, ask: 1, deny: 2 };
const strictest = (...effects: (PolicyEffect | undefined)[]): PolicyEffect =>
  effects.reduce<PolicyEffect>(
    (result, effect) =>
      effect && RANK[effect] > RANK[result] ? effect : result,
    "allow",
  );

const EFFECTS: readonly PolicyEffect[] = ["allow", "ask", "deny"];
const OPTIONAL: readonly (PolicyEffect | undefined)[] = [undefined, ...EFFECTS];

function policy(
  fallback: PolicyEffect,
  enforced: PolicyRule[],
  defaults: PolicyRule[],
): PolicyConfig {
  return {
    id: "acme-engineering",
    version: 1,
    default: fallback,
    enforced,
    defaults,
    resourceTrust: defaultResourceTrust("managed"),
    providerTrust: defaultProviderTrust("managed"),
    projectTrust: defaultProjectTrust("managed"),
  };
}

const rules = (
  id: string,
  action: PolicyAction,
  effect: PolicyEffect | undefined,
): PolicyRule[] =>
  effect === undefined ? [] : [{ id, action, resource: "**", effect }];

// One request per family of action the layers decide: a model, a shell
// command, a file, and an MCP tool.
const REQUESTS: readonly { action: PolicyAction; resource: string }[] = [
  { action: "model.use", resource: "acme/coder" },
  { action: "shell.execute", resource: "git status" },
  { action: "filesystem.read", resource: "src/index.ts" },
  { action: "mcp.tool.call", resource: "docs:delete_document" },
];

/**
 * Every combination of a fallback, an enforced rule, a default rule, and a
 * team, project, and user rule (each absent, allow, ask, or deny) for one
 * request, with the decision the engine made and the floor the distribution
 * alone sets.
 */
function everyCombination(
  request: (typeof REQUESTS)[number],
  userRuleMode: "narrowing" | "replace-default",
) {
  const results: {
    label: string;
    decided: PolicyEffect;
    enforced: PolicyEffect | undefined;
    distribution: PolicyEffect;
  }[] = [];
  for (const fallback of EFFECTS)
    for (const enforced of OPTIONAL)
      for (const dflt of OPTIONAL)
        for (const team of OPTIONAL)
          for (const project of OPTIONAL)
            for (const user of OPTIONAL) {
              const engine = new PolicyEngine({
                policy: policy(
                  fallback,
                  rules("enforced", request.action, enforced),
                  rules("default", request.action, dflt),
                ),
                teamRules: rules("team", request.action, team),
                projectRules: rules("project", request.action, project),
                userRules: rules("user", request.action, user),
                userRuleMode,
                context,
              });
              results.push({
                label: JSON.stringify({
                  fallback,
                  enforced,
                  dflt,
                  team,
                  project,
                  user,
                }),
                decided: engine.evaluate(request).effect,
                enforced,
                distribution: strictest(enforced, dflt ?? fallback),
              });
            }
  return results;
}

describe("no combination of layers below the distribution widens its decision", () => {
  for (const request of REQUESTS) {
    it(`${request.action}: managed mode, where user, project, and team rules only narrow`, () => {
      const results = everyCombination(request, "narrowing");
      expect(results).toHaveLength(3 * 4 * 4 * 4 * 4 * 4);
      // What the distribution alone decides is the floor.
      for (const { label, decided, distribution } of results)
        expect(RANK[decided], label).toBeGreaterThanOrEqual(RANK[distribution]);
    });

    it(`${request.action}: personal mode, where a user rule replaces a default and never an enforced rule`, () => {
      const results = everyCombination(request, "replace-default");
      expect(results).toHaveLength(3 * 4 * 4 * 4 * 4 * 4);
      for (const { label, decided, enforced } of results)
        expect(RANK[decided], label).toBeGreaterThanOrEqual(
          RANK[enforced ?? "allow"],
        );
    });
  }
});

/**
 * A rule's resource as a file rule names it, and what of the three requests
 * below it covers. A narrower rule of a lower layer under a broader rule of
 * the distribution (and the reverse) is where widening through specificity
 * would show; a matrix of rules that all say `**` cannot see it.
 */
const PATTERNS: readonly {
  glob: string;
  covers: (resource: string) => boolean;
}[] = [
  { glob: "workspace/**", covers: () => true },
  {
    glob: "workspace/private/**",
    covers: (resource) => resource.startsWith("private/"),
  },
  {
    glob: "workspace/private/key.txt",
    covers: (resource) => resource === "private/key.txt",
  },
];
const FILES = ["private/key.txt", "private/other.txt", "notes.txt"];

/** One slot of the matrix: absent, or an effect on one of the patterns. */
const SLOTS: readonly ({
  effect: PolicyEffect;
  pattern: (typeof PATTERNS)[number];
} | null)[] = [
  null,
  ...EFFECTS.flatMap((effect) =>
    PATTERNS.map((pattern) => ({ effect, pattern })),
  ),
];
type Slot = (typeof SLOTS)[number];

const slotRules = (id: string, slot: Slot): PolicyRule[] =>
  slot
    ? [
        {
          id,
          action: "filesystem.read",
          resource: slot.pattern.glob,
          effect: slot.effect,
        },
      ]
    : [];
const slotEffect = (slot: Slot, file: string): PolicyEffect | undefined =>
  slot?.pattern.covers(file) ? slot.effect : undefined;

describe("a rule that names less or more than the distribution's does not widen its decision", () => {
  // One lower layer's rule at a time (the combinations of several layers are
  // the matrix above); each against every enforced and default rule.
  for (const mode of ["narrowing", "replace-default"] as const)
    for (const layer of ["team", "user"] as const)
      it(`${mode === "narrowing" ? "managed" : "personal"} mode: a ${layer} rule over a broad, a directory and a file resource, against every enforced and default rule`, () => {
        let combinations = 0;
        for (const enforced of SLOTS)
          for (const dflt of SLOTS)
            for (const lower of SLOTS) {
              const engine = new PolicyEngine({
                policy: policy(
                  "ask",
                  slotRules("enforced", enforced),
                  slotRules("default", dflt),
                ),
                ...(layer === "team"
                  ? { teamRules: slotRules("team", lower) }
                  : { userRules: slotRules("user", lower) }),
                userRuleMode: mode,
                context,
              });
              for (const file of FILES) {
                const decided = engine.evaluate({
                  action: "filesystem.read",
                  resource: file,
                }).effect;
                // What the distribution alone decides for this file is the
                // floor (in personal mode only what it enforces).
                const enforcedHere = slotEffect(enforced, file);
                const floor =
                  mode === "narrowing"
                    ? strictest(enforcedHere, slotEffect(dflt, file) ?? "ask")
                    : (enforcedHere ?? "allow");
                expect(
                  RANK[decided],
                  JSON.stringify({ file, enforced, dflt, lower, decided }),
                ).toBeGreaterThanOrEqual(RANK[floor]);
              }
              combinations += 1;
            }
        expect(combinations).toBe(SLOTS.length ** 3);
      });

  // The team rules and the project rules are one layer, and a layer takes the
  // strictest of its matching rules, so a team `ask` does not hide a project
  // `deny` for the same request.
  it("does not let a team ask hide a project deny for the same request", () => {
    const request = { action: "shell.execute", resource: "git push" } as const;
    const engine = new PolicyEngine({
      policy: policy("allow", [], []),
      teamRules: rules("team", request.action, "ask"),
      projectRules: rules("project", request.action, "deny"),
      userRuleMode: "narrowing",
      context,
    });
    expect(engine.evaluate(request).effect).toBe("deny");
    // The control: the project's deny applies on its own too.
    const alone = new PolicyEngine({
      policy: policy("allow", [], []),
      projectRules: rules("project", request.action, "deny"),
      userRuleMode: "narrowing",
      context,
    });
    expect(alone.evaluate(request).effect).toBe("deny");
  });
});

describe("a path cannot be spelled around an enforced deny", () => {
  const home = context.homeDir;
  const secret = join(home, ".ssh", "id_rsa");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  writeFileSync(secret, "not a real key\n");
  mkdirSync(context.workspaceRoot, { recursive: true });
  symlinkSync(secret, join(context.workspaceRoot, "innocent-looking.txt"));
  symlinkSync(join(home, ".ssh"), join(context.workspaceRoot, "dotdir"));
  // A user rule allows everything, and takes the default's place.
  const engine = new PolicyEngine({
    policy: policy(
      "allow",
      [
        {
          id: "acme.secrets.read",
          action: "filesystem.read",
          resource: "~/.ssh/**",
          effect: "deny",
        },
      ],
      [],
    ),
    userRules: [
      {
        id: "me.all",
        action: "filesystem.read",
        resource: "**",
        effect: "allow",
      },
    ],
    userRuleMode: "replace-default",
    context,
  });
  const decide = (resource: string) =>
    engine.evaluate({ action: "filesystem.read", resource });

  it("allows a file that is not enforced against, so the deny below is the rule's", () => {
    expect(decide(join(context.workspaceRoot, "notes.txt")).effect).toBe(
      "allow",
    );
  });

  it.each([
    ["the plain path", secret],
    ["dot segments", join(home, "work", "..", ".ssh", ".", "id_rsa")],
    ["a doubled separator", secret.replace("/.ssh/", "//.ssh//")],
    ["a symlink to the file", "innocent-looking.txt"],
    ["a symlink to its directory", "dotdir/id_rsa"],
    ["a path that climbs out of the workspace", "../home/.ssh/id_rsa"],
  ])("denies %s, whatever a user rule allows", (_name, resource) => {
    const decision = decide(resource);
    expect(decision.effect).toBe("deny");
    expect(decision.ruleId).toBe("acme.secrets.read");
  });

  // A case-insensitive filesystem (the macOS and Windows default) opens the
  // same file under another spelling. The policy decides on the canonical
  // spelling, so the spelling is no way around it.
  const caseInsensitive = existsSync(join(home, ".SSH", "ID_RSA"));
  it.runIf(caseInsensitive)(
    "denies the same file under another letter case on a case-insensitive filesystem",
    () => {
      expect(decide(join(home, ".SSH", "ID_RSA")).effect).toBe("deny");
      expect(decide(join(home, ".Ssh", "Id_Rsa")).ruleId).toBe(
        "acme.secrets.read",
      );
    },
  );
});
