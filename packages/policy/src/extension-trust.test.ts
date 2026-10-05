// The Claude Code project configuration (`.claude/*`) that an extension such as
// pi-code loads by itself: its trust dimensions and their defaults, discovery
// from the working directory up to the project root, and the one decision
// PiShip takes for it because Pi gives an extension a single trust boolean.
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  CLAUDE_TRUST_DIMENSIONS,
  type DeploymentMode,
  type ProjectDimensionEffect,
  type ProjectTrustPolicy,
} from "@piship/schema";
import { afterAll, describe, expect, it } from "vitest";
import {
  assessExtensionProjectTrust,
  readByExtensions,
} from "./extension-trust.js";
import { makePolicy } from "./fixtures.test-helpers.js";
import {
  discoverProjectResources,
  identifyProject,
  type ProjectResourceCandidate,
  projectDimensionEffect,
} from "./project.js";
import {
  claudeDimensionEffect,
  defaultClaudeDimensions,
  defaultProjectTrust,
} from "./trust.js";

const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-claude-trust-")));
afterAll(() => rmSync(base, { recursive: true, force: true }));

let counter = 0;
function dir(name: string): string {
  counter += 1;
  const path = join(base, `${name}-${counter}`);
  mkdirSync(path, { recursive: true });
  return path;
}

function write(path: string, content = "x\n"): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/** A project that carries every kind of Claude Code configuration. */
function claudeProject(name = "claude"): string {
  const root = dir(name);
  mkdirSync(join(root, ".git"));
  for (const file of [
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    ".claude/rules/x.md",
    ".claude/commands/x.md",
    ".claude/skills/x/SKILL.md",
    ".claude/agents/x.md",
    ".claude/hooks/pre.sh",
    ".claude/output-styles/terse.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
  ])
    write(join(root, file), file.endsWith(".json") ? "{}" : "text\n");
  return root;
}

/** Project trust whose company matcher claims everything under `base`. */
function trust(
  mode: DeploymentMode,
  company: Record<string, ProjectDimensionEffect> = {},
  unknown: Record<string, ProjectDimensionEffect> = {},
): ProjectTrustPolicy {
  const defaults = defaultProjectTrust(mode);
  return {
    company: {
      match: [{ path: `${base}/**` }],
      dimensions: { ...defaults.company.dimensions, ...company },
    },
    external: defaults.external,
    unknown: {
      dimensions: { ...defaults.unknown.dimensions, ...unknown },
    },
  };
}

function discover(
  root: string,
  mode: DeploymentMode,
  projectTrust: ProjectTrustPolicy,
  options: { cwd?: string; home?: string } = {},
  overrides: Parameters<typeof makePolicy>[0] = {},
) {
  const policy = makePolicy({ projectTrust, ...overrides }, mode);
  const identity = identifyProject(options.cwd ?? root, projectTrust, {
    homeDir: options.home ?? join(base, "no-home"),
  });
  const candidates = discoverProjectResources(identity, policy, {
    homeDir: options.home ?? join(base, "no-home"),
    cwd: options.cwd ?? root,
    mode,
  });
  return { policy, identity, candidates };
}

/** `[dimension, effect]` of each discovered candidate, by path under the root. */
function summary(
  candidates: readonly ProjectResourceCandidate[],
  root: string,
  kind: ProjectResourceCandidate["kind"] = "claude",
) {
  return Object.fromEntries(
    candidates
      .filter((item) => item.kind === kind)
      .map((item) => [
        item.path.slice(root.length + 1),
        [item.dimension, item.effect],
      ]),
  );
}

describe("Claude Code trust dimensions", () => {
  it("default, in personal mode, to allow for company and external projects and ask for an unknown one", () => {
    const defaults = defaultClaudeDimensions("personal");
    for (const dimension of CLAUDE_TRUST_DIMENSIONS) {
      expect(defaults.company[dimension]).toBe("allow");
      expect(defaults.external[dimension]).toBe("allow");
      expect(defaults.unknown[dimension]).toBe("ask");
    }
  });

  it("default, in managed mode, to hooks denied and the rest company-approved, which admits no project content", () => {
    const defaults = defaultClaudeDimensions("managed");
    expect(defaults.company).toEqual({
      claudeRules: "company-approved",
      claudeCommands: "company-approved",
      claudeSkills: "company-approved",
      claudeAgents: "company-approved",
      claudeHooks: "deny",
    });
    for (const dimension of CLAUDE_TRUST_DIMENSIONS) {
      expect(defaults.external[dimension]).toBe("deny");
      expect(defaults.unknown[dimension]).toBe("deny");
    }
  });

  it("are absent from the default project trust, so a lock written before they existed does not change", () => {
    for (const mode of ["managed", "personal"] as const) {
      const policy = defaultProjectTrust(mode);
      for (const origin of ["company", "external", "unknown"] as const)
        for (const dimension of CLAUDE_TRUST_DIMENSIONS)
          expect(policy[origin].dimensions).not.toHaveProperty(dimension);
    }
  });

  it("take a declared value over the default, per dimension", () => {
    const declared = trust("managed", { claudeRules: "allow" });
    const policy = makePolicy({ projectTrust: declared });
    expect(
      claudeDimensionEffect(policy, "managed", "company", "claudeRules"),
    ).toBe("allow");
    expect(
      claudeDimensionEffect(policy, "managed", "company", "claudeHooks"),
    ).toBe("deny");
    expect(
      claudeDimensionEffect(policy, "personal", "company", "claudeCommands"),
    ).toBe("allow");
  });

  it("resourceTrust.project: allow admits Claude rules while executable dimensions still require explicit trust", () => {
    const policy = makePolicy();
    const allowed = makePolicy({
      resourceTrust: { ...policy.resourceTrust, project: "allow" },
    });
    for (const dimension of ["claudeRules"] as const)
      expect(
        projectDimensionEffect(
          allowed,
          { origin: "unknown" },
          dimension,
          "managed",
        ),
      ).toBe("allow");
    for (const dimension of [
      "claudeCommands",
      "claudeSkills",
      "claudeAgents",
      "claudeHooks",
    ] as const)
      expect(
        projectDimensionEffect(
          allowed,
          { origin: "unknown" },
          dimension,
          "managed",
        ),
      ).toBe("deny");
    const denied = makePolicy({
      resourceTrust: { ...policy.resourceTrust, project: "deny" },
    });
    expect(
      projectDimensionEffect(
        denied,
        { origin: "company" },
        "claudeRules",
        "personal",
      ),
    ).toBe("deny");
  });
});

describe("discovery of Claude Code configuration", () => {
  it("finds every kind, with its own dimension, and loads nothing itself", () => {
    const root = claudeProject();
    const found = discover(root, "personal", trust("personal"));
    expect(summary(found.candidates, root)).toEqual({
      ".claude/rules": ["claudeRules", "allow"],
      ".claude/CLAUDE.md": ["claudeRules", "allow"],
      "CLAUDE.local.md": ["claudeRules", "allow"],
      ".claude/output-styles": ["claudeRules", "allow"],
      ".claude/commands": ["claudeCommands", "allow"],
      ".claude/skills": ["claudeSkills", "allow"],
      ".claude/agents": ["claudeAgents", "allow"],
      ".claude/hooks": ["claudeHooks", "allow"],
      ".claude/settings.json": ["claudeHooks", "allow"],
      ".claude/settings.local.json": ["claudeHooks", "allow"],
    });
    // The root CLAUDE.md is still an instruction file, decided as before.
    expect(summary(found.candidates, root, "instructions")).toEqual({
      "CLAUDE.md": ["instructions", "allow"],
    });
  });

  it("asks for an unknown project in personal mode, and admits nothing in managed mode by default", () => {
    const root = claudeProject();
    const personal = discover(root, "personal", {
      ...trust("personal"),
      company: {
        match: [],
        dimensions: defaultProjectTrust("personal").company.dimensions,
      },
    });
    expect(personal.identity.origin).toBe("unknown");
    for (const [, [, effect]] of Object.entries(
      summary(personal.candidates, root),
    ) as [string, [string, string]][])
      expect(effect).toBe("ask");
    const managed = discover(root, "managed", trust("managed"));
    expect(managed.identity.origin).toBe("company");
    expect(summary(managed.candidates, root)).toMatchObject({
      ".claude/rules": ["claudeRules", "deny"],
      ".claude/commands": ["claudeCommands", "deny"],
      ".claude/skills": ["claudeSkills", "deny"],
      ".claude/agents": ["claudeAgents", "deny"],
      ".claude/hooks": ["claudeHooks", "deny"],
      ".claude/settings.json": ["claudeHooks", "deny"],
    });
    expect(
      managed.candidates.find((item) => item.path.endsWith(".claude/rules"))
        ?.reason,
    ).toBe("company-approved admits only distribution-approved items");
    expect(
      managed.candidates.find((item) => item.path.endsWith(".claude/hooks"))
        ?.reason,
    ).toMatch(/denies claudeHooks/);
  });

  it("follows a manifest that declares a dimension", () => {
    const root = claudeProject();
    const found = discover(
      root,
      "managed",
      trust("managed", {
        claudeRules: "allow",
        claudeCommands: "allow",
        claudeSkills: "allow",
        claudeAgents: "allow",
        claudeHooks: "ask",
      }),
    );
    expect(summary(found.candidates, root)).toMatchObject({
      ".claude/rules": ["claudeRules", "allow"],
      ".claude/skills": ["claudeSkills", "allow"],
      ".claude/hooks": ["claudeHooks", "ask"],
      ".claude/settings.local.json": ["claudeHooks", "ask"],
    });
  });

  it("searches every directory from the working directory up to the project root, and no further", () => {
    const root = dir("monorepo");
    mkdirSync(join(root, ".git"));
    write(join(root, ".claude", "commands", "root.md"));
    write(join(root, "packages", "app", ".claude", "rules", "app.md"));
    write(join(root, "packages", "app", "src", ".claude", "hooks", "h.sh"));
    write(join(root, "packages", "other", ".claude", "agents", "o.md"));
    const nested = join(root, "packages", "app", "src");
    const found = discover(root, "personal", trust("personal"), {
      cwd: nested,
    });
    expect(Object.keys(summary(found.candidates, root)).sort()).toEqual([
      ".claude/commands",
      "packages/app/.claude/rules",
      "packages/app/src/.claude/hooks",
    ]);
    // Without a working directory only the root is searched.
    const rootOnly = discoverProjectResources(found.identity, found.policy, {
      homeDir: join(base, "no-home"),
      mode: "personal",
    });
    expect(Object.keys(summary(rootOnly, root))).toEqual([".claude/commands"]);
  });

  it("leaves the user's home directory out: its .claude is the user's own, not the project's", () => {
    const home = dir("home");
    write(join(home, ".claude", "settings.json"), "{}");
    write(join(home, ".claude", "agents", "mine.md"));
    const found = discover(home, "managed", trust("managed"), { home });
    expect(summary(found.candidates, home)).toEqual({});
    expect(
      assessExtensionProjectTrust(found.candidates, {
        policy: found.policy,
        identity: found.identity,
        mode: "managed",
      }).surfaces,
    ).toEqual([]);
  });

  it("denies executable configuration that links outside the project, and a link inside a directory that leaves it", () => {
    const outside = dir("outside");
    write(join(outside, "evil.sh"));
    const root = dir("linked");
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, ".claude"));
    symlinkSync(outside, join(root, ".claude", "hooks"), "dir");
    write(join(root, ".claude", "commands", "ok.md"));
    symlinkSync(
      join(outside, "evil.sh"),
      join(root, ".claude", "commands", "link.md"),
    );
    const found = discover(root, "personal", trust("personal"));
    const hooks = found.candidates.find((item) =>
      item.path.endsWith(".claude/hooks"),
    );
    expect(hooks).toMatchObject({ effect: "deny", origin: "unknown" });
    expect(hooks?.reason).toMatch(/executable claudeHooks/);
    const commands = found.candidates.find((item) =>
      item.path.endsWith(".claude/commands"),
    );
    expect(commands?.effect).toBe("deny");
    expect(commands?.reason).toMatch(
      /contains a link that leaves the project root/,
    );
  });

  it("reports a dangling link so it cannot hide", () => {
    const root = dir("dangling");
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, ".claude"));
    symlinkSync(join(root, "missing"), join(root, ".claude", "skills"));
    const found = discover(root, "personal", trust("personal"));
    expect(
      found.candidates.find((item) => item.path.endsWith(".claude/skills")),
    ).toMatchObject({
      effect: "deny",
      reason: "The candidate is a dangling link",
    });
  });

  it("discovers the files an extension reads beside them, which PiShip never loads", () => {
    const root = dir("extension-config");
    mkdirSync(join(root, ".git"));
    write(join(root, ".pi", "mcp.json"), "{}");
    write(join(root, ".mcp.json"), "{}");
    write(join(root, ".pi", "agents", "a.md"));
    write(join(root, "packages", "app", ".mcp.json"), "{}");
    write(join(root, "packages", "app", ".pi", "mcp.json"), "{}");
    write(join(root, "packages", "app", ".pi", "agents", "b.md"));
    const found = discover(root, "managed", trust("managed"), {
      cwd: join(root, "packages", "app"),
    });
    // The root's `.mcp.json` and `.pi/agents` keep their own kinds: PiShip
    // uses (or ignores) them as before.
    expect(summary(found.candidates, root, "mcp")).toEqual({
      ".mcp.json": ["mcp", "company-approved"],
    });
    expect(summary(found.candidates, root, "agents")).toEqual({
      ".pi/agents": ["agents", "deny"],
    });
    expect(summary(found.candidates, root, "extension-config")).toEqual({
      ".pi/mcp.json": ["mcp", "company-approved"],
      "packages/app/.pi/mcp.json": ["mcp", "company-approved"],
      "packages/app/.mcp.json": ["mcp", "company-approved"],
      "packages/app/.pi/agents": ["agents", "deny"],
    });
    expect(
      found.candidates.filter((item) => readByExtensions(item)),
    ).toHaveLength(6);
  });
});

describe("the decision for what an extension loads from the project", () => {
  function assess(
    root: string,
    mode: DeploymentMode,
    projectTrust: ProjectTrustPolicy,
    overrides: Parameters<typeof makePolicy>[0] = {},
  ) {
    const found = discover(root, mode, projectTrust, {}, overrides);
    return assessExtensionProjectTrust(found.candidates, {
      policy: found.policy,
      identity: found.identity,
      mode,
    });
  }

  it("is allowed when every item found is admitted", () => {
    const root = claudeProject();
    const result = assess(root, "personal", trust("personal"));
    expect(result.effect).toBe("allow");
    expect(result.surfaces).toHaveLength(10);
  });

  it("asks once for the whole when an item asks", () => {
    const root = claudeProject();
    const result = assess(
      root,
      "personal",
      trust("personal", { claudeHooks: "ask" }),
    );
    expect(result.effect).toBe("ask");
    expect(result.decidedBy?.dimension).toBe("claudeHooks");
  });

  it("is denied when one item is, naming it: the configuration is admitted as a unit", () => {
    const root = claudeProject();
    const result = assess(
      root,
      "personal",
      trust("personal", { claudeHooks: "deny" }),
    );
    expect(result.effect).toBe("deny");
    expect(result.decidedBy?.path).toMatch(/\.claude\/(hooks|settings)/);
    expect(result.reason).toMatch(/denies claudeHooks/);
  });

  it("is denied in managed mode by default: company-approved admits no project content", () => {
    const root = claudeProject();
    const result = assess(root, "managed", trust("managed"));
    expect(result.effect).toBe("deny");
    expect(result.reason).toMatch(/company-approved admits only/);
  });

  it("lets a company approve rules, commands, skills, and agents while denying hooks, but only for a project without hooks or settings", () => {
    const company = {
      claudeRules: "allow",
      claudeCommands: "allow",
      claudeSkills: "allow",
      claudeAgents: "allow",
    } as const;
    const root = dir("approved");
    mkdirSync(join(root, ".git"));
    write(join(root, ".claude", "rules", "r.md"));
    write(join(root, ".claude", "skills", "s", "SKILL.md"));
    expect(assess(root, "managed", trust("managed", company)).effect).toBe(
      "allow",
    );
    write(join(root, ".claude", "settings.json"), "{}");
    const withSettings = assess(root, "managed", trust("managed", company));
    expect(withSettings.effect).toBe("deny");
    expect(withSettings.decidedBy?.path).toMatch(/settings\.json$/);
  });

  it("covers the project MCP and agent files an extension also reads", () => {
    const root = dir("mcp");
    mkdirSync(join(root, ".git"));
    write(join(root, ".claude", "rules", "r.md"));
    write(join(root, ".mcp.json"), "{}");
    const allClaude = {
      claudeRules: "allow",
      claudeCommands: "allow",
      claudeSkills: "allow",
      claudeAgents: "allow",
      claudeHooks: "allow",
    } as const;
    // `.mcp.json` is company-approved by default in managed mode: only an
    // allowlist of servers may start, which an extension's own client ignores.
    const denied = assess(root, "managed", trust("managed", allClaude));
    expect(denied.effect).toBe("deny");
    expect(denied.decidedBy?.kind).toBe("mcp");
    const admitted = assess(
      root,
      "managed",
      trust("managed", { ...allClaude, mcp: "allow" }),
    );
    expect(admitted.effect).toBe("allow");
    write(join(root, ".pi", "agents", "a.md"));
    expect(
      assess(root, "managed", trust("managed", { ...allClaude, mcp: "allow" }))
        .decidedBy?.kind,
    ).toBe("agents");
  });

  it("denies a project with nothing found in managed mode unless every Claude dimension is admitted", () => {
    const root = dir("empty");
    mkdirSync(join(root, ".git"));
    const byDefault = assess(root, "managed", trust("managed"));
    expect(byDefault).toMatchObject({ effect: "deny", surfaces: [] });
    expect(byDefault.reason).toMatch(/does not admit claudeRules/);
    const rulesOnly = assess(
      root,
      "managed",
      trust("managed", { claudeRules: "allow" }),
    );
    expect(rulesOnly.reason).toMatch(/does not admit claudeCommands/);
    const all = assess(
      root,
      "managed",
      trust("managed", {
        claudeRules: "allow",
        claudeCommands: "allow",
        claudeSkills: "allow",
        claudeAgents: "allow",
        claudeHooks: "allow",
      }),
    );
    expect(all).toMatchObject({ effect: "allow", surfaces: [] });
  });

  it("allows a project with nothing found in personal mode", () => {
    const root = dir("empty-personal");
    mkdirSync(join(root, ".git"));
    expect(assess(root, "personal", trust("personal")).effect).toBe("allow");
  });

  it("denies everything when resourceTrust.project is deny", () => {
    const root = claudeProject();
    const policy = makePolicy({}, "personal");
    const result = assess(root, "personal", trust("personal"), {
      resourceTrust: { ...policy.resourceTrust, project: "deny" },
    });
    expect(result.effect).toBe("deny");
  });
});
