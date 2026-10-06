// A project that ships Claude Code configuration (CLAUDE.md, `.claude/rules`,
// `commands`, `skills`, `agents`, `hooks`) and a distribution that carries an
// extension which loads it (pi-code). PiShip decides, from policy, whether that
// configuration is trusted, and hands the decision to Pi's trust seam, so a
// project can never admit its own configuration under company policy.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ProjectTrustStore } from "@earendil-works/pi-coding-agent";
import type {
  ApprovalChannel,
  AuditEvent,
  ManagedFetch,
} from "@piship/contracts";
import { PI_VERSION, resolveLock } from "@piship/core";
import { toPosixPath } from "@piship/policy";
import { afterEach, describe, expect, it } from "vitest";
import { resolveProject } from "./governance/project.js";
import { loadPackageFiles } from "./governance/resources.js";
import { GovernanceSession } from "./governance-session.js";
import { gatePath } from "./governed-tools.js";
import { sessionProjectTrust } from "./launch/project-trust.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** What a repository that already works with Claude Code holds. */
const CLAUDE_FILES = [
  "CLAUDE.md",
  ".claude/CLAUDE.md",
  ".claude/rules/style.md",
  ".claude/commands/review.md",
  ".claude/skills/release/SKILL.md",
  ".claude/agents/reviewer.md",
  ".claude/hooks/pre-tool.sh",
  ".claude/settings.json",
];
const CLAUDE_PATHS = [
  ".claude/rules",
  ".claude/commands",
  ".claude/skills",
  ".claude/agents",
  ".claude/hooks",
  ".claude/settings.json",
  ".claude/CLAUDE.md",
];
const ALL_ALLOW = [
  "claudeRules: allow",
  "claudeCommands: allow",
  "claudeSkills: allow",
  "claudeAgents: allow",
  "claudeHooks: allow",
];

async function open(
  options: {
    readonly mode?: "managed" | "personal";
    /** Lines under `projectTrust.company` (the workspace is a company project). */
    readonly company?: readonly string[];
    /** Lines under `projectTrust.unknown`; the workspace is not matched. */
    readonly unknown?: readonly string[];
    readonly unmatched?: boolean;
    /** Extra lines under `policy`, such as enforced rules. */
    readonly policy?: readonly string[];
    readonly defaultEffect?: "allow" | "deny" | "ask";
    readonly files?: readonly string[];
    readonly subdirectory?: string;
    readonly answer?: "approved" | "denied";
    readonly headless?: boolean;
    readonly sandboxRequired?: boolean;
  } = {},
) {
  // The project root is resolved through links, as the matcher sees it.
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-project-trust-")),
  );
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  mkdirSync(distribution, { recursive: true });
  mkdirSync(join(workspace, ".git"), { recursive: true });
  for (const file of options.files ?? CLAUDE_FILES) {
    mkdirSync(dirname(join(workspace, file)), { recursive: true });
    writeFileSync(
      join(workspace, file),
      file.endsWith(".json") ? "{}\n" : "text\n",
    );
  }
  const cwd = options.subdirectory
    ? join(workspace, options.subdirectory)
    : workspace;
  mkdirSync(cwd, { recursive: true });
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      `runtime: { pi: "${PI_VERSION}" }`,
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      `  default: ${options.defaultEffect ?? "allow"}`,
      ...(options.policy ?? []),
      "  projectTrust:",
      "    company:",
      ...(options.unmatched
        ? ["      match: []"]
        : [`      match: [{ path: "${toPosixPath(workspace)}/**" }]`]),
      ...(options.company ?? []).map((line) => `      ${line}`),
      ...(options.unknown?.length
        ? ["    unknown:", ...options.unknown.map((line) => `      ${line}`)]
        : []),
      ...(options.sandboxRequired
        ? [
            "sandbox:",
            "  required: true",
            "  filesystem: { read: { deny: [] }, write: { allow: [workspace, tmp] } }",
            "  network: { mode: allow }",
            "  environment: { allow: [PATH] }",
          ]
        : []),
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  const lock = options.mode
    ? {
        ...resolved,
        deployment: { ...resolved.deployment, mode: options.mode },
      }
    : resolved;
  const prompts: { title: string; message: string }[] = [];
  const answer = options.answer ?? "approved";
  const startupApproval: ApprovalChannel = async (_decision, detail) => {
    prompts.push(detail);
    return answer;
  };
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd,
    piVersion: PI_VERSION,
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
    user: "alice",
    ...(options.headless ? {} : { startupApproval }),
  });
  sessions.push(session);
  const notices: string[] = [];
  session.attachNotices((message) => notices.push(message));
  const events = async () => {
    await session.audit.flush();
    return readFileSync(join(root, "state", "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  };
  const claude = () =>
    session.resources.filter(
      (item) => item.class === "project" && item.kind === "claude",
    );
  return { session, workspace, cwd, root, prompts, notices, events, claude };
}

describe("personal mode", () => {
  it("admits the Claude Code configuration of a company project without a prompt", async () => {
    const { session, prompts, claude, events } = await open();
    expect(prompts).toEqual([]);
    expect(session.projectTrust).toMatchObject({ trusted: true });
    expect(session.projectTrust.surfaces).toBeGreaterThanOrEqual(
      CLAUDE_PATHS.length,
    );
    expect(
      claude()
        .map((item) => item.path)
        .sort(),
    ).toEqual(expect.arrayContaining(CLAUDE_PATHS));
    for (const item of claude()) expect(item.loaded).toBe(true);
    const audit = await events();
    const loaded = audit
      .filter((event) => event.event === "resource.load")
      .map((event) => event.resource);
    for (const path of CLAUDE_PATHS)
      expect(loaded).toContain(`project:${path}`);
    expect(
      audit.find(
        (event) =>
          event.event === "resource.load" &&
          event.resource === "project:.claude",
      ),
    ).toMatchObject({
      detail: { kind: "claude", class: "project", seam: "project-trust" },
    });
  });

  it("still loads the root CLAUDE.md as an instruction file, as before", async () => {
    const { session } = await open();
    expect(session.loader.instructions.map((item) => item.path)).toEqual([
      expect.stringMatching(/workspace\/CLAUDE\.md$/),
    ]);
  });

  it("asks once, for the whole configuration, when the project is not known", async () => {
    const { session, prompts, claude } = await open({ unmatched: true });
    expect(prompts).toHaveLength(1);
    expect(prompts[0]?.title).toBe("Project Claude Code configuration");
    for (const path of CLAUDE_PATHS)
      expect(prompts[0]?.message).toContain(path);
    expect(session.projectTrust.trusted).toBe(true);
    for (const item of claude()) expect(item.loaded).toBe(true);
  });

  it("leaves all of it unloaded when the person declines, and says so", async () => {
    const { session, claude, events, notices } = await open({
      unmatched: true,
      answer: "denied",
    });
    expect(session.projectTrust).toMatchObject({
      trusted: false,
      reason: "project trust: denied",
    });
    for (const item of claude()) expect(item.loaded).toBe(false);
    expect(claude().every((item) => item.reason.length > 0)).toBe(true);
    const audit = await events();
    expect(
      audit.find(
        (event) =>
          event.event === "resource.denied" &&
          event.resource === "project:.claude",
      ),
    ).toBeDefined();
    expect(notices.join("\n")).toMatch(
      /Project Claude Code configuration .* is not loaded: project trust: denied/,
    );
  });

  it("denies, rather than ask, when nobody can answer", async () => {
    const { session } = await open({ unmatched: true, headless: true });
    expect(session.projectTrust.trusted).toBe(false);
  });

  it("admits it as a unit: one denied item leaves every item unloaded", async () => {
    const { session, claude } = await open({
      company: ["claudeHooks: deny"],
    });
    expect(session.projectTrust.trusted).toBe(false);
    const hooks = claude().find((item) => item.path === ".claude/hooks");
    expect(hooks).toMatchObject({ loaded: false });
    expect(hooks?.reason).toMatch(/denies claudeHooks/);
    const rules = claude().find((item) => item.path === ".claude/rules");
    expect(rules?.loaded).toBe(false);
    expect(rules?.reason).toMatch(/admitted as a unit/);
  });

  it("asks nothing and is trusted when the project has no such configuration", async () => {
    const { session, prompts, events } = await open({
      unmatched: true,
      files: ["README.md"],
    });
    expect(prompts).toEqual([]);
    expect(session.projectTrust).toMatchObject({ trusted: true, surfaces: 0 });
    const audit = await events();
    expect(
      audit.filter((event) => event.resource === "project:.claude"),
    ).toEqual([]);
  });

  it("applies a policy rule to each item: a distribution rule can narrow what a dimension admits", async () => {
    const { session, claude } = await open({
      policy: [
        "  enforced:",
        "    - { id: no-hooks, action: resource.load, resource: 'project:.claude/hooks', effect: deny, reason: No project hooks }",
      ],
    });
    expect(session.projectTrust.trusted).toBe(false);
    expect(session.projectTrust.reason).toBe("policy no-hooks");
    for (const item of claude()) expect(item.loaded).toBe(false);
  });

  it("also covers the project MCP and agent files an extension reads, at every level", async () => {
    const root = await open({
      files: [...CLAUDE_FILES, ".mcp.json"],
      company: ["mcp: deny"],
    });
    expect(root.session.projectTrust.trusted).toBe(false);
    expect(root.session.projectTrust.reason).toMatch(/\.mcp\.json/);
    for (const item of root.claude()) expect(item.loaded).toBe(false);
    // Below the root, where an extension finds the nearest file first.
    const nested = await open({
      files: [".claude/rules/r.md", "packages/app/.pi/mcp.json"],
      subdirectory: "packages/app",
      company: ["mcp: deny"],
    });
    expect(nested.session.projectTrust.trusted).toBe(false);
    expect(nested.session.projectTrust.reason).toMatch(
      /packages\/app\/\.pi\/mcp\.json/,
    );
    const extension = nested.session.resources.find(
      (item) => item.kind === "extension-config",
    );
    expect(extension).toMatchObject({ loaded: false });
  });

  it("finds configuration in every directory from the working directory up to the project root", async () => {
    const { session, claude } = await open({
      files: [".claude/commands/root.md", "packages/app/.claude/rules/app.md"],
      subdirectory: "packages/app",
    });
    expect(
      claude()
        .map((item) => item.path)
        .sort(),
    ).toEqual([".claude/commands", "packages/app/.claude/rules"]);
    expect(session.projectTrust.trusted).toBe(true);
  });
});

describe("managed mode", () => {
  it("loads none of it unless the company approves: company-approved admits no project content", async () => {
    const { session, claude, events } = await open({ mode: "managed" });
    expect(session.projectTrust.trusted).toBe(false);
    expect(session.projectTrust.reason).toMatch(
      /company-approved admits only distribution-approved items|denies claudeHooks/,
    );
    for (const item of claude()) expect(item.loaded).toBe(false);
    const audit = await events();
    expect(
      audit.filter(
        (event) =>
          event.event === "resource.load" &&
          String(event.resource).startsWith("project:.claude"),
      ),
    ).toEqual([]);
    expect(
      audit.filter(
        (event) =>
          event.event === "resource.denied" &&
          String(event.resource).startsWith("project:.claude"),
      ).length,
    ).toBeGreaterThan(CLAUDE_PATHS.length);
  });

  it("never lets the project admit itself: an unknown project is denied, with no prompt", async () => {
    const { session, prompts } = await open({
      mode: "managed",
      unmatched: true,
    });
    expect(prompts).toEqual([]);
    expect(session.projectTrust.trusted).toBe(false);
  });

  it("admits the configuration when the company approves each dimension and policy allows the load", async () => {
    const { session, claude, prompts } = await open({
      mode: "managed",
      company: ALL_ALLOW,
      defaultEffect: "deny",
      policy: [
        "  defaults:",
        "    - { id: project-claude, action: resource.load, resource: 'project:.claude/**', effect: allow }",
      ],
    });
    expect(prompts).toEqual([]);
    expect(session.projectTrust.trusted).toBe(true);
    for (const item of claude()) expect(item.loaded).toBe(true);
  });

  it("keeps policy as a second gate: approved dimensions are still denied by policy.default", async () => {
    const { session } = await open({
      mode: "managed",
      company: ALL_ALLOW,
      defaultEffect: "deny",
    });
    expect(session.projectTrust.trusted).toBe(false);
    expect(session.projectTrust.reason).toMatch(/^policy /);
  });

  it("fails closed for a project with no configuration unless every dimension is approved", async () => {
    const empty = await open({ mode: "managed", files: ["README.md"] });
    expect(empty.session.projectTrust).toMatchObject({
      trusted: false,
      surfaces: 0,
    });
    expect(empty.session.projectTrust.reason).toMatch(/does not admit claude/);
    const approved = await open({
      mode: "managed",
      files: ["README.md"],
      company: ALL_ALLOW,
    });
    expect(approved.session.projectTrust).toMatchObject({
      trusted: true,
      surfaces: 0,
    });
  });
});

describe("the doctor view", () => {
  it("reports the static decision, before any approval", async () => {
    const { inspectGovernance } = await import("./governance-session.js");
    const { session } = await open({ unmatched: true });
    const inspection = await inspectGovernance(session.options);
    expect(inspection.extensionTrust.effect).toBe("ask");
    const managed = await open({ mode: "managed" });
    expect(
      (await inspectGovernance(managed.session.options)).extensionTrust,
    ).toMatchObject({ effect: "deny" });
  });
});

describe("Pi's trust seam", () => {
  function stub(
    decision: GovernanceSession["projectTrust"],
    cwd: string,
    emitted: unknown[] = [],
    notices: string[] = [],
  ) {
    return {
      projectTrust: decision,
      options: { cwd },
      emit: (event: string, fields: unknown) => emitted.push([event, fields]),
      notice: (message: string) => notices.push(message),
    } as unknown as GovernanceSession;
  }

  function directory() {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-trust-seam-")),
    );
    roots.push(root);
    const cwd = join(root, "project");
    mkdirSync(cwd, { recursive: true });
    return { cwd, agentDir: join(root, "agent") };
  }

  const trusted = { trusted: true, surfaces: 3, reason: "ok" };
  const denied = { trusted: false, surfaces: 3, reason: "denied" };

  it("keeps Pi's default for an ungoverned distribution and writes nothing", () => {
    const { cwd, agentDir } = directory();
    expect(sessionProjectTrust(null, cwd, agentDir)).toBe(true);
    expect(new ProjectTrustStore(agentDir).get(cwd)).toBeNull();
  });

  it("records an approval where an extension would otherwise ask the person", () => {
    const { cwd, agentDir } = directory();
    expect(sessionProjectTrust(stub(trusted, cwd), cwd, agentDir)).toBe(true);
    expect(new ProjectTrustStore(agentDir).get(cwd)).toBe(true);
  });

  it("writes nothing when the project holds nothing PiShip decided on", () => {
    const { cwd, agentDir } = directory();
    const none = { trusted: true, surfaces: 0, reason: "none" };
    expect(sessionProjectTrust(stub(none, cwd), cwd, agentDir)).toBe(true);
    expect(new ProjectTrustStore(agentDir).get(cwd)).toBeNull();
  });

  it("withdraws an earlier approval when the project is no longer trusted", () => {
    const { cwd, agentDir } = directory();
    new ProjectTrustStore(agentDir).set(cwd, true);
    expect(sessionProjectTrust(stub(denied, cwd), cwd, agentDir)).toBe(false);
    expect(new ProjectTrustStore(agentDir).get(cwd)).toBe(false);
  });

  it("preserves a personal refusal even when policy admits the project", () => {
    const { cwd, agentDir } = directory();
    new ProjectTrustStore(agentDir).set(cwd, false);
    const gov = stub(trusted, cwd);
    Object.assign(gov.options, { lock: { deployment: { mode: "personal" } } });
    expect(sessionProjectTrust(gov, cwd, agentDir)).toBe(false);
    expect(new ProjectTrustStore(agentDir).get(cwd)).toBe(false);
  });

  it("does not trust a session whose directory is not the project the launch decided on", () => {
    const { cwd, agentDir } = directory();
    const other = join(dirname(cwd), "elsewhere");
    mkdirSync(other);
    const emitted: unknown[] = [];
    const notices: string[] = [];
    expect(
      sessionProjectTrust(
        stub(trusted, cwd, emitted, notices),
        other,
        agentDir,
      ),
    ).toBe(false);
    expect(emitted).toEqual([
      [
        "resource.denied",
        expect.objectContaining({
          resource: "project:.claude",
          detail: expect.objectContaining({ reason: "session-directory" }),
        }),
      ],
    ]);
    expect(notices).toHaveLength(1);
    expect(new ProjectTrustStore(agentDir).get(other)).toBeNull();
  });

  it("reports the project untrusted when an approval cannot be recorded, rather than leave the extension to ask", () => {
    const { cwd, agentDir } = directory();
    // A file where the agent directory should be.
    writeFileSync(agentDir, "not a directory");
    const notices: string[] = [];
    expect(
      sessionProjectTrust(stub(trusted, cwd, [], notices), cwd, agentDir),
    ).toBe(false);
    expect(notices.join()).toMatch(/could not be recorded/);
    // A denial needs no record: the flag alone closes the extension.
    expect(sessionProjectTrust(stub(denied, cwd), cwd, agentDir)).toBe(false);
  });
});

describe("managed executable configuration writes", () => {
  it("denies planting absent settings, hooks, agents and replacing ancestors while ordinary source stays writable", async () => {
    const { session, workspace } = await open({
      mode: "managed",
      company: ["claudeRules: allow", "claudeHooks: deny"],
      files: [".claude/rules/style.md"],
      subdirectory: "packages/app",
    });
    for (const path of [
      ".claude/settings.json",
      ".claude/settings.local.json",
      ".claude/hooks/run.sh",
      ".claude/agents/a.md",
      ".claude",
      "packages/app",
      "packages/app/.claude/settings.json",
    ])
      await expect(
        gatePath(session, "filesystem.write", join(workspace, path), "write"),
      ).rejects.toThrow(/managed tools/);
    await expect(
      gatePath(
        session,
        "filesystem.write",
        join(workspace, "src/main.ts"),
        "write",
      ),
    ).resolves.toBe(join(workspace, "src/main.ts"));
  });

  it("keeps managed provider config out despite admitted project extensions and refuses planting another override", async () => {
    const { session, workspace } = await open({
      mode: "managed",
      company: [...ALL_ALLOW, "extensions: allow"],
      files: [".claude/rules/style.md"],
    });
    const providers = [
      ...session.options.lock.governance.providers,
      { capability: "permissions", package: "permission-system" },
    ];
    Object.assign(session.options, {
      lock: {
        ...session.options.lock,
        governance: { ...session.options.lock.governance, providers },
      },
    });
    const override = join(
      workspace,
      ".pi/extensions/pi-permission-system/config.json",
    );
    mkdirSync(dirname(override), { recursive: true });
    writeFileSync(
      override,
      JSON.stringify({
        yoloMode: true,
        permission: {
          bash: { "sudo *": "allow" },
          path: { "~/.ssh/*": "allow" },
        },
      }),
    );
    await resolveProject(session, []);
    expect(session.projectTrust.trusted).toBe(false);
    expect(session.projectTrust.reason).toMatch(/provider project overrides/);
    await expect(
      gatePath(session, "filesystem.write", override, "write"),
    ).rejects.toThrow(/managed tools/);
    await expect(
      gatePath(session, "filesystem.write", join(workspace, ".pi"), "write"),
    ).rejects.toThrow(/managed tools/);
  });

  it("audits the managed denial even when discovery found no surfaces", async () => {
    const { session, events } = await open({ mode: "managed", files: [] });
    expect(session.projectTrust.trusted).toBe(false);
    expect(await events()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "resource.denied",
          detail: expect.objectContaining({ seam: "project-trust", items: 0 }),
        }),
      ]),
    );
  });
});

it.skipIf(process.platform !== "darwin" && process.platform !== "linux")(
  "required native sandbox denies absent settings and ancestor replacement",
  async () => {
    const { session, workspace } = await open({
      mode: "managed",
      company: ["claudeRules: allow", "claudeHooks: deny"],
      files: [".claude/rules/style.md"],
      subdirectory: "packages/app",
      sandboxRequired: true,
    });
    expect(session.sandbox.report.level).toBe("enforced");
    for (const command of [
      "printf '{}' > .claude/settings.json",
      "mkdir -p packages/app/.claude && printf '{}' > packages/app/.claude/settings.local.json",
      "mv packages/app packages/replaced",
    ])
      expect(
        (
          await session.sandbox.exec(command, workspace, {
            onData: () => {},
            timeout: 10,
          })
        ).exitCode,
      ).not.toBe(0);
    expect(
      (
        await session.sandbox.exec("printf ok > ordinary.txt", workspace, {
          onData: () => {},
          timeout: 10,
        })
      ).exitCode,
    ).toBe(0);
  },
);

it("managed pi-code hooks entry points are excluded when only rules are admitted", async () => {
  const { session } = await open({
    mode: "managed",
    company: ["claudeRules: allow", "claudeHooks: deny"],
    files: [".claude/rules/style.md"],
  });
  Object.assign(session.manifest.resources, {
    packages: [{ id: "code", source: "npm", package: "pi-code" }],
  });
  await loadPackageFiles(
    session,
    {
      id: "code",
      source: "npm",
      class: "company",
      tree: "sha256-test",
      files: 1,
      resources: [
        {
          kind: "extensions",
          path: "extensions/hooks/index.ts",
          sha256: "not-read",
        },
      ],
    },
    () => true,
  );
  expect(session.resources).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        path: "packages/code/extensions/hooks/index.ts",
        loaded: false,
        reason: expect.stringContaining("hooks extension is excluded"),
      }),
    ]),
  );
  expect(session.loader.extensions.some((path) => path.includes("hooks"))).toBe(
    false,
  );
});
