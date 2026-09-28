import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import {
  type ExtensionContext,
  type InlineExtension,
  SessionManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { type ManagedFetch, PiShipError } from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { resolveTemplate } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import {
  askUserExtension,
  DEFAULT_PLAN_PROMPT,
  governanceHooks,
  workflowExtension,
} from "./builtins.js";
import { GovernanceSession, inspectGovernance } from "./governance-session.js";
import { governedTools, pathClass } from "./governed-tools.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const POLICY = [
  "policy:",
  "  id: unit",
  "  version: 1",
  "  default: deny",
  "  enforced:",
  '    - { id: secrets, action: filesystem.read, resource: "~/.ssh/**", effect: deny, reason: Keys stay private }',
  "  defaults:",
  '    - { id: read, action: filesystem.read, resource: "workspace/**", effect: allow }',
  '    - { id: write, action: filesystem.write, resource: "workspace/**", effect: ask }',
  '    - { id: shell, action: shell.execute, resource: "**", effect: deny }',
  "    - { id: no-bash-tool, action: tool.execute, resource: bash, effect: deny }",
  '    - { id: tools, action: tool.execute, resource: "*", effect: allow }',
];

async function open(
  extra: string[] = [],
  options: {
    readonly userRules?: readonly unknown[];
    readonly files?: Readonly<Record<string, string>>;
    readonly fetch?: ManagedFetch;
    readonly resolveTemplate?: (key: string, template: string) => string;
    readonly mode?: "managed" | "personal";
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "piship-governed-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  for (const path of [distribution, workspace, join(home, ".ssh")])
    mkdirSync(path, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), "private-key-canary\n");
  writeFileSync(join(workspace, "notes.txt"), "workspace notes\n");
  for (const [path, content] of Object.entries(options.files ?? {})) {
    mkdirSync(dirname(join(distribution, path)), { recursive: true });
    writeFileSync(join(distribution, path), content);
  }
  if (options.userRules) {
    mkdirSync(join(root, "state", "config"), { recursive: true });
    writeFileSync(
      join(root, "state", "config", "policy.json"),
      JSON.stringify(options.userRules),
    );
  }
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "0.87.1" }',
      "deployment: { mode: personal }",
      ...POLICY,
      ...extra,
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  // A managed manifest needs identity and access; the policy engine only
  // reads the deployment mode, so tests switch it on the resolved lock.
  const lock = options.mode
    ? {
        ...resolved,
        deployment: { ...resolved.deployment, mode: options.mode },
      }
    : resolved;
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: "0.87.1",
    interactive: false,
    fetch:
      options.fetch ??
      ((() => {
        throw new Error("no network in unit tests");
      }) as unknown as ManagedFetch),
    resolveTemplate: options.resolveTemplate ?? ((_key, template) => template),
    homeDir: home,
  });
  sessions.push(session);
  return { session, workspace, home, root };
}

function context(
  answer?: boolean | string,
  confirm?: (title: string, message: string) => Promise<boolean>,
): ExtensionContext {
  const hasUI = answer !== undefined;
  return {
    hasUI,
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: {
      confirm: confirm ?? (async () => answer === true),
      select: async (_title: string, options: string[]) =>
        typeof answer === "string" && answer !== "cancel"
          ? options.find((item) => item === answer)
          : undefined,
      setStatus: () => {},
      notify: () => {},
    },
  } as unknown as ExtensionContext;
}

function tool(tools: ToolDefinition[], name: string): ToolDefinition {
  const found = tools.find((item) => item.name === name);
  if (!found) throw new Error(`missing ${name}`);
  return found;
}

const run = (definition: ToolDefinition, params: unknown, ctx = context()) =>
  definition.execute("call", params as never, undefined, undefined, ctx);

function text(result: { content: { type: string; text?: string }[] }) {
  return result.content.map((item) => item.text ?? "").join("");
}

/** Collect what an inline extension registers through the public API shape. */
function load(extension: InlineExtension) {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const tools: ToolDefinition[] = [];
  const commands = new Map<
    string,
    { handler: (args: string, ctx: unknown) => Promise<void> }
  >();
  extension.factory({
    on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
      handlers.set(event, handler),
    registerTool: (definition: ToolDefinition) => tools.push(definition),
    registerCommand: (
      name: string,
      options: { handler: (args: string, ctx: unknown) => Promise<void> },
    ) => commands.set(name, options),
  } as never);
  return { handlers, tools, commands };
}

describe("governed built-in tools", () => {
  it("reads the workspace but not a secret reached through a symlink", async () => {
    const { session, workspace, home } = await open();
    symlinkSync(join(home, ".ssh", "id_rsa"), join(workspace, "innocent.txt"));
    const tools = governedTools(session, workspace);
    const read = tool(tools, "read");
    expect(text(await run(read, { path: "notes.txt" }))).toContain(
      "workspace notes",
    );
    await expect(run(read, { path: "innocent.txt" })).rejects.toThrow(
      /not allowed by unit@1 rule secrets/,
    );
    await expect(
      run(read, { path: join(home, ".ssh", "id_rsa") }),
    ).rejects.toThrow(/rule secrets/);
  });

  it("never reads a file swapped in through a directory symlink after the decision", async () => {
    const { session, workspace, home } = await open([], {
      userRules: [
        {
          id: "race",
          action: "filesystem.read",
          resource: "workspace/dir/**",
          effect: "ask",
        },
      ],
    });
    mkdirSync(join(workspace, "dir"));
    writeFileSync(join(workspace, "dir", "id_rsa"), "workspace copy\n");
    // The approval of the second check (the read itself) is the window
    // between decision and use: swap the directory for a link to ~/.ssh.
    let calls = 0;
    const swapping = context(true, async () => {
      calls += 1;
      if (calls === 2) {
        renameSync(join(workspace, "dir"), join(workspace, "dir.bak"));
        symlinkSync(join(home, ".ssh"), join(workspace, "dir"), "dir");
      }
      return true;
    });
    const read = tool(governedTools(session, workspace), "read");
    const outcome = await run(read, { path: "dir/id_rsa" }, swapping).then(
      (result) => text(result),
      (error: Error) => `rejected: ${error.message}`,
    );
    expect(calls).toBe(2);
    expect(outcome).not.toContain("private-key-canary");
    expect(outcome).toMatch(/rejected: .*(rule secrets|changed while)/);
  });

  it("never writes through a directory swapped for a symlink after the decision", async () => {
    const { session, workspace, home } = await open();
    writeFileSync(join(home, ".ssh", "authorized_keys"), "keys-canary\n");
    mkdirSync(join(workspace, "out"));
    writeFileSync(join(workspace, "out", "authorized_keys"), "original\n");
    let calls = 0;
    const swapping = context(true, async () => {
      calls += 1;
      // First the parent directory is decided (mkdir), then the file.
      if (calls === 2) {
        renameSync(join(workspace, "out"), join(workspace, "out.bak"));
        symlinkSync(join(home, ".ssh"), join(workspace, "out"), "dir");
      }
      return true;
    });
    const write = tool(governedTools(session, workspace), "write");
    await expect(
      run(
        write,
        { path: "out/authorized_keys", content: "attacker-key" },
        swapping,
      ),
    ).rejects.toThrow(/builtin:default|changed while/);
    expect(calls).toBe(2);
    expect(readFileSync(join(home, ".ssh", "authorized_keys"), "utf8")).toBe(
      "keys-canary\n",
    );
  });

  it("classifies native paths against the POSIX policy context", async () => {
    const opened = await open();
    const { session } = opened;
    // Callers pass symlink-resolved paths (macOS temp lives under /private).
    const workspace = realpathSync(opened.workspace);
    const home = realpathSync(opened.home);
    expect(pathClass(session, join(workspace, "src", "a.ts"))).toBe(
      "workspace",
    );
    // The test home sits in the temp directory, which is checked first.
    expect(pathClass(session, join(home, ".ssh", "id_rsa"))).toBe("tmp");
    expect(pathClass(session, `${workspace}-sibling`)).toBe("tmp");
    expect(pathClass(session, join(parse(workspace).root, "piship-none"))).toBe(
      "other",
    );
  });

  it("never reads or writes the distribution state, whatever the policy allows", async () => {
    const { session, workspace, root } = await open([], {
      userRules: [
        { id: "me.read", action: "filesystem.read", effect: "allow" },
        { id: "me.write", action: "filesystem.write", effect: "allow" },
      ],
    });
    expect(session.sandbox.report.level).not.toBe("enforced");
    const tools = governedTools(session, workspace);
    const policyFile = join(root, "state", "config", "policy.json");
    await expect(
      run(tool(tools, "read"), { path: policyFile }),
    ).rejects.toThrow(/distribution state directory/);
    await expect(
      run(tool(tools, "write"), { path: policyFile, content: "[]" }),
    ).rejects.toThrow(/distribution state directory/);
    expect(readFileSync(policyFile, "utf8")).toContain("me.write");
    // The same policy still lets tools write elsewhere.
    await run(tool(tools, "write"), { path: "free.txt", content: "ok" });
    expect(readFileSync(join(workspace, "free.txt"), "utf8")).toBe("ok");
  });

  it("in managed mode ignores a user allow rule, reports it, and audits a violation", async () => {
    const audit = [
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
    ];
    const userRules = [
      { id: "me.shell", action: "shell.execute", effect: "allow" },
      {
        id: "me.rm",
        action: "tool.execute",
        resource: "write",
        effect: "deny",
      },
    ];
    const managed = await open(audit, { userRules, mode: "managed" });
    expect(
      managed.session.engine.evaluate({
        action: "shell.execute",
        resource: "ls",
      }),
    ).toMatchObject({ effect: "deny", ruleId: "shell" });
    expect(
      managed.session.engine.evaluate({
        action: "tool.execute",
        resource: "write",
      }),
    ).toMatchObject({ effect: "deny", ruleId: "me.rm" });
    expect(managed.session.engine.diagnostics).toEqual([
      expect.objectContaining({ source: "user", ruleId: "me.shell" }),
    ]);
    await managed.session.close();
    const log = readFileSync(
      join(managed.root, "state", "logs", "audit.jsonl"),
      "utf8",
    );
    expect(log).toMatch(/"event":"policy\.violation"[^\n]*"rule":"me\.shell"/);
    // Personal mode keeps the local owner's user rule in place of the default.
    const personal = await open([], { userRules });
    expect(
      personal.session.engine.evaluate({
        action: "shell.execute",
        resource: "ls",
      }),
    ).toMatchObject({ effect: "allow", ruleId: "me.shell" });
    expect(personal.session.engine.diagnostics).toEqual([]);
  });

  it("does not let tools rewrite the git config that decides the project origin", async () => {
    const { session, workspace } = await open();
    mkdirSync(join(workspace, ".git"));
    const config = join(workspace, ".git", "config");
    writeFileSync(config, "[core]\n\tbare = false\n");
    const write = tool(governedTools(session, workspace), "write");
    await expect(
      run(
        write,
        {
          path: ".git/config",
          content: '[remote "origin"]\n\turl = https://git.acme.example/x\n',
        },
        context(true),
      ),
    ).rejects.toThrow(/decides this project's origin/);
    expect(readFileSync(config, "utf8")).not.toContain("acme");
    const edit = tool(governedTools(session, workspace), "edit");
    await expect(
      run(
        edit,
        {
          path: ".git/config",
          edits: [{ oldText: "bare = false", newText: "bare = true" }],
        },
        context(true),
      ),
    ).rejects.toThrow(/decides this project's origin/);
  });

  it("does not let tools plant git hooks or change git info files", async () => {
    const { session, workspace, root } = await open([
      "audit:",
      "  enabled: true",
      "  sinks:",
      "    - { id: local, type: file, required: false }",
    ]);
    mkdirSync(join(workspace, ".git"));
    writeFileSync(join(workspace, ".git", "config"), "[core]\n");
    const tools = governedTools(session, workspace);
    const write = tool(tools, "write");
    // A missing hooks directory is refused before it is created.
    await expect(
      run(
        write,
        { path: ".git/hooks/pre-commit", content: "#!/bin/sh\ntouch pwned\n" },
        context(true),
      ),
    ).rejects.toThrow(/what git runs/);
    expect(existsSync(join(workspace, ".git", "hooks"))).toBe(false);
    mkdirSync(join(workspace, ".git", "hooks"));
    await expect(
      run(
        write,
        { path: ".git/hooks/pre-commit", content: "#!/bin/sh\ntouch pwned\n" },
        context(true),
      ),
    ).rejects.toThrow(/what git runs/);
    expect(existsSync(join(workspace, ".git", "hooks", "pre-commit"))).toBe(
      false,
    );
    mkdirSync(join(workspace, ".git", "info"));
    writeFileSync(join(workspace, ".git", "info", "exclude"), "# none\n");
    await expect(
      run(
        tool(tools, "edit"),
        {
          path: ".git/info/exclude",
          edits: [{ oldText: "# none", newText: "*" }],
        },
        context(true),
      ),
    ).rejects.toThrow(/what git runs/);
    expect(
      readFileSync(join(workspace, ".git", "info", "exclude"), "utf8"),
    ).toBe("# none\n");
    // Other git files follow the policy as before (here: ask, approved).
    writeFileSync(join(workspace, ".git", "description"), "unnamed\n");
    await run(
      tool(tools, "edit"),
      {
        path: ".git/description",
        edits: [{ oldText: "unnamed", newText: "named" }],
      },
      context(true),
    );
    expect(readFileSync(join(workspace, ".git", "description"), "utf8")).toBe(
      "named\n",
    );
    await session.close();
    const audit = readFileSync(
      join(root, "state", "logs", "audit.jsonl"),
      "utf8",
    );
    expect(audit).toContain('"rule":"piship.project.git-config"');
  });

  it("shows the path or command in the approval prompt but keeps audit metadata-only", async () => {
    const { session, workspace, root } = await open(
      [
        "audit:",
        "  enabled: true",
        "  sinks:",
        "    - { id: local, type: file, required: false }",
      ],
      {
        userRules: [
          {
            id: "me.echo",
            action: "shell.execute",
            resource: "echo *",
            effect: "ask",
          },
        ],
      },
    );
    const messages: string[] = [];
    const capture = context(false, async (_title, message) => {
      messages.push(message);
      return false;
    });
    const tools = governedTools(session, workspace);
    await expect(
      run(
        tool(tools, "write"),
        { path: "prompt-canary/x.txt", content: "x" },
        capture,
      ),
    ).rejects.toThrow(/not allowed/);
    await expect(
      run(tool(tools, "bash"), { command: "echo command-canary" }, capture),
    ).rejects.toThrow(/not allowed/);
    expect(
      messages.some((message) =>
        message.includes(join(workspace, "prompt-canary")),
      ),
    ).toBe(true);
    expect(messages.at(-1)).toContain("echo command-canary");
    await session.close();
    const audit = readFileSync(
      join(root, "state", "logs", "audit.jsonl"),
      "utf8",
    );
    expect(audit).toContain("tool.denied");
    expect(audit).not.toContain("prompt-canary");
    expect(audit).not.toContain("command-canary");
  });

  it("resolves ask through the session UI and denies it headless", async () => {
    const { session, workspace } = await open();
    const write = tool(governedTools(session, workspace), "write");
    await expect(
      run(write, { path: "headless.txt", content: "x" }),
    ).rejects.toThrow(/approval needs an interactive session/);
    expect(existsSync(join(workspace, "headless.txt"))).toBe(false);
    await expect(
      run(write, { path: "declined.txt", content: "x" }, context(false)),
    ).rejects.toThrow(/not allowed/);
    expect(existsSync(join(workspace, "declined.txt"))).toBe(false);
    await run(write, { path: "approved.txt", content: "yes" }, context(true));
    expect(readFileSync(join(workspace, "approved.txt"), "utf8")).toBe("yes");
    // Outside the workspace no rule matches: the policy default (deny) holds.
    await expect(
      run(
        write,
        { path: join(tmpdir(), "piship-outside.txt"), content: "x" },
        context(true),
      ),
    ).rejects.toThrow(/builtin:default/);
  });

  it("never runs a denied command", async () => {
    const { session, workspace } = await open();
    const bash = tool(governedTools(session, workspace), "bash");
    await expect(
      run(bash, { command: "echo ran > marker.txt" }, context(true)),
    ).rejects.toThrow(/rule shell/);
    expect(existsSync(join(workspace, "marker.txt"))).toBe(false);
  });

  it("blocks a tool call when the policy decision throws", async () => {
    const { session } = await open();
    const call = load(governanceHooks(session)).handlers.get("tool_call");
    session.decide = (async () => {
      throw new Error("engine exploded token=sk-live-canary-1234567890");
    }) as typeof session.decide;
    const result = (await call?.({ toolName: "read", input: {} }, context())) as
      | { block: boolean; reason: string }
      | undefined;
    expect(result).toEqual({
      block: true,
      reason: "read was blocked because the policy check failed",
    });
    session.decide = (async () => {
      throw new PiShipError("AUDIT_UNAVAILABLE", "sink down");
    }) as typeof session.decide;
    expect(await call?.({ toolName: "read", input: {} }, context())).toEqual({
      block: true,
      reason:
        "read was blocked because the policy check failed (AUDIT_UNAVAILABLE)",
    });
  });

  it("blocks writes and commands in Plan mode even when policy allows them", async () => {
    const { session, workspace } = await open();
    session.workflowMode = "plan";
    const tools = governedTools(session, workspace);
    await expect(
      run(
        tool(tools, "write"),
        { path: "plan.txt", content: "x" },
        context(true),
      ),
    ).rejects.toThrow(/Plan mode/);
    expect(existsSync(join(workspace, "plan.txt"))).toBe(false);
    const hooks = load(governanceHooks(session));
    const call = hooks.handlers.get("tool_call");
    expect(await call?.({ toolName: "edit", input: {} }, context())).toEqual(
      expect.objectContaining({ block: true }),
    );
    // Plan mode is an allowlist: MCP and extension tools are blocked too,
    // whatever the policy says about them.
    for (const name of ["mcp__docs__search", "deploy", "grep"])
      expect(await call?.({ toolName: name, input: {} }, context())).toEqual({
        block: true,
        reason: `Plan mode does not allow ${name}. The user can switch to Build mode with /build.`,
      });
    for (const name of ["read", "ask_user"])
      expect(await call?.({ toolName: name, input: {} }, context())).toBe(
        undefined,
      );
    session.workflowMode = "build";
    expect(
      await call?.({ toolName: "mcp__docs__search", input: {} }, context()),
    ).toBe(undefined);
    expect(await call?.({ toolName: "read", input: {} }, context())).toBe(
      undefined,
    );
    // tool.execute policy applies to every tool, including extension tools.
    expect(await call?.({ toolName: "bash", input: {} }, context())).toEqual(
      expect.objectContaining({ block: true }),
    );
  });
});

describe("piship-ask-user", () => {
  it("returns approved, denied, chosen, cancelled, and unavailable answers", async () => {
    const { session } = await open();
    const [ask] = load(askUserExtension(session)).tools;
    if (!ask) throw new Error("ask_user was not registered");
    const answer = async (params: unknown, ctx: ExtensionContext) =>
      (await run(ask, params, ctx)).details as { outcome: string };
    expect(await answer({ question: "Ship it?" }, context(true))).toEqual({
      outcome: "approved",
    });
    expect(await answer({ question: "Ship it?" }, context(false))).toEqual({
      outcome: "denied",
    });
    expect(
      await answer({ question: "Which?", options: ["a", "b"] }, context("b")),
    ).toEqual({ outcome: "answered" });
    expect(
      await answer(
        { question: "Which?", options: ["a", "b"] },
        context("cancel"),
      ),
    ).toEqual({ outcome: "cancelled" });
    expect(await answer({ question: "Ship it?" }, context())).toEqual({
      outcome: "unavailable",
    });
  });
});

describe("piship-workflow", () => {
  it("starts in the configured mode, switches by command, and adds mode prompts", async () => {
    const { session } = await open();
    const workflow = load(
      workflowExtension(session, { buildPrompt: "Company build rules." }),
    );
    expect(session.workflowMode).toBe("plan");
    const handler = workflow.handlers.get("before_agent_start");
    if (!handler) throw new Error("before_agent_start was not registered");
    const start = (event: unknown, ctx: unknown) =>
      handler(event, ctx) as { systemPrompt: string };
    expect(
      (start({ systemPrompt: "base" }, context()) as { systemPrompt: string })
        .systemPrompt,
    ).toBe(`base\n\n${DEFAULT_PLAN_PROMPT}`);
    await workflow.commands.get("build")?.handler("", context(true));
    expect(session.workflowMode).toBe("build");
    expect(
      (start({ systemPrompt: "base" }, context()) as { systemPrompt: string })
        .systemPrompt,
    ).toBe("base\n\nCompany build rules.");
    await workflow.commands.get("plan")?.handler("", context(true));
    expect(session.workflowMode).toBe("plan");
  });
});

describe("Streamable HTTP MCP urls", () => {
  const mcp = (required: boolean) => [
    "variables: [UNIT_MCP_URL]",
    "mcp:",
    "  mode: allowlist",
    "  servers:",
    "    tickets:",
    "      transport: streamable-http",
    `      url: \${UNIT_MCP_URL}`,
    `      required: ${required}`,
  ];
  const allowStart =
    "    - { id: tickets, action: mcp.server.start, resource: tickets, effect: allow }";
  const env =
    (vars: Record<string, string>) => (key: string, template: string) =>
      resolveTemplate(key, template, ["UNIT_MCP_URL"], vars);

  it("resolves the url from the launch environment before connecting", async () => {
    const requested: string[] = [];
    const fetch = (async (url: string | URL) => {
      requested.push(String(url));
      throw new Error("connection refused");
    }) as unknown as ManagedFetch;
    const { session } = await open([allowStart, ...mcp(false)], {
      fetch,
      resolveTemplate: env({ UNIT_MCP_URL: "https://mcp.unit.example/rpc" }),
    });
    expect(requested[0]).toBe("https://mcp.unit.example/rpc");
    expect(session.mcpReports).toEqual([
      expect.objectContaining({ id: "tickets", state: "failed" }),
    ]);
    expect(session.mcpReports[0]?.reason).not.toContain("${");
  });

  it("reports an unset variable: a failed optional server, an unavailable required one", async () => {
    const fetch = (async () => {
      throw new Error("must not connect");
    }) as unknown as ManagedFetch;
    const { session } = await open([allowStart, ...mcp(false)], {
      fetch,
      resolveTemplate: env({}),
    });
    expect(session.mcpReports).toEqual([
      expect.objectContaining({
        id: "tickets",
        state: "failed",
        reason: expect.stringContaining(
          "Runtime variable UNIT_MCP_URL for mcp.servers.tickets.url is not set",
        ),
      }),
    ]);
    await expect(
      open([allowStart, ...mcp(true)], { fetch, resolveTemplate: env({}) }),
    ).rejects.toMatchObject({
      code: "CONFIG_UNAVAILABLE",
      message: expect.stringContaining("UNIT_MCP_URL"),
    });
  });
});

describe("capability provider loading", () => {
  const PROVIDER = [
    "capabilities:",
    "  workflow:",
    "    enabled: true",
    "    provider:",
    "      id: company/flow",
    "      version: 1.0.0",
    "      implements: [piship.capability/workflow/v1]",
    "      path: ./providers/flow",
  ];
  // The lock reads the source tree; the launch verifies the installed payload.
  const files = {
    "providers/flow/index.ts": "export default () => {};\n",
    "resources/providers/flow/index.ts": "export default () => {};\n",
  };
  const allow = (action: string, resource: string) =>
    `    - { id: allow-${action.replace(".", "-")}, action: ${action}, resource: "${resource}", effect: allow }`;

  it("loads a trusted provider only when policy allows provider.load and extension.load", async () => {
    const { session } = await open(
      [
        allow("provider.load", "company/flow"),
        allow("extension.load", "company:./providers/flow"),
        ...PROVIDER,
      ],
      { files },
    );
    expect(session.loader.extensions).toEqual([
      expect.stringMatching(/providers[\\/]flow$/),
    ]);
    expect(session.effective("workflow")).toBe(true);
  });

  it.each([
    [[] as string[], "provider.load"],
    [[allow("provider.load", "company/flow")], "extension.load"],
  ])("skips the provider when policy denies %j", async (rules, action) => {
    const { session } = await open([...rules, ...PROVIDER], { files });
    expect(session.loader.extensions).toEqual([]);
    expect(session.effective("workflow")).toBe(false);
    expect(session.resources).toContainEqual(
      expect.objectContaining({
        kind: "providers",
        path: "company/flow",
        loaded: false,
        reason: `policy builtin:default (${action})`,
      }),
    );
    // A policy refusal is a matter of `enabled`, not of health; the static
    // inspection behind `capabilities` agrees with the running session.
    const inspection = await inspectGovernance(session.options);
    for (const states of [session.capabilities, inspection.capabilities])
      expect(
        states.find((state) => state.name === "workflow")?.axes,
      ).toMatchObject({
        enabled: {
          value: "no",
          reason: expect.stringContaining(`policy builtin:default (${action})`),
        },
        healthy: { value: "n/a" },
        effective: { value: "no" },
      });
  });
});
