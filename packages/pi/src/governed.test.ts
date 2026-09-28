import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ExtensionContext,
  type InlineExtension,
  SessionManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { ManagedFetch } from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import {
  askUserExtension,
  DEFAULT_PLAN_PROMPT,
  governanceHooks,
  workflowExtension,
} from "./builtins.js";
import { GovernanceSession } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";

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

async function open(extra: string[] = []) {
  const root = mkdtempSync(join(tmpdir(), "piship-governed-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  for (const path of [distribution, workspace, join(home, ".ssh")])
    mkdirSync(path, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), "private-key-canary\n");
  writeFileSync(join(workspace, "notes.txt"), "workspace notes\n");
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
  const lock = resolveLock(manifest);
  const session = await GovernanceSession.open({
    lock: lock as Parameters<typeof GovernanceSession.open>[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: "0.87.1",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: home,
  });
  sessions.push(session);
  return { session, workspace, home, root };
}

function context(answer?: boolean | string): ExtensionContext {
  const hasUI = answer !== undefined;
  return {
    hasUI,
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: {
      confirm: async () => answer === true,
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
    session.workflowMode = "build";
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
