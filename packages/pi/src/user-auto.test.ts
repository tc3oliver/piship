// The user's auto mode (`policy.userAuto`) in governed sessions: what it
// approves, what it never touches, its audit, and how `/auto`, `policy
// explain`, and doctor report it.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ExtensionFactory,
  type ExtensionToolContext,
  type InlineExtension,
  SessionManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { AuditEvent, ManagedFetch } from "@piship/contracts";
import { resolveLock, setUserAuto, userAutoPath } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { governanceHooks } from "./builtins.js";
import { runPolicy } from "./commands/governance.js";
import { policyGroup } from "./doctor/policy.js";
import type { DoctorData } from "./doctor/data.js";
import { GovernanceSession, inspectGovernance } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";
import type { LaunchContext } from "./launch/context.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0))
    await session.close().catch(() => undefined);
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const POLICY = [
  "policy:",
  "  id: unit",
  "  version: 1",
  "  default: ask",
  "  enforced:",
  '    - { id: secrets, action: filesystem.read, resource: "~/.ssh/**", effect: deny }',
  '    - { id: keep-asking, action: filesystem.write, resource: "workspace/kept/**", effect: ask }',
  '    - { id: push, action: shell.execute, resource: "git push**", effect: ask }',
  "  defaults:",
  '    - { id: read, action: filesystem.read, resource: "workspace/**", effect: allow }',
  '    - { id: write, action: filesystem.write, resource: "workspace/**", effect: ask }',
  '    - { id: no-rm, action: shell.execute, resource: "rm **", effect: deny }',
  '    - { id: tools, action: tool.execute, resource: "*", effect: allow }',
  "audit:",
  "  enabled: true",
  "  sinks:",
  "    - { id: local, type: file, required: false }",
];

interface Setup {
  readonly userAuto?: "allowed" | "off";
  readonly mode?: "managed" | "personal";
  /** Switch auto mode on in the state before the session opens. */
  readonly on?: boolean;
  readonly userRules?: readonly unknown[];
}

/**
 * A governed distribution. The policy engine reads only the deployment mode,
 * so a v1alpha3 lock is switched to managed and given `policy.userAuto` (a
 * v1alpha5 field), as a managed v1alpha5 lock would carry it.
 */
function distribution(setup: Setup = {}) {
  const root = mkdtempSync(join(tmpdir(), "piship-user-auto-"));
  roots.push(root);
  const dir = join(root, "distribution");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  const stateDir = join(root, "state");
  for (const path of [dir, join(workspace, "kept"), join(home, ".ssh")])
    mkdirSync(path, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), "private-key-canary\n");
  writeFileSync(join(workspace, "notes.txt"), "source-canary\n");
  if (setup.userRules) {
    mkdirSync(join(stateDir, "config"), { recursive: true });
    writeFileSync(
      join(stateDir, "config", "policy.json"),
      JSON.stringify(setup.userRules),
    );
  }
  const manifest = join(dir, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.0.0" }',
      "deployment: { mode: personal }",
      ...POLICY,
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  const governance = resolved.governance;
  if (!governance) throw new Error("no governance");
  const lock = {
    ...resolved,
    deployment: { ...resolved.deployment, mode: setup.mode ?? "managed" },
    governance: {
      ...governance,
      manifest: {
        ...governance.manifest,
        policy: {
          ...governance.manifest.policy,
          ...(setup.userAuto ? { userAuto: setup.userAuto } : {}),
        },
      },
    },
  } as Parameters<typeof GovernanceSession.open>[0]["lock"];
  if (setup.on) setUserAuto(stateDir, true);
  const options = {
    lock,
    distributionDir: dir,
    stateDir,
    cwd: workspace,
    piVersion: "1.0.0",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key: string, template: string) => template,
    homeDir: home,
    user: "alice",
  };
  const events = () =>
    readFileSync(join(stateDir, "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  return { root, dir, workspace, home, stateDir, lock, options, events };
}

async function open(setup: Setup = {}) {
  const built = distribution(setup);
  const session = await GovernanceSession.open(built.options);
  sessions.push(session);
  return { ...built, session };
}

/** A tool context; with `confirm`, an interactive one whose prompts count. */
function context(confirm?: () => Promise<boolean>) {
  const notices: string[] = [];
  const status: (string | undefined)[] = [];
  const ctx = {
    hasUI: !!confirm,
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: {
      confirm: confirm ?? (async () => false),
      setStatus: (_key: string, text: string | undefined) => status.push(text),
      notify: (message: string) => notices.push(message),
    },
  } as unknown as ExtensionToolContext;
  return { ctx, notices, status };
}

const factoryOf = (extension: InlineExtension): ExtensionFactory =>
  typeof extension === "function" ? extension : extension.factory;

function hooks(session: GovernanceSession) {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const commands = new Map<
    string,
    { handler: (args: string, ctx: unknown) => Promise<void> }
  >();
  factoryOf(governanceHooks(session))({
    on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) =>
      handlers.set(event, handler),
    registerCommand: (
      name: string,
      options: { handler: (args: string, ctx: unknown) => Promise<void> },
    ) => commands.set(name, options),
  } as never);
  return { handlers, commands };
}

function tool(session: GovernanceSession, workspace: string, name: string) {
  const found = governedTools(session, workspace).find(
    (item) => item.name === name,
  ) as ToolDefinition;
  return (params: unknown, ctx: ExtensionToolContext) =>
    found.execute("call", params as never, undefined, undefined, ctx);
}

describe("user auto mode in a governed session", () => {
  it("is off by default and leaves ask, headless and interactive, unchanged", async () => {
    const { session, workspace } = await open({ userAuto: "allowed" });
    expect(session.userAuto).toEqual({
      allowed: true,
      state: "off",
      active: false,
    });
    const write = tool(session, workspace, "write");
    await expect(
      write({ path: "a.txt", content: "x" }, context().ctx),
    ).rejects.toThrow(/rule write .*approval needs an interactive session/);
    let prompts = 0;
    await write(
      { path: "a.txt", content: "x" },
      context(async () => {
        prompts += 1;
        return true;
      }).ctx,
    );
    expect(prompts).toBeGreaterThan(0);
  });

  it("approves an ask from the distribution defaults without a prompt, headless and interactive", async () => {
    const { session, workspace, events } = await open({
      userAuto: "allowed",
      on: true,
    });
    expect(session.userAuto.active).toBe(true);
    const write = tool(session, workspace, "write");
    // Headless: no approval channel, and the ask resolves to allow.
    await write({ path: "headless.txt", content: "x" }, context().ctx);
    expect(readFileSync(join(workspace, "headless.txt"), "utf8")).toBe("x");
    // Interactive: the governed tools' confirm path is never reached.
    let prompts = 0;
    await write(
      { path: "interactive.txt", content: "y" },
      context(async () => {
        prompts += 1;
        return false;
      }).ctx,
    );
    expect(prompts).toBe(0);
    expect(existsSync(join(workspace, "interactive.txt"))).toBe(true);
    // policy.default ask (no rule) is approved too.
    const resolved = await session.decide(
      "web.request",
      "example.org",
      undefined,
    );
    expect(resolved).toMatchObject({ outcome: "allow", approval: "auto" });
    await session.close();
    const auto = events().filter(
      (event) => event.event === "policy.auto_approved",
    );
    expect(auto.length).toBeGreaterThanOrEqual(3);
    expect(auto[0]).toMatchObject({
      user: "alice",
      resource: "write",
      decision: "approved",
      policy: "unit@1",
      rule: "write",
      detail: {
        action: "filesystem.write",
        path: "workspace",
        approval: "auto",
      },
    });
    // Metadata only: no file content, path, or content capture.
    const text = JSON.stringify(auto);
    expect(text).not.toContain(workspace);
    expect(text).not.toContain('"content"');
    expect(
      events().find((event) => event.event === "policy.loaded"),
    ).toMatchObject({ detail: { userAuto: true } });
  });

  it("never touches deny, an enforced rule, or an explicit ask", async () => {
    const { session, workspace, home } = await open({
      userAuto: "allowed",
      on: true,
      userRules: [
        {
          id: "mine",
          action: "filesystem.write",
          resource: "workspace/mine/**",
          effect: "ask",
        },
      ],
    });
    mkdirSync(join(workspace, "mine"));
    await expect(
      tool(
        session,
        workspace,
        "read",
      )({ path: join(home, ".ssh", "id_rsa") }, context().ctx),
    ).rejects.toThrow(/rule secrets/);
    const shell = await session.decide("shell.execute", "rm -rf /", undefined);
    expect(shell).toMatchObject({ outcome: "deny", ruleId: "no-rm" });
    // An enforced ask and the user's own ask keep their prompt.
    for (const path of ["kept/a.txt", "mine/a.txt"]) {
      let prompts = 0;
      await expect(
        tool(
          session,
          workspace,
          "write",
        )(
          { path, content: "x" },
          context(async () => {
            prompts += 1;
            return false;
          }).ctx,
        ),
      ).rejects.toThrow(/not allowed/);
      expect(prompts).toBeGreaterThan(0);
      expect(existsSync(join(workspace, path))).toBe(false);
    }
  });

  it("keeps an explicit shell ask when the command chains past its pattern", async () => {
    const { session } = await open({
      userAuto: "allowed",
      on: true,
      userRules: [
        {
          id: "mine",
          action: "shell.execute",
          resource: "npm publish**",
          effect: "ask",
        },
      ],
    });
    for (const [command, ruleId] of [
      ["git push origin main; true", "push"],
      ["git push origin main && echo ok", "push"],
      ["npm publish; true", "mine"],
    ] as const) {
      // Headless: no approval channel, so the kept ask is denied.
      expect(
        await session.decide("shell.execute", command, undefined),
      ).toMatchObject({ outcome: "deny", approval: "unavailable", ruleId });
      // Interactive: the prompt is shown.
      let prompts = 0;
      const resolved = await session.decide(
        "shell.execute",
        command,
        async () => {
          prompts += 1;
          return "denied";
        },
      );
      expect(prompts).toBe(1);
      expect(resolved).toMatchObject({ outcome: "deny", ruleId });
    }
  });

  it("has no effect while the release does not allow it, and is not offered", async () => {
    for (const userAuto of [undefined, "off"] as const) {
      const { session, workspace, stateDir } = await open({
        ...(userAuto ? { userAuto } : {}),
        on: true,
      });
      expect(session.userAuto).toEqual({
        allowed: false,
        state: "inert",
        active: false,
      });
      await expect(
        tool(
          session,
          workspace,
          "write",
        )({ path: "a.txt", content: "x" }, context().ctx),
      ).rejects.toThrow(/approval needs an interactive session/);
      // `/auto on` is refused with the policy error; nothing changes.
      const { commands } = hooks(session);
      const shown = context(async () => true);
      await commands.get("auto")?.handler("on", shown.ctx);
      expect(shown.notices.join("\n")).toMatch(
        /POLICY_DENIED.*does not allow auto mode/,
      );
      expect(session.userAuto.active).toBe(false);
      expect(existsSync(userAutoPath(stateDir))).toBe(true);
    }
  });

  it("is never offered in personal mode", async () => {
    const { session } = await open({ mode: "personal", on: true });
    expect(session.userAuto.active).toBe(false);
    expect(hooks(session).commands.has("auto")).toBe(false);
  });

  it("switches with /auto, audited, and stores the switch for later sessions", async () => {
    const { session, workspace, stateDir, events, options } = await open({
      userAuto: "allowed",
    });
    const { commands } = hooks(session);
    const auto = commands.get("auto");
    if (!auto) throw new Error("/auto is not registered");
    const on = context(async () => false);
    await auto.handler("on", on.ctx);
    expect(on.notices.at(-1)).toMatch(/^Auto mode is on/);
    expect(on.status.at(-1)).toBe("Auto");
    await tool(
      session,
      workspace,
      "write",
    )({ path: "a.txt", content: "x" }, on.ctx);
    const status = context(async () => false);
    await auto.handler("", status.ctx);
    expect(status.notices).toEqual([
      expect.stringMatching(
        /^Auto mode: on: asks from the distribution defaults are approved/,
      ),
    ]);
    // A later session starts with the stored switch.
    const later = await GovernanceSession.open(options);
    sessions.push(later);
    expect(later.userAuto.active).toBe(true);
    await later.close();
    const off = context(async () => false);
    await auto.handler("off", off.ctx);
    expect(off.status.at(-1)).toBeUndefined();
    expect(existsSync(userAutoPath(stateDir))).toBe(false);
    await session.close();
    // The write is decided before it runs and again on the file it opens.
    expect([
      ...new Set(
        events()
          .filter((event) => event.event.startsWith("policy.auto_"))
          .map((event) => `${event.event} ${event.detail?.source ?? ""}`),
      ),
    ]).toEqual([
      "policy.auto_enabled session",
      "policy.auto_approved ",
      "policy.auto_disabled session",
    ]);
  });

  it("resets when another principal binds the state", async () => {
    const built = distribution({ userAuto: "allowed" });
    const principal = join(built.stateDir, "identity", "principal.json");
    const bind = (subject: string, at: string) => {
      mkdirSync(join(built.stateDir, "identity"), { recursive: true });
      writeFileSync(
        principal,
        JSON.stringify({
          schema: "piship-principal-binding/v1",
          issuer: "https://id.example",
          subject,
          bound_at: at,
        }),
      );
    };
    bind("alice", "2026-10-01T00:00:00.000Z");
    setUserAuto(built.stateDir, true);
    let session = await GovernanceSession.open(built.options);
    sessions.push(session);
    expect(session.userAuto.state).toBe("on");
    await session.close();
    // Bob signs in; then Alice again: each change rebinds the state.
    bind("bob", "2026-10-02T00:00:00.000Z");
    session = await GovernanceSession.open(built.options);
    sessions.push(session);
    expect(session.userAuto).toMatchObject({ state: "reset", active: false });
    await session.close();
    bind("alice", "2026-10-03T00:00:00.000Z");
    session = await GovernanceSession.open(built.options);
    sessions.push(session);
    expect(session.userAuto).toMatchObject({ state: "reset", active: false });
  });
});

describe("policy explain and doctor with auto mode", () => {
  function launchContext(built: ReturnType<typeof distribution>) {
    const out: string[] = [];
    const ctx = {
      metadata: built.lock,
      distributionDir: built.dir,
      stateDir: built.stateDir,
      agentDir: join(built.stateDir, "agent"),
      mode: built.lock.deployment.mode,
      out: (message: string) => out.push(message),
      err: () => {},
    } as unknown as LaunchContext;
    return { ctx, out };
  }

  it("policy explain reports an ask as auto-approved by the user, and nothing else", async () => {
    const built = distribution({ userAuto: "allowed", on: true });
    const { ctx, out } = launchContext(built);
    await runPolicy(ctx, ["explain", "web.request", "example.org"]);
    expect(out.at(-1)).toMatch(
      /^AUTO-APPROVED\n\nEffect:\n {2}ask \(auto-approved by user\)/,
    );
    await runPolicy(ctx, ["explain", "web.request", "example.org", "--json"]);
    expect(JSON.parse(out.at(-1) as string)).toMatchObject({
      effect: "ask",
      autoApproved: true,
    });
    // Deny is unchanged.
    await runPolicy(ctx, ["explain", "shell.execute", "rm -rf /"]);
    expect(out.at(-1)).toMatch(/^DENIED/);
    // Off: the plain ask.
    setUserAuto(built.stateDir, false);
    await runPolicy(ctx, ["explain", "web.request", "example.org", "--json"]);
    expect(JSON.parse(out.at(-1) as string)).not.toHaveProperty("autoApproved");
  });

  it("doctor shows the switch, and says when the release makes it inert", async () => {
    const lines = async (setup: Setup) => {
      const built = distribution(setup);
      const inspection = await inspectGovernance(built.options);
      const shown: string[] = [];
      const record = (status: string) => (label: string, value: string) =>
        shown.push(`${status} ${label}: ${value}`);
      policyGroup(
        {
          governance: { manifest: built.lock.governance.manifest, inspection },
        } as unknown as DoctorData,
        {
          ok: record("ok"),
          warn: record("warn"),
          bad: record("fail"),
          info: record("info"),
        } as never,
      );
      return shown.filter((line) => line.includes(" auto:"));
    };
    expect(await lines({ userAuto: "allowed", on: true })).toEqual([
      expect.stringMatching(
        /^ok auto: on: asks from the distribution defaults are approved/,
      ),
    ]);
    expect(await lines({ userAuto: "allowed" })).toEqual([
      "ok auto: off (the distribution allows it)",
    ]);
    expect(await lines({ userAuto: "off", on: true })).toEqual([
      expect.stringMatching(
        /^warn auto: off: the switch is on, but this release does not allow auto mode/,
      ),
    ]);
    expect(await lines({})).toEqual([]);
  });
});
