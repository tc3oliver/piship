// `--yolo` in governed sessions: it approves asks for the running session
// only, never touches deny, stores nothing, and where an administrator owns
// the policy (managed) works only if the distribution allows auto-approval.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
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
import {
  type AuditEvent,
  type ManagedFetch,
  PiShipError,
} from "@piship/contracts";
import {
  PI_VERSION,
  resolveLock,
  setUserAuto,
  userAutoPath,
} from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { governanceHooks } from "./builtins.js";
import { GovernanceSession } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";

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

/** The user's own `ask` over what the distribution defaults allow. */
const USER_ASK = {
  id: "mine",
  action: "filesystem.read",
  resource: "workspace/private/**",
  effect: "ask",
};

interface Setup {
  readonly mode: "managed" | "personal";
  readonly userAuto?: "allowed" | "off";
  readonly yolo?: boolean;
  /** Switch the stored auto mode on before the session opens. */
  readonly stored?: boolean;
  readonly onYoloEnd?: () => string | undefined;
}

/**
 * A governed distribution. The policy engine reads only the deployment mode,
 * so a v1alpha3 lock is switched to the mode under test and given
 * `policy.userAuto` (a v1alpha5 field), as a v1alpha5 lock would carry it.
 */
function distribution(setup: Setup) {
  const root = mkdtempSync(join(tmpdir(), "piship-yolo-"));
  roots.push(root);
  const dir = join(root, "distribution");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  const stateDir = join(root, "state");
  for (const path of [
    dir,
    join(workspace, "kept"),
    join(workspace, "private"),
    join(home, ".ssh"),
  ])
    mkdirSync(path, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), "private-key-canary\n");
  writeFileSync(join(workspace, "private", "a.txt"), "private-canary\n");
  mkdirSync(join(stateDir, "config"), { recursive: true });
  writeFileSync(
    join(stateDir, "config", "policy.json"),
    JSON.stringify([USER_ASK]),
  );
  const manifest = join(dir, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      `runtime: { pi: "${PI_VERSION}" }`,
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
    deployment: { ...resolved.deployment, mode: setup.mode },
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
  if (setup.stored) setUserAuto(stateDir, true);
  const options = {
    lock,
    distributionDir: dir,
    stateDir,
    cwd: workspace,
    piVersion: PI_VERSION,
    interactive: false,
    ...(setup.yolo ? { yolo: true } : {}),
    ...(setup.onYoloEnd ? { onYoloEnd: setup.onYoloEnd } : {}),
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

async function open(setup: Setup) {
  const built = distribution(setup);
  const session = await GovernanceSession.open(built.options);
  sessions.push(session);
  return { ...built, session };
}

/** A prompt that counts how often it is shown, and answers. */
function prompt(answer: "approved" | "denied") {
  const shown = { count: 0 };
  const channel = async () => {
    shown.count += 1;
    return answer;
  };
  return { shown, channel };
}

/** A tool context; with `confirm`, an interactive one whose prompts count. */
function context(confirm?: () => Promise<boolean>) {
  const notices: { message: string; level: string }[] = [];
  const status: (string | undefined)[] = [];
  const ctx = {
    hasUI: !!confirm,
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: {
      confirm: confirm ?? (async () => false),
      // The approval prompt offers three answers through `select`; the test's
      // `confirm` still decides, and counts each prompt.
      select: async (_title: string, options: string[]) =>
        (await (confirm ?? (async () => false))()) ? options[0] : "Deny",
      setStatus: (_key: string, text: string | undefined) => status.push(text),
      notify: (message: string, level: string) =>
        notices.push({ message, level }),
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

describe("--yolo in a personal session", () => {
  it("does nothing unless it is asked for", async () => {
    const { session, workspace } = await open({ mode: "personal" });
    expect(session.yolo).toBe(false);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });

  it("approves every ask without a prompt, including the user's own rules", async () => {
    const { session, workspace, events } = await open({
      mode: "personal",
      yolo: true,
    });
    expect(session.yolo).toBe(true);
    const never = prompt("denied");
    // A default ask, an enforced ask, the user's own ask over an allow, and
    // policy.default, headless (no channel) and with a channel that must stay
    // unused.
    for (const [action, resource, ruleId] of [
      ["filesystem.write", join(workspace, "a.txt"), "write"],
      ["filesystem.write", join(workspace, "kept", "a.txt"), "keep-asking"],
      ["filesystem.read", join(workspace, "private", "a.txt"), "mine"],
      ["web.request", "example.org", undefined],
    ] as const)
      for (const channel of [undefined, never.channel])
        expect(await session.decide(action, resource, channel)).toMatchObject({
          outcome: "allow",
          approval: "auto",
          ...(ruleId ? { ruleId } : {}),
        });
    expect(never.shown.count).toBe(0);
    // End to end through a governed tool, without a terminal.
    await tool(
      session,
      workspace,
      "write",
    )({ path: "headless.txt", content: "x" }, context().ctx);
    expect(readFileSync(join(workspace, "headless.txt"), "utf8")).toBe("x");
    await session.close();
    const approved = events().filter(
      (event) => event.event === "policy.auto_approved",
    );
    expect(approved.length).toBeGreaterThanOrEqual(9);
    expect(approved[0]).toMatchObject({
      user: "alice",
      decision: "approved",
      policy: "unit@1",
      rule: "write",
      detail: {
        action: "filesystem.write",
        approval: "auto",
        autoSource: "yolo",
      },
    });
    for (const event of approved)
      expect(event.detail).toMatchObject({
        approval: "auto",
        autoSource: "yolo",
      });
    // Metadata only, as for auto mode: what the governed tool decided names
    // the tool and a path class, never the file or its content.
    const written = JSON.stringify(
      approved.filter((event) => event.resource === "write"),
    );
    expect(written).toContain('"path":"workspace"');
    expect(written).not.toContain(workspace);
    expect(JSON.stringify(approved)).not.toContain('"content"');
    expect(
      events().find((event) => event.event === "policy.loaded"),
    ).toMatchObject({ detail: { yolo: true } });
    expect(
      events().filter((event) => event.event === "policy.auto_enabled"),
    ).toEqual([expect.objectContaining({ detail: { source: "yolo" } })]);
  });

  it("never changes a deny", async () => {
    const { session, workspace, home, events } = await open({
      mode: "personal",
      yolo: true,
    });
    await expect(
      tool(
        session,
        workspace,
        "read",
      )({ path: join(home, ".ssh", "id_rsa") }, context().ctx),
    ).rejects.toThrow(/rule secrets/);
    expect(
      await session.decide("shell.execute", "rm -rf /", undefined),
    ).toMatchObject({ outcome: "deny", ruleId: "no-rm" });
    // Interactive too: a deny is never put to the person, and never approved.
    const never = prompt("approved");
    expect(
      await session.decide("shell.execute", "rm -rf /", never.channel),
    ).toMatchObject({ outcome: "deny", ruleId: "no-rm" });
    expect(never.shown.count).toBe(0);
    await session.close();
    expect(
      events().some(
        (event) =>
          event.event === "policy.auto_approved" &&
          (event.rule === "secrets" || event.rule === "no-rm"),
      ),
    ).toBe(false);
    expect(events().some((event) => event.event === "tool.denied")).toBe(true);
  });

  it("stores nothing, and the next session is as it was", async () => {
    const built = distribution({ mode: "personal", yolo: true });
    const session = await GovernanceSession.open(built.options);
    sessions.push(session);
    await session.decide(
      "filesystem.write",
      join(built.workspace, "a.txt"),
      undefined,
    );
    await session.close();
    expect(existsSync(userAutoPath(built.stateDir))).toBe(false);
    // The only file in config/ is the user's own rule file the test wrote.
    expect(readdirSync(join(built.stateDir, "config"))).toEqual([
      "policy.json",
    ]);
    const later = await GovernanceSession.open({
      ...built.options,
      yolo: false,
    });
    sessions.push(later);
    expect(later.yolo).toBe(false);
    expect(later.userAuto.active).toBe(false);
    expect(
      await later.decide(
        "filesystem.write",
        join(built.workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });
});

describe("--yolo in a managed session", () => {
  it.each([undefined, "off"] as const)(
    "is refused before anything opens when policy.userAuto is %s",
    async (userAuto) => {
      const built = distribution({
        mode: "managed",
        yolo: true,
        ...(userAuto ? { userAuto } : {}),
      });
      const error = await GovernanceSession.open(built.options).then(
        () => undefined,
        (failure: unknown) => failure,
      );
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code: "POLICY_DENIED",
        message: expect.stringMatching(
          /--yolo is not allowed.*does not allow auto-approval \(policy\.userAuto is off\)/,
        ),
      });
      expect(existsSync(join(built.stateDir, "logs", "audit.jsonl"))).toBe(
        false,
      );
      expect(existsSync(userAutoPath(built.stateDir))).toBe(false);
    },
  );

  it("works like auto mode where the distribution allows it: defaults approved, enforced and user asks keep their prompt, deny stays", async () => {
    const { session, workspace, home, stateDir, events } = await open({
      mode: "managed",
      userAuto: "allowed",
      yolo: true,
    });
    expect(session.yolo).toBe(true);
    // The stored switch is a different thing, and stays off.
    expect(session.userAuto).toMatchObject({ allowed: true, active: false });
    // An ask from the distribution defaults and policy.default: headless
    // and interactive, without a prompt.
    const never = prompt("denied");
    for (const [action, resource] of [
      ["filesystem.write", join(workspace, "a.txt")],
      ["web.request", "example.org"],
    ] as const)
      for (const channel of [undefined, never.channel])
        expect(await session.decide(action, resource, channel)).toMatchObject({
          outcome: "allow",
          approval: "auto",
        });
    expect(never.shown.count).toBe(0);
    // An enforced ask and the user's own ask keep their prompt.
    for (const [action, resource] of [
      ["filesystem.write", join(workspace, "kept", "a.txt")],
      ["filesystem.read", join(workspace, "private", "a.txt")],
    ] as const) {
      expect(await session.decide(action, resource, undefined)).toMatchObject({
        outcome: "deny",
        approval: "unavailable",
      });
      const asked = prompt("denied");
      expect(
        await session.decide(action, resource, asked.channel),
      ).toMatchObject({ outcome: "deny", approval: "denied" });
      expect(asked.shown.count).toBe(1);
    }
    // Deny stays deny.
    await expect(
      tool(
        session,
        workspace,
        "read",
      )({ path: join(home, ".ssh", "id_rsa") }, context().ctx),
    ).rejects.toThrow(/rule secrets/);
    expect(
      await session.decide("shell.execute", "rm -rf /", undefined),
    ).toMatchObject({ outcome: "deny", ruleId: "no-rm" });
    await session.close();
    expect(existsSync(userAutoPath(stateDir))).toBe(false);
    expect(
      events()
        .filter((event) => event.event === "policy.auto_approved")
        .every((event) => event.detail?.autoSource === "yolo"),
    ).toBe(true);
    expect(
      events().filter((event) => event.event === "policy.auto_enabled"),
    ).toEqual([expect.objectContaining({ detail: { source: "yolo" } })]);
  });

  it("auto off passes on that the provider's approvals stay on for a session that shares them", async () => {
    const { session } = await open({
      mode: "managed",
      userAuto: "allowed",
      yolo: true,
      onYoloEnd: () =>
        "The permission provider's own approvals stay on until the other --yolo session ends.",
    });
    const off = await session.switchUserAuto(false);
    expect(session.yolo).toBe(false);
    expect(off.warning).toContain(
      "approvals stay on until the other --yolo session ends",
    );
    await session.close();
  });

  it("auto off clears stored mode and audits even if provider restoration fails", async () => {
    const { session, stateDir, events } = await open({
      mode: "managed",
      userAuto: "allowed",
      yolo: true,
      stored: true,
      onYoloEnd: () => {
        throw new Error("restore failed");
      },
    });
    const off = await session.switchUserAuto(false);
    expect(session.yolo).toBe(false);
    expect(off.active).toBe(false);
    expect(off.warning).toContain("provider override could not be restored");
    expect(existsSync(userAutoPath(stateDir))).toBe(false);
    await session.close();
    expect(events()).toContainEqual(
      expect.objectContaining({ event: "policy.auto_disabled" }),
    );
    expect(events()).toContainEqual(
      expect.objectContaining({
        event: "policy.auto_enabled",
        detail: expect.objectContaining({ providerAutoApprove: true }),
      }),
    );
  });

  it("leaves a stored auto mode as it was, on or off", async () => {
    const { session, stateDir } = await open({
      mode: "managed",
      userAuto: "allowed",
      yolo: true,
      stored: true,
    });
    await session.close();
    expect(existsSync(userAutoPath(stateDir))).toBe(true);
    const off = await open({
      mode: "managed",
      userAuto: "allowed",
      yolo: true,
    });
    await off.session.close();
    expect(existsSync(userAutoPath(off.stateDir))).toBe(false);
  });
});

describe("the --yolo indicator", () => {
  it("shows in the status line and a notice at session start, and in /auto status", async () => {
    for (const setup of [
      { mode: "personal" as const },
      { mode: "managed" as const, userAuto: "allowed" as const },
    ]) {
      const { session } = await open({ ...setup, yolo: true });
      const { handlers, commands } = hooks(session);
      const started = context(async () => false);
      await handlers.get("session_start")?.({}, started.ctx);
      expect(started.status.at(-1)).toBe("YOLO");
      expect(
        started.notices.filter((item) =>
          item.message.startsWith("yolo is on for this session only:"),
        ),
      ).toEqual([
        {
          message: expect.stringMatching(
            /^yolo is on for this session only: .*deny.* still appl.*nothing is stored; \/auto off ends it$/,
          ),
          level: "warning",
        },
      ]);
      const shown = context(async () => false);
      await commands.get("auto")?.handler("status", shown.ctx);
      expect(shown.notices.at(-1)?.message).toMatch(
        /^Auto mode: yolo is on for this session only/,
      );
      expect(shown.status.at(-1)).toBe("YOLO");
    }
  });

  it("has no indicator, and no /auto in a personal session, without it", async () => {
    const { session } = await open({ mode: "personal" });
    const { handlers, commands } = hooks(session);
    const started = context(async () => false);
    await handlers.get("session_start")?.({}, started.ctx);
    expect(started.status.at(-1)).toBeUndefined();
    expect(started.notices).toEqual([]);
    expect(commands.has("auto")).toBe(false);
  });

  it("ends with /auto off, restores the prompts, and is recorded", async () => {
    const { session, workspace, stateDir, events } = await open({
      mode: "personal",
      yolo: true,
    });
    const off = context(async () => false);
    await hooks(session).commands.get("auto")?.handler("off", off.ctx);
    expect(off.notices.at(-1)?.message).toBe("Auto mode is off.");
    expect(off.status.at(-1)).toBeUndefined();
    expect(session.yolo).toBe(false);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
    await session.close();
    expect(existsSync(userAutoPath(stateDir))).toBe(false);
    expect(
      events()
        .filter((event) => event.event.startsWith("policy.auto_"))
        .map((event) => `${event.event} ${event.detail?.source ?? ""}`),
    ).toEqual(["policy.auto_enabled yolo", "policy.auto_disabled session"]);
  });
});
