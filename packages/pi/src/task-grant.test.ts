// Task grants in governed sessions: a grant approves an `ask` only when it
// covers every ask of the prompt, never a `deny` or an ask that keeps its
// prompt, is looked up again in the approval queue, and is audited as
// metadata only.
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {
  ApprovalAnswer,
  ApprovalChannel,
  AuditEvent,
  ManagedFetch,
} from "@piship/contracts";
import { PI_VERSION, resolveLock } from "@piship/core";
import type { TaskGrant } from "@piship/policy";
import type { TaskGrantsPolicy } from "@piship/schema";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GovernanceSession } from "./governance-session.js";
import {
  authenticateSubagentChild,
  publishSubagentOwner,
} from "./launch/subagent-owner.js";
import {
  DEFAULT_GRANT_COMMANDS,
  grantCommand,
  grantMinutes,
} from "./grant-command.js";

const realpaths = vi.hoisted(() => vi.fn());
vi.mock("@piship/sandbox", async (actual) => {
  const sandbox = await actual<typeof import("@piship/sandbox")>();
  return {
    ...sandbox,
    realpathNearest: (path: string) => {
      realpaths(path);
      return sandbox.realpathNearest(path);
    },
  };
});

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
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
  '    - { id: no-secret, action: filesystem.write, resource: "workspace/secret/**", effect: deny }',
  '    - { id: keep-asking, action: filesystem.write, resource: "workspace/kept/**", effect: ask }',
  "  defaults:",
  '    - { id: write, action: filesystem.write, resource: "workspace/**", effect: ask }',
  '    - { id: tools, action: tool.execute, resource: "*", effect: ask }',
  "audit:",
  "  enabled: true",
  "  sinks:",
  "    - { id: local, type: file, required: false }",
];

interface Setup {
  /** Rules put before the fixture's distribution defaults. */
  readonly defaults?: readonly string[];
  readonly mode?: "managed" | "personal";
  readonly yolo?: boolean;
  /** The workspace's own path below the temporary root. */
  readonly workspaceAt?: readonly string[];
  readonly workspaceOverride?: string;
  readonly taskGrantId?: string;
  readonly principal?: string | null;
  readonly subagent?: Parameters<typeof GovernanceSession.open>[0]["subagent"];
  /** Run on the workspace before the session opens. */
  readonly prepare?: (workspace: string) => void;
  /** `policy.taskGrants`, as a v1alpha5 lock would carry it. */
  readonly taskGrants?: TaskGrantsPolicy;
}

async function open(setup: Setup = {}) {
  // Real path: a grant root is resolved, and macOS tmp is a symlink.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-grant-")));
  roots.push(root);
  const dir = join(root, "distribution");
  const workspace =
    setup.workspaceOverride ??
    join(root, ...(setup.workspaceAt ?? ["workspace"]));
  const home = join(root, "home");
  const stateDir = join(root, "state");
  for (const path of [dir, join(workspace, "kept"), home])
    mkdirSync(path, { recursive: true });
  setup.prepare?.(workspace);
  const manifest = join(dir, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      `runtime: { pi: "${PI_VERSION}" }`,
      "deployment: { mode: personal }",
      ...POLICY.flatMap((line) =>
        line === "  defaults:" ? [line, ...(setup.defaults ?? [])] : [line],
      ),
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  const governance = resolved.governance;
  if (!governance) throw new Error("no governance");
  const lock = {
    ...resolved,
    ...(setup.taskGrants?.declared
      ? {
          manifest: {
            ...resolved.manifest,
            sha256: `sha256-${resolved.manifest.sha256}`,
          },
        }
      : {}),
    deployment: { ...resolved.deployment, mode: setup.mode ?? "personal" },
    governance: {
      ...governance,
      manifest: {
        ...governance.manifest,
        policy: {
          ...governance.manifest.policy,
          ...(setup.taskGrants ? { taskGrants: setup.taskGrants } : {}),
        },
      },
    },
  } as Parameters<typeof GovernanceSession.open>[0]["lock"];
  const options = {
    lock,
    distributionDir: dir,
    stateDir,
    cwd: workspace,
    piVersion: PI_VERSION,
    interactive: false,
    ...(setup.yolo ? { yolo: true } : {}),
    ...(setup.taskGrantId ? { taskGrantId: setup.taskGrantId } : {}),
    ...(setup.subagent ? { subagent: setup.subagent } : {}),
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key: string, template: string) => template,
    homeDir: home,
    user: setup.principal === null ? null : (setup.principal ?? "alice"),
  };
  const session = await GovernanceSession.open(options);
  sessions.push(session);
  const raw = async () => {
    await session.audit.flush();
    return readFileSync(join(stateDir, "logs", "audit.jsonl"), "utf8");
  };
  const events = async () =>
    (await raw())
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  return { session, workspace, home, stateDir, dir, options, raw, events };
}

/** A prompt that counts how often it is shown, and approves once. */
function counted() {
  const shown = { count: 0 };
  const channel: ApprovalChannel = async () => {
    shown.count += 1;
    return "approved";
  };
  return { shown, channel };
}

/** A prompt that stays open until released, so later calls queue behind it. */
function held() {
  const shown = { count: 0 };
  let release: (answer: ApprovalAnswer) => void = () => undefined;
  let showing: () => void = () => undefined;
  const opened = new Promise<ApprovalAnswer>((resolve) => {
    release = resolve;
  });
  const asked = new Promise<void>((resolve) => {
    showing = resolve;
  });
  const channel: ApprovalChannel = async () => {
    shown.count += 1;
    showing();
    return shown.count === 1 ? opened : "approved";
  };
  return {
    shown,
    channel,
    /** Settles once the first prompt is open. */
    asked,
    release: (answer: ApprovalAnswer) => release(answer),
  };
}

let next = 0;
function grant(
  scope: TaskGrant["scope"],
  overrides: Partial<TaskGrant> = {},
): TaskGrant {
  next += 1;
  return {
    id: `g${next}`,
    task: "canary-task-label",
    createdBy: "user-command",
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    scope,
    inheritToSubagents: false,
    ...overrides,
  };
}

describe("a task grant", () => {
  it("approves an ask inside its scope without a prompt, and counts each use", async () => {
    const { session, workspace } = await open();
    const { shown, channel } = counted();
    const added = await session.addGrant(grant({ paths: [workspace] }));
    for (const name of ["a.txt", "b.txt"])
      expect(
        await session.decide(
          "filesystem.write",
          join(workspace, name),
          channel,
        ),
      ).toMatchObject({
        outcome: "allow",
        approval: "grant",
        grantId: added.id,
        ruleId: "write",
      });
    expect(shown.count).toBe(0);
    expect(session.listGrants()).toEqual([{ grant: added, uses: 2 }]);
  });

  it("is counted as grant in local metrics, not as auto, and shows no dialog", async () => {
    const { session, workspace } = await open();
    await session.addGrant(grant({ paths: [workspace] }));
    await session.decide(
      "filesystem.write",
      join(workspace, "a.txt"),
      counted().channel,
    );
    const snapshot = session.metrics.snapshot();
    expect(snapshot.approvals).toEqual({ "filesystem.write:grant": 1 });
    expect(snapshot.prompts).toBeUndefined();
  });

  it("never approves a deny", async () => {
    const { session, workspace } = await open();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "secret", "a.txt"),
        counted().channel,
      ),
    ).toMatchObject({ outcome: "deny", ruleId: "no-secret" });
  });

  it("never approves an ask that keeps its prompt", async () => {
    const { session, workspace } = await open();
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "kept", "a.txt"),
        channel,
      ),
    ).toMatchObject({ outcome: "allow", approval: "approved" });
    expect(shown.count).toBe(1);
  });

  it("approves a combined prompt only when one grant covers its file ask, the tool ask going with it", async () => {
    const { session, workspace, home } = await open();
    session.resourceTools = new Set(["write"]);
    const { shown, channel } = counted();
    const combined = (path: string) =>
      session.withToolCall(`call-${path}`, "write", () =>
        session.decide("filesystem.write", path, channel),
      );
    // A grant of the tool alone does not cover the file ask outside it.
    await session.addGrant(grant({ tools: ["write"] }));
    expect(await combined(join(home, "a.txt"))).toMatchObject({
      approval: "approved",
    });
    expect(shown.count).toBe(1);
    const paths = await session.addGrant(grant({ paths: [workspace] }));
    expect(await combined(join(workspace, "b.txt"))).toMatchObject({
      approval: "grant",
      grantId: paths.id,
    });
    expect(shown.count).toBe(1);
  });

  it("uses the first grant that covers, and the next once it is revoked", async () => {
    const { session, workspace } = await open();
    const sub = join(workspace, "sub");
    const wide = await session.addGrant(grant({ paths: [workspace] }));
    const narrow = await session.addGrant(grant({ paths: [sub] }));
    const target = join(sub, "a.txt");
    expect(
      await session.decide("filesystem.write", target, undefined),
    ).toMatchObject({ grantId: wide.id });
    expect(session.revokeGrant(wide.id)).toBe(true);
    expect(session.revokeGrant(wide.id)).toBe(false);
    expect(
      await session.decide("filesystem.write", target, undefined),
    ).toMatchObject({ grantId: narrow.id });
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "b.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
    expect(session.listGrants()).toEqual([{ grant: narrow, uses: 1 }]);
  });

  it("does not approve once it has expired", async () => {
    const { session, workspace } = await open();
    await session.addGrant(
      grant(
        { paths: [workspace] },
        { expiresAt: new Date(Date.now() + 60_000).toISOString() },
      ),
    );
    const later = Date.now() + 120_000;
    vi.spyOn(Date, "now").mockReturnValue(later);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
    expect(session.listGrants()).toEqual([]);
  });

  it("is looked up again in the approval queue: added while waiting approves, revoked or expired does not", async () => {
    const { session, workspace } = await open();
    const target = (name: string) => join(workspace, name);
    // Added while the call waits: it is approved by the grant.
    const first = held();
    const open1 = session.decide(
      "filesystem.write",
      target("a"),
      first.channel,
    );
    const queued1 = session.decide(
      "filesystem.write",
      target("b"),
      first.channel,
    );
    await first.asked;
    const added = await session.addGrant(grant({ paths: [workspace] }));
    first.release("approved");
    await open1;
    expect(await queued1).toMatchObject({
      approval: "grant",
      grantId: added.id,
    });
    expect(first.shown.count).toBe(1);
    session.revokeGrant(added.id);

    // Added, then revoked while the call waits: it prompts.
    const second = held();
    const open2 = session.decide(
      "filesystem.write",
      target("c"),
      second.channel,
    );
    const queued2 = session.decide(
      "filesystem.write",
      target("d"),
      second.channel,
    );
    await second.asked;
    session.revokeGrant(
      (await session.addGrant(grant({ paths: [workspace] }))).id,
    );
    second.release("approved");
    await open2;
    expect(await queued2).toMatchObject({ approval: "approved" });
    expect(second.shown.count).toBe(2);

    // Expired while the call waits: it prompts.
    const third = held();
    const open3 = session.decide(
      "filesystem.write",
      target("e"),
      third.channel,
    );
    const queued3 = session.decide(
      "filesystem.write",
      target("f"),
      third.channel,
    );
    await third.asked;
    await session.addGrant(
      grant(
        { paths: [workspace] },
        { expiresAt: new Date(Date.now() + 60_000).toISOString() },
      ),
    );
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 120_000);
    third.release("approved");
    await open3;
    expect(await queued3).toMatchObject({ approval: "approved" });
    expect(third.shown.count).toBe(2);
  });

  it("never changes what --yolo approves", async () => {
    const { session, workspace } = await open({ yolo: true });
    await session.addGrant(grant({ paths: [workspace] }));
    for (const name of ["a.txt", join("kept", "a.txt")])
      expect(
        await session.decide(
          "filesystem.write",
          join(workspace, name),
          undefined,
        ),
      ).toMatchObject({ outcome: "allow", approval: "auto" });
    expect(session.listGrants()[0]?.uses).toBe(0);
    expect(session.metrics.snapshot().approvals).toEqual({
      "filesystem.write:auto": 2,
    });
  });

  it("is refused in a managed distribution", async () => {
    const { session, workspace } = await open({ mode: "managed" });
    expect(session.grantsAllowed).toBe(false);
    await expect(
      session.addGrant(grant({ paths: [workspace] })),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    expect(session.listGrants()).toEqual([]);
  });

  it("refuses a grant validateGrant refuses, a relative or .. root, a taken ID, and a 33rd grant", async () => {
    const { session, workspace, home, stateDir, dir } = await open();
    const refused = (scope: TaskGrant["scope"], overrides = {}) =>
      expect(session.addGrant(grant(scope, overrides))).rejects.toMatchObject({
        code: "CONFIG_INVALID",
      });
    await refused({ paths: [home] });
    await refused({ paths: [join(stateDir, "logs")] });
    // The files that define the policy: the user's rules and the distribution.
    await refused({ paths: [join(stateDir, "config")] });
    await refused({ paths: [dir] });
    await refused({ paths: ["workspace"] });
    await refused({ paths: [`${workspace}/../workspace`] });
    await refused({ hosts: ["*.example.com"] });
    await refused(
      { paths: [workspace] },
      { expiresAt: new Date(Date.now() + 9 * 3600_000).toISOString() },
    );
    await refused({ paths: [workspace] }, { id: "has space" });
    await session.addGrant(grant({ paths: [workspace] }, { id: "taken" }));
    await refused({ paths: [workspace] }, { id: "taken" });
    for (let index = 1; index < 32; index += 1)
      await session.addGrant(grant({ tools: [`tool-${index}`] }));
    expect(session.listGrants()).toHaveLength(32);
    await refused({ tools: ["one-more"] });
  });

  it("cannot be widened through the object it was given or the one it returns", async () => {
    const { session, workspace } = await open();
    const input = grant({ paths: [join(workspace, "sub")], tools: ["read"] });
    const added = await session.addGrant(input);
    (input.scope.paths as string[]).push(workspace);
    (input.scope.tools as string[]).push("bash");
    expect(() => (added.scope.tools as string[]).push("bash")).toThrow(
      TypeError,
    );
    expect(() => (added.scope.paths as string[]).push("/")).toThrow(TypeError);
    const [listed] = session.listGrants();
    if (!listed) throw new Error("no grant listed");
    expect(() => {
      (listed as { uses: number }).uses = 99;
    }).toThrow(TypeError);
    expect(() => (listed.grant.scope.tools as string[]).push("bash")).toThrow(
      TypeError,
    );
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
    expect(
      await session.decide("tool.execute", "bash", undefined),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });

  it("expires on the monotonic clock even when the wall clock is set back", async () => {
    const { session, workspace } = await open();
    await session.addGrant(
      grant(
        { paths: [workspace] },
        { expiresAt: new Date(Date.now() + 60_000).toISOString() },
      ),
    );
    const later = performance.now() + 120_000;
    vi.spyOn(performance, "now").mockReturnValue(later);
    expect(session.listGrants()).toEqual([]);
  });

  it("is not added when a required audit sink did not take its creation event", async () => {
    const { session, workspace } = await open();
    const status = session.audit.status();
    vi.spyOn(session.audit, "status").mockReturnValue({
      ...status,
      sinks: [
        ...status.sinks,
        { id: "collector", required: true, pending: 1, dropped: 0 },
      ],
    } as never);
    await expect(
      session.addGrant(grant({ paths: [workspace] })),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
    vi.restoreAllMocks();
    expect(session.listGrants()).toEqual([]);
  });

  it("adds no realpath work to a decision while the session holds no grant", async () => {
    const { session, workspace } = await open();
    realpaths.mockClear();
    await session.decide(
      "filesystem.write",
      join(workspace, "a.txt"),
      undefined,
    );
    expect(realpaths).not.toHaveBeenCalled();
    await session.addGrant(grant({ tools: ["other"] }));
    realpaths.mockClear();
    await session.decide(
      "filesystem.write",
      join(workspace, "a.txt"),
      undefined,
    );
    expect(realpaths).toHaveBeenCalled();
  });

  it("judges configuration below the project root only, and only for writes", async () => {
    const { session, workspace } = await open({
      workspaceAt: [".claude", "worktrees", "w"],
    });
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "src", "app.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });
    for (const name of ["AGENTS.md", join(".claude", "settings.json")])
      expect(
        await session.decide("filesystem.read", join(workspace, name), channel),
      ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(0);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, ".claude", "x"),
        channel,
      ),
    ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(1);
  });

  it("treats the target of a configuration surface's link inside the tree as configuration", async () => {
    const { session, workspace } = await open({
      prepare: (workspace) => {
        mkdirSync(join(workspace, "extensions"));
        mkdirSync(join(workspace, ".pi"));
        symlinkSync(
          join(workspace, "extensions"),
          join(workspace, ".pi", "extensions"),
        );
      },
    });
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "extensions", "x.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(1);
    for (const name of [join("src", "a.ts"), "AGENTS.md"])
      expect(
        await session.decide(
          "filesystem.write",
          join(workspace, name),
          channel,
        ),
      ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(1);
  });

  it("rechecks a configuration symlink after it is retargeted in-session", async () => {
    const { session, workspace } = await open({
      prepare: (workspace) => {
        for (const name of ["first", "second", ".pi"])
          mkdirSync(join(workspace, name));
        symlinkSync(
          join(workspace, "first"),
          join(workspace, ".pi", "extensions"),
          process.platform === "win32" ? "junction" : "dir",
        );
      },
    });
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "first", "a.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(1);

    rmSync(join(workspace, ".pi", "extensions"));
    symlinkSync(
      join(workspace, "second"),
      join(workspace, ".pi", "extensions"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "second", "b.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(2);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "ordinary.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(2);
  });

  it("protects targets of configuration links created after discovery", async () => {
    const { session, workspace } = await open({
      prepare: (workspace) => {
        for (const name of ["extensions", "claude-target", ".pi"])
          mkdirSync(join(workspace, name));
      },
    });
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "extensions", "before.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });

    const linkType = process.platform === "win32" ? "junction" : "dir";
    symlinkSync(
      join(workspace, "extensions"),
      join(workspace, ".pi", "extensions"),
      linkType,
    );
    symlinkSync(
      join(workspace, "claude-target"),
      join(workspace, ".claude"),
      linkType,
    );
    for (const name of ["extensions/after.ts", "claude-target/settings.json"])
      expect(
        await session.decide(
          "filesystem.write",
          join(workspace, name),
          channel,
        ),
      ).toMatchObject({ approval: "approved" });
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "ordinary.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(2);
  });

  it("never covers a project configuration file, by its own path or a symlink's target", async () => {
    const { session, workspace } = await open();
    const { shown, channel } = counted();
    await session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "src", "app.ts"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });
    // Instruction files are ordinary edits: covered.
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "AGENTS.md"),
        channel,
      ),
    ).toMatchObject({ approval: "grant" });
    const surfaces = [
      [".piship", "policy.json"],
      [".pi", "extensions", "x.ts"],
      [".pi", "settings.json"],
      [".mcp.json"],
      [".claude", "settings.json"],
      ["sub", ".claude", "hooks", "h.sh"],
    ];
    for (const parts of surfaces)
      expect(
        await session.decide(
          "filesystem.write",
          join(workspace, ...parts),
          channel,
        ),
      ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(surfaces.length);
    mkdirSync(join(workspace, ".piship"));
    writeFileSync(join(workspace, ".piship", "policy.json"), "[]");
    symlinkSync(
      join(workspace, ".piship", "policy.json"),
      join(workspace, "notes.txt"),
    );
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "notes.txt"),
        channel,
      ),
    ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(surfaces.length + 1);
  });

  it("records one creation event for concurrent adds of one ID or past the cap", async () => {
    const { session, workspace, events } = await open();
    const created = async () =>
      (await events()).filter((event) => event.event === "policy.grant_created")
        .length;
    const same = await Promise.allSettled([
      session.addGrant(grant({ paths: [workspace] }, { id: "twice" })),
      session.addGrant(grant({ paths: [workspace] }, { id: "twice" })),
    ]);
    expect(same.map((result) => result.status).sort()).toEqual([
      "fulfilled",
      "rejected",
    ]);
    expect(await created()).toBe(1);
    for (let index = 2; index < 32; index += 1)
      await session.addGrant(grant({ tools: [`tool-${index}`] }));
    const last = await Promise.allSettled([
      session.addGrant(grant({ tools: ["last"] })),
      session.addGrant(grant({ tools: ["over"] })),
    ]);
    expect(last.map((result) => result.status)).toEqual([
      "fulfilled",
      "rejected",
    ]);
    expect(await created()).toBe(32);
  });

  it("is not added when the session closes while its event is delivered", async () => {
    const { session, workspace, events } = await open();
    const pending = grant({ paths: [workspace] });
    let closing: Promise<unknown> | undefined;
    vi.spyOn(session.audit, "flush").mockImplementationOnce(async () => {
      closing = session.close();
    });
    await expect(session.addGrant(pending)).rejects.toMatchObject({
      code: "POLICY_DENIED",
    });
    await closing;
    expect(session.listGrants()).toEqual([]);
    const lifecycle = (await events()).filter((event) =>
      ["policy.grant_created", "policy.grant_revoked"].includes(event.event),
    );
    expect(lifecycle.map((event) => event.event)).toEqual([
      "policy.grant_created",
      "policy.grant_revoked",
    ]);
    expect(lifecycle[1]).toMatchObject({
      detail: { grant: pending.id, uses: 0, reason: "session.end" },
    });
  });

  it("takes its monotonic deadline when it takes its wall-clock time, not after the audit flush", async () => {
    const { session, workspace } = await open();
    const start = performance.now();
    const clock = vi.spyOn(performance, "now").mockReturnValue(start);
    const flush = session.audit.flush.bind(session.audit);
    vi.spyOn(session.audit, "flush").mockImplementationOnce(async () => {
      clock.mockReturnValue(start + 50_000);
      await flush();
    });
    await session.addGrant(
      grant(
        { paths: [workspace] },
        { expiresAt: new Date(Date.now() + 60_000).toISOString() },
      ),
    );
    expect(session.listGrants()).toHaveLength(1);
    clock.mockReturnValue(start + 61_000);
    expect(session.listGrants()).toEqual([]);
  });

  it("records each grant still held as revoked when the session closes", async () => {
    const { session, workspace, events } = await open();
    const held = await session.addGrant(grant({ paths: [workspace] }));
    await session.close();
    expect(
      (await events()).find((event) => event.event === "policy.grant_revoked"),
    ).toMatchObject({
      detail: { grant: held.id, uses: 0, reason: "session.end" },
    });
  });

  it("is audited as metadata only: never a path, host, tool, or the task label", async () => {
    const { session, workspace, events, raw } = await open();
    const canaryRoot = join(workspace, "canary-path-root");
    const created = await session.addGrant(
      grant({
        paths: [canaryRoot],
        hosts: ["canary-host.example"],
        tools: ["canary-tool"],
      }),
    );
    await session.decide(
      "filesystem.write",
      join(canaryRoot, "canary-file.txt"),
      undefined,
    );
    session.revokeGrant(created.id);
    await session.addGrant(
      grant(
        { paths: [canaryRoot] },
        { id: "short", expiresAt: new Date(Date.now() + 60_000).toISOString() },
      ),
    );
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 120_000);
    expect(session.listGrants()).toEqual([]);
    const grantLines = (await raw())
      .split("\n")
      .filter((line) => line.includes('"policy.grant_'));
    expect(grantLines).toHaveLength(5);
    for (const canary of [
      "canary-path",
      "canary-file",
      "canary-host",
      "canary-tool",
      "canary-task",
      workspace,
    ])
      expect(grantLines.join("\n")).not.toContain(canary);
    const grantEvents = (await events()).filter((event) =>
      event.event.startsWith("policy.grant_"),
    );
    expect(grantEvents.map((event) => event.event)).toEqual([
      "policy.grant_created",
      "policy.grant_used",
      "policy.grant_revoked",
      "policy.grant_created",
      "policy.grant_expired",
    ]);
    expect(grantEvents[0]?.detail).toEqual({
      grant: created.id,
      createdBy: "user-command",
      expiresAt: created.expiresAt,
      paths: 1,
      hosts: 1,
      tools: 1,
    });
    expect(grantEvents[1]?.detail).toEqual({
      grant: created.id,
      action: "filesystem.write",
      uses: 1,
    });
    expect(grantEvents[2]?.detail).toEqual({ grant: created.id, uses: 1 });
  });

  it("rejects inheritable interactive grants and untrusted manifest provenance", async () => {
    const { session, workspace } = await open();
    await expect(
      session.addGrant(
        grant({ paths: [workspace] }, { inheritToSubagents: true }),
      ),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
    await expect(
      session.addGrant(
        grant({ paths: [workspace] }, { createdBy: "manifest" }),
      ),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
    expect(session.listGrants()).toEqual([]);
  });

  it("never exposes an interactive grant to a subagent child", async () => {
    const { session, workspace, options } = await open();
    await session.addGrant(grant({ paths: [workspace] }));
    const child = await GovernanceSession.open({
      ...options,
      subagent: { parentSession: session.sessionId },
    });
    sessions.push(child);
    expect(child.listGrants()).toEqual([]);
    expect(
      await child.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });
});

/** A UI context whose confirm answers `answer` and records what it showed. */
function ui(answer = true) {
  const dialogs: string[] = [];
  const notices: { message: string; level: string }[] = [];
  const ctx = {
    hasUI: true,
    ui: {
      confirm: async (_title: string, message: string) => {
        dialogs.push(message);
        return answer;
      },
      notify: (message: string, level: string) =>
        notices.push({ message, level }),
    },
  } as unknown as ExtensionContext;
  return { ctx, dialogs, notices };
}

describe("/grant", () => {
  it("grants the project root for 120 minutes by default, after one confirm that is not a counted prompt", async () => {
    const { session, workspace } = await open();
    const { ctx, dialogs, notices } = ui();
    const before = Date.now();
    await grantCommand(session, "", ctx);
    expect(dialogs).toHaveLength(1);
    expect(dialogs[0]).toContain(`files under ${workspace}`);
    const [entry] = session.listGrants();
    expect(entry?.grant).toMatchObject({
      createdBy: "user-command",
      scope: { paths: [workspace] },
      inheritToSubagents: false,
    });
    expect(entry?.grant.id).toMatch(/^[0-9a-f]{8}$/);
    const ttl = Date.parse(entry?.grant.expiresAt ?? "") - before;
    expect(ttl).toBeGreaterThan(119 * 60_000);
    expect(ttl).toBeLessThanOrEqual(120 * 60_000 + 5_000);
    expect(notices[0]?.message).toContain(entry?.grant.id);
    expect(session.metrics.snapshot().prompts).toBeUndefined();
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ approval: "grant" });
  });

  it("takes a path, --for, and --task, and adds nothing when the confirm is declined", async () => {
    const { session, workspace } = await open();
    const declined = ui(false);
    await grantCommand(session, ".", declined.ctx);
    expect(session.listGrants()).toEqual([]);
    const { ctx, dialogs } = ui();
    await grantCommand(session, 'add kept --for 30m --task "fix login"', ctx);
    expect(dialogs[0]).toContain("Task: fix login");
    const [entry] = session.listGrants();
    expect(entry?.grant).toMatchObject({
      task: "fix login",
      scope: { paths: [join(workspace, "kept")] },
    });
    expect(
      Date.parse(entry?.grant.expiresAt ?? "") - Date.now(),
    ).toBeLessThanOrEqual(30 * 60_000);
  });

  it("lists and revokes, one or all", async () => {
    const { session } = await open();
    const { ctx, notices } = ui();
    await grantCommand(session, "", ctx);
    await grantCommand(session, "kept", ctx);
    const [first, second] = session.listGrants();
    await grantCommand(session, "list", ctx);
    expect(notices.at(-1)?.message).toContain(`${first?.grant.id}:`);
    expect(notices.at(-1)?.message).toContain("used 0 times");
    await grantCommand(session, `revoke ${first?.grant.id}`, ctx);
    expect(session.listGrants().map(({ grant }) => grant.id)).toEqual([
      second?.grant.id,
    ]);
    await grantCommand(session, "revoke nope", ctx);
    expect(notices.at(-1)?.level).toBe("warning");
    await grantCommand(session, "revoke all", ctx);
    expect(session.listGrants()).toEqual([]);
    await grantCommand(session, "list", ctx);
    expect(notices.at(-1)?.message).toBe("No task grants in this session.");
  });

  it("refuses a bad duration, an unknown flag, or a lifetime past the cap, without a dialog", async () => {
    const { session } = await open();
    const { ctx, dialogs, notices } = ui();
    for (const args of ["--for soon", "--forever", ". --for 9h"])
      await grantCommand(session, args, ctx);
    expect(notices.map((notice) => notice.level)).toEqual([
      "error",
      "error",
      "error",
    ]);
    expect(dialogs).toEqual([]);
    expect(notices[2]?.message).toBe("A task grant lasts at most 8h here");
    expect(session.listGrants()).toEqual([]);
    expect(grantMinutes("1h30m")).toBe(90);
    expect(grantMinutes("0m")).toBeUndefined();
  });

  it("refuses home-relative tilde paths before asking for approval", async () => {
    const { session } = await open();
    const { ctx, dialogs, notices } = ui();
    for (const path of ["~", "~/notes", String.raw`~\notes`])
      await grantCommand(session, path, ctx);
    expect(notices).toHaveLength(3);
    for (const notice of notices) {
      expect(notice.level).toBe("error");
      expect(notice.message).toContain("/grant does not expand ~");
    }
    expect(dialogs).toEqual([]);
    expect(session.listGrants()).toEqual([]);
  });

  it("follows policy.taskGrants: mode, maxTtlMinutes, and actions", async () => {
    expect((await open({ mode: "managed" })).session.grantsAllowed).toBe(false);
    expect(
      (await open({ taskGrants: { mode: "off" } })).session.grantsAllowed,
    ).toBe(false);
    const { session, workspace } = await open({
      mode: "managed",
      taskGrants: {
        mode: "session",
        maxTtlMinutes: 60,
        actions: ["filesystem.read"],
      },
    });
    expect(session.grantsAllowed).toBe(true);
    const { ctx } = ui();
    await grantCommand(session, "", ctx);
    const [entry] = session.listGrants();
    expect(
      Date.parse(entry?.grant.expiresAt ?? "") - Date.now(),
    ).toBeLessThanOrEqual(60 * 60_000);
    expect(
      await session.decide(
        "filesystem.read",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ approval: "grant" });
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "a.txt"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });

  it("covers a path spelled through a symlinked root, and still checks where it resolves", async () => {
    const { session, workspace } = await open();
    const alias = join(workspace, "..", "alias");
    symlinkSync(workspace, alias);
    await session.addGrant(grant({ paths: [alias] }));
    expect(session.listGrants()[0]?.grant).toMatchObject({
      scope: { paths: [workspace] },
      pathAliases: [alias],
    });
    expect(
      await session.decide("filesystem.write", join(alias, "a.txt"), undefined),
    ).toMatchObject({ approval: "grant" });
  });
});

describe("/grant and shell commands", () => {
  it("covers one plain build or test command by default, alone or with the bash tool's ask", async () => {
    const { session } = await open();
    session.resourceTools = new Set(["bash", "write"]);
    const { ctx, dialogs } = ui();
    await grantCommand(session, "", ctx);
    expect(dialogs[0]).toContain("runs whatever code it is given");
    expect(session.listGrants()[0]?.grant.scope).toMatchObject({
      commands: [...DEFAULT_GRANT_COMMANDS],
    });
    expect(session.listGrants()[0]?.grant.scope).not.toHaveProperty("tools");
    const { shown, channel } = counted();
    for (const command of ["npm test", "pytest -q"])
      expect(
        await session.decide("shell.execute", command, channel),
      ).toMatchObject({ approval: "grant" });
    expect(
      await session.withToolCall("c1", "bash", () =>
        session.decide("shell.execute", "npm test", channel),
      ),
    ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(0);
    for (const command of [
      "npm test && curl x",
      "bash x.sh",
      "env FOO=1 npm test",
      "npm test $(curl x)",
      "npm test > ../x",
      "node x.js",
      "npx something",
      "git push origin feat",
    ])
      expect(
        await session.decide("shell.execute", command, channel),
      ).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(8);
  });

  it("--run replaces the programs, --no-run and --run none cover files only", async () => {
    const { session } = await open();
    const { ctx } = ui();
    await grantCommand(session, "--run cargo,make", ctx);
    await grantCommand(session, "kept --no-run", ctx);
    await grantCommand(session, "kept --run none", ctx);
    const scopes = session
      .listGrants()
      .map(({ grant }) => grant.scope.commands);
    expect(scopes).toEqual([["cargo", "make"], undefined, undefined]);
    const bad = ui();
    await grantCommand(session, "--run bash", bad.ctx);
    expect(bad.notices[0]?.level).toBe("error");
    expect(session.listGrants()).toHaveLength(3);
  });

  it("covers no shell command in a managed distribution whose actions leave out shell.execute, and says so", async () => {
    const { session } = await open({
      mode: "managed",
      taskGrants: {
        mode: "session",
        actions: ["filesystem.write", "tool.execute"],
      },
    });
    const { ctx, dialogs, notices } = ui();
    await grantCommand(session, "", ctx);
    expect(dialogs[0]).not.toContain("shell commands starting with");
    expect(notices[0]?.message).toContain("does not list shell.execute");
    expect(session.listGrants()[0]?.grant.scope.commands).toBeUndefined();
    expect(
      await session.decide("shell.execute", "npm test", undefined),
    ).toMatchObject({ outcome: "deny", approval: "unavailable" });
  });

  it("covers shell commands in a managed distribution that lists shell.execute", async () => {
    const { session } = await open({
      mode: "managed",
      taskGrants: { mode: "session", actions: ["shell.execute"] },
    });
    await grantCommand(session, "", ui().ctx);
    expect(
      await session.decide("shell.execute", "npm test", undefined),
    ).toMatchObject({ approval: "grant" });
  });
});

describe("a governed tool's own ask under /grant", () => {
  it("is covered only together with a file or command ask the grant covers, never alone", async () => {
    const { session, workspace, home } = await open({
      defaults: [
        '    - { id: sh, action: shell.execute, resource: "curl **", effect: allow }',
        '    - { id: rd, action: filesystem.read, resource: "**", effect: allow }',
      ],
    });
    session.resourceTools = new Set(["bash", "read"]);
    await grantCommand(session, "--no-run", ui().ctx);
    const { shown, channel } = counted();
    // The command and the file are allowed, so the tool ask is the only one.
    expect(
      await session.withToolCall("c1", "bash", () =>
        session.decide("shell.execute", "curl x", channel),
      ),
    ).toMatchObject({ approval: "approved", ruleId: "tools" });
    expect(
      await session.withToolCall("c2", "read", () =>
        session.decide("filesystem.read", join(home, "notes.txt"), channel),
      ),
    ).toMatchObject({ approval: "approved", ruleId: "tools" });
    expect(shown.count).toBe(2);
    // With a write the grant covers, the same tool ask goes with it.
    session.resourceTools = new Set(["write"]);
    expect(
      await session.withToolCall("c3", "write", () =>
        session.decide("filesystem.write", join(workspace, "a.txt"), channel),
      ),
    ).toMatchObject({ approval: "grant" });
    expect(shown.count).toBe(2);
  });

  it("says so when policy.taskGrants.actions leaves out tool.execute", async () => {
    const { session } = await open({
      mode: "managed",
      taskGrants: { mode: "session", actions: ["filesystem.write"] },
    });
    const { ctx, notices } = ui();
    await grantCommand(session, "", ctx);
    expect(notices[0]?.message).toContain("does not list tool.execute");
  });
});

describe("/grant while its folder moves", () => {
  it("stores nothing when the folder resolves elsewhere after it was confirmed", async () => {
    const { session, workspace } = await open();
    for (const name of ["a", "b"]) mkdirSync(join(workspace, name));
    const link = join(workspace, "current");
    symlinkSync(join(workspace, "a"), link);
    const { ctx, notices } = ui();
    (ctx.ui as unknown as { confirm: () => Promise<boolean> }).confirm =
      async () => {
        rmSync(link);
        symlinkSync(join(workspace, "b"), link);
        return true;
      };
    await grantCommand(session, "current", ctx);
    expect(notices[0]).toMatchObject({ level: "error" });
    expect(notices[0]?.message).toContain("run /grant again");
    expect(session.listGrants()).toEqual([]);
  });
});

const declaredPolicy: TaskGrantsPolicy = {
  mode: "session",
  maxTtlMinutes: 30,
  declared: [
    {
      id: "ci-fix",
      task: "CI repair",
      ttlMinutes: 20,
      scope: {
        paths: ["src", "kept", "secret", ".pi"],
        commands: ["npm"],
        mcp: [{ server: "docs", tools: ["search"] }],
      },
      inheritToSubagents: true,
    },
  ],
};

describe("locked headless task grants", () => {
  it("refuses managed task authority without an authenticated principal", async () => {
    await expect(
      open({
        mode: "managed",
        principal: null,
        taskGrants: declaredPolicy,
        taskGrantId: "ci-fix",
      }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
  });

  it("requires an explicit task identity, preserves deny and keepsPrompt", async () => {
    const unselected = await open({ taskGrants: declaredPolicy });
    expect(unselected.session.listGrants()).toEqual([]);
    const { session, workspace, events } = await open({
      taskGrants: declaredPolicy,
      taskGrantId: "ci-fix",
    });
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "src", "a.ts"),
        undefined,
      ),
    ).toMatchObject({ outcome: "allow", approval: "grant", grantId: "ci-fix" });
    expect(
      await session.decide("shell.execute", "npm test", undefined),
    ).toMatchObject({ outcome: "allow", approval: "grant" });
    expect(
      await session.decide("mcp.tool.call", "docs:search", undefined),
    ).toMatchObject({ outcome: "allow", approval: "grant" });
    expect(
      await session.decide("mcp.tool.call", "docs:delete", undefined),
    ).toMatchObject({ outcome: "deny" });
    for (const path of [
      join(workspace, "other.ts"),
      join(workspace, "secret", "a.ts"),
      join(workspace, "kept", "a.ts"),
      join(workspace, ".pi", "extensions", "unsafe.ts"),
    ])
      expect(
        await session.decide("filesystem.write", path, undefined),
      ).toMatchObject({ outcome: "deny" });
    const audit = await events();
    const created = audit.find(
      (event) => event.event === "policy.grant_created",
    );
    expect(created?.detail).toMatchObject({
      grant: "ci-fix",
      createdBy: "manifest",
      paths: 4,
    });
    expect(JSON.stringify(created)).not.toContain("CI repair");
    expect(JSON.stringify(created)).not.toContain(workspace);
    expect(session.revokeGrant("ci-fix")).toBe(true);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "src", "b.ts"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny" });
  });

  it("fails closed on an undeclared identity and a symlink escaping the project", async () => {
    await expect(
      open({ taskGrants: declaredPolicy, taskGrantId: "not-declared" }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    await expect(
      open({
        taskGrants: declaredPolicy,
        taskGrantId: "ci-fix",
        prepare: (workspace) => {
          const outside = join(workspace, "..", "outside");
          mkdirSync(outside);
          symlinkSync(outside, join(workspace, "src"), "dir");
        },
      }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
  });

  it("inherits only an authenticated live manifest grant and revokes in a running child", async () => {
    const parent = await open({
      taskGrants: declaredPolicy,
      taskGrantId: "ci-fix",
    });
    const binding = parent.session.manifestGrantBinding;
    expect(binding).toMatchObject({ id: "ci-fix" });
    const env: NodeJS.ProcessEnv = {};
    publishSubagentOwner(
      parent.stateDir,
      {
        session: parent.session.sessionId,
        workspace: parent.workspace,
        ...(binding ? { grant: binding } : {}),
      },
      env,
    );
    const owner = authenticateSubagentChild(parent.stateDir, env);
    const child = await open({
      taskGrants: declaredPolicy,
      workspaceOverride: parent.workspace,
      subagent: {
        parentSession: owner.session,
        ...(owner.grant ? { grant: owner.grant } : {}),
        ...(owner.grantActive ? { grantActive: owner.grantActive } : {}),
      },
    });
    const file = join(parent.workspace, "src", "child.ts");
    expect(
      await child.session.decide("filesystem.write", file, undefined),
    ).toMatchObject({
      outcome: "allow",
      approval: "grant",
    });
    expect(parent.session.revokeGrant("ci-fix")).toBe(true);
    expect(
      await child.session.decide("filesystem.write", file, undefined),
    ).toMatchObject({
      outcome: "deny",
    });
    expect(child.session.listGrants()).toEqual([]);
  });

  it("refuses forged policy bindings and does not inherit interactive approvals", async () => {
    const parent = await open({
      taskGrants: declaredPolicy,
      taskGrantId: "ci-fix",
    });
    const binding = parent.session.manifestGrantBinding;
    if (!binding) throw new Error("missing manifest grant");
    await expect(
      open({
        taskGrants: declaredPolicy,
        workspaceOverride: parent.workspace,
        subagent: {
          parentSession: parent.session.sessionId,
          grant: { ...binding, policyDigest: "0".repeat(64) },
          grantActive: () => true,
        },
      }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    const noGrant = await open({
      taskGrants: declaredPolicy,
      workspaceOverride: parent.workspace,
      subagent: { parentSession: parent.session.sessionId },
    });
    expect(noGrant.session.listGrants()).toEqual([]);
    expect(
      await noGrant.session.decide(
        "filesystem.write",
        join(parent.workspace, "src", "child.ts"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny" });
  });
  it("revokes a published child grant when the parent's monotonic deadline expires", async () => {
    const parent = await open({
      taskGrants: declaredPolicy,
      taskGrantId: "ci-fix",
    });
    const binding = parent.session.manifestGrantBinding;
    if (!binding) throw new Error("missing manifest grant");
    const env: NodeJS.ProcessEnv = {};
    publishSubagentOwner(
      parent.stateDir,
      {
        session: parent.session.sessionId,
        workspace: parent.workspace,
        grant: binding,
      },
      env,
    );
    const owner = authenticateSubagentChild(parent.stateDir, env);
    expect(owner.grantActive?.()).toBe(true);
    const later = performance.now() + 30 * 60_000;
    vi.spyOn(performance, "now").mockReturnValue(later);
    expect(parent.session.listGrants()).toEqual([]);
    expect(parent.session.manifestGrantBinding).toBeUndefined();
    expect(owner.grantActive?.()).toBe(false);
  });

  it("expires a locked grant without refreshing its lifetime", async () => {
    const { session, workspace } = await open({
      taskGrants: declaredPolicy,
      taskGrantId: "ci-fix",
    });
    const expiresAt = session.listGrants()[0]?.grant.expiresAt;
    if (!expiresAt) throw new Error("missing expiry");
    vi.spyOn(Date, "now").mockReturnValue(Date.parse(expiresAt) + 1);
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "src", "expired.ts"),
        undefined,
      ),
    ).toMatchObject({ outcome: "deny" });
    expect(session.listGrants()).toEqual([]);
  });
});
