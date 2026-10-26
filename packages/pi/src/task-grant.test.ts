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
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  ApprovalAnswer,
  ApprovalChannel,
  AuditEvent,
  ManagedFetch,
} from "@piship/contracts";
import { PI_VERSION, resolveLock } from "@piship/core";
import type { TaskGrant } from "@piship/policy";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GovernanceSession } from "./governance-session.js";

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
  readonly mode?: "managed" | "personal";
  readonly yolo?: boolean;
}

async function open(setup: Setup = {}) {
  // Real path: a grant root is resolved, and macOS tmp is a symlink.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-grant-")));
  roots.push(root);
  const dir = join(root, "distribution");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  const stateDir = join(root, "state");
  for (const path of [dir, join(workspace, "kept"), home])
    mkdirSync(path, { recursive: true });
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
  const lock = {
    ...resolved,
    deployment: { ...resolved.deployment, mode: setup.mode ?? "personal" },
  } as Parameters<typeof GovernanceSession.open>[0]["lock"];
  const options = {
    lock,
    distributionDir: dir,
    stateDir,
    cwd: workspace,
    piVersion: PI_VERSION,
    interactive: false,
    ...(setup.yolo ? { yolo: true } : {}),
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key: string, template: string) => template,
    homeDir: home,
    user: "alice",
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
  return { session, workspace, home, stateDir, options, raw, events };
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
    const added = session.addGrant(grant({ paths: [workspace] }));
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
    session.addGrant(grant({ paths: [workspace] }));
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
    session.addGrant(grant({ paths: [workspace] }));
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
    session.addGrant(grant({ paths: [workspace] }));
    expect(
      await session.decide(
        "filesystem.write",
        join(workspace, "kept", "a.txt"),
        channel,
      ),
    ).toMatchObject({ outcome: "allow", approval: "approved" });
    expect(shown.count).toBe(1);
  });

  it("approves a combined prompt only when one grant covers every ask in it", async () => {
    const { session, workspace } = await open();
    session.resourceTools = new Set(["write"]);
    const { shown, channel } = counted();
    const combined = (name: string) =>
      session.withToolCall(`call-${name}`, "write", () =>
        session.decide("filesystem.write", join(workspace, name), channel),
      );
    // The path is covered, the tool ask is not: one grant per scope kind
    // does not add up to one that covers both.
    const paths = session.addGrant(grant({ paths: [workspace] }));
    session.addGrant(grant({ tools: ["write"] }));
    expect(await combined("a.txt")).toMatchObject({ approval: "approved" });
    expect(shown.count).toBe(1);
    const both = session.addGrant(
      grant({ paths: [workspace], tools: ["write"] }),
    );
    expect(await combined("b.txt")).toMatchObject({
      approval: "grant",
      grantId: both.id,
    });
    expect(shown.count).toBe(1);
    expect(
      session.listGrants().find((entry) => entry.grant.id === paths.id)?.uses,
    ).toBe(0);
  });

  it("uses the first grant that covers, and the next once it is revoked", async () => {
    const { session, workspace } = await open();
    const sub = join(workspace, "sub");
    const wide = session.addGrant(grant({ paths: [workspace] }));
    const narrow = session.addGrant(grant({ paths: [sub] }));
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
    session.addGrant(
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
    const added = session.addGrant(grant({ paths: [workspace] }));
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
    session.revokeGrant(session.addGrant(grant({ paths: [workspace] })).id);
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
    session.addGrant(
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
    session.addGrant(grant({ paths: [workspace] }));
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
    expect(() => session.addGrant(grant({ paths: [workspace] }))).toThrow(
      expect.objectContaining({ code: "POLICY_DENIED" }),
    );
    expect(session.listGrants()).toEqual([]);
  });

  it("refuses a grant validateGrant refuses, a relative or .. root, and a taken ID", async () => {
    const { session, workspace, home, stateDir } = await open();
    const refused = (scope: TaskGrant["scope"], overrides = {}) =>
      expect(() => session.addGrant(grant(scope, overrides))).toThrow(
        expect.objectContaining({ code: "CONFIG_INVALID" }),
      );
    refused({ paths: [home] });
    refused({ paths: [join(stateDir, "logs")] });
    refused({ paths: ["workspace"] });
    refused({ paths: [`${workspace}/../workspace`] });
    refused({ hosts: ["*.example.com"] });
    refused(
      { paths: [workspace] },
      { expiresAt: new Date(Date.now() + 9 * 3600_000).toISOString() },
    );
    refused({ paths: [workspace] }, { id: "has space" });
    session.addGrant(grant({ paths: [workspace] }, { id: "taken" }));
    refused({ paths: [workspace] }, { id: "taken" });
  });

  it("is audited as metadata only: never a path, host, tool, or the task label", async () => {
    const { session, workspace, events, raw } = await open();
    const canaryRoot = join(workspace, "canary-path-root");
    const created = session.addGrant(
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
    session.addGrant(
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

  it("is not seen by a subagent child, even when it asks to be inherited", async () => {
    const { session, workspace, options } = await open();
    session.addGrant(
      grant({ paths: [workspace] }, { inheritToSubagents: true }),
    );
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
