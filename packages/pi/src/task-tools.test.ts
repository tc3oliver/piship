// Background tasks are decided exactly as the bash tool decides a command:
// the same deny, ask, grant, plan mode, and headless refusal, and no prompt
// of their own. They run until stopped, their timeout, or the session's end.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ExtensionToolContext,
  SessionManager,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import type { AuditEvent, ManagedFetch } from "@piship/contracts";
import { PI_VERSION, resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { GovernanceSession } from "./governance-session.js";
import { governedTools } from "./governed-tools.js";
import { taskTools } from "./task-tools.js";

/** The generic task tests use POSIX commands; Windows has its own Bash test. */
const tasksRun = process.platform !== "win32";

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
  '    - { id: no-rm, action: shell.execute, resource: "rm **", effect: deny }',
  "  defaults:",
  '    - { id: echo, action: shell.execute, resource: "echo *", effect: allow }',
  '    - { id: sleepy, action: shell.execute, resource: "sleep *", effect: allow }',
  '    - { id: tools, action: tool.execute, resource: "*", effect: allow }',
  "audit:",
  "  enabled: true",
  "  sinks:",
  "    - { id: local, type: file, required: false }",
];

async function open(options: { subagent?: boolean } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-tasks-")));
  roots.push(root);
  const dir = join(root, "distribution");
  const workspace = join(root, "workspace");
  const stateDir = join(root, "state");
  for (const path of [dir, workspace, join(root, "home")])
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
  const session = await GovernanceSession.open({
    lock: resolveLock(manifest) as Parameters<
      typeof GovernanceSession.open
    >[0]["lock"],
    distributionDir: dir,
    stateDir,
    cwd: workspace,
    piVersion: PI_VERSION,
    interactive: false,
    ...(options.subagent ? { subagent: { parentSession: "parent" } } : {}),
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key: string, template: string) => template,
    homeDir: join(root, "home"),
    user: "alice",
  });
  sessions.push(session);
  const events = async () => {
    await session.audit.flush();
    return readFileSync(join(stateDir, "logs", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
  };
  const tools = governedTools(session, workspace);
  const call = (name: string) => (params: unknown, ctx: ExtensionToolContext) =>
    (tools.find((tool) => tool.name === name) as ToolDefinition).execute(
      `call-${name}-${Math.random()}`,
      params as never,
      undefined,
      undefined,
      ctx,
    );
  return { session, workspace, tools, call, events };
}

/** A tool context; with `answer`, an interactive one whose prompts count. */
function context(answer?: boolean) {
  const prompts = { count: 0 };
  const ctx = {
    hasUI: answer !== undefined,
    sessionManager: SessionManager.inMemory(tmpdir()),
    ui: {
      confirm: async () => {
        prompts.count += 1;
        return answer === true;
      },
      select: async (_title: string, options: string[]) => {
        prompts.count += 1;
        return answer ? options[0] : "Deny";
      },
      setStatus: () => {},
      notify: () => {},
    },
  } as unknown as ExtensionToolContext;
  return { ctx, prompts };
}

/** How a tool call ended: its error text, or "ok". */
async function outcome(run: Promise<unknown>): Promise<string> {
  try {
    await run;
    return "ok";
  } catch (error) {
    return (error as Error).message;
  }
}

const text = (result: unknown) =>
  (result as { content: { text: string }[] }).content[0]?.text ?? "";

describe("task_start decides a command as bash does", () => {
  it.runIf(tasksRun).each([
    ["an allowed command", "echo hi", undefined, "ok"],
    ["a denied command", "rm -rf x", true, "not allowed by unit@1 rule no-rm"],
    ["an ask, approved", "true", true, "ok"],
    ["an ask, declined", "true", false, "not allowed"],
    ["an ask, headless", "true", undefined, "approval needs an interactive"],
  ])("%s", async (_name, command, answer, expected) => {
    const { call } = await open();
    const results: string[] = [];
    const counts: number[] = [];
    for (const tool of ["bash", "task_start"]) {
      const { ctx, prompts } = context(answer);
      results.push(await outcome(call(tool)({ command }, ctx)));
      counts.push(prompts.count);
    }
    for (const result of results) expect(result).toContain(expected);
    // No prompt of its own: as many as bash, each a single combined one.
    expect(counts[1]).toBe(counts[0]);
    expect(counts[0]).toBeLessThanOrEqual(1);
  });

  it.runIf(tasksRun)(
    "is refused in Plan mode, as bash is, while reading and stopping a task are not",
    async () => {
      const { session, call } = await open();
      const started = await call("task_start")(
        { command: "sleep 30" },
        context().ctx,
      );
      const id = (started as { details: { id: string } }).details.id;
      session.workflowMode = "plan";
      for (const tool of ["bash", "task_start"])
        expect(
          await outcome(call(tool)({ command: "echo hi" }, context(true).ctx)),
        ).toMatch(/Plan mode/);
      expect(text(await call("task_output")({ id }, context().ctx))).toContain(
        ": running",
      );
      expect(text(await call("task_stop")({ id }, context().ctx))).toContain(
        ": stopped",
      );
    },
  );

  it.runIf(tasksRun)(
    "is covered by a task grant that covers the command, with no prompt",
    async () => {
      const { session, workspace, call } = await open();
      await session.addGrant({
        id: "g1",
        task: "",
        createdBy: "user-command",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        scope: { paths: [workspace], commands: ["true"] },
        inheritToSubagents: false,
      });
      for (const tool of ["bash", "task_start"]) {
        const { ctx, prompts } = context(false);
        expect(await outcome(call(tool)({ command: "true" }, ctx))).toBe("ok");
        expect(prompts.count).toBe(0);
      }
    },
  );

  it("defers its tool ask to the command's decision, as bash does", async () => {
    const { session } = await open();
    expect([...session.resourceTools]).toEqual(
      expect.arrayContaining(["bash", "task_start"]),
    );
    expect(session.resourceTools.has("task_output")).toBe(false);
  });

  it.runIf(process.platform === "win32")(
    "runs uncontained tasks with Pi Bash quoting, without a separate approval",
    async () => {
      const { session, call } = await open();
      expect(session.sandbox.report.level).not.toBe("enforced");
      const { ctx, prompts } = context();
      const started = await call("task_start")(
        { command: "echo 'piship-bash-ok'" },
        ctx,
      );
      const first = started as {
        details: { id: string; status: string; exitCode: number | null };
      };
      let output = text(started);
      if (first.details.status === "running") {
        await session.backgroundTasks!.settled(first.details.id);
        const finished = await call("task_output")(
          { id: first.details.id },
          ctx,
        );
        expect((finished as typeof first).details).toMatchObject({
          status: "exited",
          exitCode: 0,
        });
        output += "\n" + text(finished);
      } else {
        expect(first.details).toMatchObject({ status: "exited", exitCode: 0 });
      }
      expect(output).toMatch(/\npiship-bash-ok(?:\r?\n|$)/);
      expect(output).not.toMatch(/\n'piship-bash-ok'(?:\r?\n|$)/);
      expect(prompts.count).toBe(0);
    },
    25_000,
  );

  it.runIf(process.platform === "win32")(
    "stops a detached descendant of an uncontained Windows task",
    async () => {
      const { session, workspace, call } = await open();
      expect(session.sandbox.report.level).not.toBe("enforced");
      writeFileSync(
        join(workspace, "child.cjs"),
        [
          'const { appendFileSync, existsSync } = require("node:fs");',
          "setInterval(() => {",
          '  if (existsSync("stop")) return;',
          '  appendFileSync("heartbeat", ".");',
          "}, 50);",
        ].join("\n"),
      );
      writeFileSync(
        join(workspace, "parent.cjs"),
        [
          'const { spawn } = require("node:child_process");',
          'spawn(process.execPath, ["child.cjs"], { detached: true, stdio: "ignore" }).unref();',
          "setInterval(() => {}, 1000);",
        ].join("\n"),
      );
      const started = await call("task_start")(
        { command: "node parent.cjs" },
        context(true).ctx,
      );
      const id = (started as { details: { id: string } }).details.id;
      const heartbeat = join(workspace, "heartbeat");
      const size = () => (existsSync(heartbeat) ? statSync(heartbeat).size : 0);
      try {
        const deadline = Date.now() + 15_000;
        while (size() === 0 && Date.now() < deadline)
          await new Promise((done) => setTimeout(done, 100));
        expect(size()).toBeGreaterThan(0);
        const stopped = await call("task_stop")({ id }, context().ctx);
        expect(
          (stopped as { details: { status: string } }).details.status,
        ).toBe("stopped");
        await new Promise((done) => setTimeout(done, 300));
        const afterStop = size();
        await new Promise((done) => setTimeout(done, 400));
        expect(size()).toBe(afterStop);
      } finally {
        // If containment fails, let the escaped child stop itself.
        writeFileSync(join(workspace, "stop"), "");
        await session.backgroundTasks?.stop(id);
      }
    },
    30_000,
  );

  it("is not offered to a subagent child", async () => {
    const { tools } = await open({ subagent: true });
    expect(tools.map((tool) => tool.name)).not.toContain("task_start");
    expect(tools.map((tool) => tool.name)).toContain("bash");
  });
});

describe.runIf(tasksRun)("a background task", () => {
  it("redacts credential shapes in what the model reads", async () => {
    const { call } = await open();
    const interactive = context(true).ctx;
    const first = await call("task_start")(
      { command: "echo 'Authorization: Bearer abcdefghijklmnop' && sleep 30" },
      interactive,
    );
    expect(text(first)).toContain("[REDACTED]");
    expect(text(first)).not.toContain("abcdefghijklmnop");
    const id = (first as { details: { id: string } }).details.id;
    await call("task_stop")({ id }, interactive);
  });

  it("returns at once with its first output, reads new output, and stops", async () => {
    const { call, events } = await open();
    const { ctx } = context();
    const started = await call("task_start")(
      { command: "echo ready && sleep 30" },
      ctx,
    ).catch((error: Error) => error.message);
    // `&&` chains past the echo rule: headless, it is refused.
    expect(started).toContain("approval needs an interactive");
    const interactive = context(true).ctx;
    const first = await call("task_start")(
      { command: "echo ready && sleep 30" },
      interactive,
    );
    expect(text(first)).toMatch(/^Started\. Task [0-9a-f]{16}: running\nready/);
    const id = (first as { details: { id: string } }).details.id;
    expect(text(await call("task_output")({ id }, ctx))).toContain(
      "(no new output)",
    );
    const stopped = await call("task_stop")({ id }, ctx);
    expect(text(stopped)).toContain(`Task ${id}: stopped`);
    const kinds = (await events())
      .filter((event) => event.event.startsWith("task."))
      .map((event) => [event.event, event.detail?.status]);
    expect(kinds).toEqual([
      ["task.start", "running"],
      ["task.stop", "stopped"],
    ]);
    // Metadata only: the command is not recorded without capture opt-in.
    expect(JSON.stringify(await events())).not.toContain("sleep 30");
  });

  it("reports a task that ended, with its exit code, and then that it was shown", async () => {
    const { call } = await open();
    const { ctx } = context();
    const result = await call("task_start")({ command: "echo done" }, ctx);
    expect(text(result)).toMatch(/: exited \(exit code 0\)\ndone/);
    const id = (result as { details: { id: string } }).details.id;
    expect(await outcome(call("task_output")({ id }, ctx))).toBe(
      `Task ${id} already ended, and its last output was already shown.`,
    );
  });

  it("refuses an id that is not this session's", async () => {
    const { call } = await open();
    const other = await open();
    const { ctx } = context();
    const started = await other.call("task_start")(
      { command: "sleep 30" },
      ctx,
    );
    const id = (started as { details: { id: string } }).details.id;
    for (const tool of ["task_output", "task_stop"])
      expect(await outcome(call(tool)({ id }, ctx))).toContain(
        `No background task ${id} in this session`,
      );
  });

  it("refuses a fifth running task before it asks anything", async () => {
    const { call, events } = await open();
    const { ctx } = context();
    for (let index = 0; index < 4; index++)
      await call("task_start")({ command: "sleep 30" }, ctx);
    const prompted = context(true);
    expect(
      await outcome(call("task_start")({ command: "true" }, prompted.ctx)),
    ).toContain("4 background tasks are already running");
    expect(prompted.prompts.count).toBe(0);
    expect(
      (await events())
        .filter((event) => event.event === "task.start")
        .map((event) => event.decision),
    ).toEqual(["allowed", "allowed", "allowed", "allowed", "denied"]);
  });

  it("is stopped when the session closes", async () => {
    const { session, call, events } = await open();
    const { ctx } = context();
    await call("task_start")({ command: "sleep 30" }, ctx);
    await session.close();
    const tasks = session.backgroundTasks;
    expect(tasks?.running).toBe(0);
    expect(
      (await events()).find((event) => event.event === "task.stop")?.detail,
    ).toMatchObject({ reason: "close" });
  });
});
