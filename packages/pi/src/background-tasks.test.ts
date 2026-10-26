import { describe, expect, it } from "vitest";
import {
  TASK_LIMITS,
  type TaskEvent,
  TaskLimitError,
  TaskRegistry,
  type TaskRunner,
} from "./background-tasks.js";

/** A runner whose commands run until the test ends or aborts them. */
function fake() {
  const runs: {
    command: string;
    timeout: number;
    print: (text: string) => void;
    exit: (code: number | null) => void;
    fail: (message: string) => void;
    signal: AbortSignal;
  }[] = [];
  const run: TaskRunner = (command, options) =>
    new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () =>
        reject(new Error("aborted")),
      );
      runs.push({
        command,
        timeout: options.timeout,
        print: (text) => options.onData(Buffer.from(text)),
        exit: (code) => resolve({ exitCode: code }),
        fail: (message) => reject(new Error(message)),
        signal: options.signal,
      });
    });
  const events: { kind: string; event: TaskEvent }[] = [];
  const record = (kind: string) => (event: TaskEvent) =>
    events.push({ kind, event });
  return {
    runs,
    events,
    registry: (limits = TASK_LIMITS) =>
      new TaskRegistry(
        run,
        {
          start: record("start"),
          exit: record("exit"),
          stop: record("stop"),
          refused: record("refused"),
        },
        limits,
      ),
  };
}

const tick = () => new Promise((done) => setTimeout(done, 0));

describe("TaskRegistry", () => {
  it("runs a task in the background and reads its output once, in order", async () => {
    const { runs, events, registry } = fake();
    const tasks = registry();
    const id = tasks.start("npm run dev");
    expect(id).toMatch(/^[0-9a-f]{16}$/);
    await tick();
    runs[0]?.print("ready ");
    runs[0]?.print("on 3000\n");
    expect(tasks.read(id)).toMatchObject({
      status: "running",
      output: "ready on 3000\n",
      dropped: 0,
    });
    expect(tasks.read(id)?.output).toBe("");
    runs[0]?.print("GET /\n");
    runs[0]?.exit(0);
    await tasks.settled(id);
    expect(tasks.read(id)).toMatchObject({
      status: "exited",
      exitCode: 0,
      output: "GET /\n",
    });
    expect(events.map((item) => item.kind)).toEqual(["start", "exit"]);
    expect(events[1]?.event).toMatchObject({
      id,
      status: "exited",
      exitCode: 0,
    });
  });

  it("keeps only the newest output and says how much it dropped", async () => {
    const { runs, registry } = fake();
    const tasks = registry({ ...TASK_LIMITS, bufferBytes: 8 });
    const id = tasks.start("x");
    await tick();
    runs[0]?.print("0123456789");
    runs[0]?.print("ab");
    expect(tasks.read(id)).toMatchObject({ output: "456789ab", dropped: 4 });
    runs[0]?.print("c".repeat(20));
    expect(tasks.read(id)).toMatchObject({ output: "cccccccc", dropped: 12 });
  });

  it("stops a task through its signal and records why", async () => {
    const { runs, events, registry } = fake();
    const tasks = registry();
    const id = tasks.start("sleep 100");
    await tick();
    runs[0]?.print("tail");
    expect(await tasks.stop(id)).toMatchObject({
      status: "stopped",
      output: "tail",
    });
    expect(runs[0]?.signal.aborted).toBe(true);
    expect(events.at(-1)).toMatchObject({
      kind: "stop",
      event: { id, status: "stopped", reason: "user" },
    });
    expect(await tasks.stop("unknown")).toBeUndefined();
    expect(tasks.read("unknown")).toBeUndefined();
  });

  it("refuses past the running limit, and frees a slot when a task ends", async () => {
    const { runs, events, registry } = fake();
    const tasks = registry({ ...TASK_LIMITS, maxTasks: 2 });
    const first = tasks.start("a");
    tasks.start("b");
    expect(() => tasks.start("c")).toThrow(TaskLimitError);
    expect(events.at(-1)).toMatchObject({
      kind: "refused",
      event: { command: "c", reason: "limit" },
    });
    await tick();
    runs[0]?.exit(1);
    await tasks.settled(first);
    expect(tasks.read(first)).toMatchObject({ status: "exited", exitCode: 1 });
    expect(() => tasks.start("c")).not.toThrow();
  });

  it("passes the default timeout, caps a longer one, and reports a timeout", async () => {
    const { runs, registry } = fake();
    const tasks = registry();
    tasks.start("a");
    tasks.start("b", 10 * 60 * 60);
    const short = tasks.start("c", 5);
    await tick();
    expect(runs.map((run) => run.timeout)).toEqual([
      TASK_LIMITS.defaultTimeoutSeconds,
      TASK_LIMITS.maxTimeoutSeconds,
      5,
    ]);
    runs[2]?.fail("timeout:5");
    await tasks.settled(short);
    expect(tasks.read(short)?.status).toBe("timed-out");
  });

  it("reports a runner failure as failed, with its message in the output", async () => {
    const { runs, registry } = fake();
    const tasks = registry();
    const id = tasks.start("a");
    await tick();
    runs[0]?.fail("Working directory does not exist: /x");
    await tasks.settled(id);
    expect(tasks.read(id)).toMatchObject({
      status: "failed",
      output: "\nWorking directory does not exist: /x\n",
    });
  });

  it("stops every task on close and refuses new ones", async () => {
    const { runs, events, registry } = fake();
    const tasks = registry();
    tasks.start("a");
    tasks.start("b");
    await tick();
    await tasks.closeAll();
    expect(runs.every((run) => run.signal.aborted)).toBe(true);
    expect(
      events
        .filter((item) => item.kind === "stop")
        .map((item) => item.event.reason),
    ).toEqual(["close", "close"]);
    expect(tasks.running).toBe(0);
    expect(() => tasks.start("c")).toThrow(/closing/);
  });

  it("does not wait forever for a runner that ignores its abort", async () => {
    const tasks = new TaskRegistry(
      () => new Promise(() => {}),
      { start() {}, exit() {}, stop() {}, refused() {} },
      { ...TASK_LIMITS, stopWaitMs: 10 },
    );
    const id = tasks.start("stuck");
    expect(await tasks.stop(id)).toMatchObject({ status: "stopped" });
  });
});
