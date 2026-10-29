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
    write: (data: Buffer) => void;
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
        write: (data) => options.onData(data),
        exit: (code) => resolve({ exitCode: code }),
        fail: (message) => reject(new Error(message)),
        signal: options.signal,
      });
    });
  const events: { kind: string; event: TaskEvent }[] = [];
  const record = (kind: string) => (event: TaskEvent) =>
    events.push({ kind, event });
  return {
    run,
    runs,
    events,
    registry: (limits = TASK_LIMITS) =>
      new TaskRegistry(
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
    const { run, runs, events, registry } = fake();
    const tasks = registry();
    const id = tasks.start(run, "npm run dev");
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
    const { run, runs, registry } = fake();
    const tasks = registry({ ...TASK_LIMITS, bufferBytes: 8 });
    const id = tasks.start(run, "x");
    await tick();
    runs[0]?.print("0123456789");
    runs[0]?.print("ab");
    expect(tasks.read(id)).toMatchObject({ output: "456789ab", dropped: 4 });
    runs[0]?.print("c".repeat(20));
    expect(tasks.read(id)).toMatchObject({ output: "cccccccc", dropped: 12 });
  });

  it("never splits a multi-byte character at a read or buffer edge", async () => {
    const { run, runs, registry } = fake();
    const tasks = registry({ ...TASK_LIMITS, bufferBytes: 8 });
    const id = tasks.start(run, "x");
    await tick();
    const euro = Buffer.from("€"); // e2 82 ac
    // A read boundary inside a character waits for the rest of it.
    runs[0]?.write(Buffer.concat([Buffer.from("a"), euro.subarray(0, 2)]));
    expect(tasks.read(id)).toMatchObject({ output: "a", dropped: 0 });
    runs[0]?.write(euro.subarray(2));
    expect(tasks.read(id)).toMatchObject({ output: "€", dropped: 0 });
    // The buffer edge cuts the next character: its tail is dropped, not U+FFFD.
    runs[0]?.write(Buffer.from("€€€"));
    const report = tasks.read(id);
    expect(report?.output).toBe("€€");
    expect(report?.dropped).toBe(3);
    // A stream that ends mid-character shows what it has.
    runs[0]?.write(euro.subarray(0, 1));
    expect(tasks.read(id)?.output).toBe("");
    runs[0]?.exit(0);
    await tasks.settled(id);
    expect(tasks.read(id)?.output).toBe("\ufffd");
  });

  it("stops a task through its signal and records why", async () => {
    const { run, runs, events, registry } = fake();
    const tasks = registry();
    const id = tasks.start(run, "sleep 100");
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
    const { run, runs, events, registry } = fake();
    const tasks = registry({ ...TASK_LIMITS, maxTasks: 2 });
    const first = tasks.start(run, "a");
    tasks.start(run, "b");
    expect(() => tasks.start(run, "c")).toThrow(TaskLimitError);
    expect(events.at(-1)).toMatchObject({
      kind: "refused",
      event: { command: "c", reason: "limit" },
    });
    await tick();
    runs[0]?.exit(1);
    await tasks.settled(first);
    expect(tasks.read(first)).toMatchObject({ status: "exited", exitCode: 1 });
    expect(() => tasks.start(run, "c")).not.toThrow();
  });

  it("passes the default timeout, caps a longer one, and reports a timeout", async () => {
    const { run, runs, registry } = fake();
    const tasks = registry();
    tasks.start(run, "a");
    tasks.start(run, "b", 10 * 60 * 60);
    const short = tasks.start(run, "c", 5);
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
    const { run, runs, registry } = fake();
    const tasks = registry();
    const id = tasks.start(run, "a");
    await tick();
    runs[0]?.fail("Working directory does not exist: /x");
    await tasks.settled(id);
    expect(tasks.read(id)).toMatchObject({
      status: "failed",
      output: "\nWorking directory does not exist: /x\n",
    });
  });

  it("stops every task on close and refuses new ones", async () => {
    const { run, runs, events, registry } = fake();
    const tasks = registry();
    tasks.start(run, "a");
    tasks.start(run, "b");
    await tick();
    await tasks.closeAll();
    expect(runs.every((run) => run.signal.aborted)).toBe(true);
    expect(
      events
        .filter((item) => item.kind === "stop")
        .map((item) => item.event.reason),
    ).toEqual(["close", "close"]);
    expect(tasks.running).toBe(0);
    expect(() => tasks.start(run, "c")).toThrow(/closing/);
  });

  it("does not wait forever for a runner that ignores its abort", async () => {
    const tasks = new TaskRegistry(
      { start() {}, exit() {}, stop() {}, refused() {} },
      { ...TASK_LIMITS, stopWaitMs: 10 },
    );
    const id = tasks.start(() => new Promise(() => {}), "stuck");
    expect(await tasks.stop(id)).toMatchObject({ status: "stopped" });
  });

  it.each([-1, 0, Number.NaN, Number.POSITIVE_INFINITY, "5"])(
    "gives a timeout of %s the default",
    async (timeout) => {
      const { run, runs, registry } = fake();
      registry().start(run, "a", timeout as number);
      await tick();
      expect(runs[0]?.timeout).toBe(TASK_LIMITS.defaultTimeoutSeconds);
    },
  );

  it("drops a finished task once its last output was read, and keeps at most 16 finished", async () => {
    const { run, runs, registry } = fake();
    const tasks = registry();
    const id = tasks.start(run, "a");
    await tick();
    runs[0]?.print("bye");
    runs[0]?.exit(0);
    await tasks.settled(id);
    expect(tasks.read(id)).toMatchObject({ status: "exited", output: "bye" });
    expect(tasks.read(id)).toBeUndefined();
    expect(tasks.gone(id)).toBe("read");
    expect(tasks.gone("never")).toBeUndefined();
    const ids: string[] = [];
    for (let index = 0; index < 20; index++) {
      const next = tasks.start(run, `t${index}`);
      ids.push(next);
      await tick();
      runs.at(-1)?.exit(0);
      await tasks.settled(next);
    }
    expect(ids.slice(0, 4).map((item) => tasks.read(item))).toEqual([
      undefined,
      undefined,
      undefined,
      undefined,
    ]);
    expect(tasks.read(ids[19] as string)?.status).toBe("exited");
    expect(tasks.gone(ids[0] as string)).toBe("dropped");
  });

  it("holds a stopped task's slot until its process has ended", async () => {
    let finish: () => void = () => {};
    const slow: TaskRunner = () =>
      new Promise((resolve) => {
        finish = () => resolve({ exitCode: null });
      });
    const tasks = new TaskRegistry(
      { start() {}, exit() {}, stop() {}, refused() {} },
      { ...TASK_LIMITS, maxTasks: 1, stopWaitMs: 10 },
    );
    const id = tasks.start(slow, "a");
    await tasks.stop(id);
    expect(tasks.running).toBe(1);
    expect(() => tasks.start(slow, "b")).toThrow(TaskLimitError);
    finish();
    await tasks.settled(id);
    expect(tasks.running).toBe(0);
  });

  it("records a task still ending at close during closeAll, and nothing after", async () => {
    let finish: () => void = () => {};
    const events: string[] = [];
    const tasks = new TaskRegistry(
      {
        start: () => events.push("start"),
        exit: () => events.push("exit"),
        stop: (event) => events.push(`stop:${event.reason}`),
        refused: () => events.push("refused"),
      },
      { ...TASK_LIMITS, stopWaitMs: 10 },
    );
    const id = tasks.start(
      () =>
        new Promise((resolve) => {
          finish = () => resolve({ exitCode: null });
        }),
      "a",
    );
    await tasks.closeAll();
    expect(events).toEqual(["start", "stop:close"]);
    finish();
    await tasks.settled(id);
    expect(events).toEqual(["start", "stop:close"]);
  });
});
