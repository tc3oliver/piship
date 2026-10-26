// Background tasks of one governed session: commands started by `task_start`
// that keep running after the tool call returns. Each keeps the newest
// output in a bounded buffer; the registry stops every task when the session
// closes. Policy is decided before a task reaches `start`.
import { randomBytes } from "node:crypto";

/** Runs one command until it exits, the signal aborts, or the timeout passes. */
export type TaskRunner = (
  command: string,
  options: {
    readonly onData: (data: Buffer) => void;
    readonly signal: AbortSignal;
    /** Seconds, as the sandbox and Pi's bash tool take it. */
    readonly timeout: number;
  },
) => Promise<{ exitCode: number | null }>;

export type TaskStatus =
  | "running"
  | "exited"
  | "stopped"
  | "timed-out"
  | "failed";

export interface TaskLimits {
  /** Tasks running at once. */
  readonly maxTasks: number;
  /** Newest output kept per task. */
  readonly bufferBytes: number;
  readonly defaultTimeoutSeconds: number;
  readonly maxTimeoutSeconds: number;
  /** How long `stop` waits for a stopped task to end before it reports. */
  readonly stopWaitMs: number;
}

export const TASK_LIMITS: TaskLimits = {
  maxTasks: 4,
  bufferBytes: 256 * 1024,
  defaultTimeoutSeconds: 30 * 60,
  maxTimeoutSeconds: 2 * 60 * 60,
  stopWaitMs: 5000,
};

/** What a task's events record: metadata, plus the command for capture opt-in. */
export interface TaskEvent {
  readonly id: string;
  readonly command: string;
  readonly status: TaskStatus;
  readonly exitCode: number | null;
  readonly reason?: "user" | "close" | "limit";
  readonly durationMs: number;
}

export interface TaskEvents {
  start(task: TaskEvent): void;
  exit(task: TaskEvent): void;
  stop(task: TaskEvent): void;
  refused(task: TaskEvent): void;
}

/** A task's state and the output it printed since the last read. */
export interface TaskReport {
  readonly id: string;
  readonly status: TaskStatus;
  readonly exitCode: number | null;
  readonly output: string;
  /** Bytes printed since the last read that the buffer no longer holds. */
  readonly dropped: number;
}

/** The newest `limit` bytes of a stream, and how many were written in all. */
class Tail {
  #chunks: Buffer[] = [];
  #held = 0;
  written = 0;

  constructor(readonly limit: number) {}

  append(data: Buffer): void {
    this.written += data.length;
    const chunk =
      data.length > this.limit ? data.subarray(data.length - this.limit) : data;
    this.#chunks.push(chunk);
    this.#held += chunk.length;
    while (this.#held > this.limit) {
      const first = this.#chunks[0] as Buffer;
      const over = this.#held - this.limit;
      if (first.length <= over) {
        this.#chunks.shift();
        this.#held -= first.length;
      } else {
        this.#chunks[0] = first.subarray(over);
        this.#held -= over;
      }
    }
  }

  /** Everything written from byte `offset` on that is still held. */
  since(offset: number): { text: string; dropped: number } {
    const start = this.written - this.#held;
    const skip = Math.max(0, offset - start);
    return {
      text: Buffer.concat(this.#chunks).subarray(skip).toString("utf8"),
      dropped: Math.max(0, start - offset),
    };
  }
}

class Task {
  readonly id = randomBytes(8).toString("hex");
  readonly controller = new AbortController();
  readonly tail: Tail;
  readonly startedAt = Date.now();
  status: TaskStatus = "running";
  exitCode: number | null = null;
  read = 0;
  stopReason: TaskEvent["reason"];
  done: Promise<void> = Promise.resolve();

  constructor(
    readonly command: string,
    bufferBytes: number,
  ) {
    this.tail = new Tail(bufferBytes);
  }

  event(): TaskEvent {
    return {
      id: this.id,
      command: this.command,
      status: this.status,
      exitCode: this.exitCode,
      ...(this.stopReason ? { reason: this.stopReason } : {}),
      durationMs: Date.now() - this.startedAt,
    };
  }
}

export class TaskLimitError extends Error {}

export class TaskRegistry {
  readonly #tasks = new Map<string, Task>();
  #closed = false;

  constructor(
    readonly events: TaskEvents,
    readonly limits: TaskLimits = TASK_LIMITS,
  ) {}

  /** Tasks still running. */
  get running(): number {
    return [...this.#tasks.values()].filter((task) => task.status === "running")
      .length;
  }

  /**
   * Start `command` in the background. Throws TaskLimitError (and records
   * the refusal) when the registry is closed or as many tasks as it allows
   * are running.
   */
  start(run: TaskRunner, command: string, timeoutSeconds?: number): string {
    const refusal = this.refusal(command);
    if (refusal) throw new TaskLimitError(refusal);
    const task = new Task(command, this.limits.bufferBytes);
    const timeout = Math.min(
      timeoutSeconds ?? this.limits.defaultTimeoutSeconds,
      this.limits.maxTimeoutSeconds,
    );
    this.#tasks.set(task.id, task);
    this.events.start(task.event());
    task.done = Promise.resolve()
      .then(() =>
        run(command, {
          onData: (data) => task.tail.append(data),
          signal: task.controller.signal,
          timeout,
        }),
      )
      .then(
        (result) => {
          task.exitCode = result.exitCode;
          if (task.status === "running") task.status = "exited";
        },
        (error: unknown) => {
          if (task.status !== "running") return;
          const message = error instanceof Error ? error.message : "";
          task.status = message.startsWith("timeout:")
            ? "timed-out"
            : task.controller.signal.aborted
              ? "stopped"
              : "failed";
          if (task.status === "failed")
            task.tail.append(Buffer.from(`\n${message || "failed"}\n`));
        },
      )
      .then(() =>
        (task.stopReason ? this.events.stop : this.events.exit).call(
          this.events,
          task.event(),
        ),
      );
    return task.id;
  }

  /**
   * Why `command` cannot start now (the registry is closed or full), with
   * the refusal recorded; undefined when it can.
   */
  refusal(command: string): string | undefined {
    if (!this.#closed && this.running < this.limits.maxTasks) return undefined;
    const task = new Task(command, this.limits.bufferBytes);
    task.status = "failed";
    task.stopReason = "limit";
    this.events.refused(task.event());
    return this.#closed
      ? "The session is closing; no background task can start"
      : `${this.limits.maxTasks} background tasks are already running; stop one with task_stop first`;
  }

  /** The task's state and its output since the last read; undefined for an unknown id. */
  read(id: string): TaskReport | undefined {
    const task = this.#tasks.get(id);
    if (!task) return undefined;
    const { text, dropped } = task.tail.since(task.read);
    task.read = task.tail.written;
    return {
      id,
      status: task.status,
      exitCode: task.exitCode,
      output: text,
      dropped,
    };
  }

  /** Settles once the task has ended (or at once for an unknown id). */
  async settled(id: string): Promise<void> {
    await this.#tasks.get(id)?.done;
  }

  /** Stop a task and its process tree; undefined for an unknown id. */
  async stop(
    id: string,
    reason: "user" | "close" = "user",
  ): Promise<TaskReport | undefined> {
    const task = this.#tasks.get(id);
    if (!task) return undefined;
    if (task.status === "running") {
      task.status = "stopped";
      task.stopReason = reason;
      task.controller.abort();
    }
    // A runner that ignores its abort must not hold the caller.
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      task.done,
      new Promise((done) => {
        timer = setTimeout(done, this.limits.stopWaitMs);
      }),
    ]);
    clearTimeout(timer);
    return this.read(id);
  }

  /** Stop every running task and refuse new ones; the session is closing. */
  async closeAll(): Promise<void> {
    this.#closed = true;
    await Promise.all(
      [...this.#tasks.keys()].map((id) => this.stop(id, "close")),
    );
  }
}
