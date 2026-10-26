// `task_start`, `task_output`, and `task_stop`: a command that keeps running
// after its tool call (a dev server, a watcher, a long test run). The start
// is decided exactly as the bash tool decides a command, and the task runs
// through the session's sandbox, which tracks and stops its process tree.
import {
  DEFAULT_MAX_BYTES,
  formatSize,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  type TaskEvent,
  TaskLimitError,
  TaskRegistry,
  type TaskReport,
} from "./background-tasks.js";
import type { GovernanceSession } from "./governance-session.js";
import {
  blocked,
  gateCommand,
  piBashSpawn,
  planRefusal,
  uncontainedEnvironment,
} from "./governed-tools.js";

/** How long `task_start` waits for the first output before it returns. */
const FIRST_OUTPUT_MS = 1000;

/**
 * The session's task registry. Its tasks start through `gov.sandbox.exec`:
 * contained when the sandbox is enforced, and otherwise as a tracked local
 * process that the session and process exit stop.
 */
export function sessionTasks(gov: GovernanceSession): TaskRegistry {
  if (gov.backgroundTasks) return gov.backgroundTasks;
  const record = (
    event: "task.start" | "task.stop" | "task.exit",
    task: TaskEvent,
    decision?: "allowed" | "denied",
  ) =>
    gov.emit(event, {
      resource: "task_start",
      ...(decision ? { decision } : {}),
      detail: {
        task: task.id,
        status: task.status,
        commandBytes: Buffer.byteLength(task.command),
        durationMs: task.durationMs,
        ...(task.exitCode !== null ? { exitCode: task.exitCode } : {}),
        ...(task.reason ? { reason: task.reason } : {}),
      },
      content: { command: task.command },
    });
  const tasks = new TaskRegistry({
    start: (task) => record("task.start", task, "allowed"),
    exit: (task) => record("task.exit", task),
    stop: (task) => record("task.stop", task),
    refused: (task) => record("task.start", task, "denied"),
  });
  gov.backgroundTasks = tasks;
  return tasks;
}

function report(task: TaskReport, prefix = ""): string {
  // The model gets Pi's tool output limit of the newest output.
  const bytes = Buffer.byteLength(task.output);
  const output =
    bytes > DEFAULT_MAX_BYTES
      ? Buffer.from(task.output)
          .subarray(bytes - DEFAULT_MAX_BYTES)
          .toString()
      : task.output;
  const dropped = task.dropped + Math.max(0, bytes - DEFAULT_MAX_BYTES);
  return [
    `${prefix}Task ${task.id}: ${task.status}${task.exitCode !== null ? ` (exit code ${task.exitCode})` : ""}`,
    ...(dropped
      ? [`[${formatSize(dropped)} of earlier output not shown]`]
      : []),
    output || "(no new output)",
  ].join("\n");
}

const reply = (text: string, task: TaskReport) => ({
  content: [{ type: "text" as const, text }],
  details: { id: task.id, status: task.status, exitCode: task.exitCode },
});

const idParameter = {
  type: "object",
  properties: {
    id: { type: "string", description: "The id task_start returned." },
  },
  required: ["id"],
  additionalProperties: false,
} as never;

/** The background task tools of a top-level session. */
export function taskTools(
  gov: GovernanceSession,
  cwd: string,
  platform: NodeJS.Platform = process.platform,
): ToolDefinition[] {
  const tasks = sessionTasks(gov);
  const unknown = (id: string) => {
    const gone = tasks.gone(id);
    return blocked(
      gone === "read"
        ? `Task ${id} already ended, and its last output was already shown.`
        : gone === "dropped"
          ? `Task ${id} ended, and its output is no longer kept.`
          : `No background task ${id} in this session.`,
    );
  };
  return [
    {
      name: "task_start",
      label: "Start background task",
      description:
        "Run a shell command in the background (a dev server, a watcher, a long build) and return at once with its id and first output. It is decided like a bash command. Read its output with task_output and stop it with task_stop; it stops when its timeout passes or the session ends.",
      promptSnippet: "task_start: run a long-running command in the background",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "The shell command." },
          timeout: {
            type: "number",
            minimum: 1,
            description:
              "Seconds before the task is stopped (default 1800, at most 7200).",
          },
        },
        required: ["command"],
        additionalProperties: false,
      } as never,
      async execute(id, params, _signal, _onUpdate, ctx) {
        const refusal = planRefusal(gov, "task_start");
        if (refusal) throw blocked(refusal);
        const input = params as { command: string; timeout?: number };
        if (gov.sandbox.report.isolation === "remote")
          throw blocked(
            `Background tasks run on this machine; the ${gov.sandbox.report.adapter} sandbox backend runs commands elsewhere. Use bash instead.`,
          );
        const enforced = gov.sandbox.report.level === "enforced";
        // Uncontained, the sandbox runs cmd.exe on Windows while the bash
        // tool runs Pi's bash, whose syntax the command checks assume.
        if (!enforced && platform === "win32")
          throw blocked(
            "Background tasks need an enforced sandbox on Windows, where an uncontained task would run in cmd.exe rather than the shell the bash tool uses. Use bash instead.",
          );
        // Refused before the decision, so a full registry asks nothing.
        const full = tasks.refusal(input.command);
        if (full) throw blocked(`${full}.`);
        // Decided as the bash tool decides it: the command Pi would spawn.
        const spawn = await piBashSpawn(
          cwd,
          id,
          { command: input.command },
          ctx,
        );
        const commandRefusal = await gateCommand(gov, spawn.command, "bash");
        if (commandRefusal) throw blocked(commandRefusal);
        let started: string;
        try {
          started = tasks.start(
            (command, options) =>
              gov.sandbox.exec(command, spawn.cwd, {
                onData: options.onData,
                signal: options.signal,
                timeout: options.timeout,
                // The sandbox narrows an environment it contains; an
                // uncontained task is narrowed as the bash tool narrows it.
                ...(enforced
                  ? spawn.env
                    ? { env: spawn.env }
                    : {}
                  : { env: uncontainedEnvironment(spawn.env, "bash") }),
              }),
            spawn.command,
            input.timeout,
          );
        } catch (error) {
          if (error instanceof TaskLimitError) throw blocked(error.message);
          throw error;
        }
        let timer: NodeJS.Timeout | undefined;
        await Promise.race([
          tasks.settled(started),
          new Promise((done) => {
            timer = setTimeout(done, FIRST_OUTPUT_MS);
          }),
        ]);
        clearTimeout(timer);
        const first = tasks.read(started) as TaskReport;
        return reply(report(first, "Started. "), first);
      },
    },
    {
      name: "task_output",
      label: "Background task output",
      description:
        "Show a background task's status, exit code, and the output it printed since the last task_output.",
      promptSnippet: "task_output: read a background task's new output",
      parameters: idParameter,
      async execute(_id, params) {
        const refusal = planRefusal(gov, "task_output");
        if (refusal) throw blocked(refusal);
        const { id } = params as { id: string };
        const task = tasks.read(id);
        if (!task) throw unknown(id);
        return reply(report(task), task);
      },
    },
    {
      name: "task_stop",
      label: "Stop background task",
      description:
        "Stop a background task and every process it started, and show its last output.",
      promptSnippet: "task_stop: stop a background task",
      parameters: idParameter,
      async execute(_id, params) {
        const refusal = planRefusal(gov, "task_stop");
        if (refusal) throw blocked(refusal);
        const { id } = params as { id: string };
        const task = await tasks.stop(id);
        if (!task) throw unknown(id);
        return reply(report(task), task);
      },
    },
  ];
}
