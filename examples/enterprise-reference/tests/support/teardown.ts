import { rmSync } from "node:fs";
import { keepLogs as keepContainerLogs, logDirectory } from "./logs.js";

// Stopping a reference stack: keep its logs as evidence, `docker compose down`,
// remove the temporary directory that holds its env file. Shared by both stack
// helpers (tests/enterprise-reference/stack.ts and ./stack.ts).
//
// The three steps are independent, and the stack counts as stopped only when
// its resources are actually released. So a failing step never skips the ones
// after it, every failure is reported, and calling the returned function again
// retries exactly what is left: a `docker compose down` that failed once is
// not forgotten, and a teardown that finished stays finished.

/** What teardown needs to know of a finished `docker compose` command. */
export interface ComposeResult {
  readonly status: number | null;
  /** Null when the command could not be started at all. */
  readonly stdout?: string | null;
  readonly stderr?: string | null;
  readonly error?: Error | undefined;
}

export interface StackTeardown {
  readonly project: string;
  /** The generated env file: the log scrubber reads the stack's secrets from it. */
  readonly envFile: string;
  /** The temporary directory that holds the env file and any Compose override. */
  readonly directory: string;
  /** Run `docker compose` for this one project with these arguments. */
  readonly compose: (args: readonly string[]) => ComposeResult;
  /** The arguments of the `down` command: never `-v`, never a prune. */
  readonly downArguments: readonly string[];
  /** Replaceable, so a test can make the log keeper fail. */
  readonly keepLogs?: typeof keepContainerLogs;
  /** Replaceable, so a test can make the removal fail. */
  readonly removeDirectory?: (directory: string) => void;
}

const reason = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

/** Why a finished command failed, from what it printed or from why it never started. */
const detail = (result: ComposeResult) =>
  (result.stderr ?? "").trim() ||
  result.error?.message ||
  `exit status ${result.status}`;

/**
 * Register the stack's teardown for the process's exit, SIGINT and SIGTERM, so
 * a worker that is interrupted, terminated, or exits between start and
 * afterAll still stops its stack, and return it for afterAll. Those handlers
 * are removed once the teardown is complete, not before: a failed stop leaves
 * them in place to try again. A worker killed outright cannot stop its stack;
 * tests/enterprise-reference/global-setup.ts removes it on the next run.
 *
 * The function throws when a step failed (one failure as it is, several as an
 * AggregateError), after it has run every step it could.
 */
export function registerTeardown(options: StackTeardown): () => void {
  const {
    project,
    envFile,
    directory,
    compose,
    downArguments,
    keepLogs = keepContainerLogs,
    removeDirectory = (path) => rmSync(path, { recursive: true, force: true }),
  } = options;
  let logsKept = false;
  let down = false;
  let removed = false;

  const collectLogs = () => {
    const logs = compose(["logs", "--no-color", "--timestamps"]);
    keepLogs(project, envFile, `${logs.stdout ?? ""}${logs.stderr ?? ""}`);
  };
  // `downArguments` has no `-v`: the stack keeps no volume, and a volume is
  // never pruned here.
  const stopProject = () => {
    const result = compose(downArguments);
    if (result.status !== 0) throw new Error(detail(result));
  };

  const stop = () => {
    if (down && removed) return;
    const failures: Error[] = [];
    const attempt = (what: string, step: () => void) => {
      try {
        step();
        return true;
      } catch (error) {
        failures.push(new Error(`${what}: ${reason(error)}`, { cause: error }));
        return false;
      }
    };

    // The logs first, while the containers exist. Once `down` has succeeded
    // there is nothing left to read, so a failure here is not retried then.
    if (!down && !logsKept && logDirectory())
      logsKept = attempt(
        `keeping the container logs of ${project} failed`,
        collectLogs,
      );
    if (!down)
      down = attempt(`docker compose down failed for ${project}`, stopProject);
    // The directory holds the env file and the override that a retry of `down`
    // needs, so it stays until `down` has succeeded.
    if (down && !removed)
      removed = attempt(`removing ${directory} failed`, () =>
        removeDirectory(directory),
      );
    if (down && removed) {
      process.off("exit", stop);
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    }

    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(
        failures,
        `${failures.length} steps of the teardown of ${project} failed:\n${failures.map((failure) => `- ${failure.message}`).join("\n")}`,
      );
  };
  const onSignal = (signal: NodeJS.Signals) => {
    try {
      stop();
    } finally {
      process.exit(signal === "SIGINT" ? 130 : 143);
    }
  };
  process.once("exit", stop);
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  return stop;
}
