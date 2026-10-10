import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { basename, join } from "node:path";

export interface Result {
  status: number | null;
  stdout: string;
  stderr: string;
  /** What `approve` resolved with, when the command printed a sign-in URL. */
  approval?: unknown;
}

export function launcher(artifact: string, command: string): string {
  return join(
    artifact,
    "bin",
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}

/** Kill a command and what it started; `cmd.exe` leaves its child running. */
function kill(child: ChildProcess): void {
  if (process.platform === "win32" && child.pid !== undefined)
    spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
    });
  else child.kill("SIGKILL");
}

/**
 * The stdin error codes that mean the child closed its read end first — a
 * race every command that never reads stdin can lose, not a failure of the
 * run, which its own exit status still judges.
 */
const STDIN_CLOSED_CODES: ReadonlySet<string> = new Set([
  "EPIPE",
  "ECONNRESET",
  "ERR_STREAM_DESTROYED",
]);

/** The characters `cmd.exe` gives a meaning of their own outside quotes. */
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/**
 * One argument quoted for the MSVCRT argv rules (what the program finally
 * parses), then with every `cmd.exe` metacharacter caret-escaped so no
 * argument can end the command line (`&`, `|`, `>` …) or move a caret into
 * the child's argv. With `doubleEscape` each metacharacter takes two caret
 * levels, because a `.cmd`/`.bat` target parses the arguments twice: once
 * for the `/c` line and once when the batch re-expands `%*` into its own
 * command line (npm's promise-spawn applies the same rule).
 *
 * `%VAR%` expansion runs before carets are read, but the caret on `%`
 * reaches the variable name too (`^%PATH^%` scans as `P^A^T^H^`, which no
 * variable is called), so an argument's `%VAR%` reaches the child as the
 * literal text it was written as. `!` stays literal as well: `cmd.exe /c`
 * runs without delayed expansion.
 */
function cmdArgument(arg: string, doubleEscape: boolean): string {
  const quoted = `"${arg
    // Backslashes directly before a quote: double them, escape the quote.
    .replace(/(?=(\\+?)?)\1"/g, '$1$1\\"')
    // Trailing backslashes: double them so they cannot eat the closing quote.
    .replace(/(?=(\\+?)?)\1$/, "$1$1")}"`;
  const escaped = quoted.replace(CMD_META, "^$1");
  return doubleEscape ? escaped.replace(CMD_META, "^$1") : escaped;
}

/**
 * The argument vector `branded()` hands `cmd.exe` on Windows: the command
 * and every argument escaped so the child receives exactly `args`, with no
 * boundary an argument can cross to become a second command. There is no
 * `call` in front: it re-parses the line, adding a caret stage whose count
 * nothing pins down, and `cmd.exe /c` runs a batch file (and propagates its
 * exit code) without it.
 *
 * Pure, so the Windows quoting is testable on any platform.
 */
export function windowsArgv(
  command: string,
  args: readonly string[],
): string[] {
  const batch = /\.(?:cmd|bat)$/i.test(command);
  const line = [
    command.replace(CMD_META, "^$1"),
    ...args.map((arg) => cmdArgument(arg, batch)),
  ].join(" ");
  // With `/s`, `cmd.exe` strips the first and the last quote of the `/c`
  // string and runs the rest, which keeps the quotes that carry the
  // argument boundaries intact.
  return ["/d", "/s", "/c", `"${line}"`];
}

/**
 * Run a branded command; acts as the browser for any printed sign-in URL.
 * With `timeoutMs`, a command still running then is killed and the promise
 * rejects with its arguments and the output so far, instead of the test
 * hanging until its own timeout with no sign of the step.
 */
export function branded(
  command: string,
  args: readonly string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    approve?: (url: string) => Promise<unknown>;
    input?: string;
    timeoutMs?: number;
    /**
     * Send SIGINT (Ctrl-C) once `approve` has finished, as a person who gave
     * up on the sign-in would. POSIX only: Windows cannot deliver it.
     */
    interruptAfterApprove?: boolean;
  },
): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child =
      process.platform === "win32"
        ? spawn("cmd.exe", windowsArgv(command, args), {
            cwd: options.cwd,
            env: options.env,
            windowsVerbatimArguments: true,
          })
        : spawn(command, [...args], { cwd: options.cwd, env: options.env });
    let stdout = "";
    let stderr = "";
    let approved = false;
    let approval: unknown;
    let approving: Promise<unknown> = Promise.resolve();
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      const match = /(http:\/\/127\.0\.0\.1:\d+\/idp\/authorize\S+)/.exec(
        stderr,
      );
      if (match?.[1] && options.approve && !approved) {
        approved = true;
        approving = options.approve(match[1]).then((value) => {
          approval = value;
          if (options.interruptAfterApprove) child.kill("SIGINT");
          return value;
        });
        approving.catch(() => {});
      }
    });
    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            kill(child);
            reject(
              new Error(
                `${basename(command)} ${args.join(" ")} did not finish in ${options.timeoutMs} ms\nstdout: ${stdout}\nstderr: ${stderr}`,
              ),
            );
          }, options.timeoutMs);
    // A child that never reads stdin can close its read end while a write is
    // still queued, and the flush then fails asynchronously — the EPIPE that
    // turned a fully green macOS unit run red as one unhandled error. The
    // handler must exist before the write, or the event can fire first. Only
    // the expected pipe-closure codes are ignored; anything else kills the
    // child and rejects, so a real stdin failure never resolves as success.
    child.stdin.on("error", (error) => {
      if (STDIN_CLOSED_CODES.has((error as NodeJS.ErrnoException).code ?? ""))
        return;
      clearTimeout(timer);
      kill(child);
      reject(
        new Error(
          `${basename(command)} ${args.join(" ")} stdin failed: ${error.message}\nstdout: ${stdout}\nstderr: ${stderr}`,
        ),
      );
    });
    child.stdin.end(options.input ?? "");
    child.on("close", (status) => {
      clearTimeout(timer);
      void approving
        .catch(() => {})
        .then(() =>
          resolve({
            status,
            stdout,
            stderr,
            ...(approved ? { approval } : {}),
          }),
        );
    });
  });
}
