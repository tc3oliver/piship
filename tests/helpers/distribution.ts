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
        ? spawn(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${command}" ${args.join(" ")}`],
            {
              cwd: options.cwd,
              env: options.env,
              windowsVerbatimArguments: true,
            },
          )
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
    child.stdin.end(options.input ?? "");
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
