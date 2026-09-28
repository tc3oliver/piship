import { spawn } from "node:child_process";
import { join } from "node:path";

export interface Result {
  status: number | null;
  stdout: string;
  stderr: string;
}

export function launcher(artifact: string, command: string): string {
  return join(
    artifact,
    "bin",
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}

/** Run a branded command; acts as the browser for any printed sign-in URL. */
export function branded(
  command: string,
  args: readonly string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    approve?: (url: string) => Promise<unknown>;
    input?: string;
  },
): Promise<Result> {
  return new Promise((resolve) => {
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
        void options.approve(match[1]);
      }
    });
    child.stdin.end(options.input ?? "");
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}
