// npm, git, and tar invocations for package resolution. Credentials come only
// from npm / git configuration in the environment; PiShip passes none.
import { spawnSync } from "node:child_process";
import { packageError } from "./refs.js";

export interface CommandOptions {
  readonly cwd: string;
  /** Environment for the child; defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  readonly input?: Buffer;
}

export interface CommandOutput {
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: string;
}

export type CommandRunner = (
  command: "npm" | "git" | "tar",
  args: readonly string[],
  options: CommandOptions,
) => CommandOutput;

/** Runs the command; npm goes through cmd.exe on Windows, where it is a .cmd shim. */
export const runCommand: CommandRunner = (command, args, options) => {
  const spawnOptions = {
    cwd: options.cwd,
    env: options.env ?? process.env,
    maxBuffer: 256 * 1024 * 1024,
    timeout: 600_000,
    ...(options.input ? { input: options.input } : {}),
  };
  const result =
    command === "npm" && process.platform === "win32"
      ? // Quoted verbatim, so a range such as ^1.2 is not a cmd escape.
        spawnSync(
          "cmd.exe",
          [
            "/d",
            "/s",
            "/c",
            `"npm ${args.map((arg) => `"${arg}"`).join(" ")}"`,
          ],
          { ...spawnOptions, windowsVerbatimArguments: true },
        )
      : spawnSync(command, [...args], spawnOptions);
  return {
    status: result.status,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: `${result.stderr?.toString() ?? ""}${result.error?.message ?? ""}`,
  };
};

/** Run and require exit 0; the failure names the package and npm/git's first lines. */
export function mustRun(
  run: CommandRunner,
  id: string,
  command: "npm" | "git" | "tar",
  args: readonly string[],
  options: CommandOptions,
): Buffer {
  const result = run(command, args, options);
  if (result.status !== 0)
    throw packageError(
      /EINTEGRITY|integrity/i.test(result.stderr)
        ? "INTEGRITY_FAILED"
        : "UPDATE_FAILED",
      id,
      `${command} ${args[0] ?? ""} failed: ${result.stderr.trim().split("\n").slice(0, 6).join(" ").slice(0, 600)}`,
    );
  return result.stdout;
}
