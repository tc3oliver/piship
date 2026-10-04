// npm, git, and tar invocations for package resolution. Credentials come only
// from npm / git configuration in the environment; PiShip passes none.
import { spawnSync } from "node:child_process";
import { windowsNpmInvocation } from "../windows-npm.js";
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

/** Runs the command; on Windows npm runs as node + npm-cli.js, never through a shell. */
export const runCommand: CommandRunner = (command, args, options) => {
  const spawnOptions = {
    cwd: options.cwd,
    env: options.env ?? process.env,
    maxBuffer: 256 * 1024 * 1024,
    timeout: 600_000,
    ...(options.input ? { input: options.input } : {}),
  };
  const invocation =
    command === "npm" && process.platform === "win32"
      ? windowsNpmInvocation(args, spawnOptions.env, options.cwd)
      : { file: command, args };
  const result = spawnSync(invocation.file, [...invocation.args], spawnOptions);
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
  // The subcommand, past git's leading `-c <name=value>` and `-C <dir>`.
  const subcommand = args.find(
    (arg, index) =>
      !arg.startsWith("-") && !/^-[cC]$/.test(args[index - 1] ?? ""),
  );
  if (result.status !== 0)
    throw packageError(
      /EINTEGRITY|integrity/i.test(result.stderr)
        ? "INTEGRITY_FAILED"
        : "UPDATE_FAILED",
      id,
      `${command} ${subcommand ?? args[0] ?? ""} failed: ${result.stderr.trim().split("\n").slice(0, 6).join(" ").slice(0, 600)}`,
    );
  return result.stdout;
}
