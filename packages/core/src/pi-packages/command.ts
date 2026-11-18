// npm, git, and tar invocations for package resolution. Credentials come only
// from npm / git configuration in the environment; PiShip passes none.
import { spawnSync } from "node:child_process";
import { supervisedNpm } from "../npm-process.js";
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
    // npm's limit is kept by its supervisor, which also stops npm's children.
    ...(command === "npm" ? {} : { timeout: 600_000 }),
    ...(options.input ? { input: options.input } : {}),
  };
  let invocation: { file: string; args: readonly string[] } = {
    file: command,
    args,
  };
  if (command === "npm") {
    if (process.platform === "win32")
      invocation = windowsNpmInvocation(args, spawnOptions.env, options.cwd);
    invocation = supervisedNpm(invocation.file, invocation.args);
  }
  const result = spawnSync(invocation.file, [...invocation.args], spawnOptions);
  return {
    status: result.status,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: `${result.stderr?.toString() ?? ""}${result.error?.message ?? ""}`,
  };
};

/**
 * Run and require exit 0; the failure names the package and npm/git's first lines.
 * `explain` recognizes a manifest mistake (a wrong name or version) and reports it as CONFIG_INVALID.
 */
export function mustRun(
  run: CommandRunner,
  id: string,
  command: "npm" | "git" | "tar",
  args: readonly string[],
  options: CommandOptions,
  explain?: (stderr: string) => string | undefined,
): Buffer {
  const result = run(command, args, options);
  const explained =
    result.status !== 0 && explain ? explain(result.stderr) : undefined;
  if (explained) throw packageError("CONFIG_INVALID", id, explained);
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
      `${command} ${subcommand ?? args[0] ?? ""} failed: ${result.stderr
        .trim()
        .split("\n")
        // npm's JavaScript stack says nothing about the cause.
        .filter((line) => !/^(npm error)?\s+at /.test(line))
        .slice(0, 6)
        .join(" ")
        .slice(0, 600)}`,
      command === "npm" && NPM_REGISTRY_FAILURE.test(result.stderr)
        ? NPM_REGISTRY_ACTION
        : `Fix what ${command}'s output names (network, credentials in your ${command} configuration, the package's source), then run the command again`,
    );
  return result.stdout;
}

/** npm could not reach the registry, or the registry refused it. */
const NPM_REGISTRY_FAILURE =
  /\b(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|E401|E403|E404)\b/;
const NPM_REGISTRY_ACTION =
  "Resolving and installing Pi packages needs npm registry access: check the network and proxy (`npm config get registry`, `proxy`, `https-proxy`), and the registry credentials in your npm configuration for E401/E403, then run the command again";
