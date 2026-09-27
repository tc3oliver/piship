import { readFileSync } from "node:fs";

const commands = [
  "init",
  "validate",
  "lock",
  "dev",
  "build",
  "inspect",
] as const;
const packageVersion = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version: string };

export interface CliOutput {
  readonly stdout: (message: string) => void;
  readonly stderr: (message: string) => void;
}

export function runCli(args: readonly string[], output: CliOutput): number {
  const [command] = args;
  if (command === undefined || command === "--help" || command === "-h") {
    output.stdout(
      `PiShip ${packageVersion.version}\n\nUsage: piship <command>\n\nPlanned commands (not yet available):\n${commands.map((item) => `  ${item}`).join("\n")}\n\nOptions:\n  --help     Show this help\n  --version  Show version`,
    );
    return 0;
  }
  if (command === "--version" || command === "-v") {
    output.stdout(packageVersion.version);
    return 0;
  }
  if (commands.includes(command as (typeof commands)[number])) {
    output.stderr(`piship ${command} is not available yet.`);
    return 2;
  }
  output.stderr(`Unknown command: ${command}. Run piship --help.`);
  return 2;
}
