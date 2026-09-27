import {
  buildDistribution,
  checkPiVersion,
  lockManifest,
  resolveResources,
} from "@piship/core";
import { readManifest, ManifestError } from "@piship/schema";
import { readFileSync } from "node:fs";

const availableCommands = ["validate", "lock", "build"] as const;
const plannedCommands = ["init", "dev", "inspect"] as const;
const packageVersion = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version: string };
export interface CliOutput {
  readonly stdout: (message: string) => void;
  readonly stderr: (message: string) => void;
}
export function runCli(args: readonly string[], output: CliOutput): number {
  const [command, manifestPath, ...rest] = args;
  if (command === undefined || command === "--help" || command === "-h") {
    output.stdout(
      `PiShip ${packageVersion.version}\n\nUsage: piship <command> [manifest]\n\nCommands:\n${availableCommands.map((item) => `  ${item}`).join("\n")}\n\nPlanned commands (not yet available):\n${plannedCommands.map((item) => `  ${item}`).join("\n")}\n\nOptions:\n  --help     Show this help\n  --version  Show version`,
    );
    return 0;
  }
  if (command === "--version" || command === "-v") {
    output.stdout(packageVersion.version);
    return 0;
  }
  if (plannedCommands.includes(command as (typeof plannedCommands)[number])) {
    output.stderr(`piship ${command} is not available yet.`);
    return 2;
  }
  if (
    !availableCommands.includes(command as (typeof availableCommands)[number])
  ) {
    output.stderr(`Unknown command: ${command}. Run piship --help.`);
    return 2;
  }
  if (!manifestPath || rest.length) {
    output.stderr(`Usage: piship ${command} <manifest-path>`);
    return 2;
  }
  try {
    if (command === "validate") {
      const manifest = readManifest(manifestPath);
      checkPiVersion(manifest);
      resolveResources(manifest, manifestPath);
      output.stdout("Manifest is valid.");
    } else if (command === "lock")
      output.stdout(`Wrote ${lockManifest(manifestPath)}`);
    else output.stdout(`Built ${buildDistribution(manifestPath)}`);
    return 0;
  } catch (error) {
    output.stderr(
      error instanceof ManifestError || error instanceof Error
        ? error.message
        : String(error),
    );
    return 1;
  }
}
