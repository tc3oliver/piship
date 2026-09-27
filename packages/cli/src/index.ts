import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  binHome,
  buildDistribution,
  checkPiVersion,
  initDistribution,
  installDistribution,
  lockManifest,
  PISHIP_VERSION,
  purgeDistributionState,
  readInstallReceipt,
  requireCurrentLock,
  resolveResources,
  runtimeStateDirectory,
  uninstallDistribution,
  verifyPayload,
} from "@piship/core";
import { readManifest, ManifestError } from "@piship/schema";

const commands = [
  "init",
  "dev",
  "validate",
  "lock",
  "build",
  "test",
  "inspect",
  "doctor",
  "install",
  "uninstall",
  "purge",
] as const;
export interface CliOutput {
  readonly stdout: (message: string) => void;
  readonly stderr: (message: string) => void;
}
function launcher(artifact: string, command: string): string {
  return join(
    artifact,
    "bin",
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}
function runLauncher(
  artifact: string,
  command: string,
  args: string[],
  interactive = false,
): { status: number | null; stdout: string; stderr: string } {
  const target = launcher(artifact, command);
  const result =
    process.platform === "win32"
      ? spawnSync(
          "cmd.exe",
          ["/d", "/s", "/c", `call "${target}" ${args.join(" ")}`],
          {
            encoding: "utf8",
            stdio: interactive ? "inherit" : "pipe",
            windowsVerbatimArguments: true,
          },
        )
      : spawnSync(target, args, {
          encoding: "utf8",
          stdio: interactive ? "inherit" : "pipe",
        });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
}
function artifactFor(target: string): string {
  const path = resolve(target);
  if (existsSync(path) && statSync(path).isDirectory()) return path;
  return readInstallReceipt(target).payload;
}
export function runCli(args: readonly string[], output: CliOutput): number {
  const [command, target, ...rest] = args;
  if (command === undefined || command === "--help" || command === "-h") {
    output.stdout(
      `PiShip ${PISHIP_VERSION}\n\nUsage: piship <command> <target>\n\nCommands:\n${commands.map((item) => `  ${item}`).join("\n")}\n\nInstall defaults: ${binHome()} (add to PATH yourself)\n\nOptions:\n  --help     Show this help\n  --version  Show PiShip version`,
    );
    return 0;
  }
  if (command === "--version" || command === "-v") {
    output.stdout(PISHIP_VERSION);
    return 0;
  }
  if (!commands.includes(command as (typeof commands)[number])) {
    output.stderr(`Unknown command: ${command}. Run piship --help.`);
    return 2;
  }
  if (
    !target ||
    (rest.length &&
      !(
        (command === "purge" && rest.join(" ") === "--yes") ||
        (command === "install" && rest.join(" ") === "--use-existing-state")
      ))
  ) {
    output.stderr(
      `Usage: piship ${command} <target>${command === "purge" ? " --yes" : ""}`,
    );
    return 2;
  }
  try {
    if (command === "init")
      output.stdout(`Created ${initDistribution(target)}`);
    else if (command === "validate") {
      const manifest = readManifest(target);
      checkPiVersion(manifest);
      resolveResources(manifest, target);
      output.stdout("Manifest is valid.");
    } else if (command === "lock")
      output.stdout(`Wrote ${lockManifest(target)}`);
    else if (command === "build")
      output.stdout(`Built ${buildDistribution(target)}`);
    else if (command === "install") {
      const receipt = installDistribution(
        target,
        rest[0] === "--use-existing-state",
      );
      output.stdout(
        `Installed ${receipt.app.id}@${receipt.app.version}: ${receipt.commandPath}\nAdd ${binHome()} to PATH if needed.`,
      );
    } else if (command === "uninstall") {
      output.stdout(
        `Uninstalled ${target}. State preserved: ${uninstallDistribution(target)}`,
      );
    } else if (command === "purge") {
      if (rest[0] !== "--yes")
        throw new Error(
          "Purge deletes this distribution's state; repeat with --yes after checking the id",
        );
      output.stdout(`Purged ${purgeDistributionState(target)}`);
    } else if (command === "inspect") {
      if (existsSync(resolve(target)) && statSync(resolve(target)).isFile()) {
        const lock = requireCurrentLock(target);
        output.stdout(
          JSON.stringify(
            {
              app: lock.app,
              runtime: lock.runtime,
              resources: lock.resources,
              state: runtimeStateDirectory({ value: lock.app.id }),
            },
            null,
            2,
          ),
        );
      } else {
        const artifact = artifactFor(target);
        const lock = verifyPayload(artifact);
        output.stdout(
          JSON.stringify(
            {
              app: lock.app,
              runtime: lock.runtime,
              resources: lock.resources,
              artifact,
              state: runtimeStateDirectory({ value: lock.app.id }),
            },
            null,
            2,
          ),
        );
      }
    } else if (command === "dev" || command === "test") {
      const artifact = buildDistribution(target);
      const lock = requireCurrentLock(target);
      const result = runLauncher(
        artifact,
        lock.app.command,
        command === "test" ? ["--smoke"] : [],
        command === "dev",
      );
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      if (command === "test")
        output.stdout(`Personal acceptance passed: ${result.stdout.trim()}`);
    } else if (command === "doctor") {
      const artifact = artifactFor(target);
      const lock = verifyPayload(artifact);
      const result = runLauncher(artifact, lock.app.command, ["--smoke"]);
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      output.stdout(
        `Healthy ${lock.app.id}@${lock.app.version}: ${result.stdout.trim()}`,
      );
    }
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
