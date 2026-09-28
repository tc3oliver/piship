import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  binHome,
  buildDistribution,
  checkPiVersion,
  explainConfiguration,
  formatExplanation,
  initDistribution,
  installDistribution,
  lockManifest,
  payloadApp,
  PISHIP_VERSION,
  purgeDistributionState,
  readInstallReceipt,
  requireCurrentLock,
  resolveResources,
  runtimeStateDirectory,
  uninstallDistribution,
  verifyPayload,
} from "@piship/core";
import { formatError, redact } from "@piship/contracts";
import {
  readManifest,
  ManifestError,
  migrateManifestSource,
} from "@piship/schema";
import { readFileSync, writeFileSync } from "node:fs";

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
  "migrate",
  "config",
] as const;
const allowedOptions: Record<string, readonly string[]> = {
  purge: ["--yes"],
  install: ["--use-existing-state"],
  init: ["--managed"],
  migrate: ["--write"],
  test: ["--model-request"],
};
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
export async function runCli(
  args: readonly string[],
  output: CliOutput,
): Promise<number> {
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
  if (command === "config") {
    if (target !== "explain" || rest.length !== 1) {
      output.stderr("Usage: piship config explain <manifest|artifact|id>");
      return 2;
    }
  } else if (
    !target ||
    (rest.length &&
      !(rest.length === 1 && allowedOptions[command]?.includes(rest[0] ?? "")))
  ) {
    output.stderr(
      `Usage: piship ${command} <target>${allowedOptions[command] ? ` [${allowedOptions[command].join("|")}]` : ""}`,
    );
    return 2;
  }
  if (!target) return 2;
  try {
    if (command === "init")
      output.stdout(
        `Created ${initDistribution(target, { managed: rest[0] === "--managed" })}`,
      );
    else if (command === "validate") {
      const manifest = readManifest(target);
      checkPiVersion(manifest);
      resolveResources(manifest, target);
      const variables = manifest.access?.variables ?? [];
      const missing = variables.filter((name) => !process.env[name]);
      output.stdout(
        `Manifest is valid.\nSchema ${manifest.schema}, mode ${manifest.deployment.mode}.${variables.length ? `\nRuntime variables (resolved at launch, never locked): ${variables.join(", ")}` : ""}`,
      );
      if (missing.length)
        output.stderr(
          `Note: ${missing.join(", ")} not set in this shell; the branded command fails visibly until they are set at launch.`,
        );
    } else if (command === "migrate") {
      const plan = migrateManifestSource(readFileSync(target, "utf8"));
      if (!plan.changes.length)
        output.stdout(`Already ${plan.to}; nothing to migrate.`);
      else if (rest[0] === "--write") {
        writeFileSync(target, plan.source);
        output.stdout(
          `Migrated ${target} from ${plan.from} to ${plan.to}:\n${plan.changes.map((item) => `  - ${item}`).join("\n")}`,
        );
      } else
        output.stdout(
          `Migration plan ${plan.from} -> ${plan.to} (dry run; add --write to apply):\n${plan.changes.map((item) => `  - ${item}`).join("\n")}\n\n${plan.source}`,
        );
    } else if (command === "config") {
      const configTarget = rest[0] ?? "";
      const path = resolve(configTarget);
      if (existsSync(path) && statSync(path).isFile()) {
        // Explain straight from the manifest; no artifact is assembled.
        const manifest = readManifest(configTarget);
        checkPiVersion(manifest);
        output.stdout(
          formatExplanation(
            manifest.app.name,
            await explainConfiguration({
              app: manifest.app,
              mode: manifest.deployment.mode,
              access: manifest.access,
              stateDir: runtimeStateDirectory({ value: manifest.app.id }),
              distributionDir: dirname(path),
            }),
          ),
        );
      } else {
        const artifact = artifactFor(configTarget);
        const app = payloadApp(artifact);
        const result = runLauncher(artifact, app.command, [
          "config",
          "explain",
        ]);
        if (result.status !== 0)
          throw new Error(result.stderr || String(result.status));
        output.stdout(result.stdout.trimEnd());
      }
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
              deployment: lock.deployment,
              runtime: lock.runtime,
              resources: lock.resources,
              ...(lock.access ? { access: lock.access } : {}),
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
              deployment: lock.deployment,
              runtime: lock.runtime,
              resources: lock.resources,
              ...(lock.access ? { access: lock.access } : {}),
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
        command === "test"
          ? [rest[0] === "--model-request" ? "--smoke-model" : "--smoke"]
          : [],
        command === "dev",
      );
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      if (command === "test")
        output.stdout(
          `${lock.deployment.mode === "managed" ? "Managed" : "Personal"} acceptance passed: ${result.stdout.trim()}`,
        );
    } else if (command === "doctor") {
      const artifact = artifactFor(target);
      const app = payloadApp(artifact);
      const lock = verifyPayload(artifact);
      if (lock.access) {
        const report = runLauncher(artifact, app.command, ["doctor"]);
        output.stdout(report.stdout.trimEnd());
        if (report.status !== 0)
          throw new Error(report.stderr.trim() || "doctor found problems");
      }
      const result = runLauncher(artifact, app.command, ["--smoke"]);
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      output.stdout(
        `Healthy ${app.id}@${app.version}: ${result.stdout.trim()}`,
      );
    }
    return 0;
  } catch (error) {
    output.stderr(
      error instanceof ManifestError
        ? redact(error.message)
        : formatError(error),
    );
    return 1;
  }
}
