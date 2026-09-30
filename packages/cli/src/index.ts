import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  binHome,
  buildDistribution,
  buildRelease,
  checkGovernance,
  checkPiVersion,
  checkStateMigration,
  storageOf,
  compareReleases,
  diffLocks,
  explainConfiguration,
  formatDiff,
  formatExplanation,
  formatMigrationReport,
  generateSigningKey,
  initDistribution,
  installDistribution,
  keyFingerprint,
  lockManifest,
  payloadApp,
  payloadStateSchemas,
  PISHIP_VERSION,
  purgeDistributionState,
  readInstallReceipt,
  requireCurrentLock,
  resolveResources,
  runtimeStateDirectory,
  signChannel,
  uninstallAndPurgeDistribution,
  uninstallDistribution,
  verifyPayload,
  verifyRelease,
  writePrivateKey,
  type AbandonedStaging,
  type DistributionLock,
  type PurgeResult,
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
  "release",
  "verify-release",
  "diff",
  "update",
  "rollback",
  "migrate-check",
  "keygen",
  "sign-channel",
  "reproducibility",
] as const;
/** Commands with named options: positional count and accepted flags. */
const lifecycleCommands: Record<
  string,
  {
    readonly usage: string;
    readonly positional: [number, number];
    readonly values: readonly string[];
    readonly flags: readonly string[];
  }
> = {
  release: {
    usage:
      "release <manifest> [--out <dir>] [--channel <name>] [--reclaim-staging]",
    positional: [1, 1],
    values: ["--out", "--channel"],
    flags: ["--reclaim-staging"],
  },
  "verify-release": {
    usage: "verify-release <archive|release-dir> [--sha256 <hex>] [--json]",
    positional: [1, 1],
    values: ["--sha256"],
    flags: ["--json"],
  },
  diff: {
    usage: "diff <before> <after> [--json]",
    positional: [2, 2],
    values: [],
    flags: ["--json"],
  },
  update: {
    usage:
      "update <id> [--channel <name>] [--from <dir|url>] [--check] [--accept-review]",
    positional: [1, 1],
    values: ["--channel", "--from"],
    flags: ["--check", "--accept-review"],
  },
  uninstall: {
    usage: "uninstall <id> [--purge --yes]",
    positional: [1, 1],
    values: [],
    flags: ["--purge", "--yes"],
  },
  rollback: {
    usage: "rollback <id>",
    positional: [1, 1],
    values: [],
    flags: [],
  },
  "migrate-check": {
    usage: "migrate-check <id> <archive|release-dir|payload>",
    positional: [2, 2],
    values: [],
    flags: [],
  },
  keygen: {
    usage: "keygen <private-key-file> --id <key-id> [--force-in-worktree]",
    positional: [1, 1],
    values: ["--id"],
    flags: ["--force-in-worktree"],
  },
  "sign-channel": {
    usage:
      "sign-channel <channel-dir> <archive>... --channel <name> --key <private-key-file> --key-id <id> [--sequence <n>] [--expires-days <n>]",
    positional: [2, 64],
    values: ["--channel", "--key", "--key-id", "--sequence", "--expires-days"],
    flags: [],
  },
  reproducibility: {
    usage: "reproducibility <release-a> <release-b> [--out <report.json>]",
    positional: [2, 2],
    values: ["--out"],
    flags: [],
  },
};
interface Parsed {
  readonly positional: string[];
  readonly options: Record<string, string>;
  readonly flags: Set<string>;
}
function parseArguments(
  spec: (typeof lifecycleCommands)[string],
  args: readonly string[],
): Parsed | undefined {
  const positional: string[] = [];
  const options: Record<string, string> = {};
  const flags = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (spec.values.includes(arg)) {
      const value = args[index + 1];
      if (value === undefined || arg in options) return undefined;
      options[arg] = value;
      index += 1;
    } else if (spec.flags.includes(arg)) flags.add(arg);
    else if (arg.startsWith("--")) return undefined;
    else positional.push(arg);
  }
  if (
    positional.length < spec.positional[0] ||
    positional.length > spec.positional[1]
  )
    return undefined;
  return { positional, options, flags };
}
/** A lock from a manifest, lock file, payload, release, archive, or installed id. */
async function lockFor(target: string): Promise<DistributionLock> {
  const path = resolve(target);
  if (existsSync(path) && statSync(path).isFile()) {
    if (path.endsWith(".tar.gz")) {
      const verified = await verifyRelease(path);
      verified.cleanup();
      return verified.lock;
    }
    if (path.endsWith(".lock"))
      return JSON.parse(
        (await import("node:fs")).readFileSync(path, "utf8"),
      ) as DistributionLock;
    return requireCurrentLock(target);
  }
  if (existsSync(path) && existsSync(join(path, "release.json")))
    return (await verifyRelease(path)).lock;
  if (existsSync(path)) return verifyPayload(path);
  return verifyPayload(readInstallReceipt(target).payload);
}
const allowedOptions: Record<string, readonly string[]> = {
  build: ["--reclaim-staging"],
  purge: ["--yes"],
  install: ["--use-existing-state"],
  init: ["--managed"],
  migrate: ["--write"],
  test: ["--model-request"],
  dev: ["--smoke"],
};
export interface CliOutput {
  readonly stdout: (message: string) => void;
  readonly stderr: (message: string) => void;
}
/**
 * What a build or release says about the staging directories of killed runs
 * in its output directory. They are removed only on request: the output
 * directory is usually inside a project that sandboxed commands can write.
 */
function stagingNotice(found: AbandonedStaging): string {
  const what = `${found.count} abandoned staging ${found.count === 1 ? "directory" : "directories"} of killed runs in ${found.directory}`;
  return found.attempted
    ? `${what} could not be removed; check its permissions.`
    : `${what}. They are not removed unless you ask, because this directory may be writable by sandboxed commands; run again with --reclaim-staging to remove them.`;
}
function purgeReport(purged: PurgeResult): string {
  const count = purged.deletedSecrets.length;
  return `Purged ${purged.state}${count ? `\nDeleted ${count} secret-store entr${count === 1 ? "y" : "ies"}` : ""}`;
}
function runLauncher(
  artifact: string,
  command: string,
  args: string[],
  interactive = false,
): { status: number | null; stdout: string; stderr: string } {
  const target = join(artifact, "bin", command);
  const options = {
    encoding: "utf8",
    stdio: interactive ? "inherit" : "pipe",
  } as const;
  // On Windows the payload's `.cmd` shim only runs this script with Node, and
  // going through cmd.exe would split and interpret the arguments (spaces,
  // & | ^ %), so Node runs it directly and each argument arrives unchanged.
  const result =
    process.platform === "win32"
      ? spawnSync(process.execPath, [target, ...args], options)
      : spawnSync(target, args, options);
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
  const lifecycle = lifecycleCommands[command];
  if (lifecycle) {
    const parsed = parseArguments(lifecycle, args.slice(1));
    if (!parsed) {
      output.stderr(`Usage: piship ${lifecycle.usage}`);
      return 2;
    }
    try {
      return await runLifecycle(command, parsed, output);
    } catch (error) {
      output.stderr(
        error instanceof ManifestError
          ? redact(error.message)
          : formatError(error),
      );
      return 1;
    }
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
      // The same resource and governance checks as lock, without writing it.
      checkGovernance(manifest, target, resolveResources(manifest, target));
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
      output.stdout(
        `Built ${buildDistribution(target, undefined, {
          reclaimStaging: rest[0] === "--reclaim-staging",
          abandonedStaging: (found) => output.stderr(stagingNotice(found)),
        })}`,
      );
    else if (command === "install") {
      const receipt = await installDistribution(
        target,
        rest[0] === "--use-existing-state",
      );
      output.stdout(
        `Installed ${receipt.app.id}@${receipt.app.version}: ${receipt.commandPath}\nAdd ${binHome()} to PATH if needed.`,
      );
    } else if (command === "purge") {
      if (rest[0] !== "--yes")
        throw new Error(
          "Purge deletes this distribution's state; repeat with --yes after checking the id",
        );
      output.stdout(purgeReport(await purgeDistributionState(target)));
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
              ...(lock.governance ? { governance: lock.governance } : {}),
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
              ...(lock.governance ? { governance: lock.governance } : {}),
              artifact,
              state: runtimeStateDirectory({ value: lock.app.id }),
            },
            null,
            2,
          ),
        );
      }
    } else if (command === "dev" || command === "test") {
      // Local iteration: the supply-chain gates run on build and release.
      const artifact = buildDistribution(target, undefined, {
        supplyChainGates: false,
        abandonedStaging: (found) => output.stderr(stagingNotice(found)),
      });
      const lock = requireCurrentLock(target);
      // `dev --smoke` runs the same isolated launch headlessly, for scripts.
      const interactive = command === "dev" && rest[0] !== "--smoke";
      const result = runLauncher(
        artifact,
        lock.app.command,
        command === "test"
          ? [rest[0] === "--model-request" ? "--smoke-model" : "--smoke"]
          : interactive
            ? []
            : ["--smoke"],
        interactive,
      );
      if (result.status !== 0)
        throw new Error(`Pi launch failed: ${result.stderr || result.status}`);
      if (command === "test")
        output.stdout(
          `${lock.deployment.mode === "managed" ? "Managed" : "Personal"} acceptance passed: ${result.stdout.trim()}`,
        );
      else if (!interactive) output.stdout(result.stdout.trim());
    } else if (command === "doctor") {
      const artifact = artifactFor(target);
      const app = payloadApp(artifact);
      const lock = verifyPayload(artifact);
      if (lock.access || lock.governance) {
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

async function runLifecycle(
  command: string,
  { positional, options, flags }: Parsed,
  output: CliOutput,
): Promise<number> {
  const [first = "", second = ""] = positional;
  if (command === "release") {
    const built = await buildRelease(first, {
      ...(options["--out"] ? { outputRoot: options["--out"] } : {}),
      ...(options["--channel"] ? { channel: options["--channel"] } : {}),
      reclaimStaging: flags.has("--reclaim-staging"),
      abandonedStaging: (found) => output.stderr(stagingNotice(found)),
    });
    output.stdout(
      `Built release ${built.name} (${built.metadata.channel})\n  archive  ${built.archive}\n  sha256   ${built.sha256}\n  tests    ${built.metadata.tests.map((test) => test.name).join(", ")}\n  SBOM     ${built.metadata.sbom.packages} packages\nThis local build is unsigned: publish it through a signed channel (piship sign-channel) or verified provenance before calling it a release.`,
    );
  } else if (command === "verify-release") {
    const verified = await verifyRelease(first, {
      ...(options["--sha256"] ? { expectedSha256: options["--sha256"] } : {}),
    });
    try {
      const { metadata } = verified;
      output.stdout(
        flags.has("--json")
          ? JSON.stringify(metadata, null, 2)
          : `Verified ${metadata.distribution.name} ${metadata.distribution.version} for ${metadata.target} (${metadata.channel})\n  PiShip ${metadata.piship.version}, Pi ${metadata.pi.version} (${metadata.pi.compatibility})\n  payload ${metadata.payload.files} files match their inventory\n  SBOM ${metadata.sbom.packages} packages, notices, checksums, and vulnerability scan (${metadata.vulnerabilities.verdict}, fail on ${metadata.vulnerabilities.failOn}) verified\n  tests ${metadata.tests.map((test) => test.name).join(", ")}\nPublisher identity is not checked here: verify the channel signature or build provenance.`,
      );
    } finally {
      verified.cleanup();
    }
  } else if (command === "diff") {
    const report = diffLocks(await lockFor(first), await lockFor(second));
    output.stdout(
      flags.has("--json")
        ? JSON.stringify(report, null, 2)
        : formatDiff(report).trimEnd(),
    );
  } else if (command === "uninstall") {
    if (flags.has("--yes") && !flags.has("--purge")) {
      output.stderr(`Usage: piship ${lifecycleCommands.uninstall?.usage}`);
      return 2;
    }
    if (!flags.has("--purge"))
      output.stdout(
        `Uninstalled ${first}. State preserved: ${uninstallDistribution(first)}`,
      );
    else {
      if (!flags.has("--yes"))
        throw new Error(
          "Uninstall with --purge also deletes this distribution's state; repeat with --yes after checking the id",
        );
      // The installed release is often the only PiShip the user has, so the
      // purge happens here rather than after it is gone.
      output.stdout(
        `Uninstalled ${first}. ${purgeReport(await uninstallAndPurgeDistribution(first))}`,
      );
    }
  } else if (command === "update" || command === "rollback") {
    // The active release performs the switch so its audit and credential
    // handling apply.
    const receipt = readInstallReceipt(first);
    const args = [command, ...Object.entries(options).flat(), ...[...flags]];
    const result = runLauncher(receipt.payload, receipt.app.command, args);
    if (result.stdout.trim()) output.stdout(result.stdout.trimEnd());
    if (result.status !== 0) {
      output.stderr(result.stderr.trim() || `${command} failed`);
      return 1;
    }
    if (result.stderr.trim()) output.stderr(result.stderr.trimEnd());
  } else if (command === "migrate-check") {
    const receipt = readInstallReceipt(first);
    const current = verifyPayload(receipt.payload);
    const path = resolve(second);
    const verified =
      statSync(path).isFile() || existsSync(join(path, "release.json"))
        ? await verifyRelease(path)
        : undefined;
    try {
      const target = verified?.lock ?? verifyPayload(path);
      if (target.app.id !== first)
        throw new Error(`${second} is ${target.app.id}, not ${first}`);
      const report = checkStateMigration(
        runtimeStateDirectory({ value: first }),
        {
          version: target.app.version,
          pi: target.runtime.version,
          schemas:
            verified?.metadata.stateSchemas ?? payloadStateSchemas(target),
          ...storageOf(target),
        },
        {
          version: receipt.active,
          pi: current.runtime.version,
          ...storageOf(current),
        },
      );
      output.stdout(formatMigrationReport(report));
      if (report.verdict === "unsupported") return 1;
    } finally {
      verified?.cleanup();
    }
  } else if (command === "keygen") {
    const id = options["--id"];
    if (!id) throw new Error("keygen needs --id <key-id>");
    const pair = generateSigningKey(id);
    const location = writePrivateKey(first, pair.privateKeyPem, {
      forceInWorktree: flags.has("--force-in-worktree"),
    });
    if (location === "tracked-worktree")
      output.stderr(
        `Warning: ${first} is inside a git work tree and not git-ignored; do not commit it.`,
      );
    output.stdout(
      `Wrote the private key to ${first}. Keep it out of the repository and out of CI logs.\nAdd the public key to piship.yaml:\n\nupdates:\n  trust:\n    keys:\n      - id: ${id}\n        publicKey: ${pair.publicKey}\n\nFingerprint: ${keyFingerprint(pair.publicKey)}`,
    );
  } else if (command === "sign-channel") {
    const channel = options["--channel"];
    const key = options["--key"];
    const keyId = options["--key-id"];
    if (!channel || !key || !keyId)
      throw new Error("sign-channel needs --channel, --key, and --key-id");
    const { readFileSync } = await import("node:fs");
    const number = (value: string | undefined, name: string) => {
      if (value === undefined) return undefined;
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed < 1)
        throw new Error(`${name} must be a positive integer`);
      return parsed;
    };
    const sequence = number(options["--sequence"], "--sequence");
    const expiresDays = number(options["--expires-days"], "--expires-days");
    const signed = await signChannel({
      directory: first,
      channel,
      archives: positional.slice(1),
      privateKeyPem: readFileSync(key, "utf8"),
      keyId,
      ...(sequence ? { sequence } : {}),
      ...(expiresDays ? { expiresDays } : {}),
    });
    output.stdout(
      `Signed ${signed.path} (sequence ${signed.metadata.sequence}, expires ${signed.metadata.expires}) with ${keyId}:\n${signed.metadata.releases.map((item) => `  ${item.version} ${item.target} ${item.archive}`).join("\n")}`,
    );
  } else if (command === "reproducibility") {
    const report = await compareReleases(first, second);
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (options["--out"])
      (await import("node:fs")).writeFileSync(options["--out"], text);
    output.stdout(text.trimEnd());
    if (!report.payloadEqual) {
      output.stderr(
        `Payloads differ in ${report.payloadDifferences.length} file(s) for ${report.target}`,
      );
      return 1;
    }
  }
  return 0;
}
