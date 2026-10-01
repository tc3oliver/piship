/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  VERSION,
  type createAgentSession,
} from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import {
  assertDisjointRoots,
  type DistributionLock,
  runConfig,
  runLogin,
  runLogout,
  runRollback,
  runSandbox,
  reclaimLaunchTemporaries,
  runUpdate,
  runtimeStateDirectory,
  sweepStateTemporaries,
} from "@piship/core";
import { runDoctor } from "./commands/doctor.js";
import { runCapabilities, runPolicy } from "./commands/governance.js";
import { runModels } from "./commands/models.js";
import { runInteractive, runSmoke } from "./commands/session.js";
import type { LaunchContext } from "./launch/context.js";

export {
  governModelRuntime,
  isCredentialRejection,
  isModelDenial,
  type ModelGovernance,
  type ModelPolicy,
  type GovernedRuntime,
} from "./governance.js";
export {
  GovernanceSession,
  inspectGovernance,
  type GovernanceInspection,
  type GovernanceOptions,
} from "./governance-session.js";
export { NO_CREDENTIAL_PLACEHOLDER } from "./launch/model-runtime.js";

export const PINNED_PI_VERSION = "0.87.1" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
export type PiSessionFactory = typeof createAgentSession;
export interface LaunchOptions {
  readonly distributionDir: string;
  readonly metadata: DistributionLock;
  readonly args: readonly string[];
}

/** Starts Pi's real SDK/runtime and the branded management commands. */
export async function launchPiDistribution(
  options: LaunchOptions,
): Promise<void> {
  const { metadata } = options;
  if (
    metadata.runtime.package !== "@earendil-works/pi-coding-agent" ||
    metadata.runtime.version !== PINNED_PI_VERSION ||
    VERSION !== PINNED_PI_VERSION
  )
    throw new Error(
      "Built Pi metadata does not match the pinned upstream runtime",
    );
  let args = [...options.args];
  let requestedModel: string | undefined;
  let newSession = false;
  // The session options come first, in either order.
  for (;;) {
    if (args[0] === "--model" && requestedModel === undefined) {
      requestedModel = args[1];
      if (!requestedModel)
        throw new PiShipError("CONFIG_INVALID", "--model needs a model id");
      args = args.slice(2);
    } else if (args[0] === "--new-session" && !newSession) {
      newSession = true;
      args = args.slice(1);
    } else break;
  }
  const sessionOption = !!requestedModel || newSession;
  // Pi's interactive TUI waits for keyboard input forever without a terminal,
  // and there is no non-interactive prompt mode. Refuse before any state,
  // identity session, credential or sandbox exists.
  if (args.length === 0 && !(process.stdin.isTTY && process.stdout.isTTY)) {
    const command = metadata.app.command;
    throw new PiShipError(
      "CONFIG_INVALID",
      `${command} needs a terminal: the interactive session cannot run with stdin or stdout redirected, and there is no non-interactive prompt mode`,
      {
        userAction: `Run ${command} in a terminal. Without one, use ${command} --smoke (or --smoke-model) for an acceptance check, or a subcommand such as ${command} doctor (see ${command} --help).`,
      },
    );
  }
  // Before anything is written to a layout in which one lifecycle operation
  // could delete another's files.
  assertDisjointRoots();
  const stateDir = runtimeStateDirectory({ value: metadata.app.id });
  const agentDir = join(stateDir, "agent");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(agentDir, { recursive: true, mode: 0o700 });
  // Temporaries of state writers killed before their rename.
  sweepStateTemporaries(stateDir);
  // Directories of PiShip operations killed before they cleaned up: session
  // sandbox temp, verification and launch-check scratch, install and update
  // staging. Only those whose owner is gone are removed, within a bounded
  // time: what is left waits for a later start, and the user is told.
  const reclaimNotice = reclaimLaunchTemporaries(metadata.app.id);
  if (reclaimNotice) console.error(reclaimNotice);
  const ctx: LaunchContext = {
    metadata,
    distributionDir: resolve(options.distributionDir),
    stateDir,
    agentDir,
    mode: metadata.deployment.mode,
    out: (message) => console.log(message),
    err: (message) => console.error(message),
  };
  const [command, ...rest] = args;
  if (
    !sessionOption &&
    args.length === 1 &&
    (command === "--version" || command === "version")
  ) {
    ctx.out(
      `${metadata.app.name} ${metadata.app.version}\nPiShip ${metadata.runtime.pishipVersion}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!sessionOption && args.length === 1 && command === "--help") {
    const governanceHelp = metadata.governance
      ? `\n  policy explain <action> <resource> [--json] | capabilities [--json]${
          metadata.governance.manifest.sandbox.credential === "stored"
            ? "\n  sandbox login | sandbox logout"
            : ""
        }`
      : "";
    // Pi-native access signs in inside the Pi session; branded login and
    // logout refuse it, so they are not advertised.
    const piNative = metadata.access?.credential.provider === "pi-native";
    const accessCommands = piNative
      ? "doctor | models | version"
      : "login | logout | doctor | models | version";
    const piNativeHelp = piNative
      ? `\n\nSign-in happens inside Pi: start ${metadata.app.command}, then use /login and /logout, and /model to choose the provider and model.`
      : "";
    const managedHelp = metadata.access
      ? `\n\nCommands:\n  ${accessCommands}\n  update [--channel <name>] [--from <dir|url>] [--check] | rollback\n  config explain [--json] | config set <key> <value> | config unset <key>${governanceHelp}\n  [--model <id>] [--new-session] [--smoke | --smoke-model]${piNativeHelp}`
      : metadata.governance
        ? `\n\nCommands:\n  doctor | version | update [--check] | rollback${governanceHelp}\n  [--new-session] [--smoke]`
        : "\n\nCommands:\n  doctor | version";
    ctx.out(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke] [--new-session]${managedHelp}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!sessionOption) {
    if (args.length === 1 && command === "login") return runLogin(ctx);
    if (args.length === 1 && command === "logout") return runLogout(ctx);
    if (args.length === 1 && command === "doctor") return runDoctor(ctx);
    if (args.length === 1 && command === "models") return runModels(ctx);
    if (command === "update") return runUpdate(ctx, rest);
    if (args.length === 1 && command === "rollback") return runRollback(ctx);
    if (command === "config") return runConfig(ctx, rest);
    // Every sandbox subcommand goes to the runner, which refuses anything
    // but login and logout without echoing the command line: a mistyped one
    // may hold the secret.
    if (command === "sandbox") return runSandbox(ctx, rest);
    if (command === "policy") return runPolicy(ctx, rest);
    if (command === "capabilities") return runCapabilities(ctx, rest);
  }
  if (
    args.length === 1 &&
    (command === "--smoke" || command === "--smoke-model")
  )
    return runSmoke(
      ctx,
      requestedModel,
      command === "--smoke-model",
      newSession,
    );
  if (args.length > 0)
    throw new Error(
      `Unknown branded command option: ${args.join(" ")}\n${metadata.app.command} has no non-interactive prompt mode; see ${metadata.app.command} --help.`,
    );
  return runInteractive(ctx, requestedModel, newSession);
}
