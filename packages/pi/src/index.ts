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
  runAuto,
  runUpdate,
  runtimeStateDirectory,
  sweepDistributionData,
  sweepStateTemporaries,
} from "@piship/core";
import { runDoctor } from "./commands/doctor.js";
import { runCapabilities, runPolicy } from "./commands/governance.js";
import { runModels } from "./commands/models.js";
import { runInteractive, runSmoke } from "./commands/session.js";
import type { LaunchContext } from "./launch/context.js";
import { applyPiEnvironment } from "./launch/pi-defaults.js";
import { liveOwner, SessionOwnership } from "./launch/session-file.js";

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

export const PINNED_PI_VERSION = "1.0.2" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
/**
 * Pi's sibling packages at the exact versions reviewed with the pinned Pi.
 * Pi 1.0.1+ ships no npm shrinkwrap and declares them with `^`, so the root
 * package.json `overrides` hold them here when the npm lock is regenerated;
 * the compatibility suite asserts the overrides, the lock, and the install.
 */
export const PI_SIBLING_PINS: Readonly<Record<string, string>> = {
  "@earendil-works/chord": "1.0.2",
  "@earendil-works/pi-agent-core": "1.0.2",
  "@earendil-works/pi-ai": "1.0.2",
  "@earendil-works/pi-codemode": "1.0.2",
  "@earendil-works/pi-mcp": "1.0.2",
  "@earendil-works/pi-telemetry": "1.0.2",
  "@earendil-works/pi-tui": "1.0.2",
};
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
  applyPiEnvironment(agentDir, metadata.deployment.mode);
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
        }${
          metadata.governance.manifest.policy.userAuto === "allowed" &&
          metadata.deployment.mode === "managed"
            ? "\n  auto on | auto off | auto status"
            : ""
        }`
      : "";
    // Pi-native access signs in inside the Pi session; branded login and
    // logout refuse it, so they are not advertised.
    const piNative = metadata.access?.credential.provider === "pi-native";
    const accessCommands = piNative
      ? "doctor [--json] | models | version"
      : "login | logout | doctor [--json] | models | version";
    const piNativeHelp = piNative
      ? `\n\nSign-in happens inside Pi: start ${metadata.app.command}, then use /login and /logout, and /model to choose the provider and model.`
      : "";
    const managedHelp = metadata.access
      ? `\n\nCommands:\n  ${accessCommands}\n  update [--channel <name>] [--from <dir|url>] [--check] | rollback\n  config explain [--json] | config set <key> <value> | config unset <key>${governanceHelp}\n  [--model <id>] [--new-session] [--smoke | --smoke-model]${piNativeHelp}`
      : metadata.governance
        ? `\n\nCommands:\n  doctor [--json] | version | update [--check] | rollback${governanceHelp}\n  [--new-session] [--smoke]`
        : "\n\nCommands:\n  doctor [--json] | version";
    ctx.out(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke] [--new-session]${managedHelp}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!sessionOption) {
    if (args.length === 1 && command === "login") return runLogin(ctx);
    if (args.length === 1 && command === "logout") return runLogout(ctx);
    if (command === "doctor") return runDoctor(ctx, rest);
    if (args.length === 1 && command === "models") return runModels(ctx);
    if (command === "update") return runUpdate(ctx, rest);
    if (args.length === 1 && command === "rollback") return runRollback(ctx);
    if (command === "config") return runConfig(ctx, rest);
    // Every sandbox subcommand goes to the runner, which refuses anything
    // but login and logout without echoing the command line: a mistyped one
    // may hold the secret.
    if (command === "sandbox") return runSandbox(ctx, rest);
    if (command === "policy") return runPolicy(ctx, rest);
    if (command === "auto") return runAuto(ctx, rest);
    if (command === "capabilities") return runCapabilities(ctx, rest);
  }
  const smoke =
    args.length === 1 && (command === "--smoke" || command === "--smoke-model");
  if (args.length > 0 && !smoke)
    throw new Error(
      `Unknown branded command option: ${args.join(" ")}\n${metadata.app.command} has no non-interactive prompt mode; see ${metadata.app.command} --help.`,
    );
  // The data retention sweep runs when a session launches, before it claims
  // a session file; a session another launch holds is kept, and one is
  // deleted only under the sweep's own claim, so a launch resuming it at the
  // same time keeps it.
  await sweepDistributionData(ctx, "launch", {
    sessionHeld: (file) => liveOwner(file) !== undefined,
    claimSession: (file) => {
      const ownership = new SessionOwnership();
      return ownership.claim(file) ? () => ownership.release() : undefined;
    },
  });
  if (smoke)
    return runSmoke(
      ctx,
      requestedModel,
      command === "--smoke-model",
      newSession,
    );
  return runInteractive(ctx, requestedModel, newSession);
}
