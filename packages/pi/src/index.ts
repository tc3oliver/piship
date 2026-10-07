/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import {
  type createAgentSession,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import { PiShipError, startupMark, startupNote } from "@piship/contracts";
import {
  applyAgentFiles,
  applyPackageEnvironment,
  assertDisjointRoots,
  type DistributionLock,
  inlineLoginOffered,
  loginInline,
  runAuto,
  runConfig,
  runLogin,
  runLogout,
  runRollback,
  runSandbox,
  runtimeStateDirectory,
  runUpdate,
  sessionAutoApproveTarget,
  yoloRefusal,
} from "@piship/core";
import { runDoctor } from "./commands/doctor.js";
import { runCapabilities, runPolicy } from "./commands/governance.js";
import { runModels } from "./commands/models.js";
import { runInteractive, runSmoke } from "./commands/session.js";
import { piAgentDirectory } from "./environment.js";
import type { LaunchContext } from "./launch/context.js";
import { applyPiEnvironment } from "./launch/pi-defaults.js";
import {
  deferredDownloadNotice,
  deferredToolDownloads,
  installSearchTools,
} from "./launch/search-tools.js";

export {
  type GovernedRuntime,
  governModelRuntime,
  isCredentialRejection,
  isModelDenial,
  type ModelGovernance,
  type ModelPolicy,
} from "./governance.js";
export {
  type GovernanceInspection,
  type GovernanceOptions,
  GovernanceSession,
  inspectGovernance,
} from "./governance-session.js";
export { NO_CREDENTIAL_PLACEHOLDER } from "./launch/model-runtime.js";

export const PINNED_PI_VERSION = "1.0.3" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
/**
 * Pi's sibling packages at the exact versions reviewed with the pinned Pi.
 * Pi 1.0.1+ ships no npm shrinkwrap and declares them with `^`, so the root
 * package.json `overrides` hold them here when the npm lock is regenerated;
 * the compatibility suite asserts the overrides, the lock, and the install.
 */
export const PI_SIBLING_PINS: Readonly<Record<string, string>> = {
  "@earendil-works/chord": "1.0.3",
  "@earendil-works/pi-agent-core": "1.0.3",
  "@earendil-works/pi-ai": "1.0.3",
  "@earendil-works/pi-codemode": "1.0.3",
  "@earendil-works/pi-mcp": "1.0.3",
  "@earendil-works/pi-telemetry": "1.0.3",
  "@earendil-works/pi-tui": "1.0.3",
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
  startupNote("distribution", `${metadata.app.id}@${metadata.app.version}`);
  startupNote("piship_runtime", metadata.runtime.pishipVersion);
  startupNote("pi", VERSION);
  startupMark("launch_pi_distribution");
  if (
    metadata.runtime.package !== "@earendil-works/pi-coding-agent" ||
    metadata.runtime.version !== PINNED_PI_VERSION ||
    VERSION !== PINNED_PI_VERSION
  )
    throw new Error(
      "Built Pi metadata does not match the pinned upstream runtime",
    );
  // Pi fixed its tool directory from PI_CODING_AGENT_DIR when it was
  // imported, before this ran. An entry point that skipped
  // `preparePiEnvironment` would leave Pi on `~/.pi/agent/bin` and PATH.
  const agentDir = piAgentDirectory(metadata.app.id);
  const imported = process.env.PI_CODING_AGENT_DIR;
  if (!imported || resolve(imported) !== agentDir)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Pi was loaded with PI_CODING_AGENT_DIR ${imported ? `set to ${imported}` : "unset"}, not ${agentDir}`,
      {
        userAction:
          "Start the distribution through its branded command, which calls preparePiEnvironment from @piship/pi/environment before it imports @piship/pi",
      },
    );
  let args = [...options.args];
  let requestedModel: string | undefined;
  let newSession = false;
  let yolo = false;
  // The session options come first, in any order.
  for (;;) {
    if (args[0] === "--model" && requestedModel === undefined) {
      requestedModel = args[1];
      if (!requestedModel)
        throw new PiShipError("CONFIG_INVALID", "--model needs a model id");
      args = args.slice(2);
    } else if (args[0] === "--new-session" && !newSession) {
      newSession = true;
      args = args.slice(1);
    } else if (args[0] === "--yolo" && !yolo) {
      yolo = true;
      args = args.slice(1);
    } else break;
  }
  const sessionOption = !!requestedModel || newSession || yolo;
  if (yolo) {
    // It changes how a session decides asks: for a subcommand, --version, or
    // --help it means nothing, and nothing is started or written before that
    // is said. Where the distribution does not allow it, say so just as early.
    const command = metadata.app.command;
    if (
      args.length > 1 ||
      (args.length === 1 &&
        args[0] !== "--smoke" &&
        args[0] !== "--smoke-model")
    )
      throw new PiShipError(
        "CONFIG_INVALID",
        "--yolo applies only when a session starts: it cannot be combined with a subcommand, --help, or --version",
        {
          userAction: `Run ${command} --yolo on its own or with --model, --new-session, --smoke, or --smoke-model`,
        },
      );
    const refusal = yoloRefusal(metadata);
    if (refusal) throw refusal;
  }
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
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(agentDir, { recursive: true, mode: 0o700 });
  applyPiEnvironment(agentDir, metadata.deployment.mode);
  // What the packages declare for themselves: their environment, and the
  // configuration files they read from the agent directory. A managed launch
  // sets the environment again after it removed the shell's `PI_*` variables.
  applyPackageEnvironment(metadata, stateDir);
  // `--yolo` also switches on the permission provider's own session-wide
  // auto-approval where the distribution declares its key, for this launch
  // only: the file is put back when the process ends, and by the next launch
  // if this one is killed. A distribution without such a provider has nothing
  // to switch.
  const sessionAutoApprove =
    yolo && sessionAutoApproveTarget(metadata) !== undefined;
  // At a terminal in a managed distribution (see `inlineLoginOffered`), a
  // plain `login` that succeeds goes on into the session it was run for.
  const atTerminal = inlineLoginOffered(
    metadata.deployment.mode,
    { stdinTTY: !!process.stdin.isTTY, stdoutTTY: !!process.stdout.isTTY },
    process.env,
  );
  const loginContinues =
    !sessionOption && args.length === 1 && args[0] === "login" && atTerminal;
  const startsSession =
    args.length === 0 ||
    loginContinues ||
    (args.length === 1 &&
      (args[0] === "--smoke" || args[0] === "--smoke-model"));
  const agentFiles = startsSession
    ? applyAgentFiles(metadata, agentDir, {
        sessionAutoApprove,
        session: true,
      })
    : { restore: () => {}, endAutoApprove: undefined };
  process.once("exit", () => {
    try {
      agentFiles.restore();
    } catch {
      console.error(
        "The provider session settings could not be restored; the next launch will recover the abandoned override.",
      );
    }
  });
  // Bundled fd and rg go where Pi looks before PATH. The launcher pointed
  // Pi's agent directory here before Pi was imported (environment.ts).
  startupMark("search_tools_start");
  installSearchTools(metadata, options.distributionDir, agentDir);
  // Pi's interactive mode would wait for a download of a missing fd or rg.
  const deferred = deferredToolDownloads(metadata, agentDir);
  if (deferred.length) {
    process.env.PI_OFFLINE = "1";
    console.error(deferredDownloadNotice(deferred));
    startupNote("tool_downloads_deferred", deferred.join(","));
  }
  startupMark("search_tools_done");
  const ctx: LaunchContext = {
    metadata,
    distributionDir: resolve(options.distributionDir),
    stateDir,
    agentDir,
    mode: metadata.deployment.mode,
    out: (message) => console.log(message),
    err: (message) => console.error(message),
    // Only the interactive launch (no subcommand) may sign in on the spot.
    ...(args.length === 0 && atTerminal
      ? { loginInline: (access) => loginInline(ctx, access) }
      : {}),
    ...(yolo ? { yolo: true } : {}),
    ...(yolo && sessionAutoApprove && agentFiles.endAutoApprove
      ? { endProviderAutoApprove: agentFiles.endAutoApprove }
      : {}),
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
    // Only where it can work: a policy to relax, and in a managed
    // distribution the administrator's allowance.
    const yoloOffered = !!metadata.governance && !yoloRefusal(metadata);
    const yoloOption = yoloOffered ? " [--yolo]" : "";
    const yoloHelp = !yoloOffered
      ? ""
      : metadata.deployment.mode === "managed"
        ? "\n\n--yolo approves asks from the distribution defaults without a prompt for this session only, audited; deny and enforced rules still apply, and nothing is stored."
        : "\n\n--yolo approves every ask without a prompt for this session only, audited; deny still applies, and nothing is stored.";
    const loginHelp = piNative
      ? ""
      : "\n\nlogin signs in; run bare at a terminal in a managed distribution, it then starts the session.";
    const piNativeHelp = piNative
      ? `\n\nSign-in happens inside Pi: start ${metadata.app.command}, then use /login and /logout, and /model to choose the provider and model.`
      : "";
    const managedHelp = metadata.access
      ? `\n\nCommands:\n  ${accessCommands}\n  update [--channel <name>] [--from <dir|url>] [--check] | rollback\n  config explain [--json] | config set <key> <value> | config unset <key>${governanceHelp}\n  [--model <id>] [--new-session]${yoloOption} [--smoke | --smoke-model]${yoloHelp}${loginHelp}${piNativeHelp}`
      : metadata.governance
        ? `\n\nCommands:\n  doctor [--json] | version | update [--check] | rollback${governanceHelp}\n  [--new-session]${yoloOption} [--smoke]${yoloHelp}`
        : "\n\nCommands:\n  doctor [--json] | version";
    ctx.out(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke] [--new-session]${managedHelp}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!sessionOption) {
    if (args.length === 1 && command === "login") {
      // A failed or cancelled login throws here and starts nothing.
      await runLogin(ctx);
      if (!loginContinues) return;
      ctx.err(`Signed in. Starting ${metadata.app.command}...`);
      return runInteractive(ctx, requestedModel, newSession);
    }
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
  // Maintenance runs after the session ends, outside the boot path.
  if (smoke)
    return runSmoke(
      ctx,
      requestedModel,
      command === "--smoke-model",
      newSession,
    );
  return runInteractive(ctx, requestedModel, newSession);
}
