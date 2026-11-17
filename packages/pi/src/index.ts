/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { VERSION } from "@earendil-works/pi-coding-agent";
import {
  PiShipError,
  startupMark,
  startupNote,
  UsageError,
} from "@piship/contracts";
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
  runUninstall,
  runUpdate,
  sessionAutoApproveTarget,
  UNINSTALL_OPTIONS,
  UPDATE_OPTIONS,
  yoloRefusal,
} from "@piship/core";
import { runDoctor } from "./commands/doctor.js";
import { runCapabilities, runPolicy } from "./commands/governance.js";
import { runModels } from "./commands/models.js";
import {
  runInteractive,
  runSmoke,
  runSubagentChild,
} from "./commands/session.js";
import { piAgentDirectory } from "./environment.js";
import type { LaunchContext } from "./launch/context.js";
import { applyPiEnvironment } from "./launch/pi-defaults.js";
import { forgetPiTrust } from "./launch/project-trust.js";
import {
  deferredDownloadNotice,
  deferredToolDownloads,
  installSearchTools,
  searchToolProblemNotice,
} from "./launch/search-tools.js";
import {
  isSubagentChild,
  launchOutput,
  parseSubagentChild,
  unknownOptionMessage,
} from "./launch/subagent-child.js";
import {
  assertChildWorkspace,
  authenticateSubagentChild,
  type SubagentParent,
} from "./launch/subagent-owner.js";

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
// What a session publishes for its subagent children; a test stands in for one.
export { publishSubagentOwner } from "./launch/subagent-owner.js";

export const PINNED_PI_VERSION = "1.5.0" as const;
/**
 * Pi's sibling packages at the exact versions reviewed with the pinned Pi.
 * Pi 1.0.1+ ships no npm shrinkwrap, so the root
 * package.json `overrides` hold them here when the npm lock is regenerated;
 * the compatibility suite asserts the overrides, the lock, and the install.
 */
export const PI_SIBLING_PINS: Readonly<Record<string, string>> = {
  "@earendil-works/pi-agent-core": "1.5.0",
  "@earendil-works/pi-ai": "1.5.0",
  "@earendil-works/pi-codemode": "1.5.0",
  "@earendil-works/pi-mcp": "1.5.0",
  "@earendil-works/pi-schema": "1.5.0",
  "@earendil-works/pi-telemetry": "1.5.0",
  "@earendil-works/pi-tui": "1.5.0",
};
export interface LaunchOptions {
  readonly distributionDir: string;
  readonly metadata: DistributionLock;
  readonly args: readonly string[];
}

const SIMPLE_COMMAND_USAGE: Readonly<Record<string, string>> = {
  login:
    "Sign in; run bare at a terminal in a managed distribution, it then starts the session.",
  logout: "Sign out and remove the stored sign-in.",
  models:
    "List the models this distribution offers; --json prints them as JSON.",
  rollback: "Return to the previously installed release.",
  version: "Print the distribution, PiShip, and Pi versions.",
};

/** The subcommands, for naming a mistyped one and a known one misused. */
const BRANDED_COMMANDS = [
  "login",
  "logout",
  "doctor",
  "models",
  "version",
  "update",
  "rollback",
  "uninstall",
  "config",
  "sandbox",
  "policy",
  "auto",
  "capabilities",
];

/** `help` after a command means its `--help`. */
const helpArgs = (rest: readonly string[]): readonly string[] =>
  rest.length === 1 && rest[0] === "help" ? ["--help"] : rest;

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
  // pi-code's subagent tool runs this command as `--mode json -p ... <task>`
  // under PI_CODE_SUBAGENT=1. The options are parsed by allowlist before
  // anything starts; the child then takes the launch below as a session with
  // no arguments, and ends in Pi's print mode (see launch/subagent-child.ts).
  // It also proves a running session of this distribution started the child
  // and puts the child in that session's workspace (launch/subagent-owner.ts),
  // before the arguments are looked at.
  let parent: SubagentParent | undefined;
  if (isSubagentChild(args, process.env)) {
    parent = authenticateSubagentChild(
      runtimeStateDirectory({ value: metadata.app.id }),
    );
    assertChildWorkspace(parent.workspace);
  }
  const child = parent ? parseSubagentChild(args, process.env) : undefined;
  if (child) args = [];
  // A child's model is passed to the access check from `child` itself.
  let requestedModel: string | undefined;
  let newSession = false;
  let yolo = false;
  let taskGrantId: string | undefined;
  // `--session <id>` (and Pi's resume hint's `--session-dir <dir>`, which
  // must be this distribution's own) resumes one session, governed.
  let resume: { id: string; dir?: string } | undefined;
  // The session options come first, in any order.
  for (;;) {
    if (args[0] === "--model" && requestedModel === undefined) {
      requestedModel = args[1];
      if (!requestedModel)
        throw new PiShipError("CONFIG_INVALID", "--model needs a model id", {
          usage: true,
        });
      args = args.slice(2);
    } else if (args[0] === "--new-session" && !newSession) {
      newSession = true;
      args = args.slice(1);
    } else if (args[0] === "--task-grant" && !taskGrantId) {
      taskGrantId = args[1];
      if (!taskGrantId || !/^[A-Za-z0-9_-]{1,64}$/.test(taskGrantId))
        throw new PiShipError(
          "CONFIG_INVALID",
          "--task-grant needs a declared grant ID",
          {
            userAction: `Name one of the distribution's declared task grants: ${metadata.app.command} --task-grant <id>`,
            usage: true,
          },
        );
      args = args.slice(2);
    } else if (args[0] === "--yolo" && !yolo) {
      yolo = true;
      args = args.slice(1);
    } else if (args[0] === "--session" && !resume?.id) {
      const id = args[1] ?? "";
      if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id))
        throw new PiShipError(
          "CONFIG_INVALID",
          "--session needs a session ID",
          {
            userAction: `Run ${metadata.app.command} --session <id> with the ID the last session printed when it ended`,
            usage: true,
          },
        );
      resume = { ...resume, id };
      args = args.slice(2);
    } else if (args[0] === "--session-dir" && resume?.dir === undefined) {
      const dir = args[1];
      if (!dir)
        throw new PiShipError(
          "CONFIG_INVALID",
          "--session-dir needs a directory",
          { usage: true },
        );
      resume = { id: resume?.id ?? "", dir };
      args = args.slice(2);
    } else break;
  }
  if (resume && (!resume.id || newSession || args.length > 0))
    throw new PiShipError(
      "CONFIG_INVALID",
      "--session resumes one session: it needs a session ID and cannot be combined with --new-session or a subcommand",
      {
        userAction: `Run ${metadata.app.command} --session <id> on its own or with --model`,
        usage: true,
      },
    );
  const sessionOption =
    !!requestedModel || newSession || yolo || !!taskGrantId || !!resume;
  if (taskGrantId && (yolo || !metadata.governance))
    throw new PiShipError(
      "CONFIG_INVALID",
      "--task-grant requires governance and cannot be combined with --yolo",
    );
  if (
    taskGrantId &&
    args.length > 0 &&
    !(
      args.length === 1 &&
      (args[0] === "--smoke" || args[0] === "--smoke-model")
    )
  )
    throw new PiShipError(
      "CONFIG_INVALID",
      "--task-grant applies only to a session",
      {
        userAction: `Start a session with ${metadata.app.command} --task-grant <id>, without a subcommand`,
        usage: true,
      },
    );
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
          usage: true,
        },
      );
    const refusal = yoloRefusal(metadata);
    if (refusal) throw refusal;
  }
  // Pi's interactive TUI waits for keyboard input forever without a terminal,
  // and there is no non-interactive prompt mode. Refuse before any state,
  // identity session, credential or sandbox exists.
  if (
    !child &&
    args.length === 0 &&
    !(process.stdin.isTTY && process.stdout.isTTY)
  ) {
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
  // Only a session has files to put back; a listener per call would pile up.
  if (startsSession)
    process.once("exit", () => {
      try {
        agentFiles.restore();
      } catch {
        console.error(
          "The provider session settings could not be restored; the next launch will recover the abandoned override.",
        );
      }
    });
  const ctx: LaunchContext = {
    metadata,
    distributionDir: resolve(options.distributionDir),
    stateDir,
    agentDir,
    mode: metadata.deployment.mode,
    forgetPiTrust: (written) => forgetPiTrust(agentDir, written),
    // A child's stdout is the JSON event stream only.
    out: launchOutput(!!child),
    err: (message) => console.error(message),
    // Only the interactive launch (no subcommand) may sign in on the spot.
    ...(!child && args.length === 0 && atTerminal
      ? { loginInline: (access) => loginInline(ctx, access) }
      : {}),
    ...(yolo ? { yolo: true } : {}),
    ...(taskGrantId ? { taskGrantId } : {}),
    ...(parent
      ? {
          subagent: {
            parentSession: parent.session,
            ...(parent.grant ? { grant: parent.grant } : {}),
            ...(parent.grantActive ? { grantActive: parent.grantActive } : {}),
          },
        }
      : {}),
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
  if (
    !sessionOption &&
    args.length === 1 &&
    (command === "--help" || command === "-h" || command === "help")
  ) {
    const governanceHelp = metadata.governance
      ? `\n  policy explain <action> <resource> [--json] | capabilities [--json]${
          metadata.governance.manifest.sandbox.credential === "stored"
            ? "\n  sandbox login | sandbox logout"
            : ""
        }${
          metadata.governance.manifest.sandbox.workspace === "remote"
            ? "\n  sandbox pull [--diff] [--yes] [--branch [<name>]] | --discard"
            : ""
        }${
          metadata.deployment.mode === "personal"
            ? "\n  config trust list | config trust forget [<path>|--all]"
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
      ? "doctor [--json] | models [--json] | version"
      : "login | logout | doctor [--json] | models [--json] | version";
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
    const smokeHelp = "\n\n--smoke prints the launch report as JSON and exits.";
    const smokeModelHelp =
      "\n\n--smoke prints the launch report as JSON and exits; --smoke-model also sends one acceptance prompt to the selected model.";
    const managedHelp = metadata.access
      ? `\n\nCommands:\n  ${accessCommands}\n  update ${UPDATE_OPTIONS} | rollback | uninstall ${UNINSTALL_OPTIONS}\n  config explain [--json] | config set <key> <value> | config unset <key>${governanceHelp}\n  [--model <id>] [--new-session] [--task-grant <id>]${yoloOption} [--smoke | --smoke-model]${smokeModelHelp}${yoloHelp}${loginHelp}${piNativeHelp}`
      : metadata.governance
        ? `\n\nCommands:\n  doctor [--json] | models [--json] | version | update ${UPDATE_OPTIONS} | rollback | uninstall ${UNINSTALL_OPTIONS}${governanceHelp}\n  [--new-session] [--task-grant <id>]${yoloOption} [--smoke | --smoke-model]${smokeModelHelp}${yoloHelp}`
        : `\n\nCommands:\n  doctor [--json] | models [--json] | version | uninstall ${UNINSTALL_OPTIONS}${smokeHelp}`;
    ctx.out(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke] [--new-session | --session <id>]${managedHelp}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  // Bundled fd and rg go where Pi looks before PATH. The launcher pointed
  // Pi's agent directory here before Pi was imported (environment.ts). A
  // problem with them (a lock without the target, a missing payload file, a
  // read-only agent directory, a payload copy that does not match the lock)
  // is a warning, never a failure: the command goes on without the tool, and
  // never runs one that is not the pinned executable. `--version` and
  // `--help` do not need them and never touch the agent directory.
  startupMark("search_tools_start");
  try {
    installSearchTools(
      metadata,
      options.distributionDir,
      agentDir,
      undefined,
      (tool, error) => ctx.err(searchToolProblemNotice(tool, error)),
    );
  } catch (error) {
    // Reading the receipt or the tool directory failed as a whole.
    ctx.err(
      `Warning: the bundled search tools could not be checked (${error instanceof Error ? error.message : String(error)}). This start goes on without them.`,
    );
  }
  // Pi's interactive mode would wait for a download of a missing fd or rg.
  const deferred = deferredToolDownloads(metadata, agentDir);
  if (deferred.length) {
    process.env.PI_OFFLINE = "1";
    console.error(deferredDownloadNotice(deferred));
    startupNote("tool_downloads_deferred", deferred.join(","));
  }
  startupMark("search_tools_done");
  if (!sessionOption) {
    // `<command> <cmd> --help` (or `help`) shows that command's usage; the
    // five below otherwise match only with no further argument.
    const wantsHelp =
      args.length === 2 &&
      (args[1] === "--help" || args[1] === "-h" || args[1] === "help");
    const simpleUsage = command ? SIMPLE_COMMAND_USAGE[command] : undefined;
    if (wantsHelp && simpleUsage) {
      ctx.out(`Usage: ${metadata.app.command} ${command}\n\n${simpleUsage}`);
      return;
    }
    if (args.length === 1 && command === "login") {
      // A failed or cancelled login throws here and starts nothing.
      await runLogin(ctx);
      if (!loginContinues) return;
      ctx.err(`Signed in. Starting ${metadata.app.command}...`);
      return runInteractive(ctx, requestedModel, newSession);
    }
    if (args.length === 1 && command === "logout") return runLogout(ctx);
    if (command === "doctor") return runDoctor(ctx, helpArgs(rest));
    if (
      command === "models" &&
      (args.length === 1 || (args.length === 2 && args[1] === "--json"))
    )
      return runModels(ctx, args.length === 2);
    if (command === "update") return runUpdate(ctx, helpArgs(rest));
    if (args.length === 1 && command === "rollback") return runRollback(ctx);
    if (command === "uninstall") return runUninstall(ctx, helpArgs(rest));
    if (command === "config") return runConfig(ctx, helpArgs(rest));
    // Every sandbox subcommand goes to the runner, which refuses anything
    // but login, logout and pull without echoing the command line: a
    // mistyped one may hold the secret.
    if (command === "sandbox") return runSandbox(ctx, rest);
    if (command === "policy") return runPolicy(ctx, rest);
    if (command === "auto") return runAuto(ctx, rest);
    if (command === "capabilities") return runCapabilities(ctx, rest);
  }
  if (child) return runSubagentChild(ctx, child);
  const smoke =
    args.length === 1 && (command === "--smoke" || command === "--smoke-model");
  if (args.length > 0 && !smoke)
    throw new UsageError(
      unknownOptionMessage(
        args,
        metadata.app.command,
        sessionOption ? [] : BRANDED_COMMANDS,
      ),
    );
  // Maintenance runs after the session ends, outside the boot path.
  if (smoke)
    return runSmoke(
      ctx,
      requestedModel,
      command === "--smoke-model",
      newSession,
    );
  return runInteractive(ctx, requestedModel, newSession, resume);
}
