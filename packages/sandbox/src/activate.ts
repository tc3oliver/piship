// Sandbox activation: select a backend, check that its capabilities can
// enforce the policy, prove it (a live probe for local backends, an outside
// check for the others), and expose wrap/exec for tool subprocesses. PiShip
// owns the environment, timeout, and cancellation of every command. A
// required sandbox never falls back.
import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { constants as osConstants, homedir, tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import {
  createTemporaryDirectory,
  PiShipError,
  processNetworkEnvironment,
  reclaimTemporaryDirectories,
  redact,
  type TemporaryDirectory,
} from "@piship/contracts";
import type { SandboxAdapter, WrappedCommand } from "./adapter.js";
import {
  capabilityMismatch,
  claimedGuarantees,
  enforcesPathPolicy,
  GIT_CONTROL_PROTECTION,
  HOST_FILESYSTEM_ISOLATION,
  networkProbe,
  PATH_POLICY_PLANES,
  type SandboxGuarantee,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxInstance,
  type SandboxNetworkProbe,
  type SandboxProvider,
  type SandboxWorkspaceDeclaration,
  WORKSPACE_CONFINEMENT,
  workspaceDeclaration,
} from "./backend.js";
import {
  filterEnvironment,
  stripCredentials,
  withApprovedNetwork,
} from "./environment.js";
import { NativeBackend } from "./native.js";
import { type ProbeTarget, probeSandbox } from "./probe.js";
import { spawnProcess } from "./process.js";
import {
  isWithin,
  type ProtectedPaths,
  realpathNearest,
  resolveProfile,
  type SandboxPolicy,
  type SandboxProfile,
} from "./profile.js";
import { selectAdapter } from "./select.js";
import {
  describeWorkspace,
  gitControlUnproven,
  initialWorkspaceReport,
  localWorkspaceReport,
  missingControlFiles,
  missingFilesWarning,
  verifyWorkspace,
  WORKSPACE_VALIDITY_MS,
  type WorkspaceReport,
  workspaceWindowMs,
} from "./workspace.js";

export type ContainmentLevel = "enforced" | "unavailable" | "not-required";

/**
 * How the enforced planes are known. `live-probe`: a real child inside the
 * backend failed to cross each plane. `backend-attested`: the backend
 * declares them; PiShip checked what it can from outside (the command
 * round trip and the environment it sends, and in deny mode the backend's
 * network probe when it declares one: see `NetworkDenialReport`).
 */
export type ContainmentVerification = "live-probe" | "backend-attested";

/**
 * How network denial is known, in deny mode. `verified`: the live probe
 * proved it (local backends), or a connection to the backend's network
 * probe succeeded from a temporary allow-mode sandbox of the same backend
 * and failed from the session's sandbox. `attested`: the backend's word;
 * PiShip could not show that the same target is reachable with the network
 * allowed, so a failed connection proves nothing and none is claimed.
 */
export interface NetworkDenialReport {
  readonly evidence: "verified" | "attested";
  /** Whether the backend declared a network probe. */
  readonly probe: boolean;
  /** Why it is attested: a fixed sentence, never an address. */
  readonly reason?: string;
}

export interface ContainmentReport {
  readonly level: ContainmentLevel;
  /** The backend id, such as `linux-bubblewrap` or `e2b-compatible`. */
  readonly adapter: string;
  readonly provider: SandboxProvider;
  readonly required: boolean;
  /**
   * Guarantees enforced by the backend; empty unless enforced. The
   * `filesystem-*` planes mean PiShip's path policy is enforced;
   * `host-filesystem-isolation` means only that a remote backend cannot
   * reach the host's files.
   */
  readonly planes: readonly SandboxGuarantee[];
  readonly network: "deny" | "allow";
  /** Set when enforced. */
  readonly verification?: ContainmentVerification;
  /** Set when enforced in deny mode. */
  readonly networkDenial?: NetworkDenialReport;
  /** Whether local processes (MCP stdio servers) can be contained. */
  readonly localProcesses: boolean;
  readonly reason?: string;
  readonly warnings: readonly string[];
  /** Where commands run: on this host, or on another machine. Set when enforced. */
  readonly isolation?: "local" | "remote";
  /**
   * How the sandbox sees the workspace, at activation. Set when enforced. A
   * shared or synchronized remote workspace is `pending` here: it is
   * verified before the first sandboxed command (`ActiveSandbox.workspace()`).
   */
  readonly workspace?: WorkspaceReport;
}

export interface ActivationContext {
  readonly workspace: string;
  /** Defaults to the OS home directory. */
  readonly homeDir?: string;
  /** Private per-session temp directory; created (and owned) when omitted. */
  readonly tmpDir?: string;
  readonly extraWritable?: readonly string[];
  readonly extraReadOnly?: readonly string[];
  /** Paths kept read-only even inside a writable path. */
  readonly protectedPaths?: ProtectedPaths;
  /** Activate even when not required; a failure then reports `unavailable`. */
  readonly enable?: boolean;
  readonly platform?: NodeJS.Platform;
  /** Native adapter override (tests, diagnostics). */
  readonly adapter?: SandboxAdapter;
  /** The backend; defaults to the native backend for the platform. */
  readonly backend?: SandboxBackend;
  /** Source environment for sandboxed commands. Defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  readonly probeTimeoutMs?: number;
  /**
   * How long PiShip waits for a backend to settle after it timed out or
   * cancelled a command before it stops waiting and retires the instance.
   */
  readonly settleMs?: number;
  /**
   * The project's origin. A backend's working-tree `sentinelDir` is used for
   * the workspace check only in a `company` project. Default `unknown`.
   */
  readonly projectOrigin?: "company" | "external" | "unknown";
  /** Wall clock for the workspace check's `verifiedAt` (tests). */
  readonly now?: () => number;
  /**
   * Monotonic clock for the workspace check's validity window and
   * propagation wait (tests). Default `performance.now`.
   */
  readonly monotonic?: () => number;
}

/** Structurally compatible with Pi's `BashOperations.exec` options. */
export interface SandboxExecOptions {
  onData: (data: Buffer) => void;
  signal?: AbortSignal;
  /** Seconds, as in Pi's bash tool. */
  timeout?: number;
  env?: NodeJS.ProcessEnv;
}

export interface ActiveSandbox {
  readonly report: ContainmentReport;
  readonly profile: SandboxProfile;
  /**
   * Wrap a command for spawning. With `env`, that approved environment is used
   * (credential names still stripped); otherwise the profile allowlist is
   * applied to the source environment. A backend that cannot contain local
   * processes refuses with SANDBOX_UNAVAILABLE.
   */
  wrap(
    file: string,
    args: readonly string[],
    cwd: string,
    env?: Readonly<Record<string, string>>,
  ): WrappedCommand;
  /**
   * Run one command. For a remote backend with a shared or synchronized
   * workspace, the workspace is verified first when no verification is valid
   * (the first command, 30 minutes later, or a new backend environment).
   */
  exec(
    command: string,
    cwd: string,
    options: SandboxExecOptions,
  ): Promise<{ exitCode: number | null }>;
  /** The live workspace report, updated after each verification. */
  workspace(): WorkspaceReport | undefined;
  /** Called with each new workspace report a verification produces. */
  onWorkspaceReport(listener: (report: WorkspaceReport) => void): void;
  /** Release the backend instance and remove the owned session temp directory. */
  dispose(): Promise<void>;
}

/** Variables the sandbox sets itself: the private session temp dir and the working directory. */
export const INJECTED_VARIABLES = ["TMPDIR", "PWD"] as const;

/**
 * Variables the operating system adds to every new process by itself. macOS
 * sets `__CF_USER_TEXT_ENCODING` (the user's text encoding id, not a secret)
 * in each child even from an empty environment.
 */
export function platformInjectedVariables(
  platform: NodeJS.Platform | string,
): readonly string[] {
  return platform === "darwin" ? ["__CF_USER_TEXT_ENCODING"] : [];
}

function sessionEnvironment(
  profile: SandboxProfile,
  approved: Record<string, string>,
): Record<string, string> {
  const env = { ...approved };
  delete env.TMPDIR;
  if (profile.writeAllow.some((path) => isWithin(profile.tmpDir, path)))
    env.TMPDIR = profile.tmpDir;
  return env;
}

function nodeDirectory(): string | undefined {
  try {
    return dirname(realpathSync(process.execPath));
  } catch {
    return undefined;
  }
}

function withNodeReadable(profile: SandboxProfile): SandboxProfile {
  // Keep the probe's interpreter reachable if it lives under a hidden /tmp,
  // without turning a writable location read-only.
  const dir = nodeDirectory();
  if (
    !dir ||
    profile.writeAllow.some((path) => isWithin(dir, path)) ||
    profile.readOnly.includes(dir)
  )
    return profile;
  return { ...profile, readOnly: [...profile.readOnly, dir] };
}

function shellFor(platform: NodeJS.Platform): { file: string; flag: string[] } {
  if (platform === "win32")
    return { file: process.env.ComSpec ?? "cmd.exe", flag: ["/d", "/s", "/c"] };
  return {
    file: existsSync("/bin/bash") ? "/bin/bash" : "/bin/sh",
    flag: ["-c"],
  };
}

function exitCodeOf(
  code: number | null,
  signal: NodeJS.Signals | null,
): number {
  if (code !== null) return code;
  return signal ? 128 + (osConstants.signals[signal] ?? 0) : 1;
}

/**
 * Variables that describe this host. A remote backend never receives them,
 * even when allowlisted: its own environment provides them.
 */
export const HOST_BOUND_VARIABLES = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "PWD",
] as const;

/** The working directory relative to the workspace, or undefined outside it. */
function workspacePath(workspace: string, cwd: string): string | undefined {
  const real = realpathNearest(cwd);
  if (!isWithin(real, workspace)) return undefined;
  const path = relative(workspace, real);
  return path === "" ? "." : path.split(sep).join("/");
}

const ABANDONED = Symbol("abandoned");

/** The default for `ActivationContext.settleMs`. */
const DEFAULT_SETTLE_MS = 5000;

interface GovernedRun {
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly settleMs: number;
  readonly onData: (chunk: Buffer) => void;
  /** Called when the backend ignored an abort for `settleMs`. */
  readonly retire: () => void;
}

type GovernedOutcome =
  | { readonly kind: "exit"; readonly exitCode: number }
  | { readonly kind: "timeout" }
  | { readonly kind: "cancelled" };

/**
 * Run one command through a backend instance with PiShip's timeout and
 * cancellation. PiShip decides the outcome: once it times out or cancels,
 * whatever the backend reports afterwards is ignored, output stops being
 * forwarded, and a backend that does not settle within `settleMs` has its
 * instance retired.
 */
async function runGoverned(
  instance: SandboxInstance,
  request: SandboxExecRequest,
  run: GovernedRun,
): Promise<GovernedOutcome> {
  if (run.signal?.aborted) return { kind: "cancelled" };
  const controller = new AbortController();
  let timedOut = false;
  let cancelled = false;
  let open = true;
  let settleTimer: NodeJS.Timeout | undefined;
  const onAbort = () => {
    cancelled = true;
    controller.abort();
  };
  run.signal?.addEventListener("abort", onAbort, { once: true });
  const timer =
    run.timeoutMs !== undefined && run.timeoutMs > 0
      ? setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, run.timeoutMs)
      : undefined;
  const abandoned = new Promise<typeof ABANDONED>((resolvePromise) => {
    controller.signal.addEventListener(
      "abort",
      () => {
        // The outcome is decided: nothing the backend prints afterwards counts.
        open = false;
        settleTimer = setTimeout(() => resolvePromise(ABANDONED), run.settleMs);
      },
      { once: true },
    );
  });
  const forward = (chunk: Buffer) => {
    if (open) run.onData(chunk);
  };
  const pending = Promise.resolve().then(() =>
    instance.exec(request, {
      signal: controller.signal,
      onStdout: forward,
      onStderr: forward,
    }),
  );
  // A late rejection after PiShip stopped waiting must not go unhandled.
  pending.catch(() => undefined);
  let result: SandboxExecResult | typeof ABANDONED | undefined;
  try {
    result = await Promise.race([pending, abandoned]);
  } catch (error) {
    if (!timedOut && !cancelled)
      throw new Error(redact(String((error as Error)?.message ?? error)));
  } finally {
    open = false;
    if (timer) clearTimeout(timer);
    if (settleTimer) clearTimeout(settleTimer);
    run.signal?.removeEventListener("abort", onAbort);
  }
  if (result === ABANDONED) run.retire();
  if (timedOut) return { kind: "timeout" };
  if (cancelled) return { kind: "cancelled" };
  const exit = result as SandboxExecResult | undefined;
  const code = Number.isInteger(exit?.exitCode)
    ? (exit?.exitCode as number)
    : null;
  return { kind: "exit", exitCode: exitCodeOf(code, exit?.signal ?? null) };
}

interface Session {
  readonly report: ContainmentReport;
  readonly profile: SandboxProfile;
  readonly backend: SandboxBackend;
  readonly instance: SandboxInstance | undefined;
  readonly capabilities: SandboxCapabilities | undefined;
  readonly sourceEnv: NodeJS.ProcessEnv;
  readonly platform: NodeJS.Platform;
  readonly ownedTmp: TemporaryDirectory | undefined;
  readonly settleMs: number;
  /** The validated workspace declaration; set when enforced. */
  readonly declaration?: SandboxWorkspaceDeclaration;
  readonly projectOrigin: "company" | "external" | "unknown";
  readonly now: () => number;
  readonly monotonic: () => number;
  /** Added to the workspace window to bound the workspace check command. */
  readonly checkTimeoutMs: number;
}

function unsafeWorkspaceError(
  report: ContainmentReport,
  mode: string,
  reason: string,
): PiShipError {
  return new PiShipError(
    "SANDBOX_UNAVAILABLE",
    `The ${report.adapter} sandbox backend declares a ${mode} workspace, but ${reason}; PiShip retired it and runs no command in it`,
    {
      component: "sandbox",
      userAction:
        "Make the sandbox backend keep the project's git control files and hooks read-only from inside the sandbox, then start a new session",
      sanitizedDetail: { adapter: report.adapter, provider: report.provider },
    },
  );
}

function retiredError(report: ContainmentReport): PiShipError {
  return new PiShipError(
    "SANDBOX_UNAVAILABLE",
    `The ${report.adapter} sandbox backend did not stop a timed-out or cancelled command, so PiShip retired it; start a new session`,
    { component: "sandbox" },
  );
}

/** The approved environment for one command inside an enforced backend. */
function commandEnvironment(
  session: Pick<Session, "profile" | "platform" | "capabilities">,
  source: NodeJS.ProcessEnv,
): Record<string, string> {
  const filtered = filterEnvironment(
    source,
    session.profile.environmentAllow,
    {},
    session.platform,
  );
  // In a managed distribution no command receives a proxy, CA or TLS setting
  // that the allowlist happened to name: `withApprovedNetwork` drops them all.
  // A local command in a sandbox that allows the network then gets the approved
  // proxy and CA settings. A remote backend never does (they name this host's
  // proxy and files), and with the network denied there is nothing to
  // configure. A personal distribution has no approved settings, so its
  // command keeps what the sandbox allowed.
  const network = processNetworkEnvironment();
  const local = session.capabilities?.isolation !== "remote";
  const scoped = network
    ? withApprovedNetwork(
        filtered,
        local && session.profile.network === "allow"
          ? network
          : { ...network, variables: {} },
      )
    : filtered;
  if (local) return sessionEnvironment(session.profile, scoped);
  const hostBound = new Set<string>(HOST_BOUND_VARIABLES);
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(scoped))
    if (!hostBound.has(name.toUpperCase())) output[name] = value;
  return output;
}

function createActiveSandbox(session: Session): ActiveSandbox {
  const { report, profile, instance, sourceEnv, platform } = session;
  const enforced = report.level === "enforced" && instance !== undefined;
  let retired = false;
  let disposed = false;
  const retire = () => {
    if (retired) return;
    retired = true;
    void instance?.dispose().catch(() => undefined);
  };
  const approvedEnv = (env?: Readonly<Record<string, string>>) =>
    sessionEnvironment(
      profile,
      env
        ? stripCredentials(env)
        : filterEnvironment(sourceEnv, profile.environmentAllow, {}, platform),
    );
  const wrap: ActiveSandbox["wrap"] = (file, args, cwd, env) => {
    if (!enforced)
      return {
        file,
        args: [...args],
        cwd,
        env: env ? { ...env } : stripCredentials(sourceEnv),
      };
    if (retired || disposed) throw retiredError(report);
    if (!report.localProcesses || !instance.wrap)
      throw new PiShipError(
        "SANDBOX_UNAVAILABLE",
        `The ${report.adapter} sandbox backend cannot contain local processes such as MCP stdio servers`,
        {
          component: "sandbox",
          userAction:
            "Use an HTTP MCP server, or a sandbox backend that contains local processes",
        },
      );
    return instance.wrap({ file, args, cwd, env: approvedEnv(env) });
  };
  // Workspace verification (remote shared or synchronized only): lazily,
  // before the first command that reaches the sandbox, then again once the
  // result expires or the backend reports a new environment.
  const declaration = session.declaration;
  const verifies =
    enforced &&
    session.capabilities?.isolation === "remote" &&
    declaration !== undefined &&
    declaration.mode !== "snapshot";
  let workspace = report.workspace;
  const listeners: ((report: WorkspaceReport) => void)[] = [];
  let checkedAt: number | undefined;
  let checkedEpoch: string | undefined;
  let unsafe: PiShipError | undefined;
  let verifying: Promise<boolean> | undefined;
  const epoch = () => {
    try {
      const value = instance?.epoch?.();
      return typeof value === "string" ? value : undefined;
    } catch {
      return undefined;
    }
  };
  const due = () =>
    verifies &&
    (checkedAt === undefined ||
      session.monotonic() - checkedAt >= WORKSPACE_VALIDITY_MS ||
      epoch() !== checkedEpoch);
  /** One verification; false when the caller's signal cancelled it. */
  const verifyOnce = async (signal?: AbortSignal): Promise<boolean> => {
    if (!instance || !declaration) return true;
    const outcome = await verifyWorkspace(
      async (command, onData) => {
        const result = await runGoverned(
          instance,
          {
            command,
            cwd: profile.workspace,
            workspacePath: ".",
            env: commandEnvironment(session, sourceEnv),
          },
          {
            // Bounded by the window plus the command itself, and never
            // charged to the user's command timeout.
            timeoutMs: workspaceWindowMs(declaration) + session.checkTimeoutMs,
            ...(signal ? { signal } : {}),
            settleMs: session.settleMs,
            onData,
            retire,
          },
        );
        if (result.kind === "exit") return result.exitCode;
        throw new Error(`the workspace check ${result.kind}`);
      },
      {
        workspace: profile.workspace,
        origin: session.projectOrigin,
        declaration,
        protectedPaths: profile.writeProtect,
        now: session.now,
        monotonic: session.monotonic,
      },
    ).catch(() => ({
      // Anything unexpected on the host side proves nothing: fail closed.
      report: {
        ...(workspace ?? initialWorkspaceReport(declaration)),
        verification: "failed" as const,
        effective: "snapshot" as const,
        complete: false,
      },
      unsafe: "the workspace check could not run",
    }));
    if (signal?.aborted) return false;
    if (outcome.unsafe) {
      unsafe = unsafeWorkspaceError(report, declaration.mode, outcome.unsafe);
      retire();
    }
    workspace = outcome.report;
    checkedAt = session.monotonic();
    checkedEpoch = epoch();
    for (const listener of listeners)
      try {
        listener(workspace);
      } catch {
        // a listener never decides the command
      }
    return true;
  };
  const ensureVerified = async (signal?: AbortSignal) => {
    while (due()) {
      if (unsafe) throw unsafe;
      if (retired || disposed) throw retiredError(report);
      verifying ??= verifyOnce(signal).finally(() => {
        verifying = undefined;
      });
      // Another command's cancelled check does not count; run our own.
      if (await verifying) break;
      if (signal?.aborted) throw new Error("aborted");
    }
    if (unsafe) throw unsafe;
  };
  const exec: ActiveSandbox["exec"] = async (command, cwd, options) => {
    if (options.signal?.aborted) throw new Error("aborted");
    const remote = session.capabilities?.isolation === "remote";
    if (!(enforced && remote) && !existsSync(cwd))
      throw new Error(`Working directory does not exist: ${cwd}`);
    if (!enforced) {
      // Not contained: behave like a plain local shell, environment untouched.
      const shell = shellFor(platform);
      const exit = await spawnProcess({
        file: shell.file,
        args: [...shell.flag, command],
        cwd,
        env: options.env ?? sourceEnv,
        ...(options.timeout ? { timeoutMs: options.timeout * 1000 } : {}),
        graceMs: 1000,
        ...(options.signal ? { signal: options.signal } : {}),
        onStdout: options.onData,
        onStderr: options.onData,
      }).exited;
      if (exit.error) throw new Error(exit.error);
      if (exit.cancelled) throw new Error("aborted");
      if (exit.timedOut) throw new Error(`timeout:${options.timeout}`);
      return { exitCode: exitCodeOf(exit.code, exit.signal) };
    }
    if (unsafe) throw unsafe;
    if (retired || disposed) throw retiredError(report);
    const relativeCwd = workspacePath(profile.workspace, cwd);
    if (remote && relativeCwd === undefined)
      throw new Error(
        `Working directory is outside the workspace, where the ${report.adapter} sandbox backend cannot run commands: ${cwd}`,
      );
    await ensureVerified(options.signal);
    if (retired || disposed) throw retiredError(report);
    const outcome = await runGoverned(
      instance,
      {
        command,
        cwd,
        workspacePath: relativeCwd,
        env: commandEnvironment(session, options.env ?? sourceEnv),
      },
      {
        ...(options.timeout ? { timeoutMs: options.timeout * 1000 } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
        settleMs: session.settleMs,
        onData: options.onData,
        retire,
      },
    );
    if (outcome.kind === "cancelled") throw new Error("aborted");
    if (outcome.kind === "timeout")
      throw new Error(`timeout:${options.timeout}`);
    return { exitCode: outcome.exitCode };
  };
  return {
    report,
    profile,
    wrap,
    exec,
    workspace: () => workspace,
    onWorkspaceReport: (listener) => {
      listeners.push(listener);
    },
    dispose: async () => {
      if (disposed) return;
      disposed = true;
      if (!retired) await instance?.dispose().catch(() => undefined);
      removeSessionTmp(session.ownedTmp);
    },
  };
}

const sessionTmpDirs = new Set<TemporaryDirectory>();
let tmpExitHookInstalled = false;

/**
 * The session's temp directory: `piship-sandbox-*` holding the ownership
 * marker and, beside it, the `tmp` directory the sandbox gets as its TMPDIR.
 * The marker stays outside `tmp`, where contained commands can write, so
 * they can neither remove it (which would make the directory unrecoverable)
 * nor forge one. The exit hook removes the directory when the process ends
 * normally; a session killed by SIGKILL or a machine reset leaves it, and the
 * next activation reclaims it once its process is gone.
 */
function createSessionTmp(): TemporaryDirectory {
  reclaimTemporaryDirectories(tmpdir(), ["sandbox"]);
  const dir = createTemporaryDirectory(tmpdir(), "sandbox");
  sessionTmpDirs.add(dir);
  if (!tmpExitHookInstalled) {
    tmpExitHookInstalled = true;
    process.on("exit", () => {
      for (const path of sessionTmpDirs) removeSessionTmp(path);
    });
  }
  return dir;
}

function removeSessionTmp(dir: TemporaryDirectory | undefined): void {
  if (!dir) return;
  sessionTmpDirs.delete(dir);
  try {
    dir.remove();
  } catch {
    // best effort
  }
}

function unavailable(
  config: SandboxPolicy,
  backend: SandboxBackend,
  reason: string,
  warnings: readonly string[],
): ContainmentReport {
  if (config.required)
    throw new PiShipError(
      "SANDBOX_UNAVAILABLE",
      `The distribution requires a sandbox, but it cannot be enforced: ${reason}`,
      {
        component: "sandbox",
        userAction:
          backend.id === "unsupported"
            ? "Run this distribution on Linux (bubblewrap) or macOS (sandbox-exec), or use a remote sandbox backend"
            : "Fix the sandbox backend reported above; PiShip does not fall back to running unsandboxed",
        sanitizedDetail: { adapter: backend.id, provider: backend.provider },
      },
    );
  return {
    level: "unavailable",
    adapter: backend.id,
    provider: backend.provider,
    required: false,
    planes: [],
    network: config.network.mode,
    localProcesses: false,
    reason: redact(reason),
    warnings,
  };
}

function message(error: unknown): string {
  return redact(String((error as Error)?.message ?? error)).slice(0, 400);
}

/** Printed by the check command when it ran inside the backend. */
export const SANDBOX_READY_MARKER = "piship-sandbox-ready";
/** Set in the check command's source environment; it must never arrive. */
const UNLISTED_MARKER = "PISHIP_PROBE_UNLISTED";

function connectionCheck(host: string, port: number): string {
  // bash's /dev/tcp, else nc: whichever the image has decides.
  return `if command -v timeout >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then if timeout 5 bash -c 'exec 3<>/dev/tcp/${host}/${port}' >/dev/null 2>&1; then echo piship-network-reachable; else echo piship-network-blocked; fi; elif command -v nc >/dev/null 2>&1; then if nc -z -w 5 ${host} ${port} >/dev/null 2>&1; then echo piship-network-reachable; else echo piship-network-blocked; fi; else echo piship-network-unchecked; fi`;
}

function checkCommand(target: SandboxNetworkProbe | undefined): string {
  const lines = [
    `printf '%s %s\\n' ${SANDBOX_READY_MARKER} "\${${UNLISTED_MARKER}:-unset}"`,
  ];
  if (target) lines.push(connectionCheck(target.host, target.port));
  return lines.join("\n");
}

type NetworkCheck = "reachable" | "blocked" | "unchecked";

/**
 * The outside check for a backend PiShip cannot live-probe: a command must
 * run and report back, and the unlisted marker must not arrive. With a
 * `target`, the command also tries to connect to it and the result says
 * whether it could. Returns a failure reason and warnings.
 */
async function checkAttested(
  instance: SandboxInstance,
  session: Pick<Session, "profile" | "platform" | "capabilities">,
  sourceEnv: NodeJS.ProcessEnv,
  options: {
    timeoutMs: number;
    settleMs: number;
    target?: SandboxNetworkProbe;
  },
): Promise<{ failure?: string; warnings: string[]; network?: NetworkCheck }> {
  let output = "";
  const outcome = await runGoverned(
    instance,
    {
      command: checkCommand(options.target),
      cwd: session.profile.workspace,
      workspacePath: ".",
      env: commandEnvironment(session, {
        ...sourceEnv,
        [UNLISTED_MARKER]: "1",
      }),
    },
    {
      timeoutMs: options.timeoutMs,
      settleMs: options.settleMs,
      onData: (chunk) => {
        if (output.length < 4096) output += chunk.toString("utf8");
      },
      retire: () => {},
    },
  ).catch((error: unknown) => ({ kind: "error" as const, error }));
  if (outcome.kind === "error")
    return {
      failure: `the sandbox check command failed: ${message(outcome.error)}`,
      warnings: [],
    };
  if (outcome.kind !== "exit")
    return { failure: "the sandbox check command timed out", warnings: [] };
  const lines = output.split(/\r?\n/).map((line) => line.trim());
  const ready = lines.find((line) =>
    line.startsWith(`${SANDBOX_READY_MARKER} `),
  );
  if (outcome.exitCode !== 0 || !ready)
    return {
      failure: `the sandbox check command did not report back (exit ${outcome.exitCode})`,
      warnings: [],
    };
  if (ready !== `${SANDBOX_READY_MARKER} unset`)
    return {
      failure:
        "an unapproved environment variable reached the sandboxed command",
      warnings: [],
    };
  if (!options.target) return { warnings: [] };
  // A connection that succeeded counts whatever else the output says.
  const network: NetworkCheck = lines.includes("piship-network-reachable")
    ? "reachable"
    : lines.includes("piship-network-blocked")
      ? "blocked"
      : "unchecked";
  return { warnings: [], network };
}

/**
 * How network denial is known for a backend PiShip cannot live-probe, given
 * the session sandbox's check (`denied`). A connection to the probe from the
 * denied sandbox fails the activation. A blocked connection proves denial
 * only when the same probe is reachable from an allow-mode sandbox of the
 * same backend, which is created only then and only when the backend can
 * allow the network; anything else leaves the backend's word.
 */
async function networkDenial(
  backend: SandboxBackend,
  capabilities: SandboxCapabilities,
  probe: SandboxNetworkProbe | undefined,
  denied: NetworkCheck | undefined,
  contrast: () => Promise<NetworkCheck | undefined>,
): Promise<{ failure: string } | { report: NetworkDenialReport }> {
  const attested = (reason: string): { report: NetworkDenialReport } => ({
    report: { evidence: "attested", probe: probe !== undefined, reason },
  });
  if (!probe)
    return attested("the backend declares no network probe to check it with");
  if (denied === "reachable")
    return {
      failure:
        "a connection to the backend's network probe succeeded although the network is denied",
    };
  if (denied !== "blocked")
    return attested(
      "the connection check could not run inside the sandbox (it needs bash and timeout, or nc)",
    );
  const modes = Array.isArray(capabilities.network) ? capabilities.network : [];
  if (!modes.includes("allow"))
    return attested(
      "the backend cannot allow the network, so PiShip cannot show that its network probe is reachable at all",
    );
  let allowed: NetworkCheck | undefined;
  try {
    allowed = await contrast();
  } catch {
    return attested(
      `the ${backend.id} sandbox backend could not prepare an allow-mode sandbox to reach its network probe from`,
    );
  }
  if (allowed !== "reachable")
    return attested(
      "the backend's network probe was not reachable from an allow-mode sandbox either, so a blocked connection proves nothing",
    );
  return { report: { evidence: "verified", probe: true } };
}

/**
 * The profile of the allow-mode sandbox that contrasts network denial: an
 * empty workspace and temp directory under `root`, writable and nothing else,
 * with no path protected, hidden, or kept readable and no variable allowed.
 */
function contrastProfile(
  root: string,
  profile: SandboxProfile,
): SandboxProfile {
  const workspace = join(root, "workspace");
  const tmp = join(root, "tmp");
  mkdirSync(workspace, { mode: 0o700 });
  mkdirSync(tmp, { mode: 0o700 });
  const real = realpathSync(workspace);
  const realTmp = realpathSync(tmp);
  return {
    workspace: real,
    homeDir: profile.homeDir,
    tmpDir: realTmp,
    readDeny: [],
    writeAllow: [real, realTmp],
    readOnly: [],
    writeProtect: { files: [], directories: [] },
    network: "allow",
    environmentAllow: [],
    warnings: [],
  };
}

/** A probe target that prepares a separate wrapping instance per probe. */
function probeTarget(backend: SandboxBackend): ProbeTarget {
  return {
    prepare: async (profile) => {
      const instance = await backend.prepare({ profile });
      const wrap = instance.wrap?.bind(instance);
      if (!wrap) {
        await instance.dispose().catch(() => undefined);
        throw new Error("the backend instance cannot wrap a local process");
      }
      return {
        wrap,
        dispose: () => instance.dispose().catch(() => undefined),
      };
    },
  };
}

/**
 * Activate the configured sandbox. Required and not enforceable throws
 * SANDBOX_UNAVAILABLE; never falls back to an unrestricted run.
 */
export async function activateSandbox(
  config: SandboxPolicy,
  ctx: ActivationContext,
): Promise<ActiveSandbox> {
  const platform = ctx.platform ?? process.platform;
  const backend =
    ctx.backend ??
    new NativeBackend(ctx.adapter ?? selectAdapter(platform), platform);
  const active = config.required || ctx.enable === true;
  const ownedTmp = active && !ctx.tmpDir ? createSessionTmp() : undefined;
  // Without activation nothing is contained, so no session directory is made.
  const tmpDir =
    ctx.tmpDir ?? (ownedTmp ? join(ownedTmp.path, "tmp") : tmpdir());
  if (active) mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
  const settleMs = ctx.settleMs ?? DEFAULT_SETTLE_MS;
  let instance: SandboxInstance | undefined;
  const cleanupOnThrow = async () => {
    await instance?.dispose().catch(() => undefined);
    removeSessionTmp(ownedTmp);
  };
  try {
    const profile = withNodeReadable(
      resolveProfile(config, {
        workspace: ctx.workspace,
        homeDir: ctx.homeDir ?? homedir(),
        tmpDir,
        ...(ctx.extraWritable ? { extraWritable: ctx.extraWritable } : {}),
        ...(ctx.extraReadOnly ? { extraReadOnly: ctx.extraReadOnly } : {}),
        ...(ctx.protectedPaths ? { protectedPaths: ctx.protectedPaths } : {}),
      }),
    );
    const sourceEnv = ctx.env ?? process.env;
    const base = {
      profile,
      backend,
      sourceEnv,
      platform,
      ownedTmp,
      settleMs,
      projectOrigin: ctx.projectOrigin ?? ("unknown" as const),
      now: ctx.now ?? Date.now,
      monotonic: ctx.monotonic ?? (() => performance.now()),
      checkTimeoutMs: ctx.probeTimeoutMs ?? 30_000,
    };
    const fail = async (reason: string) => {
      await instance?.dispose().catch(() => undefined);
      instance = undefined;
      return createActiveSandbox({
        ...base,
        instance: undefined,
        capabilities: undefined,
        report: unavailable(config, backend, reason, profile.warnings),
      });
    };
    if (!active)
      return createActiveSandbox({
        ...base,
        instance: undefined,
        capabilities: undefined,
        report: {
          level: "not-required",
          adapter: backend.id,
          provider: backend.provider,
          required: false,
          planes: [],
          network: config.network.mode,
          localProcesses: false,
          warnings: profile.warnings,
        },
      });
    const availability = await Promise.resolve()
      .then(() => backend.available())
      .catch((error: unknown) => ({
        available: false as const,
        reason: message(error),
      }));
    if (
      !availability ||
      typeof availability !== "object" ||
      (availability.available !== true && availability.available !== false)
    )
      return await fail(
        `the ${backend.id} sandbox backend reported no availability`,
      );
    if (!availability.available)
      return await fail(message(availability.reason));
    let capabilities: SandboxCapabilities;
    try {
      capabilities = backend.capabilities();
    } catch (error) {
      return await fail(
        `the ${backend.id} sandbox backend reported no capabilities: ${message(error)}`,
      );
    }
    const mismatch = capabilityMismatch(capabilities, config.network.mode);
    if (mismatch)
      return await fail(
        `the ${backend.id} sandbox backend cannot enforce this policy: ${mismatch}`,
      );
    // Valid here: capabilityMismatch rejects a malformed declaration.
    const declared = workspaceDeclaration(capabilities);
    const declaration =
      "declaration" in declared
        ? declared.declaration
        : ({ mode: "snapshot" } as const);
    try {
      instance = await backend.prepare({ profile });
    } catch (error) {
      return await fail(
        `the ${backend.id} sandbox backend could not prepare a sandbox: ${message(error)}`,
      );
    }
    const session = { ...base, capabilities, declaration };
    const live =
      capabilities.isolation === "local" && typeof instance.wrap === "function";
    let verification: ContainmentVerification;
    let planes: readonly SandboxGuarantee[];
    let networkReport: NetworkDenialReport | undefined;
    const warnings = [...profile.warnings];
    if (live) {
      const env = sessionEnvironment(
        profile,
        filterEnvironment(
          { ...sourceEnv, [UNLISTED_MARKER]: "1" },
          profile.environmentAllow,
          {},
          platform,
        ),
      );
      const probe = await probeSandbox(
        backend instanceof NativeBackend
          ? backend.adapter
          : probeTarget(backend),
        profile,
        {
          env,
          injected: [
            ...INJECTED_VARIABLES,
            ...platformInjectedVariables(platform),
          ],
          ...(ctx.probeTimeoutMs ? { timeoutMs: ctx.probeTimeoutMs } : {}),
        },
      ).catch((error: unknown) => ({
        ok: false as const,
        reason: `the sandbox probe could not run: ${message(error)}`,
      }));
      if (!probe.ok) return await fail(probe.reason);
      verification = "live-probe";
      planes = probe.planes;
      if (profile.network === "deny")
        networkReport = { evidence: "verified", probe: false };
      warnings.push(...(probe.warnings ?? []));
    } else {
      const declaredProbe = networkProbe(capabilities);
      // Valid here: capabilityMismatch rejects a malformed probe.
      const probe =
        profile.network === "deny" && declaredProbe && "probe" in declaredProbe
          ? declaredProbe.probe
          : undefined;
      const checkOptions = {
        timeoutMs: ctx.probeTimeoutMs ?? 60_000,
        settleMs,
        ...(probe ? { target: probe } : {}),
      };
      const check = await checkAttested(
        instance,
        session,
        sourceEnv,
        checkOptions,
      );
      if (check.failure)
        return await fail(
          `the ${backend.id} sandbox backend failed its check: ${check.failure}`,
        );
      if (profile.network === "deny") {
        const denial = await networkDenial(
          backend,
          capabilities,
          probe,
          check.network,
          async () => {
            // The allow-mode sandbox sees none of the user's files or
            // environment: an empty workspace PiShip made, nothing protected
            // in it, and no variable to pass.
            const scratch = createTemporaryDirectory(tmpdir(), "sandbox");
            let allowed: SandboxInstance | undefined;
            try {
              const allowProfile = contrastProfile(scratch.path, profile);
              allowed = await backend.prepare({ profile: allowProfile });
              const contrast = await checkAttested(
                allowed,
                { ...session, profile: allowProfile },
                {},
                checkOptions,
              );
              return contrast.failure ? undefined : contrast.network;
            } finally {
              await allowed?.dispose().catch(() => undefined);
              scratch.remove();
            }
          },
        );
        if ("failure" in denial)
          return await fail(
            `the ${backend.id} sandbox backend failed its check: ${denial.failure}`,
          );
        networkReport = denial.report;
        // Lower than the backend declared: it named a probe that proved nothing.
        if (denial.report.evidence === "attested" && denial.report.probe)
          warnings.push(
            `network denial is attested by the backend, not verified: ${denial.report.reason}`,
          );
      }
      warnings.push(...check.warnings);
      verification = "backend-attested";
      planes = claimedGuarantees(capabilities, config.network.mode);
    }
    // What the isolator does about a protected file that does not exist yet:
    // it decides whether git control can be reported as verified.
    const isolator = {
      writable: profile.writeAllow,
      guardsMissingFiles: capabilities.guardsMissingFiles === true,
    };
    if (live && planes.includes(GIT_CONTROL_PROTECTION)) {
      const unguarded = missingFilesWarning(
        profile.workspace,
        missingControlFiles(profile.workspace, profile.writeProtect, isolator),
        backend.id,
        capabilities.guardsMissingFiles === true
          ? "directory"
          : capabilities.guardsMissingFiles === false
            ? "cannot"
            : "say",
      );
      if (unguarded) warnings.push(unguarded);
    }
    return createActiveSandbox({
      ...session,
      instance,
      report: {
        level: "enforced",
        adapter: backend.id,
        provider: backend.provider,
        required: config.required,
        planes,
        network: config.network.mode,
        verification,
        ...(networkReport ? { networkDenial: networkReport } : {}),
        localProcesses:
          capabilities.localProcesses &&
          capabilities.isolation === "local" &&
          typeof instance.wrap === "function",
        warnings,
        isolation: capabilities.isolation,
        workspace:
          capabilities.isolation === "local"
            ? localWorkspaceReport(
                live &&
                  planes.includes(GIT_CONTROL_PROTECTION) &&
                  !gitControlUnproven(
                    profile.workspace,
                    profile.writeProtect,
                    "local",
                    isolator,
                  ),
              )
            : initialWorkspaceReport(declaration),
      },
    });
  } catch (error) {
    await cleanupOnThrow();
    throw error;
  }
}

/**
 * One doctor line: the effective containment level and its planes, and for
 * an enforced remote backend how it sees the workspace (`workspace`, the live
 * report, defaults to the one at activation).
 */
export function describeContainment(
  report: ContainmentReport,
  workspace: WorkspaceReport | undefined = report.workspace,
): string {
  const requirement = report.required ? "required" : "optional";
  switch (report.level) {
    case "enforced": {
      const how =
        report.verification === "backend-attested"
          ? `${requirement}, attested by the backend`
          : requirement;
      const scope = report.localProcesses
        ? "Contains tool subprocesses and MCP stdio servers"
        : "Contains shell commands; MCP stdio servers cannot be contained by this backend and do not start";
      const partial = PATH_POLICY_PLANES.filter((plane) =>
        report.planes.includes(plane),
      );
      const paths = enforcesPathPolicy(report.planes)
        ? ""
        : partial.length
          ? ` sandbox.filesystem path rules are only partly enforced by the backend (${partial.join(", ")} only); PiShip's local file tools still apply them in full.`
          : report.planes.includes(HOST_FILESYSTEM_ISOLATION)
            ? " The sandbox cannot reach this host's files, but it does not enforce sandbox.filesystem path rules; they govern only the local file tools."
            : report.planes.includes(WORKSPACE_CONFINEMENT)
              ? " The sandbox reaches this host's files only through the workspace, where it does not enforce sandbox.filesystem path rules: a read-denied path inside the workspace is readable by sandboxed commands."
              : " sandbox.filesystem path rules are not enforced by the backend.";
      const network =
        report.networkDenial?.evidence === "verified"
          ? " (verified)"
          : report.networkDenial
            ? " (attested by the backend, not verified)"
            : "";
      const line = `enforced by ${report.adapter} (${how}): ${report.planes.join(", ")}; network ${report.network}${network}. ${scope}, not the agent process or in-process extensions${paths ? `.${paths}` : ""}`;
      if (report.isolation !== "remote" || !workspace) return line;
      return `${line}${line.endsWith(".") ? "" : "."} ${describeWorkspace(workspace)}`;
    }
    case "unavailable":
      return `unavailable on ${report.adapter} (${requirement}): ${redact(report.reason ?? "unknown reason")}. Tool subprocesses run with the user's privileges`;
    default:
      return "not required: no sandbox is active; tool subprocesses run with the user's privileges";
  }
}
