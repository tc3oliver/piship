// Sandbox activation: select an adapter, prove it with a live probe, and
// expose wrap/exec for tool subprocesses. A required sandbox never falls back.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { constants as osConstants, homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PiShipError, redact } from "@piship/contracts";
import type {
  SandboxAdapter,
  SandboxAdapterId,
  WrappedCommand,
} from "./adapter.js";
import { filterEnvironment, stripCredentials } from "./environment.js";
import { type ContainmentPlane, probeSandbox } from "./probe.js";
import { spawnManaged, spawnProcess } from "./process.js";
import {
  isWithin,
  type ProtectedPaths,
  resolveProfile,
  type SandboxPolicy,
  type SandboxProfile,
} from "./profile.js";
import { selectAdapter } from "./select.js";

export type ContainmentLevel = "enforced" | "unavailable" | "not-required";

export interface ContainmentReport {
  readonly level: ContainmentLevel;
  readonly adapter: SandboxAdapterId;
  readonly required: boolean;
  /** Planes verified by the live probe; empty unless enforced. */
  readonly planes: readonly ContainmentPlane[];
  readonly network: "deny" | "allow";
  readonly reason?: string;
  readonly warnings: readonly string[];
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
  /** Adapter override (tests, diagnostics). */
  readonly adapter?: SandboxAdapter;
  /** Source environment for sandboxed commands. Defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  readonly probeTimeoutMs?: number;
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
   * applied to the source environment.
   */
  wrap(
    file: string,
    args: readonly string[],
    cwd: string,
    env?: Readonly<Record<string, string>>,
  ): WrappedCommand;
  exec(
    command: string,
    cwd: string,
    options: SandboxExecOptions,
  ): Promise<{ exitCode: number | null }>;
  /** Remove the owned session temp directory. */
  dispose(): void;
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

interface Session {
  readonly report: ContainmentReport;
  readonly profile: SandboxProfile;
  readonly adapter: SandboxAdapter;
  readonly sourceEnv: NodeJS.ProcessEnv;
  readonly platform: NodeJS.Platform;
  readonly ownedTmp: string | undefined;
}

function createActiveSandbox(session: Session): ActiveSandbox {
  const { report, profile, adapter, sourceEnv, platform } = session;
  const enforced = report.level === "enforced";
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
    return adapter.wrap(profile, { file, args, cwd, env: approvedEnv(env) });
  };
  const exec: ActiveSandbox["exec"] = async (command, cwd, options) => {
    if (options.signal?.aborted) throw new Error("aborted");
    if (!existsSync(cwd))
      throw new Error(`Working directory does not exist: ${cwd}`);
    const shell = shellFor(platform);
    const common = {
      file: shell.file,
      args: [...shell.flag, command],
      cwd,
      ...(options.timeout ? { timeoutMs: options.timeout * 1000 } : {}),
      graceMs: 1000,
      ...(options.signal ? { signal: options.signal } : {}),
      onStdout: options.onData,
      onStderr: options.onData,
    };
    const child = enforced
      ? spawnManaged({
          ...common,
          env: filterEnvironment(
            options.env ?? sourceEnv,
            profile.environmentAllow,
            {},
            platform,
          ),
          sandbox: { wrap },
        })
      : // Not contained: behave like a plain local shell, environment untouched.
        spawnProcess({ ...common, env: options.env ?? sourceEnv });
    const exit = await child.exited;
    if (exit.error) throw new Error(exit.error);
    if (exit.cancelled) throw new Error("aborted");
    if (exit.timedOut) throw new Error(`timeout:${options.timeout}`);
    return { exitCode: exitCodeOf(exit.code, exit.signal) };
  };
  return {
    report,
    profile,
    wrap,
    exec,
    dispose: () => removeSessionTmp(session.ownedTmp),
  };
}

const sessionTmpDirs = new Set<string>();
let tmpExitHookInstalled = false;

function createSessionTmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-sandbox-"));
  sessionTmpDirs.add(dir);
  if (!tmpExitHookInstalled) {
    tmpExitHookInstalled = true;
    process.on("exit", () => {
      for (const path of sessionTmpDirs) removeSessionTmp(path);
    });
  }
  return dir;
}

function removeSessionTmp(dir: string | undefined): void {
  if (!dir) return;
  sessionTmpDirs.delete(dir);
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // best effort
  }
}

function unavailable(
  config: SandboxPolicy,
  adapter: SandboxAdapterId,
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
          adapter === "unsupported"
            ? "Run this distribution on Linux (bubblewrap) or macOS (sandbox-exec)"
            : "Fix the sandbox mechanism reported above; PiShip does not fall back to running unsandboxed",
        sanitizedDetail: { adapter },
      },
    );
  return {
    level: "unavailable",
    adapter,
    required: false,
    planes: [],
    network: config.network.mode,
    reason: redact(reason),
    warnings,
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
  const adapter = ctx.adapter ?? selectAdapter(platform);
  const active = config.required || ctx.enable === true;
  const ownedTmp = active && !ctx.tmpDir ? createSessionTmp() : undefined;
  // Without activation nothing is contained, so no session directory is made.
  const tmpDir = ctx.tmpDir ?? ownedTmp ?? tmpdir();
  if (active) mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
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
  const session = { profile, adapter, sourceEnv, platform, ownedTmp };
  const cleanupOnThrow = () => removeSessionTmp(ownedTmp);
  try {
    if (!active)
      return createActiveSandbox({
        ...session,
        report: {
          level: "not-required",
          adapter: adapter.id,
          required: false,
          planes: [],
          network: config.network.mode,
          warnings: profile.warnings,
        },
      });
    const availability = await adapter.available();
    let report: ContainmentReport;
    if (!availability.available)
      report = unavailable(
        config,
        adapter.id,
        availability.reason,
        profile.warnings,
      );
    else {
      const env = sessionEnvironment(
        profile,
        filterEnvironment(
          { ...sourceEnv, PISHIP_PROBE_UNLISTED: "1" },
          profile.environmentAllow,
          {},
          platform,
        ),
      );
      const probe = await probeSandbox(adapter, profile, {
        env,
        injected: [
          ...INJECTED_VARIABLES,
          ...platformInjectedVariables(platform),
        ],
        ...(ctx.probeTimeoutMs ? { timeoutMs: ctx.probeTimeoutMs } : {}),
      });
      report = probe.ok
        ? {
            level: "enforced",
            adapter: adapter.id,
            required: config.required,
            planes: probe.planes,
            network: config.network.mode,
            warnings: profile.warnings,
          }
        : unavailable(config, adapter.id, probe.reason, profile.warnings);
    }
    return createActiveSandbox({ ...session, report });
  } catch (error) {
    cleanupOnThrow();
    throw error;
  }
}

/** One doctor line: the effective containment level and its planes. */
export function describeContainment(report: ContainmentReport): string {
  const requirement = report.required ? "required" : "optional";
  switch (report.level) {
    case "enforced":
      return `enforced by ${report.adapter} (${requirement}): ${report.planes.join(", ")}; network ${report.network}. Contains tool subprocesses and MCP stdio servers, not the agent process or in-process extensions`;
    case "unavailable":
      return `unavailable on ${report.adapter} (${requirement}): ${redact(report.reason ?? "unknown reason")}. Tool subprocesses run with the user's privileges`;
    default:
      return "not required: no OS sandbox is active; tool subprocesses run with the user's privileges";
  }
}
