// Governed child processes: approved environment only, process-group
// lifetime, timeout with grace, AbortSignal cancellation, orphan cleanup.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { redact } from "@piship/contracts";
import type { WrappedCommand } from "./adapter.js";
import { stripCredentials } from "./environment.js";
import { windowsJobCommand } from "./windows-job.js";

/** Anything that can place a command inside a sandbox (an ActiveSandbox). */
export interface SandboxWrapper {
  wrap(
    file: string,
    args: readonly string[],
    cwd: string,
    env?: Readonly<Record<string, string>>,
  ): WrappedCommand;
}

export interface ManagedSpawnOptions {
  readonly file: string;
  readonly args?: readonly string[];
  readonly cwd: string;
  /** The approved child environment; credential-looking names are still stripped. */
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly sandbox?: SandboxWrapper;
  readonly timeoutMs?: number;
  /** Time between SIGTERM and SIGKILL of the process group. Default 2000 ms. */
  readonly graceMs?: number;
  readonly signal?: AbortSignal;
  readonly onStdout?: (chunk: Buffer) => void;
  readonly onStderr?: (chunk: Buffer) => void;
  readonly stdin?: "pipe" | "ignore";
  /** Test seam for the Windows termination path. */
  readonly platform?: NodeJS.Platform;
}

export interface ManagedExit {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  /** Redacted spawn failure, when the process could not be started. */
  readonly error?: string;
}

export interface ManagedProcess {
  readonly pid: number | undefined;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  readonly exited: Promise<ManagedExit>;
  /** Terminate the whole process tree (SIGTERM, then SIGKILL after grace). */
  terminate(): void;
}

const DEFAULT_GRACE_MS = 2000;
const STREAM_DRAIN_MS = 500;

// Process groups (POSIX) or pids (Windows) still owned by this process.
const live = new Map<number, NodeJS.Platform>();
let exitHookInstalled = false;

// Only ever signal the group: once the leader is reaped its pid may be reused
// by an unrelated process, while the group id stays ours until it is empty.
function signalGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-pid, signal);
  } catch {
    // group already gone
  }
}

function killTree(pid: number, platform: NodeJS.Platform): void {
  if (platform === "win32") {
    try {
      spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 5000,
      });
    } catch {
      // best effort
    }
    return;
  }
  signalGroup(pid, "SIGKILL");
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // Synchronous best effort: never leave governed children behind.
  process.on("exit", () => {
    for (const [pid, platform] of live) killTree(pid, platform);
    live.clear();
  });
}

/** Kill every governed child still running (for shutdown paths that skip 'exit'). */
export function killAllManaged(): void {
  for (const [pid, platform] of live) killTree(pid, platform);
  live.clear();
}

function cancelledBeforeStart(): ManagedProcess {
  return {
    pid: undefined,
    stdin: null,
    stdout: null,
    stderr: null,
    exited: Promise.resolve({
      code: null,
      signal: null,
      timedOut: false,
      cancelled: true,
    }),
    terminate: () => {},
  };
}

function waitForExit(
  child: ChildProcess,
  onExit: () => void,
): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
  error?: string;
}> {
  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = (value: {
      code: number | null;
      signal: NodeJS.Signals | null;
      error?: string;
    }) => {
      if (settled) return;
      settled = true;
      resolvePromise(value);
    };
    child.once("error", (error) => {
      onExit();
      finish({ code: null, signal: null, error: redact(error.message) });
    });
    child.once("exit", (code, signal) => {
      onExit();
      // Descendants that kept the pipes open are gone now; give the streams a
      // moment to deliver buffered output, then stop waiting for them.
      const timer = setTimeout(() => {
        child.stdout?.destroy();
        child.stderr?.destroy();
        finish({ code, signal });
      }, STREAM_DRAIN_MS);
      child.once("close", () => {
        clearTimeout(timer);
        finish({ code, signal });
      });
    });
  });
}

/**
 * Spawn a governed child: its own process group, the approved environment
 * with credential-looking names stripped, optional sandbox wrapping, timeout
 * and cancellation that terminate the whole tree.
 */
export function spawnManaged(options: ManagedSpawnOptions): ManagedProcess {
  return spawnProcess({ ...options, env: stripCredentials(options.env) });
}

/**
 * Process-group lifecycle without environment stripping. Internal: used for
 * the uncontained local shell, where the caller's environment is kept as is.
 */
export function spawnProcess(options: ManagedSpawnOptions): ManagedProcess {
  if (options.signal?.aborted) return cancelledBeforeStart();
  const platform = options.platform ?? process.platform;
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(options.env))
    if (value !== undefined) env[name] = value;
  const args = options.args ?? [];
  const target = options.sandbox
    ? options.sandbox.wrap(options.file, args, options.cwd, env)
    : { file: options.file, args, cwd: options.cwd, env };
  const launched = platform === "win32" ? windowsJobCommand(target) : target;
  const child = spawn(launched.file, [...launched.args], {
    cwd: target.cwd,
    env: { ...launched.env },
    detached: platform !== "win32",
    stdio: [options.stdin ?? "ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const pid = child.pid;
  if (pid !== undefined) {
    installExitHook();
    live.set(pid, platform);
  }
  if (options.onStdout) child.stdout?.on("data", options.onStdout);
  let jobError = false;
  child.stderr?.on("data", (chunk: Buffer) => {
    if (
      platform === "win32" &&
      chunk.toString("utf8").includes("PISHIP_WINDOWS_JOB_ERROR")
    )
      jobError = true;
    else options.onStderr?.(chunk);
  });
  child.stdin?.on("error", () => {});

  let done = false;
  let timedOut = false;
  let cancelled = false;
  let terminating = false;
  let graceTimer: NodeJS.Timeout | undefined;
  let timeoutTimer: NodeJS.Timeout | undefined;

  const terminate = () => {
    if (done || pid === undefined || terminating) return;
    terminating = true;
    if (platform === "win32") {
      killTree(pid, platform);
      return;
    }
    signalGroup(pid, "SIGTERM");
    graceTimer = setTimeout(
      () => killTree(pid, platform),
      options.graceMs ?? DEFAULT_GRACE_MS,
    );
  };
  const onAbort = () => {
    cancelled = true;
    terminate();
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  if (options.timeoutMs !== undefined && options.timeoutMs > 0)
    timeoutTimer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutMs);

  const cleanup = () => {
    done = true;
    if (timeoutTimer) clearTimeout(timeoutTimer);
    if (graceTimer) clearTimeout(graceTimer);
    options.signal?.removeEventListener("abort", onAbort);
    if (pid !== undefined) {
      // The leader is gone: nothing in its group may outlive it.
      if (platform !== "win32") signalGroup(pid, "SIGKILL");
      live.delete(pid);
    }
  };
  const exited = waitForExit(child, cleanup).then((result) => ({
    ...result,
    ...(jobError
      ? { error: "ENOENT or Windows Job Object startup failed" }
      : {}),
    timedOut,
    cancelled,
  }));
  return {
    pid,
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    exited,
    terminate,
  };
}
