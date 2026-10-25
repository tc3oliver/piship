// Governed child processes: approved environment only, process-group
// lifetime, timeout with grace, AbortSignal cancellation, orphan cleanup.
import {
  type ChildProcess,
  execFile,
  execFileSync,
  spawn,
  spawnSync,
} from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { redact } from "@piship/contracts";
import type { WrappedCommand } from "./adapter.js";
import { stripCredentials } from "./environment.js";
import { SANDBOX_EXEC } from "./seatbelt.js";
import { windowsJobSupervisor } from "./windows-job.js";

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

// macOS has no PID namespace: a descendant that calls setsid() or setpgid()
// leaves the process group the kill reaches. So while a command contained by
// Seatbelt runs, its descendants that left the group are recorded with their
// start time, and are killed with it. An uncontained command keeps the plain
// process-group lifetime, as on Linux, so a server a user detaches survives.
// shortcut: one whose parent exits between two snapshots (an immediate double
// fork) is never seen; closing that needs native process tracking.
interface Recorded {
  readonly start: string;
  /** The newest snapshot that confirmed it. */
  seen: number;
}
interface Tracked {
  readonly since: number;
  /** The last snapshot taken before tracking began; only later ones show it. */
  readonly from: number;
  /** Each descendant outside the leader's group, by pid. */
  readonly known: Map<number, Recorded>;
}
const tracked = new Map<number, Tracked>();
let snapshots = 0;
let pollTimer: NodeJS.Timeout | undefined;
let pollDue = 0;
let inFlight: { readonly child: ChildProcess; readonly at: number } | undefined;

interface PsRow {
  readonly ppid: number;
  readonly pgid: number;
  readonly start: string;
}

/** The process table, numbered in the order the snapshots were taken. */
export interface Snapshot {
  readonly seq: number;
  readonly rows: ReadonlyMap<number, PsRow>;
}

const PS_ARGS = ["-Ao", "pid=,ppid=,pgid=,lstart="];
// A fixed locale and zone make one process's start time read the same each time.
const PS_ENV = { PATH: "/usr/bin:/bin", TZ: "UTC0", LC_ALL: "C" };
const PS_TIMEOUT_MS = 1000;

export function parsePs(text: string): Map<number, PsRow> {
  const rows = new Map<number, PsRow>();
  for (const line of text.split("\n")) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S.*\S)\s*$/.exec(line);
    if (match)
      rows.set(Number(match[1]), {
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        start: match[4] as string,
      });
  }
  return rows;
}

// A snapshot that fails or takes over a second reclaims nothing: the command
// then has only its process-group lifetime.
function readPs(): Snapshot | undefined {
  const seq = ++snapshots;
  try {
    return {
      seq,
      rows: parsePs(
        execFileSync("/bin/ps", PS_ARGS, {
          encoding: "utf8",
          env: PS_ENV,
          timeout: PS_TIMEOUT_MS,
          killSignal: "SIGKILL",
          stdio: ["ignore", "pipe", "ignore"],
        }),
      ),
    };
  } catch {
    return undefined;
  }
}

/**
 * Add to `known` every descendant outside the leader's group of the leader
 * (only while `alive`: an unreaped leader), of the members of its group (the
 * group ID stays reserved while it has members, and setpgid cannot leave the
 * session, so a member whose parent exited is still ours), and of the
 * recorded processes this snapshot shows with their start time. A record is
 * dropped only by a snapshot at least as new as the one that last confirmed
 * it, when that snapshot lacks it or shows its pid with another start time
 * (exited, and the pid may be reused); an older snapshot read late never
 * drops or follows it. This process and its ancestors are never recorded.
 */
export function trackDescendants(
  snapshot: Snapshot,
  leader: number,
  alive: boolean,
  known: Map<number, Recorded>,
  self: number = process.pid,
): void {
  const { rows, seq } = snapshot;
  const queue = alive ? [leader] : [];
  for (const [pid, record] of known) {
    if (rows.get(pid)?.start === record.start) {
      record.seen = Math.max(record.seen, seq);
      queue.push(pid);
    } else if (record.seen <= seq) known.delete(pid);
  }
  const ancestors = new Set<number>();
  let ancestor = self;
  while (ancestor > 1 && !ancestors.has(ancestor)) {
    ancestors.add(ancestor);
    ancestor = rows.get(ancestor)?.ppid ?? 0;
  }
  const children = new Map<number, number[]>();
  for (const [pid, row] of rows) {
    const list = children.get(row.ppid);
    if (list) list.push(pid);
    else children.set(row.ppid, [pid]);
    if (row.pgid === leader && !ancestors.has(pid)) queue.push(pid);
  }
  const seen = new Set(queue);
  while (queue.length > 0)
    for (const pid of children.get(queue.shift() as number) ?? []) {
      const row = rows.get(pid) as PsRow;
      if (seen.has(pid) || ancestors.has(pid) || pid <= 1) continue;
      seen.add(pid);
      queue.push(pid);
      if (row.pgid !== leader && !known.has(pid))
        known.set(pid, { start: row.start, seen: seq });
    }
}

/** Signal the recorded descendants of `leader` that still run, after one more snapshot. */
function reclaim(
  leader: number,
  alive: boolean,
  signal: NodeJS.Signals,
  shared?: Snapshot,
): void {
  const entry = tracked.get(leader);
  if (!entry) return;
  const snapshot = shared ?? readPs();
  if (!snapshot) return;
  trackDescendants(snapshot, leader, alive, entry.known);
  for (const [pid, record] of entry.known) {
    // Only what this snapshot itself confirmed is signalled.
    if (record.seen !== snapshot.seq) continue;
    try {
      process.kill(pid, signal);
    } catch {
      // already gone
    }
  }
}

/** Track a leader's escaping descendants until `untrackLeader`. Exported for tests. */
export function trackLeader(pid: number): void {
  tracked.set(pid, { since: Date.now(), from: snapshots, known: new Map() });
  schedulePoll();
}

export function untrackLeader(pid: number): void {
  tracked.delete(pid);
  if (tracked.size === 0 && pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = undefined;
  }
}

// One poller for every tracked leader: often while the youngest is new, then
// less, since most escapes happen as a command starts. A pending tick is only
// ever brought forward, so commands that keep starting cannot postpone it.
function schedulePoll(): void {
  if (tracked.size === 0) return;
  const youngest = Math.min(
    ...[...tracked.values()].map((entry) => Date.now() - entry.since),
  );
  const due =
    Date.now() + (youngest < 5_000 ? 250 : youngest < 30_000 ? 1000 : 2000);
  if (pollTimer && pollDue <= due) return;
  if (pollTimer) clearTimeout(pollTimer);
  pollDue = due;
  pollTimer = setTimeout(poll, due - Date.now());
  pollTimer.unref();
}

function poll(): void {
  pollTimer = undefined;
  // Skip a tick while a snapshot is read; one stuck well past its own
  // timeout is killed and replaced.
  if (inFlight && Date.now() - inFlight.at < 5 * PS_TIMEOUT_MS) {
    schedulePoll();
    return;
  }
  inFlight?.child.kill("SIGKILL");
  const seq = ++snapshots;
  const child = execFile(
    "/bin/ps",
    PS_ARGS,
    { env: PS_ENV, timeout: PS_TIMEOUT_MS, killSignal: "SIGKILL" },
    (error, stdout) => {
      if (inFlight?.child === child) inFlight = undefined;
      if (!error) {
        const snapshot = { seq, rows: parsePs(stdout) };
        // An entry is removed when its leader is reaped, so a leader still
        // here and tracked before the snapshot was taken was alive in it.
        for (const [leader, entry] of tracked)
          if (entry.from < seq)
            trackDescendants(snapshot, leader, true, entry.known);
      }
      schedulePoll();
    },
  );
  inFlight = { child, at: Date.now() };
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // Synchronous best effort: never leave governed children behind.
  process.on("exit", () => killAllManaged());
}

/** Kill every governed child still running (for shutdown paths that skip 'exit'). */
export function killAllManaged(): void {
  const snapshot = [...live.keys()].some((pid) => tracked.has(pid))
    ? readPs()
    : undefined;
  for (const [pid, platform] of live) {
    if (snapshot) reclaim(pid, true, "SIGKILL", snapshot);
    killTree(pid, platform);
  }
  live.clear();
}

function notStarted(error?: string): ManagedProcess {
  return {
    pid: undefined,
    stdin: null,
    stdout: null,
    stderr: null,
    exited: Promise.resolve({
      code: null,
      signal: null,
      timedOut: false,
      cancelled: error === undefined,
      ...(error === undefined ? {} : { error }),
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
  if (options.signal?.aborted) return notStarted();
  const platform = options.platform ?? process.platform;
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(options.env))
    if (value !== undefined) env[name] = value;
  const args = options.args ?? [];
  const target = options.sandbox
    ? options.sandbox.wrap(options.file, args, options.cwd, env)
    : { file: options.file, args, cwd: options.cwd, env };
  let launched: {
    file: string;
    args: readonly string[];
    env: NodeJS.ProcessEnv;
  };
  try {
    launched = platform === "win32" ? windowsJobSupervisor(target) : target;
  } catch (error) {
    // Fail closed: never fall back to an unresolved supervisor.
    return notStarted(redact((error as Error).message));
  }
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
  // Only a command Seatbelt contains (what the sandbox wraps, and so the MCP
  // servers started under it), never the uncontained local shell.
  const track =
    platform === "darwin" &&
    process.platform === "darwin" &&
    pid !== undefined &&
    launched.file === SANDBOX_EXEC;
  if (track) trackLeader(pid);

  const terminate = () => {
    if (done || pid === undefined || terminating) return;
    terminating = true;
    if (platform === "win32") {
      killTree(pid, platform);
      return;
    }
    if (track) reclaim(pid, true, "SIGTERM");
    signalGroup(pid, "SIGTERM");
    graceTimer = setTimeout(() => {
      if (track) reclaim(pid, true, "SIGKILL");
      killTree(pid, platform);
    }, options.graceMs ?? DEFAULT_GRACE_MS);
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
      // The leader is gone: nothing in its group may outlive it. The snapshot
      // comes first, while the group's members still lead to what they started.
      if (track) reclaim(pid, false, "SIGKILL");
      if (platform !== "win32") signalGroup(pid, "SIGKILL");
      if (track) untrackLeader(pid);
      live.delete(pid);
    }
  };
  const exited = waitForExit(child, cleanup).then((result) => ({
    ...result,
    ...(jobError
      ? {
          code: null,
          signal: null,
          error: "ENOENT or Windows Job Object startup failed",
        }
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
