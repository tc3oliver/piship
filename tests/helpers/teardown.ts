import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

// Teardown and cross-file coordination for the E2E scenarios. Kept apart
// from lifecycle.ts, which needs the fixture services and Vitest's provided
// context, so the unit suite can exercise it without a live store.

type Step = () => unknown;

/**
 * Run every step in order, each even when an earlier one failed, then
 * rethrow: the one failure as is, several as an AggregateError.
 */
export async function runAll(steps: readonly Step[]): Promise<void> {
  const errors: unknown[] = [];
  for (const step of steps)
    try {
      await step();
    } catch (error) {
      errors.push(error);
    }
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1)
    throw new AggregateError(errors, `${errors.length} teardown steps failed`);
}

/**
 * The teardown of a scenario on the platform store: the store is cleared
 * first, while nothing depends on the fixture services, then the services
 * close, and the lease is released whatever failed before it.
 */
export function storeScenarioTeardown(steps: {
  readonly clearStore: Step;
  readonly closeServices: Step;
  readonly release: Step;
}): () => Promise<void> {
  return () => runAll([steps.clearStore, steps.closeServices, steps.release]);
}

export interface LeaseOptions {
  /** How long to wait for another holder, in milliseconds. */
  readonly deadlineMs?: number;
  readonly pollMs?: number;
  /** Whether a process still runs; a lease of a dead one is broken. */
  readonly alive?: (pid: number) => boolean;
  /**
   * How long a lease may lack its owner file before it is broken: its
   * creator died between creating it and writing its PID.
   */
  readonly ownerlessGraceMs?: number;
  /** Test hook: runs after a stale lease is found, before it is broken. */
  readonly beforeBreak?: () => void;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

const ownerOf = (lease: string): number | null => {
  try {
    const pid = Number(readFileSync(join(lease, "owner"), "utf8"));
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
};

/** How long the lease directory has existed; 0 when it is gone. */
function ownerlessSince(lease: string): number {
  try {
    return Date.now() - statSync(lease).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * Break a stale lease that `owner` held (null: it has no owner file).
 * Several waiters may find the same stale lease, and one of them may have
 * broken it and taken a new one already, so the lease is renamed aside
 * first: only one rename can succeed, and what was renamed is deleted only
 * if it is still the stale lease; a live one is put back. If a third
 * waiter took the name in between, the caller simply waits again. Returns
 * whether the stale lease was deleted.
 */
function breakLease(lease: string, owner: number | null): boolean {
  const aside = `${lease}.stale-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    renameSync(lease, aside);
  } catch {
    return false;
  }
  if (ownerOf(aside) === owner) {
    rmSync(aside, { recursive: true, force: true });
    return true;
  }
  try {
    renameSync(aside, lease);
  } catch {
    // Another waiter holds the name now; the displaced lease stays aside.
  }
  return false;
}

/**
 * Hold a lease directory: created atomically, with the holder's PID inside.
 * A lease whose holder no longer runs, or that has had no owner for
 * longer than a grace period, is broken; a live holder is waited for until
 * the deadline, which then fails naming it instead of hanging.
 * The returned release removes the lease only while this process holds it.
 */
export async function acquireLease(
  lease: string,
  options: LeaseOptions = {},
): Promise<() => void> {
  const deadlineMs = options.deadlineMs ?? 15 * 60_000;
  const pollMs = options.pollMs ?? 500;
  const alive = options.alive ?? processAlive;
  const ownerlessGraceMs = options.ownerlessGraceMs ?? 10_000;
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    try {
      mkdirSync(lease);
      writeFileSync(join(lease, "owner"), String(process.pid));
      return () => {
        if (ownerOf(lease) === process.pid)
          rmSync(lease, { recursive: true, force: true });
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    // A lease without an owner file is only just being created, unless it
    // has been ownerless for longer than the grace period.
    const owner = ownerOf(lease);
    const stale =
      owner === null ? ownerlessSince(lease) > ownerlessGraceMs : !alive(owner);
    if (stale) {
      options.beforeBreak?.();
      if (breakLease(lease, owner)) continue;
    }
    if (Date.now() >= deadline)
      throw new Error(
        `Waited ${Math.round(deadlineMs / 1000)} s for ${lease}, held by process ${owner ?? "unknown"}; an earlier scenario did not finish its teardown`,
      );
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

export interface Holder {
  readonly pid: number;
  readonly command: string;
}

/**
 * The running processes, other than this one, whose command line names
 * `path`: what a test started there and may still have files open in it.
 * Chrome's helper processes name their profile directory this way, and
 * outlive the browser process the package waits for on Windows.
 */
export function processesNaming(path: string): Holder[] {
  const windows = process.platform === "win32";
  const fold = (text: string) => {
    const slashes = text.replaceAll("\\", "/");
    return windows ? slashes.toLowerCase() : slashes;
  };
  const names = new Set([path]);
  try {
    names.add(realpathSync(path));
  } catch {
    // Gone already: only the given spelling can be named.
  }
  const needles = [...names].map(fold);
  const listed = windows
    ? spawnSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
        ],
        { encoding: "utf8", timeout: 30_000, windowsHide: true },
      )
    : spawnSync("ps", ["-Ao", "pid=,args="], {
        encoding: "utf8",
        timeout: 30_000,
      });
  if (listed.status !== 0)
    throw new Error(
      `Could not list processes: ${listed.error?.message ?? listed.stderr}`,
    );
  const all: Holder[] = windows
    ? (
        JSON.parse(listed.stdout) as {
          ProcessId: number;
          CommandLine: string | null;
        }[]
      ).map((item) => ({
        pid: item.ProcessId,
        command: item.CommandLine ?? "",
      }))
    : listed.stdout.split("\n").flatMap((line) => {
        const match = /^\s*(\d+)\s+(.*)$/.exec(line);
        return match
          ? [{ pid: Number(match[1]), command: match[2] ?? "" }]
          : [];
      });
  return all.filter(
    (item) =>
      item.pid !== process.pid &&
      needles.some((needle) => fold(item.command).includes(needle)),
  );
}

function killTree(pid: number): void {
  if (process.platform === "win32")
    spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], {
      stdio: "ignore",
    });
  else
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // It exited after it was listed.
    }
}

export interface RemoveTreeOptions {
  /** How long the processes that name the tree get to exit, in milliseconds. */
  readonly deadlineMs?: number;
  readonly pollMs?: number;
  readonly holders?: (path: string) => readonly Holder[];
  readonly kill?: (pid: number) => void;
  readonly remove?: (path: string) => void;
}

const describeHolders = (holders: readonly Holder[]) =>
  holders.map((item) => `${item.pid} ${item.command}`).join("\n");

/**
 * Remove a scenario's temporary tree once nothing it started runs there.
 * Windows refuses to delete a directory a process has open, so the processes
 * that name the tree are waited for first; any still running at the deadline
 * leaked from the test: they are stopped so the tree can go, and the removal
 * then fails naming them. A removal that fails anyway names what still runs.
 */
export async function removeTree(
  path: string,
  options: RemoveTreeOptions = {},
): Promise<void> {
  const holders = options.holders ?? processesNaming;
  const kill = options.kill ?? killTree;
  const remove =
    options.remove ??
    ((target: string) =>
      rmSync(target, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 200,
      }));
  const pollMs = options.pollMs ?? 500;
  const deadline = Date.now() + (options.deadlineMs ?? 15_000);
  let running = holders(path);
  while (running.length > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    running = holders(path);
  }
  const leaked = running;
  for (const item of leaked) kill(item.pid);
  if (leaked.length > 0) {
    // Give what was killed a moment to release its handles.
    const killedBy = Date.now() + 5_000;
    while (holders(path).length > 0 && Date.now() < killedBy)
      await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  try {
    remove(path);
  } catch (error) {
    const still = holders(path);
    throw new Error(
      `Could not remove ${path}: ${(error as Error).message}${
        still.length > 0
          ? `\nProcesses naming it still run:\n${describeHolders(still)}`
          : "\nNo running process names it."
      }`,
      { cause: error },
    );
  }
  if (leaked.length > 0)
    throw new Error(
      `${leaked.length} process(es) started under ${path} still ran ${Math.round((options.deadlineMs ?? 15_000) / 1000)} s after the scenario and were stopped:\n${describeHolders(leaked)}`,
    );
}
