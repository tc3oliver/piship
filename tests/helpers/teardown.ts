import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

/**
 * Hold a lease directory: created atomically, with the holder's PID inside.
 * A lease whose holder no longer runs is broken; a live holder is waited
 * for until the deadline, which then fails naming it instead of hanging.
 * The returned release removes the lease only while this process holds it.
 */
export async function acquireLease(
  lease: string,
  options: LeaseOptions = {},
): Promise<() => void> {
  const deadlineMs = options.deadlineMs ?? 15 * 60_000;
  const pollMs = options.pollMs ?? 500;
  const alive = options.alive ?? processAlive;
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
    // A lease without an owner file yet was only just created.
    const owner = ownerOf(lease);
    if (owner !== null && !alive(owner)) {
      rmSync(lease, { recursive: true, force: true });
      continue;
    }
    if (Date.now() >= deadline)
      throw new Error(
        `Waited ${Math.round(deadlineMs / 1000)} s for ${lease}, held by process ${owner ?? "unknown"}; an earlier scenario did not finish its teardown`,
      );
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}
