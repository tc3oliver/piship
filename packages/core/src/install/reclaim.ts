// Obsolete release directories: the versions an installation no longer retains
// and the `.retained-*` directories an update moved aside. Install and update
// never delete them (removing thousands of files is the slowest step on
// Windows); this is the one place that does, and only `doctor` calls it, with
// a time budget, so it is never on the install, update, or launch path.
import { lstatSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  VERSION_NAME,
} from "./receipt.js";
import { runtimeLeases } from "./runtime-lease.js";

const DEFAULT_BUDGET_MS = 5000;
/** The budget is read after this many deletions, so a large directory stops promptly. */
const CHECK_EVERY = 64;
const ASIDE = /^\.retained-(.+)-[0-9a-f-]{36}$/;

export interface ReclaimOptions {
  /** How long to spend removing, in milliseconds (default `PISHIP_RECLAIM_BUDGET_MS`, else 5000). */
  readonly budgetMs?: number;
  /** Test seams. */
  readonly now?: () => number;
  readonly unlink?: (path: string) => void;
}

export interface ReclaimedVersions {
  /** Directories removed completely. */
  readonly removed: readonly string[];
  readonly freedBytes: number;
  /** Directories left in place, and why. */
  readonly skipped: readonly {
    readonly name: string;
    readonly reason: string;
  }[];
  /** Directories not finished because the budget ran out; the next run continues. */
  readonly remaining: readonly string[];
  readonly budgetMs: number;
  /** Another update, rollback, or uninstall holds the installation. */
  readonly busy: boolean;
}

function budgetFromEnvironment(): number {
  const value = Number(process.env.PISHIP_RECLAIM_BUDGET_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_BUDGET_MS;
}

interface Run {
  readonly now: () => number;
  readonly deadline: number;
  readonly unlink: (path: string) => void;
  deleted: number;
  freedBytes: number;
}

type Outcome = "done" | "budget" | { readonly blocked: string };

/** Remove a directory tree file by file, so the budget and a blocked file are honored. */
function removeTree(directory: string, run: Run): Outcome {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const child = join(directory, entry.name);
    if (entry.isDirectory()) {
      const outcome = removeTree(child, run);
      if (outcome !== "done") return outcome;
      continue;
    }
    if (++run.deleted % CHECK_EVERY === 0 && run.now() > run.deadline)
      return "budget";
    try {
      const size = lstatSync(child).size;
      run.unlink(child);
      run.freedBytes += size;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "error";
      if (code === "ENOENT") continue;
      return { blocked: `${entry.name} (${code})` };
    }
  }
  try {
    rmdirSync(directory);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "error";
    if (code !== "ENOENT") return { blocked: `${directory} (${code})` };
  }
  return "done";
}

/**
 * Remove what the receipt of `id` no longer needs: every version directory it
 * does not record, and every `.retained-*` directory. The recorded versions
 * (the active release and the rollback target) stay, and so does any
 * directory a live runtime lease holds. A file a scanner or another program
 * holds (EBUSY, EPERM, EACCES) leaves its directory in place and reported. The
 * work stops at the budget; what is left is removed by the next run. Holds the
 * lifecycle lock, so it never overlaps an update, rollback, or uninstall.
 */
export function reclaimObsoleteVersions(
  id: string,
  options: ReclaimOptions = {},
): ReclaimedVersions {
  const budgetMs = options.budgetMs ?? budgetFromEnvironment();
  const empty: ReclaimedVersions = {
    removed: [],
    freedBytes: 0,
    skipped: [],
    remaining: [],
    budgetMs,
    busy: false,
  };
  let receipt: ReturnType<typeof readInstallReceipt>;
  try {
    receipt = readInstallReceipt(id);
  } catch {
    // Not an installed distribution: nothing is recorded to keep or remove.
    return empty;
  }
  let hold: ReturnType<typeof acquireLock>;
  try {
    hold = acquireLock(id);
  } catch {
    return { ...empty, busy: true };
  }
  try {
    const apps = appDirectory(id);
    const keep = new Set([
      receipt.active,
      ...(receipt.previous ? [receipt.previous] : []),
      ...receipt.releases.map((release) => release.version),
    ]);
    const leases = runtimeLeases(id).filter((lease) => lease.live);
    const held = (name: string): boolean => {
      const version = ASIDE.exec(name)?.[1] ?? name;
      return leases.some(
        (lease) => lease.version === "*" || lease.version === version,
      );
    };
    let names: string[];
    try {
      names = readdirSync(apps);
    } catch {
      return empty;
    }
    const candidates = names
      .filter(
        (name) =>
          ASIDE.test(name) || (VERSION_NAME.test(name) && !keep.has(name)),
      )
      .sort(
        (a, b) =>
          Number(ASIDE.test(b)) - Number(ASIDE.test(a)) || (a < b ? -1 : 1),
      );
    const now = options.now ?? (() => performance.now());
    const run: Run = {
      now,
      deadline: now() + budgetMs,
      unlink: options.unlink ?? unlinkSync,
      deleted: 0,
      freedBytes: 0,
    };
    const removed: string[] = [];
    const skipped: { name: string; reason: string }[] = [];
    const remaining: string[] = [];
    for (const name of candidates) {
      if (remaining.length > 0 || now() > run.deadline) {
        remaining.push(name);
        continue;
      }
      if (held(name)) {
        skipped.push({ name, reason: "a running session holds it" });
        continue;
      }
      const path = join(apps, name);
      if (!lstatSync(path, { throwIfNoEntry: false })?.isDirectory()) {
        skipped.push({ name, reason: "not a directory or already gone" });
        continue;
      }
      let outcome: Outcome;
      try {
        outcome = removeTree(path, run);
      } catch (error) {
        outcome = {
          blocked: `${(error as NodeJS.ErrnoException).code ?? "error"}`,
        };
      }
      if (outcome === "done") removed.push(name);
      else if (outcome === "budget") remaining.push(name);
      else skipped.push({ name, reason: `in use: ${outcome.blocked}` });
    }
    return {
      removed,
      freedBytes: run.freedBytes,
      skipped,
      remaining,
      budgetMs,
      busy: false,
    };
  } finally {
    hold.release();
  }
}

/** What `reclaimObsoleteVersions` did, for doctor to print; undefined when there was nothing to say. */
export function describeReclaimed(
  result: ReclaimedVersions,
): string | undefined {
  const parts: string[] = [];
  if (result.removed.length > 0)
    parts.push(
      `Removed ${result.removed.length} obsolete release director${result.removed.length === 1 ? "y" : "ies"} (${result.removed.join(", ")}) and freed ${(result.freedBytes / 1_048_576).toFixed(1)} MiB.`,
    );
  else if (result.freedBytes > 0)
    parts.push(`Freed ${(result.freedBytes / 1_048_576).toFixed(1)} MiB.`);
  for (const { name, reason } of result.skipped)
    parts.push(`Left ${name} in place (${reason}).`);
  if (result.remaining.length > 0)
    parts.push(
      `Stopped at the ${result.budgetMs / 1000} s budget with ${result.remaining.length} obsolete director${result.remaining.length === 1 ? "y" : "ies"} left; run doctor again to continue.`,
    );
  if (result.busy)
    parts.push(
      "Did not remove obsolete releases: another update, rollback, or uninstall is running.",
    );
  return parts.length > 0 ? parts.join(" ") : undefined;
}
