// The installation's side of the shared file store: which store objects the
// installed releases pin, and the maintenance `doctor` runs. The store never
// decides what is installed; the receipts do.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  collectStore,
  type CollectedStore,
  type Liveness,
  type RecordedRelease,
  type VerifiedStore,
  verifyStore,
} from "../store/collect.js";
import { storeRoot } from "../store/policy.js";
import { installHome } from "../state-paths.js";
import { receiptPath } from "./receipt.js";

/** `active` and `previous` of each receipt, or unreadable for one that cannot be read. */
function pinnedReleases(): Map<string, ReadonlySet<string> | "unreadable"> {
  const pinned = new Map<string, ReadonlySet<string> | "unreadable">();
  const directory = dirname(receiptPath("x"));
  let names: string[] = [];
  try {
    names = readdirSync(directory);
  } catch {
    // No receipts: nothing is installed in this home.
  }
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const id = name.slice(0, -".json".length);
    try {
      const receipt = JSON.parse(
        readFileSync(join(directory, name), "utf8"),
      ) as {
        active?: unknown;
        previous?: unknown;
      } | null;
      const versions = [receipt?.active, receipt?.previous].filter(
        (version): version is string => typeof version === "string",
      );
      pinned.set(id, versions.length > 0 ? new Set(versions) : "unreadable");
    } catch {
      pinned.set(id, "unreadable");
    }
  }
  return pinned;
}

/**
 * What this installation says of a recorded release: live while it is a
 * distribution's active or rollback release, dead when that distribution is
 * installed here and retains something else, or is not installed here any
 * more. A receipt that cannot be read, and a release recorded for another
 * install home that still exists, are unknown, and an unknown release pins its
 * objects.
 */
export function storeLiveness(): (release: RecordedRelease) => Liveness {
  const pinned = pinnedReleases();
  const home = installHome();
  return (release) => {
    if (release.home !== home)
      return existsSync(join(release.home, "receipts")) ? "unknown" : "dead";
    const versions = pinned.get(release.id);
    if (versions === undefined) return "dead";
    if (versions === "unreadable") return "unknown";
    return versions.has(release.version) ? "live" : "dead";
  };
}

export interface MaintainedStore {
  readonly collected: CollectedStore;
  readonly verified: VerifiedStore;
}

/**
 * Collect and verify the shared file store, each within a time budget
 * (`PISHIP_RECLAIM_BUDGET_MS`, else five seconds). This is
 * the only caller of either, and `doctor` the only caller of this: no launch,
 * install, update, or rollback does it. Undefined when there is no store.
 */
export function maintainRuntimeStore(
  env: NodeJS.ProcessEnv = process.env,
): MaintainedStore | undefined {
  const root = storeRoot(env);
  if (!existsSync(root)) return undefined;
  // The budget `doctor` gives the removal of obsolete releases, for each step.
  const given = Number(env.PISHIP_RECLAIM_BUDGET_MS);
  const budgetMs = Number.isFinite(given) && given > 0 ? given : undefined;
  const collected = collectStore({
    root,
    liveness: storeLiveness(),
    ...(budgetMs ? { budgetMs } : {}),
  });
  const verified = verifyStore({
    root,
    // Objects are published whole, so a damaged one is never a half-written
    // one; it is still left alone while another operation holds the store.
    repair: !collected.deferred && !collected.busy,
    ...(budgetMs ? { budgetMs } : {}),
  });
  return { collected, verified };
}

/** What `maintainRuntimeStore` did, for doctor to print; undefined when there was nothing to say. */
export function describeStoreMaintenance(
  result: MaintainedStore | undefined,
): string | undefined {
  if (!result) return undefined;
  const { collected, verified } = result;
  const parts: string[] = [];
  if (collected.busy)
    parts.push(
      "Did not collect the file store: another collection is running.",
    );
  if (collected.deferred)
    parts.push(
      "Did not collect the file store: an install or update is filling it.",
    );
  if (collected.removedObjects > 0)
    parts.push(
      `Removed ${collected.removedObjects} file store object${collected.removedObjects === 1 ? "" : "s"} no retained release pins and freed ${(collected.freedBytes / 1_048_576).toFixed(1)} MiB.`,
    );
  if (collected.remaining)
    parts.push(
      "Stopped collecting the file store at the time budget; run doctor again to continue.",
    );
  if (verified.repaired > 0)
    parts.push(
      `Removed ${verified.repaired} damaged file store object${verified.repaired === 1 ? "" : "s"}; the next install writes them again. Installed releases are unaffected.`,
    );
  else if (verified.damaged.length > 0)
    parts.push(
      `Found ${verified.damaged.length} damaged file store object${verified.damaged.length === 1 ? "" : "s"} and left them for the next doctor; an install never places a damaged object.`,
    );
  return parts.length > 0 ? parts.join(" ") : undefined;
}
