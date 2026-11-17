// Rollback to the retained known-good release.
import { PiShipError } from "@piship/contracts";
import {
  packRepairAction,
  runtimeStateDirectory,
  verifyPayloadContents,
  type DistributionLock,
} from "../index.js";
import { refreshInstalledLauncher } from "../install/launcher.js";
import { reclaimAfterCommit } from "../install/reclaim.js";
import {
  acquireLock,
  activeLock,
  readInstallReceipt,
  requireManaged,
  type LifecycleOptions,
} from "../install/receipt.js";
import {
  checkStateMigration,
  compareVersions,
  type MigrationReport,
} from "../migration.js";
import { payloadStateSchemas } from "../release/index.js";
import { storageOf } from "../storage-transition.js";
import {
  clearCredentials,
  commitAfterClear,
  markActivated,
  repairStateMarker,
} from "./state.js";

export interface RollbackResult {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly migration: MigrationReport;
  readonly notices: readonly string[];
}

/**
 * Return to the retained known-good release. Only the immutable payload is
 * switched; sessions and settings stay in place, and credentials are never
 * restored: data the target cannot read is cleared and reacquired.
 */
export async function rollbackDistribution(
  id: string,
  options: LifecycleOptions = {},
): Promise<RollbackResult> {
  const result = await performRollback(id, options);
  // The lifecycle lock is released: obsolete releases are removed now.
  if (options.reclaim === false) return result;
  const notices = reclaimAfterCommit(id);
  return notices.length > 0
    ? { ...result, notices: [...result.notices, ...notices] }
    : result;
}

async function performRollback(
  id: string,
  options: LifecycleOptions,
): Promise<RollbackResult> {
  requireManaged(readInstallReceipt(id));
  const lifecycle = acquireLock(
    id,
    "ROLLBACK_FAILED",
    options.launchGateWaitMs,
  );
  try {
    const receipt = readInstallReceipt(id);
    const current = activeLock(receipt);
    repairStateMarker(id, current);
    const previous = receipt.releases.find(
      (item) => item.version === receipt.previous,
    );
    if (!receipt.previous || !previous)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `${receipt.app.id} has no retained release to roll back to`,
        {
          userAction: `Only a release a previous update kept can be rolled back to; run ${receipt.app.command} update to move to another version`,
        },
      );
    if (compareVersions(receipt.previous, receipt.active) > 0)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} is newer than the active ${receipt.active}; use update instead`,
        { userAction: `Run ${receipt.app.command} update` },
      );
    options.progress?.(`Verifying the retained ${receipt.previous} release`);
    let target: DistributionLock;
    try {
      target = verifyPayloadContents(previous.payload, {
        requireTarget: true,
        verifyContents: false,
      });
    } catch (error) {
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} failed verification: ${(error as Error).message}`,
        {
          userAction: previous.release?.pack
            ? `The damaged release is not activated. Restore it from its Company Pack: ${packRepairAction(id, receipt.previous)}. Then roll back again`
            : `The damaged release is not activated. Download the ${receipt.previous} release archive for this computer from the distribution's update source (its channel file names the archive), extract it, and run: node <extracted release>/payload/piship.mjs repair ${id} <extracted release>; with the PiShip CLI: piship repair ${id} <release archive of ${receipt.previous}>. Then roll back again`,
        },
      );
    }
    if (target.app.command !== receipt.app.command)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release uses command ${target.app.command}; reinstall instead`,
        {
          userAction: `To go back to ${receipt.previous}, reinstall it: ${receipt.app.command} uninstall (state is kept), then download the ${receipt.previous} release archive from the distribution's update source, extract it, and run node <extracted release>/payload/piship.mjs install <extracted release>`,
        },
      );
    options.faults?.("verified");
    const stateDir = runtimeStateDirectory({ value: id });
    const migration = checkStateMigration(
      stateDir,
      {
        version: target.app.version,
        pi: target.runtime.version,
        schemas: payloadStateSchemas(target),
        ...storageOf(target),
      },
      {
        version: receipt.active,
        pi: current.runtime.version,
        ...storageOf(current),
      },
    );
    if (migration.verdict === "unsupported")
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} cannot read this distribution's local data: ${migration.items
          .filter((item) => item.verdict === "unsupported")
          .map((item) => `${item.name} (${item.reason})`)
          .join("; ")}`,
        {
          userAction: `Keep using ${receipt.active}; rolling back would lose data the retained release cannot read. Ask the distribution owner if you need an older version`,
        },
      );
    const notices = migration.items
      .filter((item) => item.verdict === "requires-review")
      .map((item) => item.reason);
    options.progress?.(`Switching to ${receipt.previous}`);
    notices.push(...(await clearCredentials(stateDir, id, migration, options)));
    const committed = {
      ...readInstallReceipt(id),
      app: target.app,
      payload: previous.payload,
      active: receipt.previous,
      previous: receipt.active,
      lastCheck: {
        time: (options.now ?? (() => new Date()))().toISOString(),
        channel: receipt.channel ?? current.updates?.channel ?? "stable",
        result: `rolled back ${receipt.active} -> ${receipt.previous}`,
      },
    };
    commitAfterClear(
      () => lifecycle.commit(committed),
      migration,
      receipt.app.command,
    );
    // Committed: from here on nothing reports the rollback as failed.
    options.faults?.("committed");
    // A stale launcher is replaced now, as after an update.
    refreshInstalledLauncher(id, previous.payload);
    notices.push(...markActivated(stateDir, target));
    return {
      id,
      from: receipt.active,
      to: receipt.previous,
      migration,
      notices,
    };
  } finally {
    lifecycle.release();
  }
}
