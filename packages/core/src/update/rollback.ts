// Rollback to the retained known-good release.
import { PiShipError } from "@piship/contracts";
import {
  runtimeStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "../index.js";
import {
  acquireLock,
  activeLock,
  readInstallReceipt,
  recoverInstallation,
  requireManaged,
  writeReceipt,
  type LifecycleOptions,
} from "../install/receipt.js";
import {
  checkStateMigration,
  compareVersions,
  type MigrationReport,
} from "../migration.js";
import { payloadStateSchemas, runPayloadCommand } from "../release/index.js";
import {
  checkPayload,
  clearCredentials,
  repairStateMarker,
  writeStateMarker,
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
  requireManaged(readInstallReceipt(id));
  const env = options.env ?? process.env;
  const release = acquireLock(id, "ROLLBACK_FAILED");
  try {
    const receipt = readInstallReceipt(id);
    recoverInstallation(id);
    const current = activeLock(receipt);
    repairStateMarker(id, current);
    const previous = receipt.releases.find(
      (item) => item.version === receipt.previous,
    );
    if (!receipt.previous || !previous)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `${receipt.app.id} has no retained release to roll back to`,
      );
    if (compareVersions(receipt.previous, receipt.active) > 0)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} is newer than the active ${receipt.active}; use update instead`,
      );
    let target: DistributionLock;
    try {
      target = verifyPayload(previous.payload);
    } catch (error) {
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} failed verification: ${(error as Error).message}`,
        {
          userAction:
            "Reinstall a trusted release; the damaged one is not activated",
        },
      );
    }
    if (target.app.command !== receipt.app.command)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release uses command ${target.app.command}; reinstall instead`,
      );
    checkPayload(
      previous.payload,
      target,
      options.runCheck ?? runPayloadCommand,
      env,
      "ROLLBACK_FAILED",
    );
    options.faults?.("verified");
    const stateDir = runtimeStateDirectory({ value: id });
    const migration = checkStateMigration(
      stateDir,
      {
        version: target.app.version,
        pi: target.runtime.version,
        schemas: payloadStateSchemas(target),
      },
      { version: receipt.active, pi: current.runtime.version },
    );
    if (migration.verdict === "unsupported")
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} cannot read this distribution's local data: ${migration.items
          .filter((item) => item.verdict === "unsupported")
          .map((item) => `${item.name} (${item.reason})`)
          .join("; ")}`,
      );
    const notices = migration.items
      .filter((item) => item.verdict === "requires-review")
      .map((item) => item.reason);
    notices.push(...(await clearCredentials(stateDir, id, migration, options)));
    writeReceipt({
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
    });
    options.faults?.("committed");
    writeStateMarker(stateDir, target);
    return {
      id,
      from: receipt.active,
      to: receipt.previous,
      migration,
      notices,
    };
  } finally {
    release();
  }
}
