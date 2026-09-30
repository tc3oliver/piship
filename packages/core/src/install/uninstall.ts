// Uninstall: remove the owned install files and keep state.
import { existsSync, rmSync } from "node:fs";
import { runtimeStateDirectory } from "../index.js";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  receiptPath,
} from "./receipt.js";
import { runtimeLeases } from "./runtime-lease.js";

/**
 * Remove the shim, launcher, every retained release, leftovers of an
 * interrupted operation, and the receipt; keep state. Refuses while an
 * update or rollback holds the lifecycle lock.
 */
export function uninstallDistribution(id: string): string {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  const hold = existsSync(apps) ? acquireLock(id) : undefined;
  try {
    const live = runtimeLeases(id, true).filter((lease) => lease.live);
    if (live.length)
      throw new Error(
        `Cannot uninstall ${id} while ${live.length} runtime session(s) still use its payload; close them and retry`,
      );
    rmSync(receipt.commandPath, { force: true });
    rmSync(apps, { recursive: true, force: true });
    rmSync(receiptPath(id), { force: true });
    return runtimeStateDirectory({ value: id });
  } finally {
    hold?.release();
  }
}
