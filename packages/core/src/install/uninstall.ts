// Uninstall: remove the owned install files and keep state.
import { existsSync, rmSync } from "node:fs";
import { runtimeStateDirectory } from "../index.js";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  receiptPath,
} from "./receipt.js";

/**
 * Remove the shim, launcher, every retained release, leftovers of an
 * interrupted operation, and the receipt; keep state. Refuses while an
 * update or rollback holds the lifecycle lock.
 */
export function uninstallDistribution(id: string): string {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  if (existsSync(apps)) acquireLock(id);
  rmSync(receipt.commandPath, { force: true });
  rmSync(apps, { recursive: true, force: true });
  rmSync(receiptPath(id), { force: true });
  return runtimeStateDirectory({ value: id });
}
