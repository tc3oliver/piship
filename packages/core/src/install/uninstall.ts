// Uninstall: remove the owned install files and keep state, or, on request,
// purge the state as part of the same operation.
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { SecretStore } from "@piship/contracts";
import { runtimeStateDirectory } from "../index.js";
import { acquireLifecycleLock } from "./lifecycle-lock.js";
import { ownsCommandShim } from "./install.js";
import { deleteReferencedSecrets, type PurgeResult } from "./purge.js";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  receiptPath,
  type InstallReceipt,
} from "./receipt.js";
import { acquireLaunchGate, runtimeLeases } from "./runtime-lease.js";

/**
 * Take every lock an uninstall needs (the command, the lifecycle lock, and
 * the launch gate) and refuse while a runtime session is live. `remove`
 * deletes the shim, the launcher, every retained release, and the receipt.
 */
function holdForUninstall(id: string): {
  readonly remove: () => void;
  readonly release: () => void;
} {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  const releases: (() => void)[] = [];
  const release = () => {
    for (const item of releases.reverse()) item();
  };
  try {
    const commandHold = acquireLifecycleLock(
      `${receipt.commandPath}.piship.lock`,
      () =>
        new Error(
          `Another operation owns command ${receipt.app.command}; retry`,
        ),
      () => new Error(`Could not lock command ${receipt.app.command}`),
    );
    releases.push(() => commandHold.release());
    const hold = existsSync(apps) ? acquireLock(id) : undefined;
    if (hold) releases.push(() => hold.release());
    const current = readInstallReceipt(id);
    if (
      current.commandPath !== receipt.commandPath ||
      current.launcher !== receipt.launcher
    )
      throw new Error(`Install ownership changed for ${id}; retry`);
    const gate = acquireLaunchGate(id);
    releases.push(() => gate.release());
    const live = runtimeLeases(id, true).filter((lease) => lease.live);
    if (live.length)
      throw new Error(
        `Cannot uninstall ${id} while ${live.length} runtime session(s) still use its payload; close them and retry`,
      );
    const remove = () => {
      if (
        !gate.stillHeld() ||
        !commandHold.stillHeld() ||
        (hold && !hold.stillHeld())
      )
        throw new Error(`Install ownership lock for ${id} was lost`);
      removeInstall(id, receipt);
    };
    return { remove, release };
  } catch (error) {
    release();
    throw error;
  }
}

function removeInstall(id: string, receipt: InstallReceipt): void {
  if (existsSync(receipt.commandPath)) {
    // A receipt written before v1 has no launcher: its shim runs the
    // payload's command script directly.
    const target =
      receipt.launcher ?? join(receipt.payload, "bin", receipt.app.command);
    if (!ownsCommandShim(receipt.commandPath, target))
      throw new Error(
        `Command shim ${receipt.commandPath} is not owned by ${id}`,
      );
    rmSync(receipt.commandPath, { force: true });
  }
  rmSync(appDirectory(id), { recursive: true, force: true });
  rmSync(receiptPath(id), { force: true });
}

/**
 * Remove the shim, launcher, every retained release, leftovers of an
 * interrupted operation, and the receipt; keep state. Refuses while an
 * update or rollback holds the lifecycle lock.
 */
export function uninstallDistribution(id: string): string {
  const hold = holdForUninstall(id);
  try {
    hold.remove();
    return runtimeStateDirectory({ value: id });
  } finally {
    hold.release();
  }
}

/**
 * Uninstall and purge in one operation, for a user whose only PiShip is the
 * installed release: uninstall removes that release, so a separate purge
 * would have nothing left to run it. The secret-store entries the state's
 * metadata references are deleted first, under the uninstall's locks and
 * while the release is still installed; when one cannot be deleted this
 * throws SECRET_STORE_UNAVAILABLE and nothing is removed, so the same
 * command can be run again. Then the install is removed, and the state last.
 */
export async function uninstallAndPurgeDistribution(
  id: string,
  options: { readonly secretStore?: SecretStore } = {},
): Promise<PurgeResult> {
  const hold = holdForUninstall(id);
  try {
    const state = runtimeStateDirectory({ value: id });
    const deletedSecrets = await deleteReferencedSecrets(id, state, options);
    hold.remove();
    rmSync(state, { recursive: true, force: true });
    return { state, deletedSecrets };
  } finally {
    hold.release();
  }
}
