// Uninstall: remove the owned install files and keep state.
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runtimeStateDirectory } from "../index.js";
import { acquireLifecycleLock } from "./lifecycle-lock.js";
import { ownsCommandShim } from "./install.js";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  receiptPath,
} from "./receipt.js";
import { acquireLaunchGate, runtimeLeases } from "./runtime-lease.js";

/**
 * Remove the shim, launcher, every retained release, leftovers of an
 * interrupted operation, and the receipt; keep state. Refuses while an
 * update or rollback holds the lifecycle lock.
 */
export function uninstallDistribution(id: string): string {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  const commandHold = acquireLifecycleLock(
    `${receipt.commandPath}.piship.lock`,
    () =>
      new Error(`Another operation owns command ${receipt.app.command}; retry`),
    () => new Error(`Could not lock command ${receipt.app.command}`),
  );
  try {
    const hold = existsSync(apps) ? acquireLock(id) : undefined;
    try {
      const current = readInstallReceipt(id);
      if (
        current.commandPath !== receipt.commandPath ||
        current.launcher !== receipt.launcher
      )
        throw new Error(`Install ownership changed for ${id}; retry`);
      const gate = acquireLaunchGate(id);
      try {
        const live = runtimeLeases(id, true).filter((lease) => lease.live);
        if (live.length)
          throw new Error(
            `Cannot uninstall ${id} while ${live.length} runtime session(s) still use its payload; close them and retry`,
          );
        if (
          !gate.stillHeld() ||
          !commandHold.stillHeld() ||
          (hold && !hold.stillHeld())
        )
          throw new Error(`Install ownership lock for ${id} was lost`);
        if (existsSync(receipt.commandPath)) {
          // A receipt written before v1 has no launcher: its shim runs the
          // payload's command script directly.
          const target =
            receipt.launcher ??
            join(receipt.payload, "bin", receipt.app.command);
          if (!ownsCommandShim(receipt.commandPath, target))
            throw new Error(
              `Command shim ${receipt.commandPath} is not owned by ${id}`,
            );
          rmSync(receipt.commandPath, { force: true });
        }
        rmSync(apps, { recursive: true, force: true });
        rmSync(receiptPath(id), { force: true });
        return runtimeStateDirectory({ value: id });
      } finally {
        gate.release();
      }
    } finally {
      hold?.release();
    }
  } finally {
    commandHold.release();
  }
}
