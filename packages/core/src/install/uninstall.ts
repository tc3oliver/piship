// Uninstall: remove the owned install files and keep state, or, on request,
// purge the state as part of the same operation.
import { existsSync, lstatSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { PiShipError, type SecretStore } from "@piship/contracts";
import {
  assertDisjointRoots,
  binHome,
  runtimeStateDirectory,
} from "../index.js";
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
 * the launch gate) and refuse while a runtime session is live. `verify`
 * throws for everything that would make `remove` refuse, without changing
 * anything; `remove` deletes the shim, the launcher, every retained
 * release, and the receipt.
 */
function holdForUninstall(id: string): {
  readonly verify: () => void;
  readonly remove: () => void;
  readonly release: () => void;
} {
  assertDisjointRoots();
  let receipt: InstallReceipt;
  try {
    receipt = readInstallReceipt(id);
  } catch (error) {
    if (!recoverableReceipt(error)) throw error;
    return holdDamagedForUninstall(id);
  }
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
    const verify = () => {
      if (
        !gate.stillHeld() ||
        !commandHold.stillHeld() ||
        (hold && !hold.stillHeld())
      )
        throw new Error(`Install ownership lock for ${id} was lost`);
      assertOwnedShim(id, receipt);
    };
    const remove = () => {
      verify();
      removeInstall(id, receipt);
    };
    return { verify, remove, release };
  } catch (error) {
    release();
    throw error;
  }
}

/**
 * A receipt error uninstall recovers from by removing what PiShip owns for
 * the id under the current homes: a damaged receipt, or one recorded under
 * another install home. A receipt of a newer PiShip is not, and neither is a
 * command path under another bin home: that shim is removed by running
 * uninstall again with the `PISHIP_BIN_HOME` the error names.
 */
function recoverableReceipt(error: unknown): boolean {
  return (
    error instanceof PiShipError &&
    typeof error.sanitizedDetail?.check === "string" &&
    error.sanitizedDetail.variable !== "PISHIP_BIN_HOME"
  );
}

/**
 * The command shims in the current bin home that run `launcher`: the exact
 * content PiShip writes, in a regular file (never through a symlink).
 */
function shimsRunning(launcher: string): string[] {
  const bin = binHome();
  if (!existsSync(bin)) return [];
  return readdirSync(bin)
    .map((name) => join(bin, name))
    .filter((path) => {
      const stat = lstatSync(path, { throwIfNoEntry: false });
      return (
        !!stat?.isFile() && stat.size <= 4096 && ownsCommandShim(path, launcher)
      );
    });
}

/**
 * The uninstall of a distribution whose receipt cannot be used. Nothing the
 * receipt names is trusted: only the paths derived from the id under the
 * current homes are removed (`apps/<id>`, the receipt, and the shims whose
 * exact content runs `apps/<id>/launch.mjs`), under the same locks and
 * runtime-session check as an ordinary uninstall.
 */
function holdDamagedForUninstall(id: string): {
  readonly verify: () => void;
  readonly remove: () => void;
  readonly release: () => void;
} {
  const apps = appDirectory(id);
  const launcher = join(apps, "launch.mjs");
  const releases: (() => void)[] = [];
  const release = () => {
    for (const item of releases.reverse()) item();
  };
  try {
    const hold = existsSync(apps) ? acquireLock(id) : undefined;
    if (hold) releases.push(() => hold.release());
    const gate = acquireLaunchGate(id);
    releases.push(() => gate.release());
    let repaired = false;
    try {
      readInstallReceipt(id);
      repaired = true;
    } catch (error) {
      if (!recoverableReceipt(error)) throw error;
    }
    if (repaired) throw new Error(`Install ownership changed for ${id}; retry`);
    const live = runtimeLeases(id, true).filter((lease) => lease.live);
    if (live.length)
      throw new Error(
        `Cannot uninstall ${id} while ${live.length} runtime session(s) still use its payload; close them and retry`,
      );
    const shims = shimsRunning(launcher);
    const commandHolds = shims.map((shim) => {
      const commandHold = acquireLifecycleLock(
        `${shim}.piship.lock`,
        () => new Error(`Another operation owns command ${shim}; retry`),
        () => new Error(`Could not lock command ${shim}`),
      );
      releases.push(() => commandHold.release());
      return commandHold;
    });
    const verify = () => {
      if (
        !gate.stillHeld() ||
        (hold && !hold.stillHeld()) ||
        commandHolds.some((item) => !item.stillHeld())
      )
        throw new Error(`Install ownership lock for ${id} was lost`);
      for (const shim of shims)
        if (existsSync(shim) && !ownsCommandShim(shim, launcher))
          throw new Error(`Command shim ${shim} is not owned by ${id}`);
    };
    const remove = () => {
      verify();
      for (const shim of shims) rmSync(shim, { force: true });
      rmSync(apps, { recursive: true, force: true });
      rmSync(receiptPath(id), { force: true });
    };
    return { verify, remove, release };
  } catch (error) {
    release();
    throw error;
  }
}

/** Refuses a command path that holds something other than this install's shim. */
function assertOwnedShim(id: string, receipt: InstallReceipt): void {
  if (!existsSync(receipt.commandPath)) return;
  // A receipt written before v1 has no launcher: its shim runs the
  // payload's command script directly.
  const target =
    receipt.launcher ?? join(receipt.payload, "bin", receipt.app.command);
  if (!ownsCommandShim(receipt.commandPath, target))
    throw new Error(
      `Command shim ${receipt.commandPath} is not owned by ${id}`,
    );
}

function removeInstall(id: string, receipt: InstallReceipt): void {
  if (existsSync(receipt.commandPath))
    rmSync(receipt.commandPath, { force: true });
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
    // Everything that can refuse the uninstall is checked before the first
    // secret goes: a refusal afterwards would leave state that names
    // credentials that are already gone.
    hold.verify();
    const deletedSecrets = await deleteReferencedSecrets(id, state, options);
    hold.remove();
    rmSync(state, { recursive: true, force: true });
    return { state, deletedSecrets };
  } finally {
    hold.release();
  }
}
