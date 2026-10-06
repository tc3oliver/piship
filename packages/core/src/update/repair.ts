// Restore a damaged installed release from a trusted copy of the same release.
import {
  cpSync,
  existsSync,
  readFileSync,
  renameSync,
  statSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { hash } from "../digest.js";
import { type DistributionLock, verifyPayload } from "../index.js";
import {
  acquireLock,
  appDirectory,
  readInstallReceipt,
  recoverInstallation,
  requireManaged,
  syncDirectory,
  syncTree,
} from "../install/receipt.js";
import { acquireLaunchGate, runtimeLeases } from "../install/runtime-lease.js";
import { verifyRelease } from "../release/index.js";
import { createStagingDirectory } from "../temporary-directories.js";

export interface RepairResult {
  readonly status: "repaired" | "intact";
  readonly id: string;
  readonly version: string;
  /** Why the installed copy failed verification, when it did. */
  readonly problem?: string;
}

/**
 * Replace the payload of a release the installation records (the active or
 * the retained one) with a verified copy of that same release: a release
 * archive, a release directory, or a payload directory. The damaged payload
 * is never run or trusted; the copy must match the recorded version, command,
 * lock digest, and archive digest where the receipt records them. The
 * receipt, state, and credentials are not touched. An intact release is left
 * as it is.
 */
export async function repairDistribution(
  id: string,
  source: string,
): Promise<RepairResult> {
  requireManaged(readInstallReceipt(id));
  const lifecycle = acquireLock(id);
  try {
    const receipt = readInstallReceipt(id);
    recoverInstallation(id);
    const apps = appDirectory(id);
    const temporary = createStagingDirectory(apps);
    try {
      const path = resolve(source);
      const isArchive = statSync(path).isFile();
      let payload = path;
      let archiveSha256: string | undefined;
      if (isArchive || existsSync(join(path, "release.json"))) {
        const verified = await verifyRelease(path, {
          requireTarget: true,
          extractTo: join(temporary.path, "release"),
        });
        payload = verified.payload;
        archiveSha256 = verified.archiveSha256;
      }
      if (!payload.startsWith(`${temporary.path}`)) {
        // Verified below as the copy that is moved into place.
        cpSync(payload, join(temporary.path, "payload"), { recursive: true });
        payload = join(temporary.path, "payload");
      }
      const lock: DistributionLock = verifyPayload(payload);
      const { version } = lock.app;
      const entry = receipt.releases.find((item) => item.version === version);
      if (lock.app.id !== id || !entry)
        throw new PiShipError(
          "UPDATE_FAILED",
          `${source} is ${lock.app.id} ${version}, which is not a release of ${id} this installation records (${receipt.releases.map((item) => item.version).join(", ")}); repair restores a recorded release, use update or install for another`,
        );
      const problems = [
        lock.app.command !== receipt.app.command && "command",
        version === receipt.active &&
          JSON.stringify(lock.app) !== JSON.stringify(receipt.app) &&
          "app",
        entry.release &&
          hash(readFileSync(join(payload, "piship.lock"))) !==
            entry.release.lockSha256 &&
          "lock digest",
        isArchive &&
          entry.release?.archiveSha256 &&
          archiveSha256 !== entry.release.archiveSha256 &&
          "archive digest",
      ].filter(Boolean);
      if (problems.length)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `${source} does not match the ${version} release this installation records: ${problems.join(", ")}`,
          { userAction: `Use the ${version} release that was installed` },
        );
      let problem: string;
      try {
        verifyPayload(entry.payload);
        return { status: "intact", id, version };
      } catch (error) {
        problem = (error as Error).message;
      }
      const gate = acquireLaunchGate(id);
      try {
        const live = runtimeLeases(id, true).filter(
          (lease) =>
            lease.live && (lease.version === version || lease.version === "*"),
        );
        if (live.length)
          throw new PiShipError(
            "UPDATE_FAILED",
            `Cannot repair ${id} ${version} while ${live.length} runtime session(s) still use it; close them and retry`,
          );
        syncTree(payload);
        // Two renames in one directory: an interruption between them leaves
        // the release missing, which fails closed and the next repair
        // restores.
        if (existsSync(entry.payload))
          renameSync(entry.payload, join(temporary.path, "damaged"));
        renameSync(payload, entry.payload);
        syncDirectory(apps);
      } finally {
        gate.release();
      }
      verifyPayload(entry.payload);
      return { status: "repaired", id, version, problem };
    } finally {
      try {
        temporary.remove();
        if (lifecycle.stillHeld()) recoverInstallation(id);
      } catch {
        // Recovery runs again before the next operation.
      }
    }
  } finally {
    lifecycle.release();
  }
}
