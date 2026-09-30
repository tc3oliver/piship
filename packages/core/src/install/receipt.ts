// Installed release lifecycle: install ownership, the receipt that selects the
// active release, verified update, rollback, and recovery after interruption.
// Releases are immutable payload directories; switching the active release is
// one atomic receipt rename, so an interruption leaves the old or the new
// release active, never a mix.
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { PiShipError, type SecretStore } from "@piship/contracts";
import {
  type SecretStoreResolver,
  syncDirectory,
  writeFileAtomic,
} from "@piship/credentials";
import {
  binHome,
  installHome,
  distributionStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "../index.js";
import type { ReleaseMetadata, ReleaseTestRunner } from "../release/index.js";
import { acquireLifecycleLock, type LifecycleHold } from "./lifecycle-lock.js";
import { removeStaleTemporaries } from "./temporaries.js";
import { runtimeLeases } from "./runtime-lease.js";

export const RECEIPT_SCHEMA = "piship-install/v1";

export const VERSION_NAME = /^[0-9][0-9A-Za-z.+-]*$/;

export interface InstalledRelease {
  readonly version: string;
  readonly payload: string;
  readonly installedAt: string;
  /** Present when installed from a verified release artifact. */
  readonly release?: {
    readonly target: string;
    readonly channel: string;
    readonly pi: string;
    readonly piship: string;
    readonly lockSha256: string;
    readonly archiveSha256?: string;
  };
}

export interface InstallReceipt {
  readonly schema?: typeof RECEIPT_SCHEMA;
  readonly app: DistributionLock["app"];
  /** The active payload (kept for tools that read one payload path). */
  readonly payload: string;
  readonly commandPath: string;
  /** `apps/<id>/launch.mjs`; absent for receipts written before v1. */
  readonly launcher?: string;
  readonly active: string;
  /** The retained known-good release rollback returns to. */
  readonly previous?: string;
  readonly releases: readonly InstalledRelease[];
  /** Channel the user selected; defaults to the distribution's channel. */
  readonly channel?: string;
  /** Highest verified channel metadata sequence per channel (replay guard). */
  readonly channelSequences?: Readonly<Record<string, number>>;
  readonly lastCheck?: {
    readonly time: string;
    readonly channel: string;
    readonly result: string;
  };
}

export type LifecyclePhase =
  | "staged"
  | "verified"
  | "snapshot-directory"
  | "snapshot-file"
  | "snapshot-files"
  | "snapshot-manifest"
  | "snapshot-publish"
  | "installed"
  | "committed"
  | "cleaned";

export interface LifecycleOptions {
  /** Test seam: throw at a phase to simulate interruption. */
  readonly faults?: (phase: LifecyclePhase) => void;
  /** Runs a candidate payload's launcher check; defaults to Node. */
  readonly runCheck?: ReleaseTestRunner;
  /**
   * The secret store of this distribution's credentials, used when a
   * credential class the target cannot read must be cleared. Every deletion
   * is confirmed by reading the reference back; a secret that cannot be
   * deleted, or credential metadata without a store to delete its secrets
   * from, stops the switch.
   */
  readonly secretStore?: SecretStore;
  /**
   * The store of the other storage provider, for deleting what a credential
   * file records as held by it (`credential.storage.provider` changed since
   * it was written). Production creates it; without a resolver, such
   * references stay tracked and stop the switch, so a test with an injected
   * `secretStore` never reaches a real platform store by accident.
   */
  readonly secretStoreFor?: SecretStoreResolver;
  /**
   * Best-effort remote revocation of the runtime credential by the release
   * that can still read it, before it is cleared. A failure is a warning;
   * local clearing always happens.
   */
  readonly revokeCredential?: () => Promise<{
    readonly outcome: string;
    readonly problem?: string;
  }>;
  readonly now?: () => Date;
  readonly env?: NodeJS.ProcessEnv;
}

export function appDirectory(id: string): string {
  return join(installHome(), "apps", id);
}

export function receiptPath(id: string): string {
  distributionStateDirectory({ value: id });
  return join(installHome(), "receipts", `${id}.json`);
}

export function commandPathFor(command: string): string {
  return join(
    binHome(),
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}

export { syncDirectory, writeFileAtomic } from "@piship/credentials";

/**
 * Flush every file and directory of a release to stable storage, so a power
 * loss after the receipt switch cannot leave the receipt pointing at a
 * missing or truncated payload. Windows needs write access to flush a file
 * and cannot flush directories; there it is best effort.
 */
export function syncTree(root: string): void {
  const visit = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile()) {
        let fd: number;
        try {
          fd = openSync(child, process.platform === "win32" ? "r+" : "r");
        } catch (error) {
          if (process.platform === "win32") continue;
          throw error;
        }
        try {
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
      }
    }
    syncDirectory(path);
  };
  visit(root);
}

export function writeReceipt(receipt: InstallReceipt): void {
  writeFileAtomic(
    receiptPath(receipt.app.id),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
}

/** Read and validate an install receipt; paths must be the owned ones. */
export function readInstallReceipt(id: string): InstallReceipt {
  const path = receiptPath(id);
  if (!existsSync(path))
    throw new Error(`No PiShip installation recorded for ${id}`);
  const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<InstallReceipt>;
  const unsafe = () => new Error(`Unsafe installation receipt for ${id}`);
  if (!raw.app || raw.app.id !== id) throw unsafe();
  const expectedCommand = commandPathFor(raw.app.command);
  if (raw.commandPath !== expectedCommand) throw unsafe();
  if (raw.schema === undefined) {
    // Written before receipts were versioned: one release, shim to payload.
    if (raw.payload !== join(appDirectory(id), raw.app.version)) throw unsafe();
    return {
      app: raw.app,
      payload: raw.payload,
      commandPath: raw.commandPath,
      active: raw.app.version,
      releases: [
        { version: raw.app.version, payload: raw.payload, installedAt: "" },
      ],
    };
  }
  if (raw.schema !== RECEIPT_SCHEMA)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Install receipt ${raw.schema} was written by a newer PiShip; use that version to manage ${id}`,
    );
  const releases = raw.releases ?? [];
  for (const release of releases)
    if (
      !VERSION_NAME.test(release.version) ||
      release.payload !== join(appDirectory(id), release.version)
    )
      throw unsafe();
  const active = releases.find((item) => item.version === raw.active);
  if (
    !active ||
    raw.payload !== active.payload ||
    raw.launcher !== join(appDirectory(id), "launch.mjs") ||
    (raw.previous !== undefined &&
      !releases.some((item) => item.version === raw.previous))
  )
    throw unsafe();
  return raw as InstallReceipt;
}

export function releaseInfo(
  metadata: ReleaseMetadata,
  archiveSha256?: string,
): NonNullable<InstalledRelease["release"]> {
  return {
    target: metadata.target,
    channel: metadata.channel,
    pi: metadata.pi.version,
    piship: metadata.piship.version,
    lockSha256: metadata.lockSha256,
    ...(archiveSha256 ? { archiveSha256 } : {}),
  };
}

/** A lifecycle operation's hold on its distribution. */
export interface LifecycleLock extends LifecycleHold {
  /**
   * Write `receipt`, the commit of the operation, only while the lock still
   * names this operation. When another process took the lock over, nothing is
   * written and the operation fails with a retryable error: the operation
   * that holds the lock now owns the installation.
   */
  commit(receipt: InstallReceipt): void;
}

/**
 * One lifecycle operation per distribution at a time. The lock is a lease
 * (see lifecycle-lock.ts): the lock of a crashed holder is recovered at once,
 * or after a day when an unrelated process has reused its process ID.
 */
export function acquireLock(
  id: string,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED" = "UPDATE_FAILED",
): LifecycleLock {
  const path = join(appDirectory(id), ".lifecycle.lock");
  const operation = code === "UPDATE_FAILED" ? "update" : "rollback";
  const hold = acquireLifecycleLock(
    path,
    (pid) =>
      new PiShipError(
        code,
        `Another update, rollback, or uninstall of ${id} is running${pid === null ? "" : ` (process ${pid})`}`,
        {
          retryable: true,
          userAction: `Try again when it finishes; if none is running, remove ${path}`,
        },
      ),
    () => new PiShipError(code, `Could not lock ${id} for ${operation}`),
  );
  return {
    ...hold,
    commit(receipt) {
      if (!hold.stillHeld())
        throw new PiShipError(
          code,
          `The lock on ${id} was taken over while the ${operation} ran; nothing was committed`,
          {
            retryable: true,
            userAction:
              "Run the command again once no other update, rollback, or uninstall is running",
          },
        );
      writeReceipt(receipt);
    },
  };
}

/**
 * Remove leftovers of an interrupted operation: staging directories and
 * release directories the receipt does not reference, and abandoned
 * temporaries of the receipt (only the returned names are under `apps`).
 * Idempotent.
 */
export function recoverInstallation(id: string): string[] {
  const receipt = readInstallReceipt(id);
  removeStaleTemporaries(join(installHome(), "receipts"), [`${id}.json`]);
  const apps = appDirectory(id);
  const keep = new Set([
    ...receipt.releases.map((item) => item.version),
    "launch.mjs",
    ".lifecycle.lock",
    ".runtime-leases",
  ]);
  for (const lease of runtimeLeases(id, true)) {
    if (!lease.live) continue;
    if (lease.version === "*") {
      for (const name of readdirSync(apps))
        if (VERSION_NAME.test(name)) keep.add(name);
    } else keep.add(lease.version);
  }
  const removed: string[] = [];
  for (const name of readdirSync(apps))
    if (!keep.has(name)) {
      rmSync(join(apps, name), { recursive: true, force: true });
      removed.push(name);
    }
  return removed;
}

export function requireManaged(receipt: InstallReceipt): void {
  if (!receipt.launcher)
    throw new PiShipError(
      "UPDATE_FAILED",
      `${receipt.app.id} was installed by an earlier PiShip without release tracking; reinstall it to enable update and rollback`,
    );
}

export function activeLock(receipt: InstallReceipt): DistributionLock {
  const active = receipt.releases.find(
    (item) => item.version === receipt.active,
  );
  if (!active)
    throw new Error(`Unsafe installation receipt for ${receipt.app.id}`);
  return verifyPayload(active.payload);
}
