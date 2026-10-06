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
import { join, relative, sep } from "node:path";
import { PiShipError, type SecretStore } from "@piship/contracts";
import {
  type SecretStoreResolver,
  syncDirectory,
  writeFileAtomic,
} from "@piship/credentials";
import {
  assertDisjointRoots,
  binHome,
  installHome,
  distributionStateDirectory,
  verifyPayloadContents,
  type DistributionLock,
} from "../index.js";
import type { ReleaseMetadata, ReleaseTestRunner } from "../release/index.js";
import { acquireLifecycleLock, type LifecycleHold } from "./lifecycle-lock.js";
import { removeStaleTemporaries } from "./temporaries.js";
import { acquireLaunchGate, runtimeLeases } from "./runtime-lease.js";

export const RECEIPT_SCHEMA = "piship-install/v1";

export const VERSION_NAME = /^[0-9][0-9A-Za-z.+-]*$/;

export interface InstalledRelease {
  readonly version: string;
  readonly payload: string;
  readonly installedAt: string;
  /**
   * The SHA-256 of the installed `piship.lock`, recorded when a payload
   * directory was installed; a release records it in `release.lockSha256`,
   * from its signed metadata. A launch refuses a lock that differs.
   */
  readonly lockSha256?: string;
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

/**
 * A release key that a release activated on this installation stopped
 * pinning. It stays refused after a rollback to a release that still pins it.
 */
export interface RetiredKey {
  readonly id: string;
  /** `keyFingerprint` of the public key: retirement follows the key, not the id. */
  readonly fingerprint: string;
  /** The version whose activation retired the key. */
  readonly release: string;
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
  /** Keys retired by a v0.7 update; absent (none) in other receipts. */
  readonly retiredKeys?: readonly RetiredKey[];
  /**
   * The installation keeps its update trust in `trust/<id>.json`. Once set,
   * a missing trust state fails closed instead of being rebuilt from the
   * active release lock; absent on receipts written before v0.8.
   */
  readonly trustState?: true;
  readonly lastCheck?: {
    readonly time: string;
    readonly channel: string;
    readonly result: string;
  };
}

export type LifecyclePhase =
  | "root-accepted"
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
  /** Receives a short line as each long step starts (see `progressReporter`). */
  readonly progress?: (step: string) => void;
  /** Test seam: throw at a phase to simulate interruption. */
  readonly faults?: (phase: LifecyclePhase) => void;
  /** @deprecated Client activation no longer boots a candidate; qualification runs in CI. */
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

/**
 * The home a receipt path was recorded under, when it is the owned path
 * `expected` under another home: the receipt was written with a different
 * `PISHIP_INSTALL_HOME` or `PISHIP_BIN_HOME`, or that home was moved.
 */
function recordedHome(
  recorded: unknown,
  expected: string,
  home: string,
): string | undefined {
  const owned = relative(home, expected);
  if (typeof recorded !== "string" || !recorded.endsWith(`${sep}${owned}`))
    return undefined;
  const other = recorded.slice(0, -(owned.length + 1));
  return other && other !== home ? other : undefined;
}

/**
 * Read and validate an install receipt; paths must be the owned ones. A
 * receipt that cannot be read, or fails a check, is a CONFIG_INVALID error
 * naming the file and the check (`sanitizedDetail.check`); a path recorded
 * under another home also names the variable to restore
 * (`sanitizedDetail.variable`).
 */
export function readInstallReceipt(id: string): InstallReceipt {
  const path = receiptPath(id);
  if (!existsSync(path))
    throw new Error(`No PiShip installation recorded for ${id}`);
  const fail = (check: string, mismatch?: [string, string]) =>
    new PiShipError(
      "CONFIG_INVALID",
      `Unsafe installation receipt for ${id}: ${path} ${check}${mismatch ? `: it was written with ${mismatch[0]}=${mismatch[1]}` : ""}`,
      {
        userAction: mismatch
          ? `Set ${mismatch[0]}=${mismatch[1]} and run the command again`
          : `Run piship uninstall ${id}, then install ${id} again`,
        sanitizedDetail: {
          receipt: path,
          check,
          ...(mismatch ? { variable: mismatch[0], recorded: mismatch[1] } : {}),
        },
      },
    );
  let raw: Partial<InstallReceipt>;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as Partial<InstallReceipt>;
  } catch (error) {
    throw fail(
      `is damaged: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!raw || typeof raw !== "object" || !raw.app || raw.app.id !== id)
    throw fail(`does not record distribution ${id}`);
  /** A path that is not the owned one, naming the home it was recorded under. */
  const owned = (
    recorded: unknown,
    expected: string,
    what: string,
    variable: "PISHIP_INSTALL_HOME" | "PISHIP_BIN_HOME",
  ) => {
    if (recorded === expected) return;
    const home = recordedHome(
      recorded,
      expected,
      variable === "PISHIP_BIN_HOME" ? binHome() : installHome(),
    );
    throw fail(
      `records the ${what} ${String(recorded)}, not ${expected}`,
      home ? [variable, home] : undefined,
    );
  };
  if (typeof raw.app.command !== "string")
    throw fail("does not record a command");
  owned(
    raw.commandPath,
    commandPathFor(raw.app.command),
    "command path",
    "PISHIP_BIN_HOME",
  );
  if (raw.schema === undefined) {
    // Written before receipts were versioned: one release, shim to payload.
    owned(
      raw.payload,
      join(appDirectory(id), raw.app.version),
      "payload",
      "PISHIP_INSTALL_HOME",
    );
    return {
      app: raw.app,
      payload: raw.payload as string,
      commandPath: raw.commandPath as string,
      active: raw.app.version,
      releases: [
        {
          version: raw.app.version,
          payload: raw.payload as string,
          installedAt: "",
        },
      ],
    };
  }
  if (raw.schema !== RECEIPT_SCHEMA)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Install receipt ${raw.schema} was written by a newer PiShip; use that version to manage ${id}`,
    );
  if (raw.releases !== undefined && !Array.isArray(raw.releases))
    throw fail("does not record a list of releases");
  const releases = raw.releases ?? [];
  for (const release of releases) {
    if (!release || !VERSION_NAME.test(String(release.version)))
      throw fail("records a release without a valid version");
    owned(
      release.payload,
      join(appDirectory(id), release.version),
      `payload of ${release.version}`,
      "PISHIP_INSTALL_HOME",
    );
  }
  owned(
    raw.launcher,
    join(appDirectory(id), "launch.mjs"),
    "launcher",
    "PISHIP_INSTALL_HOME",
  );
  const active = releases.find((item) => item.version === raw.active);
  if (!active) throw fail(`does not record its active release ${raw.active}`);
  if (raw.payload !== active.payload)
    throw fail("records a payload that is not its active release");
  if (
    raw.previous !== undefined &&
    !releases.some((item) => item.version === raw.previous)
  )
    throw fail(`does not record its previous release ${raw.previous}`);
  if (
    raw.retiredKeys !== undefined &&
    (!Array.isArray(raw.retiredKeys) ||
      !raw.retiredKeys.every(
        (key) =>
          key &&
          typeof key.id === "string" &&
          typeof key.fingerprint === "string" &&
          /^sha256:[a-f0-9]{64}$/.test(key.fingerprint) &&
          typeof key.release === "string",
      ))
  )
    throw fail("records invalid retired release keys");
  if (raw.trustState !== undefined && raw.trustState !== true)
    throw fail("records an invalid trust state marker");
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
  assertDisjointRoots();
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
  // Admission waits only for launcher registration, without scanning or
  // reclaiming payloads. A launch already registering finishes before this
  // operation mutates state; a new registration is serialized at commit.
  try {
    const gate = acquireLaunchGate(id, code);
    gate.release();
  } catch (error) {
    hold.release();
    throw error;
  }
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
      const gate = acquireLaunchGate(id, code);
      try {
        if (!hold.stillHeld())
          throw new PiShipError(
            code,
            `The lock on ${id} was taken over before commit`,
            { retryable: true },
          );
        writeReceipt(receipt);
      } finally {
        gate.release();
      }
    },
  };
}

/**
 * Remove leftovers of an interrupted operation: staging directories and
 * release directories the receipt does not reference, and abandoned
 * temporaries of the receipt (only the returned names are under `apps`).
 * Idempotent.
 */
export function recoverInstallation(
  id: string,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED" = "UPDATE_FAILED",
): string[] {
  const gate = acquireLaunchGate(id, code);
  try {
    const receipt = readInstallReceipt(id);
    removeStaleTemporaries(join(installHome(), "receipts"), [`${id}.json`]);
    removeStaleTemporaries(join(installHome(), "trust"), [`${id}.json`]);
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
        if (!gate.stillHeld())
          throw new Error(`Launcher registration lock for ${id} was lost`);
        rmSync(join(apps, name), { recursive: true, force: true });
        removed.push(name);
      }
    return removed;
  } finally {
    gate.release();
  }
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
  return verifyPayloadContents(active.payload, {
    requireTarget: true,
    verifyContents: false,
  });
}
