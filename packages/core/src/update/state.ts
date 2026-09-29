// State handling around an activation: non-secret snapshots, the state
// marker, credential clearing, and the candidate launch check.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PiShipError, redact } from "@piship/contracts";
import {
  deleteSecretsVerified,
  metadataFileSecretRefs,
  metadataSecretRefs,
} from "@piship/credentials";
import { runtimeStateDirectory, type DistributionLock } from "../index.js";
import { writeFileAtomic, type LifecycleOptions } from "../install/receipt.js";
import {
  STATE_DATA_CLASSES,
  STATE_MARKER_FILE,
  STATE_MARKER_SCHEMA,
  readStateMarker,
  type MigrationReport,
} from "../migration.js";
import type { ReleaseTestRunner } from "../release/index.js";
import { storageTransitionNotice } from "../storage-transition.js";

export const SNAPSHOT_SCHEMA = "piship-snapshot/v1";
const SNAPSHOT_RETENTION = 3;

/** Copy preferences and user policy (never credentials) before activation. */
export function snapshotState(
  stateDir: string,
  from: string,
  to: string,
  now: Date,
): string | null {
  if (!existsSync(stateDir)) return null;
  const root = join(stateDir, "migration", "snapshots");
  const name = `${now.toISOString().replace(/[:.]/g, "-")}-${from}-to-${to}`;
  const target = join(root, name);
  const files: string[] = [];
  for (const path of ["config/preferences.json", "config/policy.json"]) {
    const source = join(stateDir, ...path.split("/"));
    if (!existsSync(source)) continue;
    mkdirSync(dirname(join(target, ...path.split("/"))), {
      recursive: true,
      mode: 0o700,
    });
    copyFileSync(source, join(target, ...path.split("/")));
    files.push(path);
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  writeFileSync(
    join(target, "snapshot.json"),
    `${JSON.stringify(
      {
        schema: SNAPSHOT_SCHEMA,
        from,
        to,
        time: now.toISOString(),
        files,
        excluded: STATE_DATA_CLASSES.filter((item) => item.credential).map(
          (item) => item.path,
        ),
      },
      null,
      2,
    )}\n`,
  );
  const snapshots = readdirSync(root).sort();
  for (const old of snapshots.slice(0, -SNAPSHOT_RETENTION))
    rmSync(join(root, old), { recursive: true, force: true });
  return target;
}

export function writeStateMarker(
  stateDir: string,
  lock: DistributionLock,
): void {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeFileAtomic(
    join(stateDir, STATE_MARKER_FILE),
    `${JSON.stringify(
      {
        schema: STATE_MARKER_SCHEMA,
        distribution: lock.app.id,
        version: lock.app.version,
        pi: lock.runtime.version,
        piship: lock.runtime.pishipVersion,
      },
      null,
      2,
    )}\n`,
  );
}

/**
 * Write the state marker once an activation has committed. The receipt is
 * the commit point, so the release it names is active whatever happens
 * here: a marker that cannot be written (a full, read-only, or failing state
 * filesystem) keeps its previous content and is reported as a notice, never
 * as a failed activation. The next update or rollback repairs it before it
 * compares state (see `repairStateMarker`).
 */
export function markActivated(
  stateDir: string,
  lock: DistributionLock,
): string[] {
  try {
    writeStateMarker(stateDir, lock);
    return [];
  } catch (error) {
    return [
      `${lock.app.version} is active, but its state marker could not be written (${redact(error instanceof Error ? error.message : String(error))}); the next update or rollback repairs it`,
    ];
  }
}

/**
 * Repair a state marker that names another release than the active one. An
 * operation interrupted after its receipt commit, or one whose marker could
 * not be written (see `markActivated`), leaves it behind; the next
 * update or rollback fixes it before comparing state against a target. A
 * missing marker is left alone: the migration check then uses the active
 * release.
 */
export function repairStateMarker(id: string, lock: DistributionLock): void {
  const stateDir = runtimeStateDirectory({ value: id });
  const marker = readStateMarker(stateDir);
  if (
    marker &&
    (marker.version !== lock.app.version || marker.pi !== lock.runtime.version)
  )
    writeStateMarker(stateDir, lock);
}

/**
 * Clear credential classes the target cannot read: their metadata files and
 * every secret they may reference (current, orphaned, and pending
 * generations). The runtime credential is first revoked remotely when the
 * current release can read it and the distribution supports revocation. The
 * target signs in or reacquires; an old credential is never restored.
 *
 * Every deletion is confirmed. When a secret cannot be deleted, or there is
 * no secret store to delete it from, no metadata is removed, so every secret
 * stays tracked, and this throws SECRET_STORE_UNAVAILABLE before anything is
 * activated: a release that cannot read the metadata must never be left with
 * secrets that nothing references.
 */
export async function clearCredentials(
  stateDir: string,
  distributionId: string,
  report: MigrationReport,
  options: Pick<LifecycleOptions, "secretStore" | "revokeCredential">,
): Promise<string[]> {
  const notices: string[] = [];
  const items = report.items.filter(
    (item) => item.action === "clear-and-reacquire",
  );
  const credentialPath = join(
    stateDir,
    "credentials-metadata",
    "inference.json",
  );
  if (
    options.revokeCredential &&
    items.some(
      (item) => join(stateDir, ...item.path.split("/")) === credentialPath,
    ) &&
    existsSync(credentialPath)
  )
    try {
      const result = await options.revokeCredential();
      if (result.outcome === "failed")
        notices.push(
          `The runtime credential could not be revoked remotely${result.problem ? ` (${redact(result.problem)})` : ""}; it was cleared locally`,
        );
    } catch (error) {
      notices.push(
        `The runtime credential could not be revoked remotely (${redact(error instanceof Error ? error.message : String(error))}); it was cleared locally`,
      );
    }
  const failed: { ref: string; problem: string }[] = [];
  for (const item of items) {
    const path = join(stateDir, ...item.path.split("/"));
    let refs: string[] = [];
    if (existsSync(path) && statSync(path).isFile()) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        parsed = undefined;
      }
      // A damaged file still names secrets in its text; they are deleted too.
      refs = [
        ...new Set([
          ...metadataSecretRefs(parsed, distributionId),
          ...metadataFileSecretRefs(
            path,
            distributionId,
            item.path.startsWith("identity/") ? "identity" : "inference",
          ),
        ]),
      ].sort();
    }
    if (!refs.length) continue;
    if (options.secretStore)
      failed.push(...(await deleteSecretsVerified(options.secretStore, refs)));
    else
      failed.push(
        ...refs.map((ref) => ({
          ref,
          problem: "no secret store is available to delete it",
        })),
      );
  }
  if (failed.length)
    throw new PiShipError(
      "SECRET_STORE_UNAVAILABLE",
      `A stored credential the target release cannot read could not be deleted from the secret store (${failed.map((item) => `${item.ref}: ${item.problem}`).join("; ")}), so the switch stopped before activation; its metadata is kept, so the secret stays tracked and the deletion is retried`,
      {
        component: "credential",
        userAction:
          "Unlock or repair the secret store, then run the update or rollback again",
        sanitizedDetail: { refs: failed.map((item) => item.ref) },
      },
    );
  for (const item of items) {
    rmSync(join(stateDir, ...item.path.split("/")), {
      recursive: true,
      force: true,
    });
    notices.push(
      item.storageTransition
        ? storageTransitionNotice(item.name, item.storageTransition)
        : `${item.name} was cleared because the target cannot read it; sign in again`,
    );
  }
  if (notices.length)
    rmSync(join(stateDir, "secrets"), { recursive: true, force: true });
  return notices;
}

export function checkPayload(
  payload: string,
  lock: DistributionLock,
  runCheck: ReleaseTestRunner,
  env: NodeJS.ProcessEnv,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED",
): void {
  // The candidate is not active yet: it runs against throwaway state, never
  // the user's.
  const state = mkdtempSync(join(tmpdir(), "piship-launch-check-"));
  let result: ReturnType<ReleaseTestRunner>;
  try {
    result = runCheck(payload, lock.app.command, ["version"], {
      ...env,
      PISHIP_STATE_HOME: state,
    });
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
  if (
    result.status !== 0 ||
    !result.stdout.includes(`Pi ${lock.runtime.version}`)
  )
    throw new PiShipError(
      code,
      `The ${lock.app.version} release failed its launch check: ${(result.stderr || result.stdout).trim().slice(0, 300)}`,
    );
}
