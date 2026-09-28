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
import { metadataSecretRefs } from "@piship/credentials";
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
 * Repair a state marker that names another release than the active one. An
 * operation interrupted after its receipt commit leaves it behind; the next
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
 */
export async function clearCredentials(
  stateDir: string,
  distributionId: string,
  report: MigrationReport,
  options: Pick<LifecycleOptions, "deleteSecret" | "revokeCredential">,
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
  for (const item of items) {
    const path = join(stateDir, ...item.path.split("/"));
    if (existsSync(path) && statSync(path).isFile()) {
      let refs: string[] = [];
      try {
        refs = metadataSecretRefs(
          JSON.parse(readFileSync(path, "utf8")),
          distributionId,
        );
      } catch {
        // Unreadable metadata still gets removed below.
      }
      for (const ref of refs)
        await options
          .deleteSecret?.(ref)
          .catch((error: Error) =>
            notices.push(
              `Could not delete a stored secret: ${redact(error.message)}`,
            ),
          );
    }
    rmSync(path, { recursive: true, force: true });
    notices.push(
      `${item.name} was cleared because the target cannot read it; sign in again`,
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
