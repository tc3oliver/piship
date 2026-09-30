// Verified update of an installed distribution from its signed channel.
import { existsSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { resolveTemplate, type UpdatesManifest } from "@piship/schema";
import {
  currentTarget,
  runtimeStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "../index.js";
import {
  acquireLock,
  activeLock,
  appDirectory,
  readInstallReceipt,
  recoverInstallation,
  releaseInfo,
  requireManaged,
  syncDirectory,
  syncTree,
  type InstallReceipt,
  type LifecycleOptions,
} from "../install/receipt.js";
import {
  checkStateMigration,
  compareVersions,
  type MigrationReport,
} from "../migration.js";
import { storageOf } from "../storage-transition.js";
import { createStagingDirectory } from "../temporary-directories.js";
import {
  checkUpdateSource,
  downloadArchive,
  readChannel,
  runPayloadCommand,
  verifyRelease,
  type ChannelRelease,
} from "../release/index.js";
import {
  checkPayload,
  clearCredentials,
  markActivated,
  repairStateMarker,
  snapshotState,
} from "./state.js";

export interface ChannelSelection {
  readonly channel: string;
  readonly notices: readonly string[];
}

/** Resolve the channel a user may use under the distribution's policy. */
export function selectChannel(
  updates: UpdatesManifest,
  requested: string | undefined,
  saved: string | undefined,
): ChannelSelection {
  if (requested !== undefined) {
    if (!(updates.channels as readonly string[]).includes(requested))
      throw new PiShipError(
        "POLICY_DENIED",
        `Channel ${requested} is not allowed by this distribution (allowed: ${updates.channels.join(", ")})`,
        { component: "update" },
      );
    return { channel: requested, notices: [] };
  }
  if (saved && (updates.channels as readonly string[]).includes(saved))
    return { channel: saved, notices: [] };
  return {
    channel: updates.channel,
    notices: saved
      ? [`Channel ${saved} is no longer allowed; using ${updates.channel}`]
      : [],
  };
}

function resolveSource(
  lock: DistributionLock,
  override: string | undefined,
  env: NodeJS.ProcessEnv,
): string {
  if (override) return checkUpdateSource(override, "--from");
  const template = lock.updates?.source;
  if (!template)
    throw new PiShipError(
      "UPDATE_FAILED",
      `${lock.app.name} declares no update source; pass --from <directory|url>`,
      { component: "update" },
    );
  let resolved: string;
  try {
    resolved = resolveTemplate(
      "updates.source",
      template,
      lock.access?.variables ?? [],
      env,
    );
  } catch (error) {
    throw new PiShipError("CONFIG_UNAVAILABLE", (error as Error).message, {
      component: "update",
    });
  }
  // The static check sees only the template; the resolved value gets the
  // same URL rules at run time.
  return checkUpdateSource(resolved, "updates.source");
}

export interface UpdateOptions extends LifecycleOptions {
  readonly channel?: string;
  /** Directory or URL overriding `updates.source`. */
  readonly source?: string;
  /** Proceed when the migration check reports `requires-review`. */
  readonly acceptReview?: boolean;
  /** Report what would happen; changes nothing but the last-check record. */
  readonly check?: boolean;
  readonly fetcher?: typeof fetch;
}

export interface UpdateResult {
  readonly status: "up-to-date" | "available" | "updated";
  readonly id: string;
  readonly from: string;
  readonly to?: string;
  readonly channel: string;
  readonly keyId?: string;
  readonly migration?: MigrationReport;
  readonly snapshot?: string | null;
  readonly notices: readonly string[];
}

function newestFor(
  releases: readonly ChannelRelease[],
  target: string,
): ChannelRelease | undefined {
  return releases
    .filter((item) => item.target === target)
    .sort((a, b) => compareVersions(b.version, a.version))[0];
}

/**
 * Verified update: channel policy, signed channel metadata, a newer release
 * for this target, archive digest, release verification, launch check,
 * migration check, non-secret snapshot, then one atomic activation.
 */
export async function updateDistribution(
  id: string,
  options: UpdateOptions = {},
): Promise<UpdateResult> {
  requireManaged(readInstallReceipt(id));
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const lifecycle = acquireLock(id);
  try {
    // Read under the lock, so a concurrent commit cannot leave it stale.
    const receipt = readInstallReceipt(id);
    recoverInstallation(id);
    const lock = activeLock(receipt);
    if (!options.check) repairStateMarker(id, lock);
    const updates = lock.updates;
    if (!updates)
      throw new PiShipError(
        "UPDATE_FAILED",
        `${lock.app.name} ${lock.app.version} has no update policy (manifest ${lock.manifest.schema}); install a piship/v1alpha4 release`,
      );
    if (!updates.trust.keys.length)
      throw new PiShipError(
        "UPDATE_FAILED",
        `${lock.app.name} trusts no release keys (updates.trust.keys), so no update can be verified`,
      );
    const selection = selectChannel(updates, options.channel, receipt.channel);
    const { channel } = selection;
    const notices = [...selection.notices];
    const source = resolveSource(lock, options.source, env);
    const minSequence = receipt.channelSequences?.[channel] ?? 0;
    const { metadata, keyId } = await readChannel(source, channel, {
      distribution: id,
      trusted: updates.trust.keys,
      minSequence,
      now,
      ...(options.fetcher ? { fetcher: options.fetcher } : {}),
    });
    const record = (result: string, extra: Partial<InstallReceipt> = {}) =>
      lifecycle.commit({
        ...readInstallReceipt(id),
        ...extra,
        // A check reports on the requested channel without switching to it.
        ...(options.check ? {} : { channel }),
        channelSequences: {
          ...(receipt.channelSequences ?? {}),
          [channel]: metadata.sequence,
        },
        lastCheck: { time: now().toISOString(), channel, result },
      });
    const entry = newestFor(metadata.releases, currentTarget());
    if (!entry)
      notices.push(
        `Channel ${channel} lists no release for ${currentTarget()}; ask the distribution owner whether this platform is still supported`,
      );
    if (!entry || compareVersions(entry.version, receipt.active) === 0) {
      record("up-to-date");
      // Finishes an update interrupted between its commit and the marker.
      const stateDir = runtimeStateDirectory({ value: id });
      if (!options.check && existsSync(stateDir))
        notices.push(...markActivated(stateDir, lock));
      return {
        status: "up-to-date",
        id,
        from: receipt.active,
        channel,
        keyId,
        notices,
      };
    }
    if (compareVersions(entry.version, receipt.active) < 0)
      throw new PiShipError(
        "UPDATE_FAILED",
        `Channel ${channel} offers ${entry.version}, older than the active ${receipt.active}; downgrades are refused (use rollback to return to a retained release)`,
      );
    const apps = appDirectory(id);
    const temporary = createStagingDirectory(apps);
    const staging = temporary.path;
    try {
      const archive = join(staging, entry.archive);
      await downloadArchive(source, entry, archive, options.fetcher);
      options.faults?.("staged");
      const verified = await verifyRelease(archive, {
        requireTarget: true,
        expectedSha256: entry.sha256,
        extractTo: join(staging, "release"),
      });
      const target = verified.metadata;
      const problems = [
        [target.distribution.id, id, "distribution"],
        [target.distribution.command, receipt.app.command, "command"],
        [target.distribution.version, entry.version, "version"],
        [target.pi.version, entry.pi, "Pi version"],
        [target.lockSha256, entry.lockSha256, "lock"],
      ].filter(([a, b]) => a !== b);
      if (problems.length)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `The ${entry.version} release does not match its signed channel entry: ${problems.map((item) => item[2]).join(", ")}`,
        );
      if (target.pi.compatibility === "unsupported")
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release runs Pi ${target.pi.version}, which it records as unsupported`,
        );
      checkPayload(
        verified.payload,
        verified.lock,
        options.runCheck ?? runPayloadCommand,
        env,
        "UPDATE_FAILED",
      );
      options.faults?.("verified");
      const stateDir = runtimeStateDirectory({ value: id });
      const migration = checkStateMigration(
        stateDir,
        {
          version: entry.version,
          pi: target.pi.version,
          schemas: target.stateSchemas,
          ...storageOf(verified.lock),
        },
        {
          version: receipt.active,
          pi: lock.runtime.version,
          ...storageOf(lock),
        },
      );
      if (migration.verdict === "unsupported")
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release cannot use this distribution's local data: ${migration.items
            .filter((item) => item.verdict === "unsupported")
            .map((item) => `${item.name} (${item.reason})`)
            .join("; ")}`,
        );
      if (
        migration.verdict === "requires-review" &&
        !options.acceptReview &&
        !options.check
      )
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release needs a migration review: ${migration.items
            .filter((item) => item.verdict === "requires-review")
            .map((item) => item.reason)
            .join("; ")}`,
          {
            userAction:
              "Review the migration check, then rerun update with --accept-review",
          },
        );
      if (options.check) {
        if (migration.verdict === "requires-review" && !options.acceptReview)
          notices.push(
            "Updating needs a migration review: rerun update with --accept-review after reading the migration check",
          );
        record(`available ${entry.version}`);
        return {
          status: "available",
          id,
          from: receipt.active,
          to: entry.version,
          channel,
          keyId,
          migration,
          notices,
        };
      }
      const snapshot = snapshotState(
        stateDir,
        receipt.active,
        entry.version,
        now(),
        options.faults,
      );
      const destination = join(apps, entry.version);
      rmSync(destination, { recursive: true, force: true });
      renameSync(verified.payload, destination);
      verifyPayload(destination);
      syncTree(destination);
      syncDirectory(apps);
      options.faults?.("installed");
      notices.push(
        ...(await clearCredentials(stateDir, id, migration, options)),
      );
      const keepPrevious =
        updates.rollback && verified.lock.updates?.rollback !== false;
      const current = readInstallReceipt(id);
      const next: InstallReceipt = {
        ...current,
        app: verified.lock.app,
        payload: destination,
        active: entry.version,
        ...(keepPrevious ? { previous: receipt.active } : {}),
        releases: [
          {
            version: entry.version,
            payload: destination,
            installedAt: now().toISOString(),
            release: releaseInfo(target, entry.sha256),
          },
          ...(keepPrevious
            ? current.releases.filter((item) => item.version === receipt.active)
            : []),
        ],
        channel,
        channelSequences: {
          ...(current.channelSequences ?? {}),
          [channel]: metadata.sequence,
        },
        lastCheck: {
          time: now().toISOString(),
          channel,
          result: `updated ${receipt.active} -> ${entry.version}`,
        },
      };
      if (!keepPrevious) delete (next as { previous?: string }).previous;
      lifecycle.commit(next);
      // Committed: from here on nothing reports the update as failed.
      options.faults?.("committed");
      notices.push(...markActivated(stateDir, verified.lock));
      try {
        verified.cleanup();
      } catch {
        // The staging directory is removed below or by the next recovery.
      }
      return {
        status: "updated",
        id,
        from: receipt.active,
        to: entry.version,
        channel,
        keyId,
        migration,
        snapshot,
        notices,
      };
    } finally {
      try {
        temporary.remove();
        // An operation that took the lock over owns what is on disk now.
        if (lifecycle.stillHeld()) recoverInstallation(id);
        options.faults?.("cleaned");
      } catch {
        // Recovery runs again before the next operation.
      }
    }
  } finally {
    lifecycle.release();
  }
}
