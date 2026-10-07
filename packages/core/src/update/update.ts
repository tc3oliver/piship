// Verified update of an installed distribution from its signed channel.
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { PiShipError, stopwatch } from "@piship/contracts";
import { resolveTemplate, type UpdatesManifest } from "@piship/schema";
import {
  currentTarget,
  installHome,
  runtimeStateDirectory,
  type DistributionLock,
} from "../index.js";
import {
  acquireLock,
  activeLock,
  appDirectory,
  readInstallReceipt,
  releaseInfo,
  requireManaged,
  syncDirectory,
  type InstalledRelease,
  type InstallReceipt,
  type LifecycleOptions,
  type RetiredKey,
} from "../install/receipt.js";
import { renameWithRetry } from "../install/files.js";
import { refreshInstalledLauncher } from "../install/launcher.js";
import { runtimeLeases } from "../install/runtime-lease.js";
import {
  advanceTrustState,
  damagedTrustState,
  initialTrustState,
  readTrustState,
  writeTrustState,
  type UpdateTrustState,
} from "../install/trust-state.js";
import {
  checkStateMigration,
  compareVersions,
  type MigrationReport,
  type StateSchemaSupport,
} from "../migration.js";
import { storageOf } from "../storage-transition.js";
import { sha256File } from "../archive.js";
import { hash } from "../digest.js";
import { verifyPayloadContents } from "../payload.js";
import { openInstallStore } from "../store/policy.js";
import type { ContentStore } from "../store/store.js";
import { refreshRoot, roleTrust, rootExpired } from "../release/root.js";
import { createStagingDirectory } from "../temporary-directories.js";
import { raiseThreadpool } from "../threadpool.js";
import { isUrlSource } from "../release/source.js";
import {
  checkUpdateSource,
  downloadArchive,
  payloadStateSchemas,
  readChannel,
  verifyRelease,
  type ChannelRelease,
} from "../release/index.js";
import {
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
  const transport = lock.updates?.transport;
  if (override) return checkUpdateSource(override, "--from", transport);
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
  return checkUpdateSource(resolved, "updates.source", transport);
}

/** Where a verified download is kept when the update stops after it. */
export const DOWNLOADS = ".downloads";

/** What an update activates: a freshly verified archive, or a retained release as it stands. */
interface Candidate {
  readonly lock: DistributionLock;
  readonly pi: string;
  readonly schemas: StateSchemaSupport;
  readonly release: NonNullable<InstalledRelease["release"]>;
  readonly cleanup: () => void;
}

/**
 * A retained release as it stands, checked against the signed entry. Throws
 * when the release is damaged or is not what the entry names; the caller
 * downloads it again.
 */
function retainedCandidate(
  directory: string,
  id: string,
  receipt: InstallReceipt,
  entry: ChannelRelease,
  retained: InstalledRelease,
): Candidate {
  const lock = verifyPayloadContents(directory, {
    requireTarget: true,
    // As a rollback does: the files were hashed against the inventory when
    // this release was installed, and doctor verifies them in full.
    verifyContents: false,
  });
  const problems = [
    [lock.app.id, id, "distribution"],
    [lock.app.command, receipt.app.command, "command"],
    [lock.app.version, entry.version, "version"],
    [lock.runtime.version, entry.pi, "Pi version"],
    [
      hash(readFileSync(join(directory, "piship.lock"))),
      entry.lockSha256,
      "lock",
    ],
  ].filter(([a, b]) => a !== b);
  if (problems.length)
    throw new Error(
      `it does not match its signed channel entry: ${problems.map((item) => item[2]).join(", ")}`,
    );
  return {
    lock,
    pi: lock.runtime.version,
    schemas: payloadStateSchemas(lock),
    release: retained.release as NonNullable<InstalledRelease["release"]>,
    cleanup: () => {},
  };
}

/** A kept download of exactly the signed archive, or undefined. */
async function usableDownload(
  path: string,
  entry: ChannelRelease,
): Promise<string | undefined> {
  try {
    if (statSync(path).size !== entry.bytes) throw new Error("size");
    if ((await sha256File(path)) === entry.sha256) return path;
  } catch {
    // Absent or not the signed bytes: downloaded again.
  }
  rmSync(path, { force: true });
  return undefined;
}

function keepDownload(
  archive: string,
  apps: string,
  cachePath: string,
  cacheable: boolean,
): void {
  if (!cacheable || archive === cachePath || !existsSync(archive)) return;
  try {
    rmSync(join(apps, DOWNLOADS), { recursive: true, force: true });
    mkdirSync(join(apps, DOWNLOADS), { recursive: true });
    renameWithRetry(archive, cachePath);
  } catch {
    // The next attempt downloads again.
  }
}

function discardDownloads(apps: string): void {
  try {
    rmSync(join(apps, DOWNLOADS), { recursive: true, force: true });
  } catch {
    // Reclaimed by doctor and the next update.
  }
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

/**
 * The installation's current update trust. A receipt written before v0.8
 * has none yet: its trust is taken once from the active release lock (its
 * v0.7 retired keys excluded) and recorded. Once recorded, a missing or
 * damaged state fails closed and is never rebuilt from a release lock.
 */
function installationTrust(
  id: string,
  receipt: InstallReceipt,
  lock: DistributionLock,
  time: Date,
): { readonly state: UpdateTrustState; readonly migrated: boolean } {
  const existing = readTrustState(id);
  if (existing) return { state: existing, migrated: false };
  if (receipt.trustState) throw damagedTrustState(id, "is missing");
  const state = initialTrustState(
    lock,
    id,
    time,
    (receipt.retiredKeys ?? []).map((key) => key.fingerprint),
  );
  if (!state)
    throw new PiShipError(
      "UPDATE_FAILED",
      `${lock.app.name} trusts no release keys (updates.trust), so no update can be verified`,
    );
  return { state, migrated: true };
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
  raiseThreadpool();
  requireManaged(readInstallReceipt(id));
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  // One fixed time for every expiry check of this attempt.
  const updateTime = now();
  const lifecycle = acquireLock(id);
  try {
    // Read under the lock, so a concurrent commit cannot leave it stale.
    const receipt = readInstallReceipt(id);
    const lock = activeLock(receipt);
    if (!options.check) repairStateMarker(id, lock);
    const updates = lock.updates;
    if (!updates)
      throw new PiShipError(
        "UPDATE_FAILED",
        `${lock.app.name} ${lock.app.version} has no update policy (manifest ${lock.manifest.schema}); install a piship/v1alpha4 release`,
      );
    const selection = selectChannel(updates, options.channel, receipt.channel);
    const { channel } = selection;
    const notices = [...selection.notices];
    const source = resolveSource(lock, options.source, env);
    const transport = updates.transport;
    const persist = (state: UpdateTrustState) => {
      if (!lifecycle.stillHeld())
        throw new PiShipError(
          "UPDATE_FAILED",
          `The lock on ${id} was taken over while the update ran; the update trust was not changed`,
          { retryable: true },
        );
      writeTrustState(state);
    };
    const trust = installationTrust(id, receipt, lock, updateTime);
    let state = trust.state;
    if (trust.migrated) {
      persist(state);
      lifecycle.commit({ ...readInstallReceipt(id), trustState: true });
    }
    // Mandatory order: refresh the root and persist each accepted version,
    // then verify the channel with the newest root's channel role, then
    // download, verify, and activate. A key a newer root removed stops
    // counting before any release is fetched.
    const refreshed = await refreshRoot({
      source,
      distribution: id,
      current: state.root,
      accept: (root) => {
        state = advanceTrustState(state, root, updateTime);
        persist(state);
        // A PiShip v0.7 CLI (after a rollback to a release it installed)
        // trusts its lock keys minus the receipt's retired keys, so a
        // channel key a root removed is retired there too. Every removed
        // channel key is carried, so a retirement an interrupted earlier
        // refresh did not record is recorded now.
        const current = readInstallReceipt(id);
        const retiredKeys: RetiredKey[] = [...(current.retiredKeys ?? [])];
        for (const key of state.removedKeys)
          if (
            key.role === "channel" &&
            !retiredKeys.some((item) => item.fingerprint === key.fingerprint)
          )
            retiredKeys.push({
              id: key.id,
              fingerprint: key.fingerprint,
              release: `root ${key.version}`,
            });
        if (retiredKeys.length !== (current.retiredKeys ?? []).length)
          lifecycle.commit({ ...current, trustState: true, retiredKeys });
        options.faults?.("root-accepted");
      },
      ...(options.fetcher ? { fetcher: options.fetcher } : {}),
      ...(transport ? { transport } : {}),
    });
    if (refreshed.transitions)
      notices.push(
        `Update trust advanced to root version ${refreshed.root.version}`,
      );
    if (rootExpired(refreshed.root, updateTime))
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Update root version ${refreshed.root.version} expired at ${refreshed.root.expires} (this computer's clock reads ${updateTime.toISOString()}); it no longer authorizes channel metadata`,
        {
          component: "update",
          userAction:
            "If this computer's clock is wrong, correct it; otherwise ask the distribution owner to publish the next root (piship trust-root next)",
        },
      );
    const role = roleTrust(refreshed.root, "channel");
    const minSequence = receipt.channelSequences?.[channel] ?? 0;
    options.progress?.(`Checking the ${channel} channel`);
    const { metadata, keyId } = await readChannel(source, channel, {
      distribution: id,
      trusted: role.keys,
      threshold: role.threshold,
      minSequence,
      now: () => updateTime,
      ...(options.fetcher ? { fetcher: options.fetcher } : {}),
      ...(transport ? { transport } : {}),
    });
    const record = (result: string, extra: Partial<InstallReceipt> = {}) =>
      lifecycle.commit({
        ...readInstallReceipt(id),
        ...extra,
        // A check reports on the requested channel without switching to it.
        ...(options.check ? {} : { channel }),
        trustState: true,
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
    const lap = stopwatch();
    const destination = join(apps, entry.version);
    const retained = receipt.releases.find(
      (release) => release.version === entry.version,
    );
    const present = existsSync(destination);
    // A release the receipt retains from this exact archive (its recorded
    // archive digest is the signed entry's) is used as it stands: nothing is
    // downloaded or extracted again. Its lock, manifest, and target are
    // checked against the signed entry here, so a damaged or mismatched copy
    // is not activated but replaced by a download.
    let local: Candidate | undefined;
    let damagedRetained = false;
    if (
      retained?.release !== undefined &&
      present &&
      retained.release.archiveSha256 === entry.sha256
    )
      try {
        local = retainedCandidate(destination, id, receipt, entry, retained);
      } catch (error) {
        damagedRetained = true;
        notices.push(
          `The retained ${entry.version} on disk failed verification (${(error as Error).message}); it is downloaded again`,
        );
      }
    const reuseRetained = local !== undefined;
    // A complete archive an earlier attempt downloaded and verified against
    // the signed digest, kept because the update stopped after it (a
    // migration review, a running session), is used instead of downloading
    // again; its digest is checked again on the bytes used.
    const cachePath = join(apps, DOWNLOADS, entry.archive);
    const cacheable = isUrlSource(source);
    const cached =
      !reuseRetained && cacheable
        ? await usableDownload(cachePath, entry)
        : undefined;
    // Over the network, a check that can be answered by the signed entry alone
    // (a newer release exists on this channel) does not fetch the archive:
    // the migration preview is the only thing it would add, and `update`
    // runs that check before it switches anything.
    if (options.check && !reuseRetained && cached === undefined && cacheable) {
      notices.push(
        "The migration check runs when you update; it stops for review before anything is switched",
      );
      record(`available ${entry.version}`);
      return {
        status: "available",
        id,
        from: receipt.active,
        to: entry.version,
        channel,
        keyId,
        notices,
      };
    }
    // A payload this update writes is extracted straight into the destination,
    // which nothing references yet; a failure before the commit leaves it as
    // an unreferenced candidate, which the next update sets aside and `doctor`
    // reclaims. Only a replaced retained release, which the receipt still
    // names, is put back.
    const extracting = options.check !== true && !reuseRetained;
    let replaced: string | undefined;
    let written = false;
    // Where the runtime, Pi package, and dependency files come from a shared
    // store, they are placed from it; the release is whole without it.
    let store: ContentStore | undefined;
    const temporary = createStagingDirectory(apps);
    const staging = temporary.path;
    let archive = join(staging, entry.archive);
    let downloaded = false;
    try {
      if (cached !== undefined) {
        archive = cached;
        options.progress?.(
          `Using the ${entry.version} archive downloaded earlier`,
        );
      } else if (!reuseRetained) {
        options.progress?.(
          `Downloading ${entry.version} (${(entry.bytes / 1_048_576).toFixed(1)} MiB)`,
        );
        // The download is hashed as it streams and checked against the signed
        // entry's digest and size, so a wrong archive is refused before it is
        // opened.
        await downloadArchive(
          source,
          entry,
          archive,
          options.fetcher,
          transport,
        );
        downloaded = true;
        lap("update download and digest");
      }
      options.faults?.("staged");
      if (extracting && present) {
        // What is at the destination is not the signed archive's bytes: a
        // candidate an earlier update left unfinished, or a retained release
        // the channel has since re-signed with other bytes. It is set aside,
        // never while a running session holds it.
        if (
          runtimeLeases(id).some(
            (lease) =>
              lease.live &&
              (lease.version === entry.version || lease.version === "*"),
          )
        )
          throw new PiShipError(
            "UPDATE_FAILED",
            `${destination} is not the ${entry.version} release the channel now offers, and a running session still uses it`,
            {
              retryable: true,
              userAction: `Close the running ${id} sessions and run the update again`,
            },
          );
        if (retained !== undefined && !damagedRetained)
          notices.push(
            `The retained ${entry.version} was built from other archive bytes than the channel now offers, so it was replaced`,
          );
        replaced = join(apps, `.retained-${entry.version}-${randomUUID()}`);
        renameWithRetry(destination, replaced);
      }
      let candidate: Candidate;
      if (local !== undefined) candidate = local;
      else {
        options.progress?.(`Verifying the ${entry.version} release`);
        // The archive is read once more, and only once: that read extracts the
        // payload into the destination, hashing the archive and every file as
        // they are written. The archive digest must be the signed entry's, and
        // every file the inventory release.json binds, before this returns. A
        // check needs only the metadata.
        written = extracting;
        store = extracting ? openInstallStore() : undefined;
        const verified = await verifyRelease(archive, {
          requireTarget: true,
          expectedSha256: entry.sha256,
          fastClient: true,
          ...(extracting
            ? { payloadTo: destination, ...(store ? { store } : {}) }
            : { extractTo: join(staging, "release"), metadataOnly: true }),
        });
        lap("update extract and verify release");
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
        candidate = {
          lock: verified.lock,
          pi: target.pi.version,
          schemas: target.stateSchemas,
          release: releaseInfo(target, entry.sha256),
          cleanup: verified.cleanup,
        };
      }
      options.faults?.("verified");
      lap("update signed-entry binding");
      const stateDir = runtimeStateDirectory({ value: id });
      const migration = checkStateMigration(
        stateDir,
        {
          version: entry.version,
          pi: candidate.pi,
          schemas: candidate.schemas,
          ...storageOf(candidate.lock),
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
      options.progress?.(`Switching to ${entry.version}`);
      const snapshot = snapshotState(
        stateDir,
        receipt.active,
        entry.version,
        now(),
        options.faults,
      );
      lap("update snapshot and preflight");
      syncDirectory(apps);
      options.faults?.("installed");
      notices.push(
        ...(await clearCredentials(stateDir, id, migration, options)),
      );
      const keepPrevious =
        updates.rollback && candidate.lock.updates?.rollback !== false;
      const current = readInstallReceipt(id);
      // The new release's lock does not touch the installation's update
      // trust: only a verified root can, so a channel signer cannot widen
      // its own authority by publishing a release with another bootstrap.
      const next: InstallReceipt = {
        ...current,
        app: candidate.lock.app,
        payload: destination,
        active: entry.version,
        ...(keepPrevious ? { previous: receipt.active } : {}),
        releases: [
          {
            version: entry.version,
            payload: destination,
            installedAt: now().toISOString(),
            release: candidate.release,
          },
          ...(keepPrevious
            ? current.releases.filter((item) => item.version === receipt.active)
            : []),
        ],
        channel,
        trustState: true,
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
      lap("update credentials and receipt record");
      // The objects this release placed are pinned while it is active or the
      // rollback target; a failure here only leaves them unpinned.
      store?.record(id, entry.version, installHome());
      lifecycle.commit(next);
      written = false;
      lap("update receipt commit");
      // Committed: from here on nothing reports the update as failed.
      options.faults?.("committed");
      // The launcher an earlier PiShip installed is not rewritten by an
      // activation; a stale one is replaced now, not at the next session.
      refreshInstalledLauncher(id, destination);
      notices.push(...markActivated(stateDir, candidate.lock));
      try {
        candidate.cleanup();
      } catch {
        // The staging directory is removed below or by the next recovery.
      }
      discardDownloads(apps);
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
    } catch (error) {
      // A complete download that failed no integrity check is kept for the
      // next attempt: a migration review, a running session, or a full disk
      // must not cost the whole transfer again.
      const integrity =
        error instanceof PiShipError && error.code === "INTEGRITY_FAILED";
      if (downloaded && !integrity)
        keepDownload(archive, apps, cachePath, cacheable);
      else if (integrity && archive === cachePath)
        rmSync(cachePath, { force: true });
      throw error;
    } finally {
      store?.end();
      // Not committed: put back the retained release this update replaced,
      // unless another operation holds the installation now and owns it.
      if (
        written &&
        replaced &&
        retained !== undefined &&
        lifecycle.stillHeld()
      )
        try {
          try {
            renameWithRetry(
              destination,
              join(apps, `.retained-${entry.version}-${randomUUID()}`),
            );
          } catch {
            rmSync(destination, { recursive: true, force: true });
          }
          renameWithRetry(replaced, destination);
        } catch {
          // Left for recovery, which keeps what the receipt names.
        }
      try {
        temporary.remove();
        lap("update staging cleanup");
        options.faults?.("cleaned");
      } catch {
        // Explicit diagnostics can remove abandoned staging later.
      }
    }
  } finally {
    lifecycle.release();
  }
}
