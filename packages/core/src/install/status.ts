// Installed lifecycle status for doctor.
import { existsSync, readdirSync } from "node:fs";
import type { DistributionLock } from "../index.js";
import { channelTrustFromLock } from "../lock.js";
import { keyFingerprint } from "../signing.js";
import {
  appDirectory,
  readInstallReceipt,
  type InstallReceipt,
} from "./receipt.js";
import { runtimeLeases } from "./runtime-lease.js";
import { readTrustState, type UpdateTrustState } from "./trust-state.js";

export interface LifecycleStatus {
  readonly installed: boolean;
  readonly tracked: boolean;
  readonly active?: string;
  readonly previous?: string;
  readonly channel?: string;
  readonly channels?: readonly string[];
  readonly source?: string;
  /** Channel keys the installation trusts. */
  readonly trustedKeys?: number;
  /**
   * The channel keys of the installation's update root (or, before it has
   * one, the active lock's), then keys taken out of the channel role;
   * `retiredBy` names the retiring root version or v0.7 release.
   */
  readonly keys?: readonly {
    readonly id: string;
    readonly fingerprint: string;
    readonly retiredBy?: string;
  }[];
  /** The installation's current update root. */
  readonly updateRoot?: {
    readonly version: number;
    readonly expires: string;
    readonly origin: UpdateTrustState["origin"];
    readonly channelThreshold: number;
  };
  /** Why the update trust state cannot be used; update fails closed. */
  readonly trustProblem?: string;
  readonly rollback?: boolean;
  readonly fromRelease?: boolean;
  readonly lastCheck?: InstallReceipt["lastCheck"];
  readonly leftovers: readonly string[];
  readonly runtimeLeases?: { readonly live: number; readonly stale: number };
}

/** Update status for doctor; never fetches anything. */
export function lifecycleStatus(
  id: string,
  lock: DistributionLock,
): LifecycleStatus {
  let receipt: InstallReceipt;
  try {
    receipt = readInstallReceipt(id);
  } catch {
    return { installed: false, tracked: false, leftovers: [] };
  }
  const apps = appDirectory(id);
  const known = new Set([
    ...receipt.releases.map((item) => item.version),
    "launch.mjs",
    ".lifecycle.lock",
    ".runtime-leases",
  ]);
  const leftovers = existsSync(apps)
    ? readdirSync(apps).filter((name) => !known.has(name))
    : [];
  const active = receipt.releases.find(
    (item) => item.version === receipt.active,
  );
  let trust: UpdateTrustState | undefined;
  let trustProblem: string | undefined;
  try {
    trust = readTrustState(id);
    if (!trust && receipt.trustState) trustProblem = "missing";
  } catch (error) {
    trustProblem = error instanceof Error ? error.message : String(error);
  }
  const keys: {
    id: string;
    fingerprint: string;
    retiredBy?: string;
  }[] = trust
    ? [
        ...trust.root.roles.channel.keyIds.flatMap((keyId) =>
          trust.root.keys
            .filter((key) => key.id === keyId)
            .map((key) => ({
              id: key.id,
              fingerprint: keyFingerprint(key.publicKey),
            })),
        ),
        ...trust.removedKeys
          .filter((key) => key.role === "channel")
          .map((key) => ({
            id: key.id,
            fingerprint: key.fingerprint,
            retiredBy: `root ${key.version}`,
          })),
      ]
    : channelTrustFromLock(lock).map((key) => {
        const fingerprint = keyFingerprint(key.publicKey);
        const retired = receipt.retiredKeys?.find(
          (item) => item.fingerprint === fingerprint,
        );
        return {
          id: key.id,
          fingerprint,
          ...(retired ? { retiredBy: retired.release } : {}),
        };
      });
  // The process asking (doctor runs in a launcher that holds a lease) is
  // not another session.
  const leases = runtimeLeases(id).filter((lease) => !lease.self);
  const live = leases.filter((lease) => lease.live).length;
  const stale = leases.length - live;
  return {
    installed: true,
    tracked: !!receipt.launcher,
    active: receipt.active,
    ...(receipt.previous ? { previous: receipt.previous } : {}),
    ...(lock.updates
      ? {
          channel:
            receipt.channel &&
            (lock.updates.channels as readonly string[]).includes(
              receipt.channel,
            )
              ? receipt.channel
              : lock.updates.channel,
          channels: lock.updates.channels,
          ...(lock.updates.source ? { source: lock.updates.source } : {}),
          trustedKeys: keys.filter((key) => !key.retiredBy).length,
          keys,
          ...(trust
            ? {
                updateRoot: {
                  version: trust.root.version,
                  expires: trust.root.expires,
                  origin: trust.origin,
                  channelThreshold: trust.root.roles.channel.threshold,
                },
              }
            : {}),
          ...(trustProblem ? { trustProblem } : {}),
          rollback: lock.updates.rollback,
        }
      : {}),
    fromRelease: !!active?.release,
    ...(receipt.lastCheck ? { lastCheck: receipt.lastCheck } : {}),
    leftovers,
    ...(leases.length ? { runtimeLeases: { live, stale } } : {}),
  };
}
