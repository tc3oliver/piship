// Installed lifecycle status for doctor.
import { existsSync, readdirSync } from "node:fs";
import type { DistributionLock } from "../index.js";
import { keyFingerprint } from "../signing.js";
import {
  appDirectory,
  readInstallReceipt,
  type InstallReceipt,
} from "./receipt.js";
import { runtimeLeases } from "./runtime-lease.js";

export interface LifecycleStatus {
  readonly installed: boolean;
  readonly tracked: boolean;
  readonly active?: string;
  readonly previous?: string;
  readonly channel?: string;
  readonly channels?: readonly string[];
  readonly source?: string;
  /** Pinned keys the installation has not retired. */
  readonly trustedKeys?: number;
  /** Every key the active lock pins; `retiredBy` names the retiring release. */
  readonly keys?: readonly {
    readonly id: string;
    readonly fingerprint: string;
    readonly retiredBy?: string;
  }[];
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
  const keys = (lock.updates?.trust.keys ?? []).map((key) => {
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
  const leases = runtimeLeases(id);
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
          rollback: lock.updates.rollback,
        }
      : {}),
    fromRelease: !!active?.release,
    ...(receipt.lastCheck ? { lastCheck: receipt.lastCheck } : {}),
    leftovers,
    ...(leases.length ? { runtimeLeases: { live, stale } } : {}),
  };
}
