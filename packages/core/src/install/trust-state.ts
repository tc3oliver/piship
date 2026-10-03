// Installation update trust: the current update root of one installed
// distribution. A fresh install starts it from the verified release lock;
// from then on only a verified root refresh changes it. Activating a
// release, rolling back, or switching channels never does, so a release lock
// cannot lower or replace the root an installation has learned.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { writeFileAtomic } from "@piship/credentials";
import {
  AccessFieldError,
  parseUpdateRoot,
  type UpdateRoot,
  type UpdateRoleName,
  type UpdateTrustKey,
} from "@piship/schema";
import {
  distributionStateDirectory,
  installHome,
  type DistributionLock,
} from "../index.js";
import { rootDigest } from "../release/root.js";
import { keyFingerprint } from "../signing.js";

export const TRUST_STATE_SCHEMA = "piship-update-trust/v1";
/**
 * Expiry of the root a piship/v1alpha4 distribution's keys stand for: those
 * keys never expired, and a migration does not invent an expiry.
 */
export const LEGACY_ROOT_EXPIRES = "9999-12-31T23:59:59Z";

/** A key a root transition took out of a role. */
export interface RemovedTrustKey {
  readonly id: string;
  /** `keyFingerprint` of the public key. */
  readonly fingerprint: string;
  readonly role: UpdateRoleName;
  /** The root version that no longer lists the key in the role. */
  readonly version: number;
}

export interface UpdateTrustState {
  readonly schema: typeof TRUST_STATE_SCHEMA;
  readonly distribution: string;
  /**
   * Where the current root came from: the release lock's bootstrap at a
   * fresh install, a piship/v1alpha4 lock's keys (both roles, threshold 1),
   * or a verified hosted root.
   */
  readonly origin: "bootstrap" | "legacy" | "remote";
  readonly root: UpdateRoot;
  /** `sha256-<hex>` of the canonical root; checked on every read. */
  readonly digest: string;
  readonly removedKeys: readonly RemovedTrustKey[];
  readonly updatedAt: string;
}

/** `<install home>/trust/<id>.json`, next to (not inside) `apps/<id>`. */
export function trustStatePath(id: string): string {
  distributionStateDirectory({ value: id });
  return join(installHome(), "trust", `${id}.json`);
}

/**
 * The root a lock bootstraps: a v1alpha5 `updates.trust.bootstrap`, or the
 * piship/v1alpha4 keys as version 1 with both roles at threshold 1, minus
 * `retired` key fingerprints (a v0.7 installation's retired keys).
 * `undefined` when the lock trusts no key (updates disabled).
 */
export function initialTrustState(
  lock: Pick<DistributionLock, "updates">,
  distribution: string,
  now: Date,
  retired: readonly string[] = [],
): UpdateTrustState | undefined {
  const trust = lock.updates?.trust;
  if (!trust) return undefined;
  let root: UpdateRoot | undefined;
  if ("keys" in trust)
    root = lockRoot(distribution, () => {
      const keys: UpdateTrustKey[] = [];
      for (const key of trust.keys)
        if (
          !retired.includes(keyFingerprint(key.publicKey)) &&
          !keys.some((item) => item.publicKey === key.publicKey)
        )
          keys.push({ id: key.id, publicKey: key.publicKey });
      if (!keys.length) return undefined;
      const role = { keyIds: keys.map((key) => key.id), threshold: 1 };
      return parseUpdateRoot(
        {
          version: 1,
          expires: LEGACY_ROOT_EXPIRES,
          keys,
          roles: { root: role, channel: role },
        },
        "updates.trust",
      );
    });
  else if (trust.bootstrap)
    root = lockRoot(distribution, () =>
      parseUpdateRoot(trust.bootstrap, "updates.trust.bootstrap"),
    );
  if (!root) return undefined;
  return {
    schema: TRUST_STATE_SCHEMA,
    distribution,
    origin: "keys" in trust ? "legacy" : "bootstrap",
    root,
    digest: rootDigest(root),
    removedKeys: [],
    updatedAt: now.toISOString(),
  };
}

/**
 * The root a release lock seeds trust with, validated. The lock is read
 * without schema validation, so a malformed one fails closed here instead of
 * becoming the installation's trust.
 */
function lockRoot(
  distribution: string,
  read: () => UpdateRoot | undefined,
): UpdateRoot | undefined {
  try {
    return read();
  } catch (error) {
    throw new PiShipError(
      "LOCK_INVALID",
      `The release lock of ${distribution} records invalid update trust: ${error instanceof AccessFieldError ? `${error.field}: ` : ""}${error instanceof Error ? error.message : String(error)}`,
      {
        component: "update",
        userAction:
          "Do not install this release; obtain it again from the trusted source, or ask the distribution owner for a release with valid updates.trust",
      },
    );
  }
}

/** The state after a verified transition to `next`. */
export function advanceTrustState(
  state: UpdateTrustState,
  next: UpdateRoot,
  now: Date,
): UpdateTrustState {
  const removedKeys = [...state.removedKeys];
  for (const role of ["root", "channel"] as const) {
    const kept = new Set(
      next.roles[role].keyIds.flatMap((id) =>
        next.keys
          .filter((key) => key.id === id)
          .map((key) => keyFingerprint(key.publicKey)),
      ),
    );
    for (const id of state.root.roles[role].keyIds) {
      const key = state.root.keys.find((item) => item.id === id);
      if (!key) continue;
      const fingerprint = keyFingerprint(key.publicKey);
      if (!kept.has(fingerprint))
        removedKeys.push({ id, fingerprint, role, version: next.version });
    }
  }
  return {
    ...state,
    origin: "remote",
    root: next,
    digest: rootDigest(next),
    removedKeys,
    updatedAt: now.toISOString(),
  };
}

/** Atomically replace the trust state (owner-only, flushed, renamed). */
export function writeTrustState(state: UpdateTrustState): void {
  writeFileAtomic(
    trustStatePath(state.distribution),
    `${JSON.stringify(state, null, 2)}\n`,
  );
}

export function removeTrustState(id: string): void {
  rmSync(trustStatePath(id), { force: true });
}

/**
 * The error for a trust state that cannot be used. It is never rebuilt from
 * the active release lock, which could restore trust a newer root removed;
 * the recovery is an explicit reinstall from a release verified out of band.
 */
export function damagedTrustState(id: string, problem: string): PiShipError {
  const path = trustStatePath(id);
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Update trust state ${path} ${problem}; refusing to update ${id}`,
    {
      component: "update",
      userAction: `Do not edit or delete it to get past this. Re-establish trust with a release you verify out of band: piship uninstall ${id} (state is kept), then piship install <release archive> --sha256 <published digest> --use-existing-state`,
      sanitizedDetail: { trustState: path, check: problem },
    },
  );
}

/**
 * Read and validate the trust state: `undefined` when there is none; a
 * damaged one (unreadable, wrong schema or distribution, invalid root, or a
 * digest that does not match the root) fails closed.
 */
export function readTrustState(id: string): UpdateTrustState | undefined {
  const path = trustStatePath(id);
  if (!existsSync(path)) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw damagedTrustState(
      id,
      `is damaged: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const value = (raw ?? {}) as Partial<Record<keyof UpdateTrustState, unknown>>;
  if (typeof raw !== "object" || Array.isArray(raw))
    throw damagedTrustState(id, "is not an object");
  if (value.schema !== TRUST_STATE_SCHEMA)
    throw damagedTrustState(id, `has schema ${String(value.schema)}`);
  if (value.distribution !== id)
    throw damagedTrustState(id, `does not record distribution ${id}`);
  if (
    value.origin !== "bootstrap" &&
    value.origin !== "legacy" &&
    value.origin !== "remote"
  )
    throw damagedTrustState(id, "records no valid origin");
  let root: UpdateRoot;
  try {
    root = parseUpdateRoot(value.root, "root");
  } catch (error) {
    throw damagedTrustState(
      id,
      `records an invalid root: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (value.digest !== rootDigest(root))
    throw damagedTrustState(
      id,
      "records a root that does not match its digest",
    );
  if (
    !Array.isArray(value.removedKeys) ||
    !value.removedKeys.every(
      (key: Partial<RemovedTrustKey> | null) =>
        !!key &&
        typeof key.id === "string" &&
        typeof key.fingerprint === "string" &&
        /^sha256:[a-f0-9]{64}$/.test(key.fingerprint) &&
        (key.role === "root" || key.role === "channel") &&
        Number.isSafeInteger(key.version),
    )
  )
    throw damagedTrustState(id, "records invalid removed keys");
  if (typeof value.updatedAt !== "string")
    throw damagedTrustState(id, "records no update time");
  return {
    schema: TRUST_STATE_SCHEMA,
    distribution: id,
    origin: value.origin,
    root,
    digest: value.digest,
    removedKeys: value.removedKeys as RemovedTrustKey[],
    updatedAt: value.updatedAt,
  };
}
