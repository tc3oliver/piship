// Purge: delete a distribution's PiShip-owned state after uninstall.
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { PiShipError, type SecretStore } from "@piship/contracts";
import {
  createSecretStore,
  deleteSecretsVerified,
  metadataFileSecretRefs,
  metadataFileSecretStore,
  metadataSecretRefs,
  secretStoreUnreachable,
  type UndeletedSecret,
  unconfirmedDiscardedRefs,
} from "@piship/credentials";
import { accessStatePaths } from "../access/index.js";
import {
  assertDisjointRoots,
  distributionStateDirectory,
  runtimeStateDirectory,
} from "../index.js";
import { receiptPath } from "./receipt.js";

export interface PurgeResult {
  /** The deleted state directory. */
  readonly state: string;
  /** Secret-store references that were deleted from the platform store. */
  readonly deletedSecrets: readonly string[];
  /**
   * Present when a discarded marker named references never confirmed
   * written whose secret store is not installed here: they were dropped
   * without deleting anything, as login and logout drop them.
   */
  readonly droppedSecrets?: readonly string[];
  /**
   * Present when a purge `withoutLogout` found the distribution signed in:
   * what it deleted locally without revoking, so it stays live at the
   * identity provider or broker until it expires.
   */
  readonly notRevoked?: readonly string[];
}

export interface PurgeOptions {
  readonly secretStore?: SecretStore;
  /**
   * Purge a signed-in distribution without its `logout`, for a user who has
   * no release left to run it. What it holds is deleted locally but not
   * revoked.
   */
  readonly withoutLogout?: boolean;
}

/**
 * What in `state` an identity provider, credential broker, or sandbox service
 * could still honor: an identity session, a runtime credential, or a stored
 * sandbox credential. A discarded marker is already signed out, and a file
 * that does not parse names nothing `logout` could revoke.
 */
export function signedInClasses(state: string): string[] {
  const paths = accessStatePaths(state);
  return (
    [
      [paths.identity, "an identity session"],
      [paths.credential, "a runtime credential"],
      [paths.sandboxCredential, "a sandbox credential"],
    ] as const
  )
    .filter(([path]) => {
      try {
        const { schema } = JSON.parse(readFileSync(path, "utf8")) as {
          schema?: unknown;
        };
        return typeof schema === "string" && !schema.includes("-discarded/");
      } catch {
        return false;
      }
    })
    .map(([, name]) => name);
}

/**
 * Refuse, before anything is deleted, to purge a distribution that is still
 * signed in: purge revokes nothing, so its credentials would stay live at
 * the broker. `logout` is the way out; `withoutLogout` purges anyway and
 * returns what stays live.
 */
export function assertSignedOut(
  id: string,
  state: string,
  logout: string,
  options: PurgeOptions,
): string[] {
  const live = signedInClasses(state);
  // A stored sandbox credential alone is cleared by `sandbox logout`, which
  // also works where sign-in is delegated to Pi and `logout` refuses.
  const step =
    live.length === 1 && live[0] === "a sandbox credential"
      ? logout.replace(/ logout$/, " sandbox logout")
      : logout;
  if (live.length && !options.withoutLogout)
    throw new Error(
      `${id} is still signed in (${live.join(", ")}). Purge deletes local state but revokes nothing, so the credential would stay live at the broker until it expires. Run ${step} first, then purge again; with no release left to run logout, add --without-logout to purge anyway`,
    );
  return live;
}

/**
 * Delete one distribution's PiShip-owned state after uninstall, including
 * the platform secret-store entries (identity token bundles, runtime
 * credentials, and the stored sandbox credential) that its metadata
 * references. Each metadata file (or
 * discarded marker) records which store holds its references: the platform
 * store's are deleted from it, and the file store's go with the state
 * directory, so a state left by a change of storage provider loses neither.
 * A file written before the store was recorded is taken to be the file
 * store's when that store holds any secret, as before. Every deletion is
 * confirmed; when a secret cannot be deleted this throws
 * SECRET_STORE_UNAVAILABLE and removes no state, so the metadata still names
 * the secret and a later purge retries it. A distribution that is still
 * signed in is refused before anything is deleted (see `assertSignedOut`).
 */
export async function purgeDistributionState(
  id: string,
  options: PurgeOptions = {},
): Promise<PurgeResult> {
  distributionStateDirectory({ value: id });
  assertDisjointRoots();
  if (existsSync(receiptPath(id)))
    throw new Error(
      `Uninstall ${id} before purging its state, or run uninstall ${id} --purge --yes`,
    );
  const state = runtimeStateDirectory({ value: id });
  // The receipt is gone, so its command is only known to the release.
  const live = assertSignedOut(
    id,
    state,
    "logout with the release's own command (node <release-dir>/payload/bin/<command> logout)",
    options,
  );
  const secrets = await deleteReferencedSecrets(id, state, options);
  rmSync(state, { recursive: true, force: true });
  return {
    state,
    deletedSecrets: secrets.deleted,
    ...(secrets.dropped.length ? { droppedSecrets: secrets.dropped } : {}),
    ...(live.length ? { notRevoked: live } : {}),
  };
}

/**
 * Delete, confirming each deletion, the platform secret-store entries that
 * the metadata in `state` references; the file store's go with the state
 * directory. Throws SECRET_STORE_UNAVAILABLE, deleting no state, when one
 * cannot be deleted. Returns the deleted references, and the `dropped` ones:
 * references of a discarded marker never confirmed written whose store is
 * not installed, as login and logout drop them (`unconfirmedDiscardedRefs`).
 * Kept, such a reference would make purge fail on every attempt.
 */
export async function deleteReferencedSecrets(
  id: string,
  state: string,
  options: { readonly secretStore?: SecretStore },
): Promise<{ deleted: string[]; dropped: string[] }> {
  const paths = accessStatePaths(state);
  // The restricted file fallback keeps its secrets under the state directory,
  // which is removed below; otherwise they live in the platform store.
  const fileFallback =
    existsSync(paths.secrets) && readdirSync(paths.secrets).length > 0;
  const refs = new Set<string>();
  const unconfirmed = new Set<string>();
  const confirmed = new Set<string>();
  for (const [path, refClass] of [
    [paths.identity, "identity"],
    [paths.credential, "inference"],
    [paths.sandboxCredential, "sandbox"],
  ] as const) {
    if (!existsSync(path)) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      parsed = undefined;
    }
    const recorded = metadataFileSecretStore(path);
    const platform =
      recorded === "system" || (recorded === undefined && !fileFallback);
    if (!platform) continue;
    const pending = unconfirmedDiscardedRefs(parsed);
    // A damaged file still names secrets in its text; they are deleted too.
    for (const ref of [
      ...metadataSecretRefs(parsed, id),
      ...metadataFileSecretRefs(path, id, refClass),
    ]) {
      refs.add(ref);
      (pending.has(ref) ? unconfirmed : confirmed).add(ref);
    }
  }
  const deleted: string[] = [];
  const dropped: string[] = [];
  if (refs.size) {
    const store =
      options.secretStore ??
      createSecretStore({ provider: "system", fileDirectory: paths.secrets });
    const sorted = [...refs].sort();
    const failures = await deleteSecretsVerified(store, sorted);
    const droppable = (item: UndeletedSecret) =>
      unconfirmed.has(item.ref) &&
      !confirmed.has(item.ref) &&
      secretStoreUnreachable(item.error);
    dropped.push(...failures.filter(droppable).map((item) => item.ref));
    const failed = failures.filter((item) => !droppable(item));
    if (failed.length)
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        `Could not delete ${failed.map((item) => `${item.ref} from the ${store.description} (${item.problem})`).join("; ")}; no state was removed, so the metadata still names ${failed.length > 1 ? "these secrets" : "this secret"}`,
        {
          component: "credential",
          userAction: `Unlock or repair the secret store, then run purge ${id} --yes again`,
          sanitizedDetail: { refs: failed.map((item) => item.ref) },
        },
      );
    deleted.push(...sorted.filter((ref) => !dropped.includes(ref)));
  }
  return { deleted, dropped };
}
