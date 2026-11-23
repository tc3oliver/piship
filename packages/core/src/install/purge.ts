// Purge: delete a distribution's PiShip-owned state after uninstall.
import {
  existsSync,
  readFileSync,
  readdirSync,
  rmSync,
  rmdirSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
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
  installHome,
  payloadApp,
  runtimeStateDirectory,
  shellArg,
  stateHome,
} from "../index.js";
import { readInstallReceipt, receiptPath } from "./receipt.js";

/**
 * Remove the directories PiShip created that the last uninstall or purge left
 * empty: `apps` and `receipts` in the install home, and the install and state
 * homes themselves when they are the defaults (a home the user chose through
 * PISHIP_INSTALL_HOME or PISHIP_STATE_HOME is theirs). rmdir removes only an
 * empty directory, so nothing with content is ever touched.
 */
export function removeEmptyPiShipDirectories(): void {
  const install = installHome();
  const own = [join(install, "apps"), join(install, "receipts")];
  if (install === resolve(homedir(), ".local", "share", "piship"))
    own.push(install);
  if (stateHome() === resolve(homedir(), ".piship")) own.push(stateHome());
  for (const directory of own)
    try {
      rmdirSync(directory);
    } catch {
      // Not empty, already gone, or in use: it stays.
    }
}

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
  /** Present when a local-secret API key was stored: purge deleted it. */
  readonly deletedApiKey?: true;
  /**
   * Present when the audit spool held events no collector had acknowledged:
   * they were deleted with the state, so they are lost to the collector.
   */
  readonly undeliveredAudit?: number;
}

/** Events a required HTTP audit sink spooled and has not delivered: one per line. */
export function undeliveredAuditEvents(state: string): number {
  const root = join(state, "logs", "audit-spool");
  let count = 0;
  try {
    for (const key of readdirSync(root))
      for (const name of readdirSync(join(root, key)))
        if (name.endsWith(".jsonl"))
          count += readFileSync(join(root, key, name), "utf8")
            .split("\n")
            .filter(Boolean).length;
  } catch {
    // No spool, or one that cannot be read: nothing to report.
  }
  return count;
}

export interface PurgeOptions {
  readonly secretStore?: SecretStore;
  /**
   * Purge a signed-in distribution without its `logout`, for a user who has
   * no release left to run it. What it holds is deleted locally but not
   * revoked.
   */
  readonly withoutLogout?: boolean;
  /** The running script, `process.argv[1]` by default, to name its release's logout. */
  readonly script?: string;
}

/** `signedInClasses` name of a local-secret key: nothing remote to revoke. */
export const STORED_API_KEY = "a stored API key";

/**
 * What in `state` an identity provider, credential broker, or sandbox service
 * could still honor: an identity session, a runtime credential, or a stored
 * sandbox credential. A discarded marker is already signed out, and a file
 * that does not parse names nothing `logout` could revoke. A local-secret
 * runtime credential is named STORED_API_KEY: it is only a local secret.
 */
export function signedInClasses(state: string): string[] {
  const paths = accessStatePaths(state);
  return (
    [
      [paths.identity, "an identity session"],
      [paths.credential, "a runtime credential"],
      [paths.sandboxCredential, "a sandbox credential"],
    ] as const
  ).flatMap(([path, name]) => {
    try {
      const { schema, mode } = JSON.parse(readFileSync(path, "utf8")) as {
        schema?: unknown;
        mode?: unknown;
      };
      if (typeof schema !== "string" || schema.includes("-discarded/"))
        return [];
      return [
        path === paths.credential && mode === "local-secret"
          ? STORED_API_KEY
          : name,
      ];
    } catch {
      return [];
    }
  });
}

/**
 * Whether `state` holds Pi's own sign-in: an `agent/auth.json` with at least
 * one stored API key or OAuth credential. Pi may leave the file as `{}`.
 */
export function piSignedIn(state: string): boolean {
  try {
    const data = JSON.parse(
      readFileSync(join(state, "agent", "auth.json"), "utf8"),
    ) as unknown;
    return (
      typeof data === "object" &&
      data !== null &&
      Object.values(data).some(
        (item) =>
          typeof item === "object" &&
          item !== null &&
          ["api_key", "oauth"].includes(
            (item as { type?: unknown }).type as string,
          ),
      )
    );
  } catch {
    return false;
  }
}

/**
 * Refuse, before anything is deleted, to purge a distribution that is still
 * signed in: purge revokes nothing, so its credentials would stay live at
 * the broker. `logout` is the way out; `withoutLogout` purges anyway and
 * returns what stays live. A stored local-secret API key is not refused:
 * purge deletes it and there is nothing remote to revoke.
 */
export function assertSignedOut(
  id: string,
  state: string,
  logout: string,
  options: PurgeOptions,
  uninstalling = false,
): string[] {
  const live = signedInClasses(state).filter((name) => name !== STORED_API_KEY);
  // A stored sandbox credential alone is cleared by `sandbox logout`, which
  // also works where sign-in is delegated to Pi and `logout` refuses.
  const step =
    live.length === 1 && live[0] === "a sandbox credential"
      ? logout.replace(/ logout$/, " sandbox logout")
      : logout;
  if (live.length && !options.withoutLogout)
    throw new Error(
      `${id} is still signed in (${live.join(", ")}). Purge deletes local state but revokes nothing, so the credential would stay live at the broker until it expires. Run ${step} first, then ${uninstalling ? "uninstall again; or add --without-logout to purge without signing out" : "purge again; with no release left to run logout, add --without-logout to purge anyway"}`,
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
  if (existsSync(receiptPath(id))) {
    let command = id;
    try {
      command = readInstallReceipt(id).app.command;
    } catch {
      // A damaged receipt still names the id; the id is the usual command.
    }
    throw new Error(
      `Uninstall ${id} before purging its state: run ${command} uninstall, or ${command} uninstall --purge --yes to do both`,
    );
  }
  const state = runtimeStateDirectory({ value: id });
  // The receipt is gone, so its command is only known to the release.
  const live = assertSignedOut(
    id,
    state,
    releaseLogout(id, options.script) ??
      "logout with the release's own command (node bin/<command> logout, in the directory that holds the release's piship.mjs)",
    options,
  );
  const key = signedInClasses(state).includes(STORED_API_KEY);
  const secrets = await deleteReferencedSecrets(id, state, options);
  const undelivered = undeliveredAuditEvents(state);
  rmSync(state, { recursive: true, force: true });
  return {
    state,
    deletedSecrets: secrets.deleted,
    ...(secrets.dropped.length ? { droppedSecrets: secrets.dropped } : {}),
    ...(live.length ? { notRevoked: live } : {}),
    ...(key ? { deletedApiKey: true } : {}),
    ...(undelivered ? { undeliveredAudit: undelivered } : {}),
  };
}

/**
 * `node <dir>/bin/<command> logout` when this purge runs from the piship.mjs
 * of a release of `id`: once the receipt is gone, that release's own command
 * is the one left that can sign out.
 */
export function releaseLogout(
  id: string,
  script: string | undefined = process.argv[1],
): string | undefined {
  if (!script || basename(script) !== "piship.mjs") return undefined;
  const directory = dirname(resolve(script));
  try {
    const app = payloadApp(directory);
    const command = join(directory, "bin", app.command);
    if (app.id === id && existsSync(command))
      return `node ${shellArg(command)} logout`;
  } catch {
    // Not a release payload: the generic instruction stands.
  }
  return undefined;
}

/**
 * The piship.mjs that can purge `id` once it is uninstalled, as a shell
 * argument: the extracted release directory it was installed from while that
 * still holds it, else a placeholder for the release or build. Read it before
 * the uninstall, which deletes the receipt that records the directory.
 */
export function purgeManager(id: string): string {
  let release: { readonly directory?: string } | undefined;
  try {
    const receipt = readInstallReceipt(id);
    release = receipt.releases.find(
      (item) => item.version === receipt.active,
    )?.release;
  } catch {
    // No readable receipt: the uninstall itself reports that.
  }
  const recorded =
    typeof release?.directory === "string"
      ? join(release.directory, "payload", "piship.mjs")
      : undefined;
  return recorded && existsSync(recorded)
    ? shellArg(recorded)
    : release
      ? "<release>/payload/piship.mjs"
      : `dist/${id}/piship.mjs`;
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
