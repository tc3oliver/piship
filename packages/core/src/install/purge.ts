// Purge: delete a distribution's PiShip-owned state after uninstall.
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { PiShipError, type SecretStore } from "@piship/contracts";
import {
  createSecretStore,
  deleteSecretsVerified,
  metadataSecretRefs,
} from "@piship/credentials";
import { accessStatePaths } from "../access/index.js";
import { distributionStateDirectory, runtimeStateDirectory } from "../index.js";
import { receiptPath } from "./receipt.js";

export interface PurgeResult {
  /** The deleted state directory. */
  readonly state: string;
  /** Secret-store references that were deleted from the platform store. */
  readonly deletedSecrets: readonly string[];
  /**
   * Always empty: a secret that cannot be deleted now fails the purge before
   * any state is removed. Kept so existing callers still compile.
   */
  readonly problems: readonly string[];
}

/**
 * Delete one distribution's PiShip-owned state after uninstall, including
 * the platform secret-store entries (identity token bundles and runtime
 * credentials) that its metadata references. Every deletion is confirmed;
 * when a secret cannot be deleted this throws SECRET_STORE_UNAVAILABLE and
 * removes no state, so the metadata still names the secret and a later
 * purge retries it.
 */
export async function purgeDistributionState(
  id: string,
  options: { readonly secretStore?: SecretStore } = {},
): Promise<PurgeResult> {
  distributionStateDirectory({ value: id });
  if (existsSync(receiptPath(id)))
    throw new Error(`Uninstall ${id} before purging its state`);
  const state = runtimeStateDirectory({ value: id });
  const paths = accessStatePaths(state);
  const refs = new Set<string>();
  for (const path of [paths.identity, paths.credential])
    try {
      if (existsSync(path))
        for (const ref of metadataSecretRefs(
          JSON.parse(readFileSync(path, "utf8")),
          id,
        ))
          refs.add(ref);
    } catch {
      // Unreadable metadata names no secret; the file is removed below.
    }
  const deletedSecrets: string[] = [];
  // The restricted file fallback keeps its secrets under the state directory,
  // which is removed below; otherwise they live in the platform store.
  const fileFallback =
    existsSync(paths.secrets) && readdirSync(paths.secrets).length > 0;
  if (refs.size && (options.secretStore || !fileFallback)) {
    const store =
      options.secretStore ??
      createSecretStore({ provider: "system", fileDirectory: paths.secrets });
    const sorted = [...refs].sort();
    const failed = await deleteSecretsVerified(store, sorted);
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
    deletedSecrets.push(...sorted);
  }
  rmSync(state, { recursive: true, force: true });
  return { state, deletedSecrets, problems: [] };
}
