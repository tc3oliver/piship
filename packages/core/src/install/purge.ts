// Purge: delete a distribution's PiShip-owned state after uninstall.
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { redact, type SecretStore } from "@piship/contracts";
import { createSecretStore, metadataSecretRefs } from "@piship/credentials";
import { accessStatePaths } from "../access/index.js";
import { distributionStateDirectory, runtimeStateDirectory } from "../index.js";
import { receiptPath } from "./receipt.js";

export interface PurgeResult {
  /** The deleted state directory. */
  readonly state: string;
  /** Secret-store references that were deleted from the platform store. */
  readonly deletedSecrets: readonly string[];
  /** Secrets that could not be deleted; the rest of the state is still removed. */
  readonly problems: readonly string[];
}

/**
 * Delete one distribution's PiShip-owned state after uninstall, including
 * the platform secret-store entries (identity token bundles and runtime
 * credentials) that its metadata references. Secret deletion is best effort:
 * a failure is reported and the state directory is removed regardless.
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
  const problems: string[] = [];
  // The restricted file fallback keeps its secrets under the state directory,
  // which is removed below; otherwise they live in the platform store.
  const fileFallback =
    existsSync(paths.secrets) && readdirSync(paths.secrets).length > 0;
  if (refs.size && (options.secretStore || !fileFallback)) {
    const store =
      options.secretStore ??
      createSecretStore({ provider: "system", fileDirectory: paths.secrets });
    for (const ref of [...refs].sort())
      try {
        await store.delete(ref);
        deletedSecrets.push(ref);
      } catch (error) {
        problems.push(
          `Could not delete ${ref} from the ${store.description}: ${redact(error instanceof Error ? error.message : String(error))}`,
        );
      }
  }
  rmSync(state, { recursive: true, force: true });
  return { state, deletedSecrets, problems };
}
