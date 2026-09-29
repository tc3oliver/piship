import { existsSync, readFileSync } from "node:fs";
import type { SecretStore } from "@piship/contracts";

/**
 * Which configured secret store holds a reference, as
 * `credential.storage.provider` names it: the restricted file store, or the
 * platform store.
 */
export type SecretStoreProvider = "file" | "system";

/**
 * Resolves the store for a provider other than the configured one, so that
 * references another store holds are deleted from that store; null (or a
 * throw) when it is not available here.
 */
export type SecretStoreResolver = (
  provider: SecretStoreProvider,
) => SecretStore | null;

/** The provider a store serves. */
export function secretStoreProvider(store: {
  readonly kind: string;
}): SecretStoreProvider {
  return store.kind === "file" ? "file" : "system";
}

/**
 * The secret store a metadata file or discarded marker records as holding
 * its references (`secret_store`). A file that parses answers with its
 * top-level field alone, so a nested key of the same name (a claim, say)
 * never picks the store; only a damaged file, which no longer parses, is
 * searched in its text. Undefined when none is recorded: such a file was
 * written, before the store was recorded, through the store of the release
 * that wrote it.
 */
export function recordedSecretStore(
  text: string,
): SecretStoreProvider | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    const match = /"secret_store"\s*:\s*"(file|system)"/.exec(text);
    return match?.[1] as SecretStoreProvider | undefined;
  }
  const recorded =
    typeof parsed === "object" && parsed !== null
      ? (parsed as { secret_store?: unknown }).secret_store
      : undefined;
  return recorded === "file" || recorded === "system" ? recorded : undefined;
}

/** `recordedSecretStore` of the file at `path`; undefined when there is none. */
export function metadataFileSecretStore(
  path: string,
): SecretStoreProvider | undefined {
  if (!existsSync(path)) return undefined;
  return recordedSecretStore(readFileSync(path, "utf8"));
}

/**
 * The store to delete references from that a file recorded for `recorded`:
 * the configured store when it is the same provider (or nothing is
 * recorded), otherwise the one `resolve` gives. Null when that store is not
 * available here, so the caller keeps the references tracked instead of
 * looking for them in a store that never held them.
 */
export function storeForRecorded(
  configured: SecretStore | null,
  configuredProvider: SecretStoreProvider,
  recorded: SecretStoreProvider | undefined,
  resolve: SecretStoreResolver | undefined,
): SecretStore | null {
  if (!recorded || recorded === configuredProvider) return configured;
  try {
    return resolve?.(recorded) ?? null;
  } catch {
    return null;
  }
}
