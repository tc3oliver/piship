// A change of `credential.storage.provider` (file <-> system) between the
// active and the target release is a credential lifecycle transition, not
// schema-compatible state: identity and credential metadata hold references
// into the store that wrote them, which the other store cannot read.
import type { SecretStoreProvider } from "@piship/credentials";
import type { MigrationItem } from "./migration.js";

/**
 * A release's `credential.storage.provider`, as a migration check takes it;
 * nothing for a release without access configuration (whose lock predates
 * it, or that stores no credential).
 */
export function storageOf(lock: {
  readonly access?:
    | {
        readonly credential?: {
          readonly storage?: { readonly provider?: SecretStoreProvider };
        };
      }
    | undefined;
}): { readonly storage?: SecretStoreProvider } {
  const provider = lock.access?.credential?.storage?.provider;
  return provider === "file" || provider === "system"
    ? { storage: provider }
    : {};
}

/** The data classes whose references live in the configured secret store. */
const STORE_BOUND = new Set([
  "identity/session.json",
  "credentials-metadata/inference.json",
  "credentials-metadata/sandbox.json",
]);

/**
 * The storage transition of a switch, or undefined when the secret store
 * stays the same (or either release has no access configuration).
 */
export function storageTransition(
  from: SecretStoreProvider | undefined,
  to: SecretStoreProvider | undefined,
):
  | { readonly from: SecretStoreProvider; readonly to: SecretStoreProvider }
  | undefined {
  return from && to && from !== to ? { from, to } : undefined;
}

/** The notice a switch prints for a class it cleared because of `transition`. */
export function storageTransitionNotice(
  name: string,
  transition: {
    readonly from: SecretStoreProvider;
    readonly to: SecretStoreProvider;
  },
): string {
  return `${name} was cleared because the secret store changes from ${transition.from} to ${transition.to}: its secrets were deleted from the ${transition.from} store; sign in again`;
}

/**
 * Turn every present identity or credential class the target would keep
 * into `clear-and-reacquire` when the secret store changes: the switching
 * release, which reads the old store, revokes the runtime credential where
 * supported and deletes every reference from the old store (confirmed)
 * before activation, so the target never looks an old-store reference up in
 * its own store and signs in or reacquires. Classes already cleared, and
 * absent ones, are left as they are.
 */
export function applyStorageTransition(
  items: readonly MigrationItem[],
  from: SecretStoreProvider | undefined,
  to: SecretStoreProvider | undefined,
): MigrationItem[] {
  const transition = storageTransition(from, to);
  if (!transition) return [...items];
  return items.map((item) =>
    STORE_BOUND.has(item.path) &&
    item.current !== null &&
    (item.action === "keep" || item.action === "clear-and-reacquire")
      ? {
          ...item,
          verdict: "safe",
          action: "clear-and-reacquire",
          reason: `The secret store changes from ${transition.from} to ${transition.to}; the ${transition.to} store cannot read what the ${transition.from} store holds, so it is deleted from the ${transition.from} store before the switch and the target signs in or reacquires the credential`,
          storageTransition: transition,
        }
      : item,
  );
}

/**
 * Linux Secret Service values over 8000 characters have been stored as parts
 * behind a `chunks:<n>:<write>` primary since lock key `credentialIssuance`
 * (both v0.7). A target whose lock lacks that key predates the layout: it
 * would read the marker as the secret and delete only the primary, leaving
 * the parts. Every present store-bound class is therefore cleared by the
 * switching release, which reads the layout, before such a target activates;
 * the target signs in again. Other stores kept their layout.
 */
export function applySecretLayoutTransition(
  items: readonly MigrationItem[],
  storage: SecretStoreProvider | undefined,
  target: { readonly credentialIssuance?: readonly string[] },
  platform: NodeJS.Platform = process.platform,
): MigrationItem[] {
  if (
    storage !== "system" ||
    platform !== "linux" ||
    target.credentialIssuance !== undefined
  )
    return [...items];
  return items.map((item) =>
    STORE_BOUND.has(item.path) &&
    item.current !== null &&
    item.action === "keep"
      ? {
          ...item,
          verdict: "safe",
          action: "clear-and-reacquire",
          reason:
            "The target predates the Linux Secret Service layout that splits long secrets into parts, so its secrets are deleted before the switch and the target signs in or reacquires the credential",
        }
      : item,
  );
}
