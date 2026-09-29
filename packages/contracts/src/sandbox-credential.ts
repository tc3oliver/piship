import type { SecretValue } from "./secret.js";

/**
 * Where a sandbox credential comes from: `stored`, a secret a person entered
 * with `<command> sandbox login`, kept in the secret store and bound to the
 * principal and the endpoint origins; `adapter`, a custom sandbox adapter's
 * `sandboxCredential` export, held in memory for one process.
 */
export type SandboxCredentialSource = "stored" | "adapter";
export type SandboxCredentialKind = "api_key" | "bearer";

/**
 * The sandbox credential as composed by core and pi for one session. Never a
 * value at construction: every request reads it, so rotation, rejection and a
 * principal change take effect at once.
 */
export interface SandboxCredentialAccess {
  readonly source: SandboxCredentialSource;
  readonly kind: SandboxCredentialKind;
  /** Origins (scheme://host:port) it may be sent to. */
  readonly origins: readonly string[];
  /**
   * The secret for one request. Rejects (SANDBOX_UNAVAILABLE) when absent,
   * rejected, or bound to another principal.
   */
  secret(signal?: AbortSignal): Promise<SecretValue>;
  /** The service answered 401/403 for this secret. */
  rejected(): Promise<void>;
}
