import { join } from "node:path";
import { writeFileAtomic } from "@piship/credentials";

export interface AccessStatePaths {
  readonly identity: string;
  /** The principal that owns this state's user-scoped PiShip data. */
  readonly principal: string;
  readonly credential: string;
  /** The stored sandbox credential's metadata (`sandbox login`). */
  readonly sandboxCredential: string;
  /** Failed remote revocations, non-secret. */
  readonly revocationRetry: string;
  /** The runtime credential's unresolved acquire or renewal, non-secret. */
  readonly credentialIssuance: string;
  readonly preferences: string;
  readonly secrets: string;
}

export function accessStatePaths(stateDir: string): AccessStatePaths {
  return {
    identity: join(stateDir, "identity", "session.json"),
    principal: join(stateDir, "identity", "principal.json"),
    credential: join(stateDir, "credentials-metadata", "inference.json"),
    sandboxCredential: join(stateDir, "credentials-metadata", "sandbox.json"),
    revocationRetry: join(
      stateDir,
      "credentials-metadata",
      "revocation-retry.json",
    ),
    credentialIssuance: join(
      stateDir,
      "credentials-metadata",
      "pending-issuance.json",
    ),
    preferences: join(stateDir, "config", "preferences.json"),
    secrets: join(stateDir, "secrets"),
  };
}

/** Replace a state file atomically (see `writeFileAtomic`). */
export function writeJsonAtomic(path: string, value: unknown): void {
  writeFileAtomic(path, `${JSON.stringify(value, null, 2)}\n`, {
    directoryMode: 0o700,
  });
}
