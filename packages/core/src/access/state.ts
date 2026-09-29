import { join } from "node:path";
import { writeFileAtomic } from "../install/atomic.js";

export interface AccessStatePaths {
  readonly identity: string;
  /** The principal that owns this state's user-scoped PiShip data. */
  readonly principal: string;
  readonly credential: string;
  /** Failed remote revocations, non-secret. */
  readonly revocationRetry: string;
  readonly preferences: string;
  readonly secrets: string;
}

export function accessStatePaths(stateDir: string): AccessStatePaths {
  return {
    identity: join(stateDir, "identity", "session.json"),
    principal: join(stateDir, "identity", "principal.json"),
    credential: join(stateDir, "credentials-metadata", "inference.json"),
    revocationRetry: join(
      stateDir,
      "credentials-metadata",
      "revocation-retry.json",
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
