import { randomBytes } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface AccessStatePaths {
  readonly identity: string;
  readonly credential: string;
  readonly preferences: string;
  readonly secrets: string;
}

export function accessStatePaths(stateDir: string): AccessStatePaths {
  return {
    identity: join(stateDir, "identity", "session.json"),
    credential: join(stateDir, "credentials-metadata", "inference.json"),
    preferences: join(stateDir, "config", "preferences.json"),
    secrets: join(stateDir, "secrets"),
  };
}

export function writeJsonAtomic(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  renameSync(temporary, path);
}
