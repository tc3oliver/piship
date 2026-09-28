import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { DistributionId } from "./lock-schema.js";

export function distributionStateDirectory(id: DistributionId): string {
  if (!/^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(id.value))
    throw new Error(
      "Distribution id must contain lowercase letters, digits or hyphens",
    );
  return `.piship/${id.value}`;
}
export function runtimeStateDirectory(
  id: DistributionId,
  stateHome = process.env.PISHIP_STATE_HOME ?? join(homedir(), ".piship"),
): string {
  distributionStateDirectory(id);
  return join(resolve(stateHome), id.value);
}

export function installHome(): string {
  return resolve(
    process.env.PISHIP_INSTALL_HOME ??
      join(homedir(), ".local", "share", "piship"),
  );
}
export function binHome(): string {
  return resolve(
    process.env.PISHIP_BIN_HOME ?? join(homedir(), ".local", "bin"),
  );
}
