import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { PiShipError } from "@piship/contracts";
import type { DistributionId } from "./lock-schema.js";

export function distributionStateDirectory(id: DistributionId): string {
  if (!/^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(id.value))
    throw new Error(
      "Distribution id must contain lowercase letters, digits or hyphens",
    );
  return `.piship/${id.value}`;
}
export function stateHome(): string {
  return resolve(process.env.PISHIP_STATE_HOME ?? join(homedir(), ".piship"));
}
export function runtimeStateDirectory(
  id: DistributionId,
  home = stateHome(),
): string {
  distributionStateDirectory(id);
  return join(resolve(home), id.value);
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

/**
 * A path as the filesystem resolves it: the real path of its nearest
 * existing ancestor, with the rest appended. Symlinked roots compare equal,
 * and on the usually case-insensitive filesystems of macOS and Windows so
 * do paths that differ only in case.
 */
function canonical(path: string): string {
  let existing = resolve(path);
  const rest: string[] = [];
  while (!existsSync(existing) && dirname(existing) !== existing) {
    rest.unshift(basename(existing));
    existing = dirname(existing);
  }
  let real = existing;
  try {
    real = realpathSync.native(existing);
  } catch {
    /* compared as given */
  }
  const full = join(real, ...rest);
  return process.platform === "win32" || process.platform === "darwin"
    ? full.toLowerCase()
    : full;
}

function within(inner: string, outer: string): boolean {
  const path = relative(outer, inner);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}

/**
 * Refuse a layout in which PiShip's state, install, and bin homes are equal
 * or nested in one another, also through a symlink or a difference in case.
 * Uninstall removes `<install-home>/apps/<id>` and purge `<state-home>/<id>`
 * recursively, so an overlap would let uninstall delete state it keeps, or
 * purge delete another distribution's command or install.
 */
export function assertDisjointRoots(): void {
  const roots = [
    ["PISHIP_STATE_HOME", stateHome()],
    ["PISHIP_INSTALL_HOME", installHome()],
    ["PISHIP_BIN_HOME", binHome()],
  ] as const;
  for (let a = 0; a < roots.length; a += 1)
    for (let b = a + 1; b < roots.length; b += 1) {
      const [nameA, pathA] = roots[a] as (typeof roots)[number];
      const [nameB, pathB] = roots[b] as (typeof roots)[number];
      const realA = canonical(pathA);
      const realB = canonical(pathB);
      if (within(realA, realB) || within(realB, realA))
        throw new PiShipError(
          "CONFIG_INVALID",
          `${nameA} (${pathA}) and ${nameB} (${pathB}) overlap; PiShip's state, install, and bin homes must be separate directories, none inside another`,
          {
            userAction: `Point ${nameA}, ${nameB}, or both at separate directories and retry`,
          },
        );
    }
}
