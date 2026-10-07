import { statfsSync } from "node:fs";
import { PiShipError } from "@piship/contracts";

/** Free bytes an unprivileged user can write to the file system holding `path`. */
export function freeBytes(path: string): number | undefined {
  try {
    const { bavail, bsize } = statfsSync(path);
    const free = Number(bavail) * Number(bsize);
    return Number.isFinite(free) && free >= 0 ? free : undefined;
  } catch {
    return undefined;
  }
}

const mebibytes = (bytes: number) => `${Math.ceil(bytes / 1048576)} MiB`;

/**
 * Refuse, before extracting, an install that cannot fit: a half-written
 * payload on a full disk fails late with a raw ENOSPC. Best effort: where the
 * file system cannot say how much is free, it passes silently.
 */
export function assertFreeSpace(
  directory: string,
  neededBytes: number,
  free: number | undefined = freeBytes(directory),
): void {
  if (free === undefined || free >= neededBytes) return;
  throw new PiShipError(
    "CONFIG_UNAVAILABLE",
    `Not enough free disk space in ${directory}: the install needs about ${mebibytes(neededBytes)} and ${mebibytes(free)} is free`,
    {
      component: "install",
      userAction:
        "Free space on that disk, or set PISHIP_INSTALL_HOME to a directory on a disk with room and run the install again",
    },
  );
}

/**
 * A floor for extracting a release archive of `archiveBytes`: twice its size.
 * The payload is mostly compressed binaries, so it rarely grows much more;
 * a floor keeps this check from refusing an install that would have fit.
 */
export function extractionNeed(archiveBytes: number): number {
  return archiveBytes * 2;
}
