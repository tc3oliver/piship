import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";

// CI runs the unit tier of each target in shards, one runner each
// (`npm test -- --shard=<i>/<n>`). Vitest's own split deals files out by a
// hash of their path, but a few files take a minute and most under a second,
// so a hashed Windows shard ran 80 seconds longer than its sibling. This
// split balances the measured durations instead.

type Platform = "linux" | "darwin" | "win32";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));

/**
 * Every unit file by its path from the repository root: the median seconds
 * its tests took in recent CI runs on Ubuntu, macOS, and Windows, as Vitest
 * reports them per file (scripts/unit-durations.mjs). A file missing here is
 * still placed, with the median of the others.
 */
const DURATIONS: Readonly<Record<string, readonly [number, number, number]>> =
  JSON.parse(
    readFileSync(new URL("./unit-durations.json", import.meta.url), "utf8"),
  );

const COLUMN: Readonly<Record<Platform, 0 | 1 | 2>> = {
  linux: 0,
  darwin: 1,
  win32: 2,
};

/**
 * Seconds every file pays before its tests, which the per-file figures leave
 * out: Vitest's import time over the file count on each runner (about 145 s
 * for 279 files on Ubuntu, 110 s on macOS, 230 s on Windows).
 */
const IMPORT: Readonly<Record<Platform, number>> = {
  linux: 0.5,
  darwin: 0.4,
  win32: 0.8,
};

function platformOf(platform: NodeJS.Platform): Platform {
  return platform === "darwin" || platform === "win32" ? platform : "linux";
}

/** The key of a unit file in the durations: its path from the root, with `/`. */
export function unitFileKey(path: string): string {
  return relative(ROOT, path).replaceAll("\\", "/");
}

/** Seconds `path` is expected to take; a file without an entry, the median. */
export function unitSeconds(
  path: string,
  platform: NodeJS.Platform = process.platform,
): number {
  const target = platformOf(platform);
  const known = DURATIONS[unitFileKey(path)];
  if (known) return known[COLUMN[target]] + IMPORT[target];
  const all = Object.values(DURATIONS)
    .map((seconds) => seconds[COLUMN[target]])
    .sort((a, b) => a - b);
  return (all[Math.floor(all.length / 2)] ?? 0) + IMPORT[target];
}

/**
 * Shard `index` (1-based) of `count` of `paths`: files are placed longest
 * first, each on the shard with the fewest seconds so far. The split depends
 * only on the file names and the platform, so every shard of a target
 * computes the same one and each file lands in exactly one shard.
 */
export function unitShard(
  paths: readonly string[],
  index: number,
  count: number,
  platform: NodeJS.Platform = process.platform,
): string[] {
  const seconds = (path: string) => unitSeconds(path, platform);
  const key = (path: string) => unitFileKey(path);
  const ordered = [...paths].sort(
    (a, b) =>
      seconds(b) - seconds(a) ||
      (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0),
  );
  const shards = Array.from({ length: count }, () => ({
    paths: [] as string[],
    load: 0,
  }));
  for (const path of ordered) {
    const chosen = shards.reduce((best, shard) =>
      shard.load < best.load ? shard : best,
    );
    chosen.load += seconds(path);
    chosen.paths.push(path);
  }
  return shards[index - 1]?.paths ?? [];
}
