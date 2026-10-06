import { basename } from "node:path";

// Portable E2E runs the E2E files of each target in shards, one runner each
// (`npm run test:e2e -- --shard=<i>/<n>`). Vitest's own split deals files
// out by count, but these files differ tenfold in duration and several use
// release fixtures that take minutes to build on a hosted runner. This split
// balances the measured durations, counts the fixtures a shard has to build
// against it, and tells each shard which fixtures to prebuild.

/** A shared lifecycle release fixture (tests/helpers/lifecycle.ts). */
export type LifecycleFixture =
  | "demo"
  | "demo-system"
  | "demo-commands"
  | "personal"
  | "personal-local";

type Platform = "linux" | "darwin" | "win32";

interface E2EFile {
  /** Seconds on each Portable E2E target, beside the rest of its shard. */
  readonly seconds: Readonly<Record<Platform, number>>;
  readonly fixtures?: readonly LifecycleFixture[];
  /**
   * Its scenario uses the live platform store, which one scenario of a run
   * holds at a time (lifecycleScenario): such files wait for each other.
   */
  readonly store?: true;
}

/**
 * Every E2E file, by name without `.test.ts`: the median seconds it took in
 * recent Portable E2E runs on each target, and the lifecycle fixtures its
 * scenarios use. A file missing here fails the unit test; a fixture missing
 * here is still built, but by the first scenario that needs it, while the
 * shard's other files compete for the cores. managed-clean-machine has no
 * passing run yet: its figures are an estimate from personal-clean-machine.
 */
export const E2E_FILES: Readonly<Record<string, E2EFile>> = {
  cli: { seconds: { linux: 171, darwin: 110, win32: 241 } },
  // Estimated, not yet measured: a build of the developer example from its
  // committed lock, one more with a locked copy, and about a dozen launches.
  "developer-profile": { seconds: { linux: 260, darwin: 330, win32: 480 } },
  governance: { seconds: { linux: 54, darwin: 79, win32: 197 } },
  headless: { seconds: { linux: 59, darwin: 77, win32: 160 } },
  "lifecycle-credentials": {
    seconds: { linux: 122, darwin: 221, win32: 288 },
    fixtures: ["demo"],
  },
  "lifecycle-install": {
    seconds: { linux: 39, darwin: 65, win32: 90 },
    fixtures: ["demo"],
  },
  "lifecycle-integrity": {
    seconds: { linux: 48, darwin: 76, win32: 131 },
    fixtures: ["demo"],
  },
  "lifecycle-rollback": {
    seconds: { linux: 74, darwin: 130, win32: 179 },
    fixtures: ["demo"],
  },
  "lifecycle-secret-store-file": {
    seconds: { linux: 97, darwin: 169, win32: 250 },
    fixtures: ["demo"],
  },
  "lifecycle-secret-store-system": {
    seconds: { linux: 90, darwin: 180, win32: 260 },
    fixtures: ["demo-system"],
    store: true,
  },
  "lifecycle-update": {
    seconds: { linux: 64, darwin: 117, win32: 161 },
    fixtures: ["demo"],
  },
  managed: { seconds: { linux: 87, darwin: 106, win32: 252 } },
  "managed-clean-machine": {
    seconds: { linux: 120, darwin: 250, win32: 330 },
    fixtures: ["demo-commands"],
    store: true,
  },
  network: { seconds: { linux: 95, darwin: 121, win32: 197 } },
  "personal-access-modes": { seconds: { linux: 45, darwin: 52, win32: 125 } },
  "personal-clean-machine-local": {
    seconds: { linux: 104, darwin: 225, win32: 300 },
    fixtures: ["personal-local"],
  },
  "personal-clean-machine-mypi": {
    seconds: { linux: 117, darwin: 182, win32: 329 },
    fixtures: ["personal"],
  },
  "personal-lifecycle": {
    seconds: { linux: 95, darwin: 119, win32: 244 },
    fixtures: ["personal"],
  },
  "personal-local-model": { seconds: { linux: 22, darwin: 31, win32: 63 } },
  // Estimated from one darwin run (lock, build, install, launch); no fixtures.
  "pi-packages": { seconds: { linux: 90, darwin: 150, win32: 240 } },
  "sandbox-credential": { seconds: { linux: 34, darwin: 43, win32: 93 } },
  "security-controls": { seconds: { linux: 126, darwin: 149, win32: 385 } },
  "security-findings-session": {
    seconds: { linux: 23, darwin: 32, win32: 49 },
  },
  "security-lifecycle": {
    seconds: { linux: 165, darwin: 267, win32: 429 },
    fixtures: ["demo"],
  },
  "security-sandbox": { seconds: { linux: 38, darwin: 48, win32: 95 } },
  "security-sweep": { seconds: { linux: 110, darwin: 128, win32: 297 } },
  // Estimated, not yet measured: the personal fixtures, one install, update,
  // rollback, and three doctors with a store, and an install without one.
  "shared-store": {
    seconds: { linux: 60, darwin: 90, win32: 150 },
    fixtures: ["personal"],
  },
  "stale-temporaries": { seconds: { linux: 18, darwin: 24, win32: 40 } },
  "user-switching-file": {
    seconds: { linux: 80, darwin: 158, win32: 190 },
    fixtures: ["demo"],
  },
  "user-switching-system": {
    seconds: { linux: 150, darwin: 200, win32: 250 },
    fixtures: ["demo-system"],
    store: true,
  },
};

/** Releases and builds (`piship release`, `piship build`) of each fixture. */
const FIXTURE_BUILDS: Readonly<Record<LifecycleFixture, number>> = {
  demo: 3,
  "demo-system": 2,
  "demo-commands": 2,
  personal: 2,
  "personal-local": 2,
};

/**
 * What one fixture build costs a shard, in the seconds of the files: the
 * prebuild runs before any file starts, so each build takes its time (about
 * 9 s on Ubuntu, 33 s on macOS, 23 s on Windows when they all build at once)
 * from every one of the runner's cores (4, 3, and 4).
 */
const FIXTURE_BUILD_COST: Readonly<Record<Platform, number>> = {
  linux: 36,
  darwin: 99,
  win32: 92,
};

function platformOf(platform: NodeJS.Platform): Platform {
  return platform === "darwin" || platform === "win32" ? platform : "linux";
}

/** The key of an E2E file in E2E_FILES: its name without `.test.ts`. */
export function e2eFileKey(path: string): string {
  return basename(path).replace(/\.test\.ts$/, "");
}

/** Orders E2E files by key, the same on every platform and locale. */
export function byKey(a: string, b: string): number {
  const [x, y] = [e2eFileKey(a), e2eFileKey(b)];
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Seconds `path` is expected to take; a file without an entry, the median. */
export function e2eSeconds(
  path: string,
  platform: NodeJS.Platform = process.platform,
): number {
  const target = platformOf(platform);
  const known = E2E_FILES[e2eFileKey(path)];
  if (known) return known.seconds[target];
  const all = Object.values(E2E_FILES)
    .map((file) => file.seconds[target])
    .sort((a, b) => a - b);
  return all[Math.floor(all.length / 2)] ?? 0;
}

/** The lifecycle fixtures the scenarios in `paths` use. */
export function e2eFixtures(paths: readonly string[]): Set<LifecycleFixture> {
  return new Set(
    paths.flatMap((path) => E2E_FILES[e2eFileKey(path)]?.fixtures ?? []),
  );
}

/**
 * Shard `index` (1-based) of `count` of `paths`, the longest file first.
 * Files are placed longest first, each on the shard it finishes soonest,
 * counting the fixtures it would add there; files that wait for the live
 * platform store are spread over the shards. The split depends only on the
 * file names and the platform, never on the runner, so every shard of a
 * target computes the same one and each file lands in exactly one shard.
 */
export function e2eShard(
  paths: readonly string[],
  index: number,
  count: number,
  platform: NodeJS.Platform = process.platform,
): string[] {
  const target = platformOf(platform);
  const seconds = (path: string) => e2eSeconds(path, platform);
  const ordered = [...paths].sort(
    (a, b) => seconds(b) - seconds(a) || byKey(a, b),
  );
  const store = (path: string) => E2E_FILES[e2eFileKey(path)]?.store === true;
  const storesPerShard = Math.ceil(ordered.filter(store).length / count);
  const shards = Array.from({ length: count }, () => ({
    paths: [] as string[],
    load: 0,
    fixtures: new Set<LifecycleFixture>(),
    stores: 0,
  }));
  for (const path of ordered) {
    const fixtures = E2E_FILES[e2eFileKey(path)]?.fixtures ?? [];
    const cost = (shard: (typeof shards)[number]) =>
      shard.load +
      seconds(path) +
      fixtures
        .filter((fixture) => !shard.fixtures.has(fixture))
        .reduce(
          (sum, fixture) =>
            sum + FIXTURE_BUILDS[fixture] * FIXTURE_BUILD_COST[target],
          0,
        );
    const open = shards.filter(
      (shard) => !store(path) || shard.stores < storesPerShard,
    );
    const chosen = open.reduce((best, shard) =>
      cost(shard) < cost(best) ? shard : best,
    );
    chosen.load = cost(chosen);
    chosen.paths.push(path);
    if (store(path)) chosen.stores++;
    for (const fixture of fixtures) chosen.fixtures.add(fixture);
  }
  return shards[index - 1]?.paths ?? [];
}
