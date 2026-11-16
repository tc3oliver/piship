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
 * recent Portable E2E runs on each target (vitest's per-file time, with the
 * lifecycle fixtures already prebuilt), and the lifecycle fixtures its
 * scenarios use. A file missing here fails the unit test; a fixture missing
 * here is still built, but by the first scenario that needs it, while the
 * shard's other files compete for the cores. Last recorded from the five
 * passing runs 43760056234 to 43827367470 (2026-11-15/16).
 */
export const E2E_FILES: Readonly<Record<string, E2EFile>> = {
  "background-tasks": { seconds: { linux: 57, darwin: 103, win32: 29 } },
  cli: { seconds: { linux: 136, darwin: 184, win32: 147 } },
  "developer-profile": { seconds: { linux: 159, darwin: 323, win32: 125 } },
  governance: { seconds: { linux: 73, darwin: 126, win32: 57 } },
  headless: { seconds: { linux: 52, darwin: 95, win32: 71 } },
  "lifecycle-credentials": {
    seconds: { linux: 20, darwin: 18, win32: 39 },
    fixtures: ["demo"],
  },
  "lifecycle-install": {
    seconds: { linux: 7, darwin: 8, win32: 13 },
    fixtures: ["demo"],
  },
  "lifecycle-integrity": {
    seconds: { linux: 9, darwin: 9, win32: 13 },
    fixtures: ["demo"],
  },
  "lifecycle-rollback": {
    seconds: { linux: 17, darwin: 20, win32: 36 },
    fixtures: ["demo"],
  },
  "lifecycle-secret-store-file": {
    seconds: { linux: 29, darwin: 26, win32: 53 },
    fixtures: ["demo"],
  },
  "lifecycle-secret-store-system": {
    seconds: { linux: 37, darwin: 46, win32: 51 },
    fixtures: ["demo-system"],
    store: true,
  },
  "lifecycle-update": {
    seconds: { linux: 15, darwin: 18, win32: 30 },
    fixtures: ["demo"],
  },
  managed: { seconds: { linux: 44, darwin: 79, win32: 147 } },
  "managed-clean-machine": {
    seconds: { linux: 34, darwin: 36, win32: 88 },
    fixtures: ["demo-commands"],
    store: true,
  },
  network: { seconds: { linux: 38, darwin: 38, win32: 53 } },
  "personal-access-modes": { seconds: { linux: 42, darwin: 92, win32: 73 } },
  "personal-clean-machine-local": {
    seconds: { linux: 20, darwin: 21, win32: 34 },
    fixtures: ["personal-local"],
  },
  "personal-clean-machine-mypi": {
    seconds: { linux: 26, darwin: 23, win32: 34 },
    fixtures: ["personal"],
  },
  "personal-lifecycle": {
    seconds: { linux: 23, darwin: 18, win32: 30 },
    fixtures: ["personal"],
  },
  "personal-local-model": { seconds: { linux: 20, darwin: 37, win32: 16 } },
  "pack-update": { seconds: { linux: 71, darwin: 76, win32: 177 } },
  "pack-install": { seconds: { linux: 28, darwin: 33, win32: 117 } },
  "pi-packages": { seconds: { linux: 15, darwin: 24, win32: 16 } },
  "remote-workspace": { seconds: { linux: 44, darwin: 92, win32: 77 } },
  // Skipped on Windows, where the pack's shell rules need an enforced sandbox.
  "routine-pack": { seconds: { linux: 18, darwin: 37, win32: 2 } },
  "registry-gates": { seconds: { linux: 4, darwin: 5, win32: 8 } },
  "runtime-release": {
    seconds: { linux: 23, darwin: 34, win32: 70 },
    fixtures: ["demo"],
  },
  "sandbox-credential": { seconds: { linux: 28, darwin: 48, win32: 26 } },
  "security-controls": { seconds: { linux: 94, darwin: 107, win32: 143 } },
  "security-findings-session": {
    seconds: { linux: 28, darwin: 52, win32: 55 },
  },
  "security-lifecycle": {
    seconds: { linux: 25, darwin: 22, win32: 43 },
    fixtures: ["demo"],
  },
  "security-sandbox": { seconds: { linux: 45, darwin: 58, win32: 28 } },
  "security-sweep": { seconds: { linux: 105, darwin: 170, win32: 178 } },
  "shared-store": {
    seconds: { linux: 22, darwin: 32, win32: 30 },
    fixtures: ["personal"],
  },
  "stale-temporaries": { seconds: { linux: 20, darwin: 39, win32: 12 } },
  "user-switching-file": {
    seconds: { linux: 15, darwin: 15, win32: 33 },
    fixtures: ["demo"],
  },
  "user-switching-system": {
    seconds: { linux: 22, darwin: 23, win32: 39 },
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

/**
 * The fixtures global setup prebuilds: those of the files the run selected
 * (`selected`, the files a filename filter matched, or every file), split as
 * the sequencer splits them when `shard` is set. Undefined, meaning every
 * fixture, for a full run without a filter or shard, or when a filter
 * matched no file (a pattern this split cannot resolve builds as before).
 */
export function prebuildFixtures(
  all: readonly string[],
  selected: readonly string[] | undefined,
  shard: { readonly index: number; readonly count: number } | undefined,
  platform: NodeJS.Platform = process.platform,
): Set<LifecycleFixture> | undefined {
  if (selected?.length === 0) return undefined;
  if (!selected && !shard) return undefined;
  const files = selected ?? all;
  return e2eFixtures(
    shard ? e2eShard(files, shard.index, shard.count, platform) : files,
  );
}
