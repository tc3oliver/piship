// Where a PiShip process reclaims the temporary directories a hard
// termination left. The rules (ownership marker, dead owner, lease, identity
// checked removal, what is never touched) live in `@piship/contracts` beside
// the code that creates the directories; this module names the roots each
// kind lives in, which starts sweep them, and which roots are swept at all.
//
// A marker is plain JSON that any process running as the user can write, so
// a sandboxed command can plant a directory with a forged marker in every
// directory it may write. Removal is built so such a directory can cost its
// forger nothing it could not delete itself (it never follows a link), but
// PiShip does not sweep a root a sandboxed command writes without being
// asked. What the profile lets a contained command write is `writeAllow`
// (packages/sandbox/src/profile.ts: the manifest's `filesystem.write.allow`,
// which takes `workspace`, `tmp`, `~`, or an absolute path, plus the session's
// extra writable paths) and a few device nodes; Seatbelt denies every other
// write (seatbelt.ts) and bubblewrap binds `/` read-only, with only that list
// writable and a private tmpfs over `/tmp` unless `/tmp` itself is listed
// (bubblewrap.ts). Root by root:
//
// - The OS temp directory, `piship-*` entries directly in it: swept at every
//   start. A session's `tmp`, the one place a contained command writes there,
//   is a level below its `piship-sandbox-*` directory, which it cannot write.
//   This holds unless the manifest itself lists the OS temp directory.
// - The install home (`.staging-*`) and `apps/<id>`: swept at start. The
//   installed payload is passed to the sandbox read-only, and nothing else
//   under the install home is in the allowlist unless the manifest lists it.
// - The output of `piship build` and `piship release` (`dist/`, its
//   `releases/`): not swept unless the user asks (`reclaimStaging`). They lie
//   in the project, which the sandbox is given to write, so this is the root a
//   contained command most plausibly writes. Their staging keeps its marker
//   beside the output it will be renamed into, and a build or release says
//   how many abandoned ones it found.
//
// Those claims rest on what a manifest lists, which PiShip does not control.
// On a system with a usable `rm` (GNU coreutils or a BSD, found at /bin/rm,
// /usr/bin/rm, or NixOS's /run/current-system/sw/bin/rm) removal does not rest
// on them: it never follows a link whatever a contained command does. Where
// there is none (Alpine's BusyBox, Windows) removal falls back to a path-based
// walk with a gap no such walk can close, and there the claims carry the
// safety: `--reclaim-staging` in a workspace-writable `dist/`, or a sweep of an
// OS temp directory that the manifest lists as writable, can be steered by a
// contained command that is still running. Windows has no native sandbox
// backend, so that case does not arise there.
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createTemporaryDirectory,
  findAbandonedTemporaryDirectories,
  LAUNCH_RECLAIM_BUDGET_MS,
  type ReclaimOptions,
  type ReclaimResult,
  reclaimTemporaryDirectories,
  type TemporaryDirectory,
  type TemporaryKind,
} from "@piship/contracts";
import { installHome } from "./state-paths.js";

/** Made under the OS temp directory. */
const OS_KINDS: readonly TemporaryKind[] = [
  "sandbox",
  "probe",
  "verify",
  "launch-check",
  "release-test",
];

/** The install home, and one distribution's `apps/<id>`. */
function installRoots(id: string | undefined): readonly string[] {
  return [installHome(), ...(id ? [join(installHome(), "apps", id)] : [])];
}

function merge(results: readonly ReclaimResult[]): ReclaimResult {
  const deferred = results.flatMap((result) => result.deferred ?? []);
  return {
    removed: results.flatMap((result) => result.removed),
    failed: results.flatMap((result) => result.failed),
    ...(deferred.length > 0 ? { deferred } : {}),
  };
}

/** The bound of a sweep: when to stop, on which clock. */
type SweepBound = Pick<ReclaimOptions, "deadline" | "monotonic">;

/**
 * Remove the abandoned sandbox, probe, verify, launch-check, and release-test
 * directories under the OS temp directory. Best effort, never throws.
 */
export function reclaimOsTemporaries(bound: SweepBound = {}): ReclaimResult {
  return reclaimTemporaryDirectories(tmpdir(), OS_KINDS, bound);
}

/**
 * Remove the abandoned `.staging-*` directories of an interrupted install or
 * update under the install home, and under `apps/<id>` when `id` is given (a
 * running update holds a live marker there, so it is never removed; the
 * update itself also removes everything unreferenced under the lifecycle
 * lock). Best effort, never throws.
 */
export function reclaimInstallTemporaries(
  id?: string,
  bound: SweepBound = {},
): ReclaimResult {
  return merge(
    installRoots(id).map((root) =>
      reclaimTemporaryDirectories(root, ["staging"], bound),
    ),
  );
}

/**
 * The sweep every launch runs, bounded by `LAUNCH_RECLAIM_BUDGET_MS` (a
 * removal that has started may run a moment longer): the OS temp directory,
 * the install home, and `apps/<id>`. The rules for what is abandoned are
 * those of every sweep. Returns a notice when some of the work was left for a
 * later start, and undefined otherwise. Best effort, never throws.
 */
export function reclaimLaunchTemporaries(
  id: string,
  options: {
    readonly budgetMs?: number;
    readonly monotonic?: () => number;
  } = {},
): string | undefined {
  const monotonic = options.monotonic ?? (() => performance.now());
  const budgetMs = options.budgetMs ?? LAUNCH_RECLAIM_BUDGET_MS;
  const bound: SweepBound = { deadline: monotonic() + budgetMs, monotonic };
  const result = merge([
    reclaimOsTemporaries(bound),
    reclaimInstallTemporaries(id, bound),
  ]);
  const left = result.deferred?.length ?? 0;
  if (left === 0) return undefined;
  return `PiShip left ${left} abandoned temporary ${left === 1 ? "directory" : "directories"} of earlier interrupted runs for a later start, so this one does not wait (it spends up to ${budgetMs / 1000} s removing them${result.removed.length > 0 ? ` and removed ${result.removed.length} now` : ""}). Each start removes more; doctor shows how many remain.`;
}

/**
 * A staging directory for an install (in the install home) or an update (in
 * `apps/<id>`): what a killed install or update left in the install home is
 * removed first, and the new one carries its owner's marker. The one call
 * both make.
 */
export function createStagingDirectory(parent: string): TemporaryDirectory {
  // Creation must not wait for recursive deletion of earlier payloads.
  // Explicit diagnostics and maintenance reclaim abandoned directories.
  return createTemporaryDirectory(parent, "staging");
}

/** What a build or release found in its output directory and left or failed to remove. */
export interface AbandonedStaging {
  /** The output directory the staging was found in. */
  readonly directory: string;
  /** How many abandoned staging directories are still there. */
  readonly count: number;
  /** False when removal was not asked for, true when it was tried and failed. */
  readonly attempted: boolean;
}

export interface OutputStagingOptions {
  /**
   * Remove the abandoned staging of killed builds or releases from the output
   * directory. The caller says the directory is one no sandboxed command can
   * write: it is not removed otherwise.
   */
  readonly reclaimStaging?: boolean;
  /** Told about abandoned staging that is still there, never with a path of it. */
  readonly abandonedStaging?: (found: AbandonedStaging) => void;
}

/**
 * What a build (`kind: "build"`, in `outputRoot`) or a release (`"release"`,
 * in the releases directory it is given, `<output>/releases`) does about the
 * staging directories of killed runs in its output directory: remove them
 * when asked to, and otherwise only report how many there are. Best effort,
 * never throws.
 */
export function sweepOutputStaging(
  outputRoot: string,
  kind: "build" | "release",
  options: OutputStagingOptions,
): void {
  if (options.reclaimStaging) reclaimTemporaryDirectories(outputRoot, [kind]);
  const count = findAbandonedTemporaryDirectories(outputRoot, [kind]).length;
  if (count > 0)
    options.abandonedStaging?.({
      directory: outputRoot,
      count,
      attempted: options.reclaimStaging === true,
    });
}

/**
 * How many abandoned directories are present now in the places a launch
 * sweeps. After the start-up sweep these are the ones that could not be
 * removed; read only, and never reported by path.
 */
export function abandonedTemporaryCount(id?: string): number {
  return (
    findAbandonedTemporaryDirectories(tmpdir(), OS_KINDS).length +
    installRoots(id).reduce(
      (sum, root) =>
        sum + findAbandonedTemporaryDirectories(root, ["staging"]).length,
      0,
    )
  );
}
