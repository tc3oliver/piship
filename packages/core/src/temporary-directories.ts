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
// Those claims rest on what a manifest lists, which PiShip does not control,
// so removal does not rest on them.
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createTemporaryDirectory,
  findAbandonedTemporaryDirectories,
  reclaimTemporaryDirectories,
  type ReclaimResult,
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
  return {
    removed: results.flatMap((result) => result.removed),
    failed: results.flatMap((result) => result.failed),
  };
}

/**
 * Remove the abandoned sandbox, probe, verify, launch-check, and release-test
 * directories under the OS temp directory. Best effort, never throws.
 */
export function reclaimOsTemporaries(): ReclaimResult {
  return reclaimTemporaryDirectories(tmpdir(), OS_KINDS);
}

/**
 * Remove the abandoned `.staging-*` directories of an interrupted install or
 * update under the install home, and under `apps/<id>` when `id` is given (a
 * running update holds a live marker there, so it is never removed; the
 * update itself also removes everything unreferenced under the lifecycle
 * lock). Best effort, never throws.
 */
export function reclaimInstallTemporaries(id?: string): ReclaimResult {
  return merge(
    installRoots(id).map((root) =>
      reclaimTemporaryDirectories(root, ["staging"]),
    ),
  );
}

/**
 * A staging directory for an install (in the install home) or an update (in
 * `apps/<id>`): what a killed install or update left in the install home is
 * removed first, and the new one carries its owner's marker. The one call
 * both make.
 */
export function createStagingDirectory(parent: string): TemporaryDirectory {
  reclaimInstallTemporaries();
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
