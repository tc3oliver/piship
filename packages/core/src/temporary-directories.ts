// Where a PiShip process reclaims the temporary directories a hard
// termination left. The rules (ownership marker, dead owner, lease, what is
// never touched) live in `@piship/contracts` beside the code that creates the
// directories; this module names the roots each kind lives in and the starts
// that sweep them: the branded launcher, the commands that create such
// directories (`build`, `test`, `dev`, `release`, `verify-release`,
// `migrate-check`, `install`, `update`, `rollback`), and the sandbox
// activation, which sweeps its own kind.
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  findAbandonedTemporaryDirectories,
  reclaimTemporaryDirectories,
  type ReclaimResult,
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
 * Remove the abandoned `kind` staging directories beside a build or release
 * output (`outputRoot` for `build`, `<outputRoot>/releases` for `release`).
 * Best effort, never throws.
 */
export function reclaimBuildTemporaries(
  outputRoot: string,
  kind: "build" | "release",
): ReclaimResult {
  return reclaimTemporaryDirectories(outputRoot, [kind]);
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
