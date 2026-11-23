// Pi's own runtime defaults that a branded distribution sets. Pi reads these
// from its settings and from environment variables, not from the SDK options
// PiShip passes, so they are applied here for every launch.
import { lstatSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import {
  type CacheWarmingMode,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import { isWithin } from "@piship/sandbox";

/**
 * Settings for the in-memory `SettingsManager` of every session. The store is
 * new on each launch, so without `lastChangelogVersion` Pi takes every
 * session for a fresh install and reports it to pi.dev.
 */
export const PI_SETTINGS = {
  // No install or update report, and no provider attribution headers.
  enableInstallTelemetry: false,
  lastChangelogVersion: VERSION,
  // No Pi logo, Pi key hints, or Pi resource listing at startup.
  quietStartup: true,
  // The terminal's own scrollback, as before Pi 1.0 made fullscreen the default.
  tuiMode: "regular",
} as const;

/**
 * `PI_SETTINGS` with the session's cache warming mode. Pi's own default is
 * `streaming`; PiShip always writes the mode, so an omitted manifest mode
 * means `off`.
 */
export function piSettings(cacheWarming: CacheWarmingMode) {
  return { ...PI_SETTINGS, cacheWarming };
}

/**
 * Pi's environment switches, set after a managed launch has removed every
 * inherited `PI_*` variable:
 * - no pi.dev version check and its "Run `pi update`" notice: a
 *   distribution's Pi changes only with a release of its own;
 * - no install telemetry;
 * - Pi's agent directory (its crash log and the `fd` and `rg` it downloads)
 *   in the distribution's state, never the user's `~/.pi/agent`;
 * - managed: offline, so Pi makes no request of its own (model catalog
 *   refresh, tool downloads) beside the declared endpoints;
 * - jiti's transpile cache (see `jitiCacheDirectory`): off when `jitiCache`
 *   is false, and off when that directory is not this user's alone.
 */
export function applyPiEnvironment(
  agentDir: string,
  mode: "managed" | "personal",
  jitiCache: string | false,
  env: NodeJS.ProcessEnv = process.env,
): void {
  env.PI_SKIP_VERSION_CHECK = "1";
  env.PI_TELEMETRY = "0";
  env.PI_CODING_AGENT_DIR = agentDir;
  // jiti reads a cached file back after checking only a hash of the source,
  // so whoever can write the directory chooses the code that runs.
  env.JITI_RESPECT_TMPDIR_ENV = "1";
  if (jitiCache === false || !ownedPrivately(jitiCache))
    env.JITI_FS_CACHE = "false";
  if (mode === "managed") {
    env.PI_OFFLINE = "1";
    delete env.CLAUDE_CONFIG_DIR;
  }
}

/**
 * The directory Pi's extension loader caches transpiled TypeScript in: jiti's
 * default, `<os.tmpdir()>/jiti` (`JITI_RESPECT_TMPDIR_ENV` keeps it from
 * second-guessing TMPDIR). Pi creates jiti without a cache path, and jiti's
 * environment switches can only turn the cache on or off, so it cannot be
 * moved into the distribution's state without patching Pi.
 */
export function jitiCacheDirectory(): string {
  return join(tmpdir(), "jiti");
}

/** The `jitiCache` argument of `applyPiEnvironment` for a distribution's lock. */
export function jitiCacheFor(metadata: {
  readonly verifyAtLaunch?: boolean;
}): string | false {
  // Like the V8 compile cache: a cache is not verified.
  return metadata.verifyAtLaunch === true ? false : jitiCacheDirectory();
}

/**
 * Turn jiti's cache off when an enforced sandbox lets contained commands
 * write it: what they plant there would run, uncontained, in the next launch
 * or subagent child. The default sandbox temp is a per-session directory
 * beside it, not `<os.tmpdir()>` itself, so it keeps the cache.
 */
export function closeJitiCacheToSandbox(
  writeAllow: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): void {
  let dir = jitiCacheDirectory();
  try {
    dir = realpathSync(dir);
  } catch {
    // Not created yet: judge it by its parent's real path, since jiti creates
    // it there (macOS's tmpdir is a symlink into /private).
    try {
      dir = join(realpathSync(dirname(dir)), basename(dir));
    } catch {}
  }
  if (writeAllow.some((root) => isWithin(root, dir)))
    env.JITI_FS_CACHE = "false";
}

/**
 * Whether `dir` is a directory only this user can write, created 0700 when
 * missing: on Linux it is the shared `/tmp/jiti` another user may have made
 * first. Windows has no POSIX owner to compare, so there it must be under the
 * user's own profile (`LOCALAPPDATA` or `USERPROFILE`), as TEMP is by default.
 */
export function ownedPrivately(dir: string): boolean {
  if (process.platform === "win32") {
    // Real paths: TEMP often holds 8.3 short names (C:\Users\RUNNER~1).
    const real = (path: string) => {
      try {
        return realpathSync.native(path);
      } catch {
        return path;
      }
    };
    const parent = real(dirname(dir));
    const under = (root: string | undefined) => {
      if (!root) return false;
      const path = relative(real(root), parent);
      return !path.startsWith("..") && !isAbsolute(path);
    };
    if (!under(process.env.LOCALAPPDATA) && !under(process.env.USERPROFILE))
      return false;
  }
  try {
    mkdirSync(dir, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
  }
  if (process.platform === "win32") return true;
  try {
    const own = lstatSync(dir);
    const parent = statSync(dirname(dir));
    const uid = process.getuid?.();
    return (
      own.isDirectory() &&
      own.uid === uid &&
      (own.mode & 0o022) === 0 &&
      // Whoever can write the parent without the sticky bit can swap it.
      ((parent.mode & 0o022) === 0 || (parent.mode & 0o1000) !== 0) &&
      (parent.uid === uid || parent.uid === 0)
    );
  } catch {
    return false;
  }
}
