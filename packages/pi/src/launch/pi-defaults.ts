// Pi's own runtime defaults that a branded distribution sets. Pi reads these
// from its settings and from environment variables, not from the SDK options
// PiShip passes, so they are applied here for every launch.
import { VERSION } from "@earendil-works/pi-coding-agent";

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
 * Pi's environment switches, set after a managed launch has removed every
 * inherited `PI_*` variable:
 * - no pi.dev version check and its "Run `pi update`" notice: a
 *   distribution's Pi changes only with a release of its own;
 * - no install telemetry;
 * - Pi's agent directory (its crash log and the `fd` and `rg` it downloads)
 *   in the distribution's state, never the user's `~/.pi/agent`;
 * - managed: offline, so Pi makes no request of its own (model catalog
 *   refresh, tool downloads) beside the declared endpoints.
 */
export function applyPiEnvironment(
  agentDir: string,
  mode: "managed" | "personal",
  env: NodeJS.ProcessEnv = process.env,
): void {
  env.PI_SKIP_VERSION_CHECK = "1";
  env.PI_TELEMETRY = "0";
  env.PI_CODING_AGENT_DIR = agentDir;
  if (mode === "managed") env.PI_OFFLINE = "1";
}
