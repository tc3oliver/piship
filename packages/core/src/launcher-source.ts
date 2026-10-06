import { createHash } from "node:crypto";

/**
 * A launcher names the build it was generated as: the first twelve hex
 * characters of the SHA-256 of its text with this placeholder in the build's
 * place. The stamp is a comment in the launcher and the value its
 * `PISHIP_DEBUG_TIMING` report prints, so a measurement shows which
 * launcher ran, and an installed launcher is current exactly when its text
 * is what the running PiShip would generate.
 */
export const LAUNCHER_BUILD_PLACEHOLDER = "@@LAUNCHER_BUILD@@";

export function stampLauncherBuild(template: string): string {
  const build = createHash("sha256")
    .update(template)
    .digest("hex")
    .slice(0, 12);
  return template.replaceAll(LAUNCHER_BUILD_PLACEHOLDER, build);
}

/** The build stamped into a launcher's text, if it carries one. */
export function launcherBuildOf(text: string): string | undefined {
  return /^\/\/ launcher-build: ([0-9a-f]{12})$/m.exec(text)?.[1];
}

/**
 * Phase marks for `PISHIP_DEBUG_TIMING=1`, written to the store
 * `@piship/contracts` reports from (startup-timing.ts) before any payload
 * module has loaded. With the variable unset `timing` is undefined and a
 * mark does nothing.
 */
export const LAUNCHER_TIMING_SNIPPET = `const timing = process.env.PISHIP_DEBUG_TIMING === "1" ? (globalThis[Symbol.for("piship.startup-timing")] ??= { marks: [], counters: {}, notes: {} }) : undefined;
const mark = (name) => { if (timing) timing.marks.push({ name, ms: performance.now() }); };
`;

/**
 * The built command. A launch error is printed through the shared redaction;
 * so is an error no await catches (an unhandled rejection, which Node raises
 * as an uncaught exception, or a throw from a callback), which then ends the
 * process with status 1 instead of Node printing it with its stack. Pi's
 * interactive mode installs its own crash handler ahead of this one while
 * its terminal UI runs, so that handler reports such an error there.
 * `@piship/pi/environment` runs before `@piship/pi` is imported, because Pi
 * reads some of its environment (its tool directory) when it is imported.
 */
export function launcherSource(): string {
  return stampLauncherBuild(`#!/usr/bin/env node
// launcher-build: ${LAUNCHER_BUILD_PLACEHOLDER}
import { fileURLToPath } from "node:url";
import { formatError } from "@piship/contracts";
import { verifyLaunchPayload } from "@piship/core";
${LAUNCHER_TIMING_SNIPPET}mark("node_entry");
if (timing) timing.notes.payload_launcher = "${LAUNCHER_BUILD_PLACEHOLDER}";
process.on("uncaughtException", (error) => { try { console.error(formatError(error)); } finally { process.exit(1); } });
const directory = fileURLToPath(new URL("..", import.meta.url));
try {
  const version = process.versions.node.split(".").map(Number);
  if (version[0] < 22 || (version[0] === 22 && version[1] < 19)) throw new Error("Node.js 22.19.0 or newer is required; install Node separately before launch");
  const metadata = verifyLaunchPayload(directory);
  mark("payload_checked");
  const { preparePiEnvironment } = await import("@piship/pi/environment");
  preparePiEnvironment(metadata.app.id);
  mark("pi_environment_ready");
  const { launchPiDistribution } = await import("@piship/pi");
  mark("pi_loaded");
  await launchPiDistribution({ distributionDir: directory, metadata, args: process.argv.slice(2) });
} catch (error) { console.error(formatError(error)); process.exitCode = 1; }
`);
}
export function portableCliSource(): string {
  return `const version = process.versions.node.split(".").map(Number);\nif (version[0] < 22 || (version[0] === 22 && version[1] < 19)) { console.error("Node.js 22.19.0 or newer is required. Install Node separately."); process.exitCode = 1; } else { const { runCli } = await import("@piship/cli"); process.exitCode = await runCli(process.argv.slice(2), { stdout: (message) => console.log(message), stderr: (message) => console.error(message) }); }\n`;
}
