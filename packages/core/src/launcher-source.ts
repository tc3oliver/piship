/**
 * The built command. A launch error is printed through the shared redaction;
 * so is an error no await catches (an unhandled rejection, which Node raises
 * as an uncaught exception, or a throw from a callback), which then ends the
 * process with status 1 instead of Node printing it with its stack. Pi's
 * interactive mode installs its own crash handler ahead of this one while
 * its terminal UI runs, so that handler reports such an error there.
 */
export function launcherSource(): string {
  return `#!/usr/bin/env node\nimport { fileURLToPath } from "node:url";\nimport { formatError } from "@piship/contracts";\nimport { verifyPayload } from "@piship/core";\nprocess.on("uncaughtException", (error) => { try { console.error(formatError(error)); } finally { process.exit(1); } });\nconst directory = fileURLToPath(new URL("..", import.meta.url));\ntry {\n  const version = process.versions.node.split(".").map(Number);\n  if (version[0] < 22 || (version[0] === 22 && version[1] < 19)) throw new Error("Node.js 22.19.0 or newer is required; install Node separately before launch");\n  const metadata = verifyPayload(directory);\n  const { launchPiDistribution } = await import("@piship/pi");\n  await launchPiDistribution({ distributionDir: directory, metadata, args: process.argv.slice(2) });\n} catch (error) { console.error(formatError(error)); process.exitCode = 1; }\n`;
}
export function portableCliSource(): string {
  return `const version = process.versions.node.split(".").map(Number);\nif (version[0] < 22 || (version[0] === 22 && version[1] < 19)) { console.error("Node.js 22.19.0 or newer is required. Install Node separately."); process.exitCode = 1; } else { const { runCli } = await import("@piship/cli"); process.exitCode = await runCli(process.argv.slice(2), { stdout: (message) => console.log(message), stderr: (message) => console.error(message) }); }\n`;
}
