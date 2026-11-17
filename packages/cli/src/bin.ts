#!/usr/bin/env node
// The check runs before anything is imported: on an old Node the modules
// below fail with a stack trace instead of this message.
const [major = 0, minor = 0] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 19)) {
  console.error(
    `Node.js 22.19.0 or newer is required; this is ${process.version}. Install a current Node.js separately (nodejs.org); a Linux distribution's own nodejs package is often older.`,
  );
  process.exit(1);
}
const { runCli } = await import("./index.js");

process.exitCode = await runCli(process.argv.slice(2), {
  stdout: (message) => process.stdout.write(`${message}\n`),
  stderr: (message) => process.stderr.write(`${message}\n`),
});
