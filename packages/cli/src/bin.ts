#!/usr/bin/env node
import { runCli } from "./index.js";

process.exitCode = runCli(process.argv.slice(2), {
  stdout: (message) => process.stdout.write(`${message}\n`),
  stderr: (message) => process.stderr.write(`${message}\n`),
});
