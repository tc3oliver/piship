import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Container logs of a test stack, kept for CI evidence only when
// PISHIP_REFERENCE_LOG_DIR names a directory (the reference E2E workflow sets
// it and uploads the directory when a run fails). The logs pass through
// scripts/scrub-logs.mjs first, which replaces every secret of the stack's env
// file and every key, token, and bearer shape; unscrubbed logs are never
// written.

const scrubber = fileURLToPath(
  new URL("../../scripts/scrub-logs.mjs", import.meta.url),
);

/** Where the logs go, or undefined when they are not kept. */
export const logDirectory = () =>
  process.env.PISHIP_REFERENCE_LOG_DIR || undefined;

/** Scrub `logs` with the secrets of `envFile` and write them as `<project>-<time>.log`. */
export function keepLogs(project: string, envFile: string, logs: string) {
  const directory = logDirectory();
  if (!directory) return;
  const scrubbed = spawnSync(
    process.execPath,
    [scrubber, "--env-file", envFile],
    { input: logs, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, `${project}-${Date.now()}.log`),
    scrubbed.status === 0
      ? scrubbed.stdout
      : `scrub-logs.mjs failed (exit ${scrubbed.status}); the logs were not kept\n`,
  );
}
