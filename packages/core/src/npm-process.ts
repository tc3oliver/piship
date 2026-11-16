// npm runs under a small Node supervisor, because every npm call here is
// synchronous (spawnSync) and the caller cannot act while it waits. The
// supervisor starts npm in its own process group (POSIX; on Windows its own
// tree), and stops that whole group when the time limit passes, when it gets
// SIGINT, SIGTERM or SIGHUP, or when the PiShip process that started it is
// gone. So a hung `npm ci` neither hangs a build for ever nor outlives it.

const DEFAULT_MINUTES = 10;
const MAX_MINUTES = Math.floor((2 ** 31 - 1) / 60_000);
/** The supervisor's exit status when npm ran out of time. */
export const NPM_TIMED_OUT = 124;

/** `PISHIP_NPM_TIMEOUT_MINUTES`, else 10, at most 35791; a value that is not a positive number is ignored. */
export function npmTimeoutMinutes(
  env: NodeJS.ProcessEnv = process.env,
): number {
  const value = Number(env.PISHIP_NPM_TIMEOUT_MINUTES);
  // setTimeout fires at once past 2^31-1 ms (about 24.8 days), so cap there.
  return Number.isFinite(value) && value > 0
    ? Math.min(value, MAX_MINUTES)
    : DEFAULT_MINUTES;
}

/**
 * How long to wait for a supervised npm run elsewhere (the build's
 * background thread): a minute past npm's own limit, so the supervisor's
 * timeout is what ends a hung npm.
 */
export function npmWaitLimitMs(env: NodeJS.ProcessEnv = process.env): number {
  return (npmTimeoutMinutes(env) + 1) * 60_000;
}

const SUPERVISOR = `
const { spawn, spawnSync } = require("node:child_process");
const { writeSync } = require("node:fs");
const { file, args, minutes, parent } = JSON.parse(process.argv[1]);
const windows = process.platform === "win32";
const child = spawn(file, args, {
  stdio: ["inherit", "inherit", "pipe"],
  detached: !windows,
  windowsHide: true,
});
const stderr = [];
child.stderr.on("data", (chunk) => stderr.push(chunk));
const finish = (code, message) => {
  if (message) writeSync(2, message + "\\n");
  writeSync(2, Buffer.concat(stderr));
  process.exit(code);
};
const stop = (code, message) => {
  if (child.pid !== undefined) {
    if (windows)
      spawnSync("taskkill", ["/T", "/F", "/PID", String(child.pid)], { stdio: "ignore", windowsHide: true });
    else
      try { process.kill(-child.pid, "SIGKILL"); } catch {}
  }
  finish(code, message);
};
child.on("error", (error) => finish(1, error.message));
child.on("close", (code) => finish(code === null ? 1 : code));
setTimeout(() => stop(${NPM_TIMED_OUT},
  "npm timed out after " + minutes + " minute" + (minutes === 1 ? "" : "s") + " and was stopped; the npm registry may be unreachable. " +
  "Check the network or npm registry settings, or set PISHIP_NPM_TIMEOUT_MINUTES to allow longer."), minutes * 60000);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => stop(130));
const parentGone = () => {
  if (!windows && process.ppid !== parent) return true;
  try { process.kill(parent, 0); return false; } catch (error) { return error.code !== "EPERM"; }
};
setInterval(() => { if (parentGone()) stop(1); }, 500);
`;

/** `file args` wrapped in the supervisor, for spawnSync or a background process. */
export function supervisedNpm(
  file: string,
  args: readonly string[],
): { file: string; args: string[] } {
  return {
    file: process.execPath,
    args: [
      "-e",
      SUPERVISOR,
      JSON.stringify({
        file,
        args,
        minutes: npmTimeoutMinutes(),
        parent: process.pid,
      }),
    ],
  };
}
