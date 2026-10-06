// The installed launcher: `apps/<id>/launch.mjs`, what the command shim runs.
import {
  chmodSync,
  existsSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  IMPORT_META_URL,
  LAUNCHER_BUILD_PLACEHOLDER,
  LAUNCHER_TIMING_SNIPPET,
  launcherBuildOf,
  stampLauncherBuild,
} from "../launcher-source.js";
import { START_TOLERANCE_MS } from "../process-identity.js";
import { appDirectory, readInstallReceipt, VERSION_NAME } from "./receipt.js";

/**
 * The text of `apps/<id>/launch.mjs`, the file the command shim runs: it
 * registers the launch under the gate, resolves the active release from the
 * receipt, and hands over to the release's own launcher. It is generated
 * here only, at install and whenever `refreshInstalledLauncher` finds the
 * installed copy differs, so what a user runs is always what this PiShip
 * would write.
 */
export function launcherSource(id: string): string {
  return stampLauncherBuild(`// PiShip launcher for ${id}: runs the active release named by the install receipt.
// launcher-build: ${LAUNCHER_BUILD_PLACEHOLDER}
import { readFileSync, realpathSync, mkdirSync, writeFileSync, rmSync, lstatSync, renameSync, linkSync, readlinkSync, existsSync, utimesSync } from "node:fs";
import { enableCompileCache } from "node:module";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { hostname, homedir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
${LAUNCHER_TIMING_SNIPPET}mark("launcher_start");
if (timing) timing.notes.installed_launcher = "${LAUNCHER_BUILD_PLACEHOLDER}";
// Node resolves this module to its real path, while the receipt records the
// install path as configured (on macOS /var is a symlink to /private/var).
// Both sides are canonicalized before comparing; a missing payload or one
// outside this directory still fails closed.
const home = dirname(fileURLToPath(${IMPORT_META_URL}));
const gatePath = join(home, "..", "..", "receipts", ${JSON.stringify(`.${id}.launch.lock`)});
// The gate and launching records name this process as a runtime lease and the
// lifecycle lock do. These helpers mirror @piship/core (process-identity.ts
// and processHostToken), which the launcher cannot load before it holds the
// gate: the start identity (the boot ID and start ticks on Linux, UTC start
// ticks on Windows, UTC start seconds elsewhere), the host token, and the
// start time. A launcher reads its own start identity only on Linux, where
// that costs no process start; elsewhere its start time stands in for it.
const identityOf = (pid) => {
  try {
    if (process.platform === "linux") {
      const stat = readFileSync("/proc/" + pid + "/stat", "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      return fields[19] ? readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() + ":" + fields[19] : null;
    }
    if (timing) timing.counters.identity_spawns = (timing.counters.identity_spawns ?? 0) + 1;
    if (process.platform === "win32") {
      const value = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "(Get-Process -Id " + pid + " -ErrorAction Stop).StartTime.ToUniversalTime().Ticks"], { encoding: "utf8", timeout: 5000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] }).trim();
      return /^\\d+$/.test(value) ? value : null;
    }
    const value = execFileSync("ps", ["-p", String(pid), "-o", "lstart="], { encoding: "utf8", timeout: 5000, env: { ...process.env, TZ: "UTC0", LC_ALL: "C" }, stdio: ["ignore", "pipe", "ignore"] }).trim();
    const match = /^\\w{3} (\\w{3}) +(\\d{1,2}) (\\d{2}):(\\d{2}):(\\d{2}) (\\d{4})$/.exec(value);
    const month = match ? "JanFebMarAprMayJunJulAugSepOctNovDec".indexOf(match[1]) : -1;
    if (!match || month < 0 || month % 3) return null;
    return String(Date.UTC(Number(match[6]), month / 3, Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5])) / 1000);
  } catch { return null; }
};
const startMs = (identity) =>
  !/^\\d+$/.test(identity) || process.platform === "linux" ? null
  : process.platform === "win32" ? Number(BigInt(identity) / 10000n) - 62135596800000
  : Number(identity) * 1000;
let namespace = "";
try { namespace = readlinkSync("/proc/self/ns/pid"); } catch {}
const host = createHash("sha256").update(hostname() + "\\0" + namespace).digest("hex").slice(0, 12);
const self = { pid: process.pid, identity: process.platform === "linux" ? identityOf(process.pid) : null, host, started: Math.round(performance.timeOrigin) };
const gateRecord = JSON.stringify({ schema: "piship-lifecycle-lock/v1", ...self, instance: randomUUID() }) + "\\n";
const alive = (pid) => {
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === "EPERM"; }
};
// Whether the process a record names is gone: true when proven, false when it
// is the same running process, null when that cannot be told (another host's
// record, or a record of an earlier PiShip that names only a process ID).
const gone = (record) => {
  if (record.host !== null && record.host !== host) return null;
  // A launcher takes the gate by creating it, so a record that names this
  // process's own ID is a dead process's, whose ID this one was given.
  if (record.pid === process.pid) return true;
  if (!alive(record.pid)) return true;
  if (record.identity === null && record.started === null) return null;
  const current = identityOf(record.pid);
  if (current === null) return null;
  if (record.identity !== null) {
    if (record.identity === current) return false;
    if (process.platform === "linux" || process.platform === "win32" || /^\\d+$/.test(record.identity)) return true;
  }
  if (record.started === null) return null;
  const start = startMs(current);
  return start === null ? null : Math.abs(start - record.started) > ${START_TOLERANCE_MS};
};
// The gate is judged as the lifecycle lock is: a holder that is gone (killed
// before its exit handler ran, or whose process ID an unrelated process took
// after a crash or a reboot) is stale at once, the same running holder never,
// and one that cannot be judged (another host's) only after 24 hours without
// a refresh. A live holder is waited for briefly.
const gateHolder = () => {
  let stat;
  try { stat = lstatSync(gatePath); } catch { return undefined; }
  let raw = null;
  try { raw = readFileSync(gatePath, "utf8"); } catch (error) { if (error.code === "ENOENT") return undefined; }
  let record = {};
  if (raw !== null && /^\\d+$/.test(raw.trim())) record = { pid: Number(raw.trim()) };
  else try {
    const value = JSON.parse(raw ?? "");
    if (value.schema === "piship-lifecycle-lock/v1" && typeof value.instance === "string") record = value;
  } catch {}
  return {
    raw,
    pid: Number.isSafeInteger(record.pid) && record.pid > 0 ? record.pid : null,
    identity: typeof record.identity === "string" && record.identity.length <= 128 ? record.identity : null,
    host: typeof record.host === "string" && /^[0-9a-f]{12}$/.test(record.host) ? record.host : null,
    started: Number.isSafeInteger(record.started) ? record.started : null,
    mtimeMs: stat.mtimeMs,
    regular: stat.isFile(),
  };
};
// A holder's verdict is read once per record: on Windows each read of a
// process start is a PowerShell start.
const verdicts = new Map();
const gateStale = (holder) => {
  const age = Date.now() - holder.mtimeMs;
  if (!holder.regular) return false;
  if (holder.raw === null) return age > 86400000;
  if (holder.raw === "") return age > 5000;
  if (holder.pid === null) return true;
  if (!verdicts.has(holder.raw)) verdicts.set(holder.raw, gone(holder));
  return verdicts.get(holder.raw) ?? age > 86400000;
};
// Moved aside under a unique name first, so only one launcher removes it; a
// gate that turned out to be another one is put back.
const breakGate = (observed) => {
  const aside = gatePath + ".p" + process.pid + "-" + randomUUID() + ".stale";
  try { renameSync(gatePath, aside); } catch { return; }
  try {
    const raw = readFileSync(aside, "utf8");
    if (raw !== observed.raw) linkSync(aside, gatePath);
  } catch {}
  try { rmSync(aside, { force: true }); } catch {}
};
const describeHolder = (holder) =>
  holder.raw === null ? "a holder whose record cannot be read"
  : holder.raw === "" ? "a holder still writing its record"
  : holder.pid === null ? "an unknown holder"
  : "process " + holder.pid + (holder.host !== null && holder.host !== host ? " on another host" : "");
const gateDeadline = Date.now() + 500;
for (;;) {
  try {
    writeFileSync(gatePath, gateRecord, { flag: "wx", mode: 0o600 });
    break;
  } catch (error) {
    // Only an existing gate is contention; anything else (EACCES, ENOSPC,
    // EROFS) is reported as it is, since retrying cannot help.
    if (error.code !== "EEXIST") {
      console.error(${JSON.stringify(`Could not register a launch of ${id}: `)} + error.message);
      process.exit(1);
    }
    const holder = gateHolder();
    if (Date.now() > gateDeadline) {
      console.error(${JSON.stringify(`A launcher or lifecycle operation for ${id} is registering: `)} + gatePath + " is held by " + (holder ? describeHolder(holder) : "another launcher") + ". Retry when it finishes; if no launcher or PiShip command is running, remove that file.");
      process.exit(1);
    }
    if (holder && gateStale(holder)) breakGate(holder);
    else if (holder) await new Promise((resolve) => setTimeout(resolve, 25));
  }
}
mark("gate_acquired");
const clearGate = () => {
  try { if (readFileSync(gatePath, "utf8") === gateRecord) rmSync(gatePath, { force: true }); } catch {}
};
process.on("exit", clearGate);
const launchingDir = join(home, ".runtime-leases", ".launching");
mkdirSync(launchingDir, { recursive: true, mode: 0o700 });
const launching = join(launchingDir, randomUUID() + ".json");
writeFileSync(launching, JSON.stringify({ schema: "piship-launching-lease/v1", ...self }) + "\\n", { flag: "wx", mode: 0o600 });
const clearLaunching = () => { try { rmSync(launching, { force: true }); } catch {} };
process.on("exit", clearLaunching);
let payload;
let command;
let version;
try {
  const receipt = JSON.parse(readFileSync(join(home, "..", "..", "receipts", ${JSON.stringify(`${id}.json`)}), "utf8"));
  const release = receipt.releases.find((item) => item.version === receipt.active);
  command = receipt.app.command;
  if (
    release &&
    ${VERSION_NAME.toString()}.test(release.version) &&
    /^[a-z][a-z0-9-]*$/.test(command) &&
    realpathSync(release.payload) === realpathSync(join(home, release.version))
  )
    { payload = realpathSync(release.payload); version = release.version; }
} catch {}
if (!payload) {
  console.error(${JSON.stringify(`The ${id} install receipt is missing or damaged; reinstall ${id}.`)});
  process.exit(1);
}
mark("receipt_resolved");
// The lease: this process holds the release it resolved until it exits. It
// is written here, under the gate and before the runtime loads, with the
// record holdRuntimeLease in @piship/core writes, so the gate is held for the
// milliseconds registration takes, not for the time a cold load of the
// runtime can (a second launch waits half a second for it, and a lifecycle
// operation three seconds). The gate is released as soon as the lease stands
// in the launching marker's place; until the process exits the lease keeps
// the release from being removed.
const leaseInstance = randomUUID();
const leaseDirectory = join(home, ".runtime-leases", version);
mkdirSync(leaseDirectory, { recursive: true, mode: 0o700 });
const leasePath = join(leaseDirectory, leaseInstance + ".json");
const leaseBytes = JSON.stringify({ schema: "piship-runtime-lease/v1", ...self, instance: leaseInstance, version }) + "\\n";
writeFileSync(leasePath, leaseBytes, { flag: "wx", mode: 0o600 });
const leaseBeat = setInterval(() => { try { const now = new Date(); utimesSync(leasePath, now, now); } catch {} }, 15000);
leaseBeat.unref();
process.on("exit", () => {
  clearInterval(leaseBeat);
  try { if (readFileSync(leasePath, "utf8") === leaseBytes) rmSync(leasePath, { force: true }); } catch {}
});
mark("lease_held");
if (readFileSync(gatePath, "utf8") !== gateRecord) throw new Error("Launcher registration lock was lost");
clearLaunching();
process.removeListener("exit", clearLaunching);
clearGate();
process.removeListener("exit", clearGate);
mark("gate_released");
// A bundled payload is a few large files, so what V8 compiled of them is kept
// in the distribution's state directory and read back at the next start. Only
// once that directory exists: a launch creates it after checking the install,
// state and bin roots do not overlap, and a first launch writes nothing there
// before that check. Never for a distribution whose lock asks for launch
// verification (runtime.verifyAtLaunch: true): a cache in state is not
// verified, and a lock that cannot be read counts as asking. Node ignores the
// call when NODE_DISABLE_COMPILE_CACHE is set.
const verifiesAtLaunch = (directory) => {
  try { return /"verifyAtLaunch":\\s*true/.test(readFileSync(join(directory, "piship.lock"), "utf8")); } catch { return true; }
};
const stateRoot = join(resolve(process.env.PISHIP_STATE_HOME ?? join(homedir(), ".piship")), ${JSON.stringify(id)});
try {
  if (existsSync(join(payload, "metadata", "bundle.json")) && existsSync(stateRoot) && !verifiesAtLaunch(payload)) {
    const cacheDir = join(stateRoot, "cache", "compile");
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    enableCompileCache(cacheDir);
  }
} catch {}
// A bundled core shares its module with Pi. Set Pi's public environment
// before importing it, just as the payload launcher does before boot.
process.env.PI_CODING_AGENT_DIR = join(stateRoot, "agent");
process.env.PI_PACKAGE_DIR = join(payload, "node_modules", "@earendil-works", "pi-coding-agent");
mark("launcher_handoff");
await import(pathToFileURL(join(payload, "bin", command)).href);
`);
}

/** The installed launcher's path for a distribution. */
export function installedLauncherPath(id: string): string {
  return join(appDirectory(id), "launch.mjs");
}

/** What is installed as a distribution's launcher, compared with what this PiShip generates. */
export interface InstalledLauncher {
  /** The build the installed text names; undefined for a launcher before builds were stamped. */
  readonly build: string | undefined;
  /** The build this PiShip generates. */
  readonly expected: string;
  readonly current: boolean;
}

/** Whether a file is a launcher PiShip wrote for this distribution. */
function isOurs(text: string, id: string): boolean {
  return text.startsWith(`// PiShip launcher for ${id}: `);
}

/**
 * The state of the installed launcher, or undefined when there is none or it
 * is not one PiShip wrote for this distribution (it is then left alone).
 */
export function inspectInstalledLauncher(
  id: string,
): InstalledLauncher | undefined {
  const path = installedLauncherPath(id);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  if (!isOurs(text, id)) return undefined;
  const expected = launcherSource(id);
  return {
    build: launcherBuildOf(text),
    expected: launcherBuildOf(expected) as string,
    current: text === expected,
  };
}

/**
 * Replace an installed launcher that differs from what this PiShip generates:
 * one an earlier PiShip wrote stays in place across updates (an update
 * activates a release, it does not rewrite `launch.mjs`), so a user who
 * installed long ago would keep running its registration and verification
 * steps. Written beside the launcher and renamed over it: a process that
 * already started has read its text, and a new one reads the old or the new
 * file whole. Only the active installed release replaces it (`running` is
 * the payload directory asking), so a build directory or a release that was
 * rolled away from never rewrites what the active one runs. Returns whether
 * it replaced the launcher; never throws, because the launcher in place
 * still works.
 */
export function refreshInstalledLauncher(id: string, running: string): boolean {
  try {
    const state = inspectInstalledLauncher(id);
    if (!state || state.current) return false;
    // Real paths: on macOS the install home may sit behind /var.
    if (realpathSync(readInstallReceipt(id).payload) !== realpathSync(running))
      return false;
    const path = installedLauncherPath(id);
    const temporary = `${path}.${process.pid}.tmp`;
    try {
      writeFileSync(temporary, launcherSource(id));
      renameSync(temporary, path);
    } finally {
      if (existsSync(temporary)) rmSync(temporary, { force: true });
    }
    return true;
  } catch {
    return false;
  }
}

const NODE_REQUIRED =
  "Node.js 22.19.0 or newer is required. Install Node separately.";

/**
 * The text of the command shim (`<bin>/<command>`, `.cmd` on Windows) that
 * runs the installed launcher with whatever `node` the PATH holds.
 *
 * On Windows it does not look for node first. The earlier shim ran
 * `where node` on every start, which is a process spawn; cmd answers a
 * command it cannot find with exit code 9009, which the shim turns into the
 * same message. It does not pin the node that installed it either: a pinned
 * path outlives the node the user switches to (a version manager keeps the
 * old one), and a running `.cmd` file cannot be rewritten safely, since cmd
 * reads it again by offset after each command.
 */
export function commandShimSource(
  launcher: string,
  platform: NodeJS.Platform = process.platform,
): string {
  return platform === "win32"
    ? `@echo off\r\nnode "${launcher}" %*\r\nif %errorlevel% equ 9009 (echo ${NODE_REQUIRED} 1>&2 & exit /b 1)\r\n`
    : `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo '${NODE_REQUIRED}' >&2; exit 1; }\nexec node '${launcher.replaceAll("'", "'\"'\"'")}' "$@"\n`;
}

/** The Windows shim of an earlier PiShip, still on disk until reinstalled. */
function legacyWindowsShimSource(launcher: string): string {
  return `@echo off\r\nwhere node >nul 2>nul || (echo ${NODE_REQUIRED} 1>&2 & exit /b 1)\r\nnode "${launcher}" %*\r\n`;
}

export function writeShim(
  commandPath: string,
  launcher: string,
  platform: NodeJS.Platform = process.platform,
): void {
  writeFileSync(commandPath, commandShimSource(launcher, platform), {
    flag: "wx",
  });
  if (platform !== "win32") chmodSync(commandPath, 0o755);
}

/** Require exact shim content before deleting or repairing an owned command. */
export function ownsCommandShim(
  commandPath: string,
  launcher: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (!existsSync(commandPath)) return false;
  const text = readFileSync(commandPath, "utf8");
  return (
    text === commandShimSource(launcher, platform) ||
    (platform === "win32" && text === legacyWindowsShimSource(launcher))
  );
}
