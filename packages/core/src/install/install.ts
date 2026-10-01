// Install a payload or a verified release for the current user: the owned
// release directory, the launcher, the command shim, and the first receipt.
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { systemError } from "@piship/contracts";
import { sha256File } from "../archive.js";
import {
  assertDisjointRoots,
  installHome,
  runtimeStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "../index.js";
import { verifyRelease } from "../release/index.js";
import { createStagingDirectory } from "../temporary-directories.js";
import {
  RECEIPT_SCHEMA,
  VERSION_NAME,
  appDirectory,
  commandPathFor,
  receiptPath,
  readInstallReceipt,
  releaseInfo,
  syncDirectory,
  syncTree,
  writeReceipt,
  type InstallReceipt,
  type InstalledRelease,
} from "./receipt.js";
import { acquireLifecycleLock } from "./lifecycle-lock.js";

const INITIAL_INSTALL_SCHEMA = "piship-initial-install/v1";

function installMarker(apps: string): string {
  return join(apps, ".initial-install.json");
}

/** A receipt owns a command even when a crash preceded writing its shim. */
function otherCommandOwner(
  command: string,
  id: string,
  receipts: string,
): string | undefined {
  for (const name of readdirSync(receipts)) {
    if (!name.endsWith(".json") || name === `${id}.json`) continue;
    let text: string;
    try {
      text = readFileSync(join(receipts, name), "utf8");
    } catch {
      // Unreadable (a directory, or gone since the listing): it records no
      // command, and a shim it wrote is still refused as an existing path.
      continue;
    }
    let value: Partial<InstallReceipt> | undefined;
    try {
      value = JSON.parse(text) as Partial<InstallReceipt>;
    } catch {
      value = undefined;
    }
    // A damaged receipt does not stop other installs: it still owns the
    // command when its remaining text names it, and a shim it wrote is
    // refused as an existing path; a shim it never wrote is not a collision.
    if (
      value?.app?.command === command ||
      value?.commandPath === commandPathFor(command) ||
      (value === undefined &&
        (text.includes(JSON.stringify(command)) ||
          text.includes(JSON.stringify(commandPathFor(command)).slice(1, -1))))
    )
      return name.slice(0, -5);
  }
  return undefined;
}

function ownedIncompleteInstall(
  id: string,
  command: string,
  apps: string,
): boolean {
  try {
    const record = JSON.parse(
      readFileSync(installMarker(apps), "utf8"),
    ) as Record<string, unknown>;
    return (
      record.schema === INITIAL_INSTALL_SCHEMA &&
      record.id === id &&
      record.command === command
    );
  } catch {
    return false;
  }
}

function launcherSource(id: string): string {
  return `// PiShip launcher for ${id}: runs the active release named by the install receipt.
import { readFileSync, realpathSync, mkdirSync, writeFileSync, rmSync, lstatSync, renameSync, linkSync, readlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
// Node resolves this module to its real path, while the receipt records the
// install path as configured (on macOS /var is a symlink to /private/var).
// Both sides are canonicalized before comparing; a missing payload or one
// outside this directory still fails closed.
const home = dirname(fileURLToPath(import.meta.url));
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
  return start === null ? null : Math.abs(start - record.started) > 5000;
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
const core = await import(pathToFileURL(join(payload, "node_modules", "@piship", "core", "dist", "index.js")).href);
// A release older than runtime leases (after a rollback, or an older archive
// installed by a newer CLI) has no holdRuntimeLease: it launches without one.
if (typeof core.holdRuntimeLease === "function") core.holdRuntimeLease(${JSON.stringify(id)}, version);
if (readFileSync(gatePath, "utf8") !== gateRecord) throw new Error("Launcher registration lock was lost");
clearLaunching();
process.removeListener("exit", clearLaunching);
clearGate();
process.removeListener("exit", clearGate);
await import(pathToFileURL(join(payload, "bin", command)).href);
`;
}

function writeShim(commandPath: string, launcher: string): void {
  if (process.platform === "win32")
    writeFileSync(
      commandPath,
      `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${launcher}" %*\r\n`,
      { flag: "wx" },
    );
  else {
    writeFileSync(
      commandPath,
      `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '${launcher.replaceAll("'", "'\"'\"'")}' "$@"\n`,
      { flag: "wx" },
    );
    chmodSync(commandPath, 0o755);
  }
}

/** Require exact shim content before deleting or repairing an owned command. */
export function ownsCommandShim(
  commandPath: string,
  launcher: string,
): boolean {
  if (!existsSync(commandPath)) return false;
  const expected =
    process.platform === "win32"
      ? `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${launcher}" %*\r\n`
      : `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '${launcher.replaceAll("'", "'\"'\"'")}' "$@"\n`;
  return readFileSync(commandPath, "utf8") === expected;
}

/**
 * Install a payload directory, a verified release directory, or a verified
 * release archive for the current user. Collisions fail; state is adopted
 * only with `useExistingState`.
 */
export async function installDistribution(
  artifact: string,
  useExistingState = false,
): Promise<InstallReceipt> {
  const source = resolve(artifact);
  let isArchive: boolean;
  try {
    isArchive = statSync(source).isFile();
  } catch (error) {
    throw (
      systemError(
        error,
        source,
        "Pass the artifact directory piship build printed, a release directory, or a release .tar.gz archive",
      ) ?? error
    );
  }
  const isRelease = isArchive || existsSync(join(source, "release.json"));
  assertDisjointRoots();
  mkdirSync(installHome(), { recursive: true });
  const temporary = createStagingDirectory(installHome());
  const staging = temporary.path;
  try {
    let payload = source;
    let lock: DistributionLock;
    let info: InstalledRelease["release"];
    if (isRelease) {
      const verified = await verifyRelease(source, {
        requireTarget: true,
        extractTo: staging,
      });
      payload = verified.payload;
      lock = verified.lock;
      info = releaseInfo(
        verified.metadata,
        isArchive ? await sha256File(source) : undefined,
      );
    } else lock = verifyPayload(source);
    const { id, command, version } = lock.app;
    if (!VERSION_NAME.test(version))
      throw new Error(`Unsupported distribution version ${version}`);
    const apps = appDirectory(id);
    const target = join(apps, version);
    const commandPath = commandPathFor(command);
    const launcher = join(apps, "launch.mjs");
    const receipts = dirname(receiptPath(id));
    mkdirSync(receipts, { recursive: true });
    mkdirSync(dirname(commandPath), { recursive: true });
    const commandHold = acquireLifecycleLock(
      `${commandPath}.piship.lock`,
      () =>
        new Error(
          `Another operation owns command ${command}; retry when it completes`,
        ),
      () => new Error(`Could not lock command ${command}`),
    );
    try {
      const hold = acquireLifecycleLock(
        join(receipts, `.${id}.initial-install.lock`),
        () =>
          new Error(
            `Another initial install of ${id} is running; retry when it completes`,
          ),
        () => new Error(`Could not acquire the initial install lock for ${id}`),
      );
      try {
        const owner = otherCommandOwner(command, id, receipts);
        if (owner)
          throw new Error(
            `Install collision: command ${command} is owned by ${owner}`,
          );
        if (
          existsSync(receiptPath(id)) &&
          ownedIncompleteInstall(id, command, apps)
        ) {
          // Committed, but interrupted before the shim was written or before
          // the marker was removed: finish it.
          const committed = readInstallReceipt(id);
          if (committed.app.command !== command)
            throw new Error(
              `Install collision for ${id}/${command}; uninstall the existing distribution first`,
            );
          if (!ownsCommandShim(commandPath, launcher)) {
            if (existsSync(commandPath))
              throw new Error(
                `Install collision for ${id}/${command}; uninstall the existing distribution first`,
              );
            verifyPayload(committed.payload);
            writeShim(commandPath, launcher);
            syncDirectory(dirname(commandPath));
          }
          rmSync(installMarker(apps), { force: true });
          return committed;
        }
        if (
          process.platform === "win32" &&
          ["%", "!", '"', "\r", "\n"].some((character) =>
            launcher.includes(character),
          )
        )
          throw new Error(
            "Install path contains characters unsafe for a Windows command shim",
          );
        if (
          existsSync(apps) &&
          !existsSync(receiptPath(id)) &&
          ownedIncompleteInstall(id, command, apps)
        )
          rmSync(apps, { recursive: true, force: true });
        if (existsSync(receiptPath(id)))
          throw new Error(
            `Install collision for ${id}/${command}; uninstall the existing distribution first`,
          );
        // No receipt and no marker: PiShip did not create it, so it is never
        // removed here, and uninstall has nothing recorded to remove.
        for (const path of [apps, commandPath])
          if (existsSync(path))
            throw new Error(
              `Install collision for ${id}/${command}: ${path} exists but no PiShip installation of ${id} is recorded; move it aside if it is not in use, then install again`,
            );
        if (
          !useExistingState &&
          existsSync(runtimeStateDirectory({ value: id }))
        )
          throw new Error(
            `State already exists for ${id}; pass --use-existing-state to explicitly reuse it`,
          );
        // The app directory appears with its marker in one rename, so an
        // interruption never leaves an unmarked apps/<id> that the next
        // install could not tell from someone else's directory.
        mkdirSync(dirname(apps), { recursive: true });
        const pending = join(staging, "initial-app");
        mkdirSync(pending);
        writeFileSync(
          installMarker(pending),
          `${JSON.stringify({ schema: INITIAL_INSTALL_SCHEMA, id, command })}\n`,
          { flag: "wx", mode: 0o600 },
        );
        syncTree(pending);
        renameSync(pending, apps);
        syncDirectory(dirname(apps));
        mkdirSync(dirname(commandPath), { recursive: true });
        try {
          if (payload.startsWith(`${staging}`)) renameSync(payload, target);
          else cpSync(payload, target, { recursive: true });
          verifyPayload(target);
          writeFileSync(launcher, launcherSource(id));
          syncTree(apps);
          syncDirectory(dirname(apps));
          const receipt: InstallReceipt = {
            schema: RECEIPT_SCHEMA,
            app: lock.app,
            payload: target,
            commandPath,
            launcher,
            active: version,
            releases: [
              {
                version,
                payload: target,
                installedAt: new Date().toISOString(),
                ...(info ? { release: info } : {}),
              },
            ],
            // Users start on the distribution's default channel, whatever
            // channel the installed archive was built for.
            ...(lock.updates ? { channel: lock.updates.channel } : {}),
          };
          if (!hold.stillHeld())
            throw new Error(`Initial install lock for ${id} was lost; retry`);
          writeReceipt(receipt);
          writeShim(commandPath, launcher);
          syncDirectory(dirname(commandPath));
          rmSync(installMarker(apps), { force: true });
          return receipt;
        } catch (error) {
          if (!existsSync(receiptPath(id))) {
            if (ownsCommandShim(commandPath, launcher))
              rmSync(commandPath, { force: true });
            rmSync(apps, { recursive: true, force: true });
          }
          throw error;
        }
      } finally {
        hold.release();
      }
    } finally {
      commandHold.release();
    }
  } finally {
    temporary.remove();
  }
}
