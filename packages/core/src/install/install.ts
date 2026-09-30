// Install a payload or a verified release for the current user: the owned
// release directory, the launcher, the command shim, and the first receipt.
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  readFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { sha256File } from "../archive.js";
import {
  installHome,
  runtimeStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "../index.js";
import { verifyRelease } from "../release/index.js";
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
import { readFileSync, realpathSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
// Node resolves this module to its real path, while the receipt records the
// install path as configured (on macOS /var is a symlink to /private/var).
// Both sides are canonicalized before comparing; a missing payload or one
// outside this directory still fails closed.
const home = dirname(fileURLToPath(import.meta.url));
const launchingDir = join(home, ".runtime-leases", ".launching");
mkdirSync(launchingDir, { recursive: true, mode: 0o700 });
const launching = join(launchingDir, randomUUID() + ".json");
writeFileSync(launching, JSON.stringify({ schema: "piship-launching-lease/v1", pid: process.pid }) + "\\n", { flag: "wx", mode: 0o600 });
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
core.holdRuntimeLease(${JSON.stringify(id)}, version);
clearLaunching();
process.removeListener("exit", clearLaunching);
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
  const isArchive = statSync(source).isFile();
  const isRelease = isArchive || existsSync(join(source, "release.json"));
  mkdirSync(installHome(), { recursive: true });
  const staging = mkdtempSync(join(installHome(), ".staging-"));
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
    const hold = acquireLifecycleLock(
      join(receipts, `.${id}.initial-install.lock`),
      () =>
        new Error(
          `Another initial install of ${id} is running; retry when it completes`,
        ),
      () => new Error(`Could not acquire the initial install lock for ${id}`),
    );
    try {
      if (
        existsSync(receiptPath(id)) &&
        ownedIncompleteInstall(id, command, apps)
      ) {
        const committed = readInstallReceipt(id);
        if (committed.app.command !== command || existsSync(commandPath))
          throw new Error(
            `Install collision for ${id}/${command}; uninstall the existing distribution first`,
          );
        verifyPayload(committed.payload);
        writeShim(commandPath, launcher);
        syncDirectory(dirname(commandPath));
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
      if (
        existsSync(receiptPath(id)) ||
        existsSync(apps) ||
        existsSync(commandPath)
      )
        throw new Error(
          `Install collision for ${id}/${command}; uninstall the existing distribution first`,
        );
      if (!useExistingState && existsSync(runtimeStateDirectory({ value: id })))
        throw new Error(
          `State already exists for ${id}; pass --use-existing-state to explicitly reuse it`,
        );
      mkdirSync(apps, { recursive: true });
      writeFileSync(
        installMarker(apps),
        `${JSON.stringify({ schema: INITIAL_INSTALL_SCHEMA, id, command })}\n`,
        { flag: "wx", mode: 0o600 },
      );
      syncDirectory(apps);
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
          rmSync(commandPath, { force: true });
          rmSync(apps, { recursive: true, force: true });
        }
        throw error;
      }
    } finally {
      hold.release();
    }
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
