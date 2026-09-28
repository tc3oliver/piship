// Installed release lifecycle: install ownership, the receipt that selects the
// active release, verified update, rollback, and recovery after interruption.
// Releases are immutable payload directories; switching the active release is
// one atomic receipt rename, so an interruption leaves the old or the new
// release active, never a mix.
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  cpSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { resolveTemplate, type UpdatesManifest } from "@piship/schema";
import { sha256File } from "./archive.js";
import {
  binHome,
  currentTarget,
  installHome,
  runtimeStateDirectory,
  distributionStateDirectory,
  verifyPayload,
  type DistributionLock,
} from "./index.js";
import {
  STATE_DATA_CLASSES,
  STATE_MARKER_FILE,
  STATE_MARKER_SCHEMA,
  checkStateMigration,
  compareVersions,
  readStateMarker,
  type MigrationReport,
} from "./migration.js";
import {
  downloadArchive,
  payloadStateSchemas,
  readChannel,
  runPayloadCommand,
  verifyRelease,
  type ChannelRelease,
  type ReleaseMetadata,
  type ReleaseTestRunner,
} from "./release.js";

export const RECEIPT_SCHEMA = "piship-install/v1";
export const SNAPSHOT_SCHEMA = "piship-snapshot/v1";
const SNAPSHOT_RETENTION = 3;
const VERSION_NAME = /^[0-9][0-9A-Za-z.+-]*$/;

export interface InstalledRelease {
  readonly version: string;
  readonly payload: string;
  readonly installedAt: string;
  /** Present when installed from a verified release artifact. */
  readonly release?: {
    readonly target: string;
    readonly channel: string;
    readonly pi: string;
    readonly piship: string;
    readonly lockSha256: string;
    readonly archiveSha256?: string;
  };
}

export interface InstallReceipt {
  readonly schema?: typeof RECEIPT_SCHEMA;
  readonly app: DistributionLock["app"];
  /** The active payload (kept for tools that read one payload path). */
  readonly payload: string;
  readonly commandPath: string;
  /** `apps/<id>/launch.mjs`; absent for receipts written before v1. */
  readonly launcher?: string;
  readonly active: string;
  /** The retained known-good release rollback returns to. */
  readonly previous?: string;
  readonly releases: readonly InstalledRelease[];
  /** Channel the user selected; defaults to the distribution's channel. */
  readonly channel?: string;
  /** Highest verified channel metadata sequence per channel (replay guard). */
  readonly channelSequences?: Readonly<Record<string, number>>;
  readonly lastCheck?: {
    readonly time: string;
    readonly channel: string;
    readonly result: string;
  };
}

export type LifecyclePhase =
  | "staged"
  | "verified"
  | "installed"
  | "committed"
  | "cleaned";

export interface LifecycleOptions {
  /** Test seam: throw at a phase to simulate interruption. */
  readonly faults?: (phase: LifecyclePhase) => void;
  /** Runs a candidate payload's launcher check; defaults to Node. */
  readonly runCheck?: ReleaseTestRunner;
  /** Deletes a secret-store reference when credentials must be cleared. */
  readonly deleteSecret?: (ref: string) => Promise<void>;
  readonly now?: () => Date;
  readonly env?: NodeJS.ProcessEnv;
}

function appDirectory(id: string): string {
  return join(installHome(), "apps", id);
}

function receiptPath(id: string): string {
  distributionStateDirectory({ value: id });
  return join(installHome(), "receipts", `${id}.json`);
}

function commandPathFor(command: string): string {
  return join(
    binHome(),
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}

/** Write `path` through a temporary file, fsync, and rename. */
function writeFileAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  if (process.platform !== "win32")
    try {
      const dir = openSync(dirname(path), "r");
      try {
        fsyncSync(dir);
      } finally {
        closeSync(dir);
      }
    } catch {
      // Directory fsync is best effort on filesystems that refuse it.
    }
}

function writeReceipt(receipt: InstallReceipt): void {
  writeFileAtomic(
    receiptPath(receipt.app.id),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
}

/** Read and validate an install receipt; paths must be the owned ones. */
export function readInstallReceipt(id: string): InstallReceipt {
  const path = receiptPath(id);
  if (!existsSync(path))
    throw new Error(`No PiShip installation recorded for ${id}`);
  const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<InstallReceipt>;
  const unsafe = () => new Error(`Unsafe installation receipt for ${id}`);
  if (!raw.app || raw.app.id !== id) throw unsafe();
  const expectedCommand = commandPathFor(raw.app.command);
  if (raw.commandPath !== expectedCommand) throw unsafe();
  if (raw.schema === undefined) {
    // Written before receipts were versioned: one release, shim to payload.
    if (raw.payload !== join(appDirectory(id), raw.app.version)) throw unsafe();
    return {
      app: raw.app,
      payload: raw.payload,
      commandPath: raw.commandPath,
      active: raw.app.version,
      releases: [
        { version: raw.app.version, payload: raw.payload, installedAt: "" },
      ],
    };
  }
  if (raw.schema !== RECEIPT_SCHEMA)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Install receipt ${raw.schema} was written by a newer PiShip; use that version to manage ${id}`,
    );
  const releases = raw.releases ?? [];
  for (const release of releases)
    if (
      !VERSION_NAME.test(release.version) ||
      release.payload !== join(appDirectory(id), release.version)
    )
      throw unsafe();
  const active = releases.find((item) => item.version === raw.active);
  if (
    !active ||
    raw.payload !== active.payload ||
    raw.launcher !== join(appDirectory(id), "launch.mjs") ||
    (raw.previous !== undefined &&
      !releases.some((item) => item.version === raw.previous))
  )
    throw unsafe();
  return raw as InstallReceipt;
}

function launcherSource(id: string): string {
  return `// PiShip launcher for ${id}: runs the active release named by the install receipt.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const home = dirname(fileURLToPath(import.meta.url));
let release;
let command;
try {
  const receipt = JSON.parse(readFileSync(join(home, "..", "..", "receipts", ${JSON.stringify(`${id}.json`)}), "utf8"));
  release = receipt.releases.find((item) => item.version === receipt.active);
  command = receipt.app.command;
  if (!release || release.payload !== join(home, release.version) || !/^[a-z][a-z0-9-]*$/.test(command)) release = undefined;
} catch {}
if (!release) {
  console.error(${JSON.stringify(`The ${id} install receipt is missing or damaged; reinstall ${id}.`)});
  process.exit(1);
}
await import(pathToFileURL(join(release.payload, "bin", command)).href);
`;
}

function writeShim(commandPath: string, launcher: string): void {
  if (process.platform === "win32")
    writeFileSync(
      commandPath,
      `@echo off\r\nwhere node >nul 2>nul || (echo Node.js 22.19.0 or newer is required. Install Node separately. 1>&2 & exit /b 1)\r\nnode "${launcher}" %*\r\n`,
    );
  else {
    writeFileSync(
      commandPath,
      `#!/bin/sh\ncommand -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }\nexec node '${launcher.replaceAll("'", "'\"'\"'")}' "$@"\n`,
    );
    chmodSync(commandPath, 0o755);
  }
}

function releaseInfo(
  metadata: ReleaseMetadata,
  archiveSha256?: string,
): NonNullable<InstalledRelease["release"]> {
  return {
    target: metadata.target,
    channel: metadata.channel,
    pi: metadata.pi.version,
    piship: metadata.piship.version,
    lockSha256: metadata.lockSha256,
    ...(archiveSha256 ? { archiveSha256 } : {}),
  };
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
    mkdirSync(dirname(commandPath), { recursive: true });
    try {
      if (payload.startsWith(`${staging}`)) renameSync(payload, target);
      else cpSync(payload, target, { recursive: true });
      verifyPayload(target);
      writeFileSync(launcher, launcherSource(id));
      writeShim(commandPath, launcher);
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
        ...(info ? { channel: info.channel } : {}),
      };
      writeReceipt(receipt);
      return receipt;
    } catch (error) {
      rmSync(commandPath, { force: true });
      rmSync(apps, { recursive: true, force: true });
      throw error;
    }
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/**
 * Remove the shim, launcher, every retained release, leftovers of an
 * interrupted operation, and the receipt; keep state. Refuses while an
 * update or rollback holds the lifecycle lock.
 */
export function uninstallDistribution(id: string): string {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  if (existsSync(apps)) acquireLock(id);
  rmSync(receipt.commandPath, { force: true });
  rmSync(apps, { recursive: true, force: true });
  rmSync(receiptPath(id), { force: true });
  return runtimeStateDirectory({ value: id });
}

/** Delete one distribution's PiShip-owned state after uninstall. */
export function purgeDistributionState(id: string): string {
  distributionStateDirectory({ value: id });
  if (existsSync(receiptPath(id)))
    throw new Error(`Uninstall ${id} before purging its state`);
  const state = runtimeStateDirectory({ value: id });
  rmSync(state, { recursive: true, force: true });
  return state;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** One lifecycle operation per distribution at a time. */
function acquireLock(
  id: string,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED" = "UPDATE_FAILED",
): () => void {
  const path = join(appDirectory(id), ".lifecycle.lock");
  for (let attempt = 0; attempt < 2; attempt += 1)
    try {
      writeFileSync(path, String(process.pid), { flag: "wx" });
      return () => rmSync(path, { force: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const owner = Number(readFileSync(path, "utf8"));
      if (Number.isSafeInteger(owner) && owner > 0 && processAlive(owner))
        throw new PiShipError(
          code,
          `Another update, rollback, or uninstall of ${id} is running (process ${owner})`,
          { retryable: true },
        );
      rmSync(path, { force: true });
    }
  throw new PiShipError(
    code,
    `Could not lock ${id} for ${code === "UPDATE_FAILED" ? "update" : "rollback"}`,
  );
}

/**
 * Remove leftovers of an interrupted operation: staging directories and
 * release directories the receipt does not reference. Idempotent.
 */
export function recoverInstallation(id: string): string[] {
  const receipt = readInstallReceipt(id);
  const apps = appDirectory(id);
  const keep = new Set([
    ...receipt.releases.map((item) => item.version),
    "launch.mjs",
    ".lifecycle.lock",
  ]);
  const removed: string[] = [];
  for (const name of readdirSync(apps))
    if (!keep.has(name)) {
      rmSync(join(apps, name), { recursive: true, force: true });
      removed.push(name);
    }
  return removed;
}

function requireManaged(receipt: InstallReceipt): void {
  if (!receipt.launcher)
    throw new PiShipError(
      "UPDATE_FAILED",
      `${receipt.app.id} was installed by an earlier PiShip without release tracking; reinstall it to enable update and rollback`,
    );
}

function activeLock(receipt: InstallReceipt): DistributionLock {
  const active = receipt.releases.find(
    (item) => item.version === receipt.active,
  );
  if (!active)
    throw new Error(`Unsafe installation receipt for ${receipt.app.id}`);
  return verifyPayload(active.payload);
}

export interface ChannelSelection {
  readonly channel: string;
  readonly notices: readonly string[];
}

/** Resolve the channel a user may use under the distribution's policy. */
export function selectChannel(
  updates: UpdatesManifest,
  requested: string | undefined,
  saved: string | undefined,
): ChannelSelection {
  if (requested !== undefined) {
    if (!(updates.channels as readonly string[]).includes(requested))
      throw new PiShipError(
        "POLICY_DENIED",
        `Channel ${requested} is not allowed by this distribution (allowed: ${updates.channels.join(", ")})`,
        { component: "update" },
      );
    return { channel: requested, notices: [] };
  }
  if (saved && (updates.channels as readonly string[]).includes(saved))
    return { channel: saved, notices: [] };
  return {
    channel: updates.channel,
    notices: saved
      ? [`Channel ${saved} is no longer allowed; using ${updates.channel}`]
      : [],
  };
}

function resolveSource(
  lock: DistributionLock,
  override: string | undefined,
  env: NodeJS.ProcessEnv,
): string {
  if (override) return override;
  const template = lock.updates?.source;
  if (!template)
    throw new PiShipError(
      "UPDATE_FAILED",
      `${lock.app.name} declares no update source; pass --from <directory|url>`,
      { component: "update" },
    );
  try {
    return resolveTemplate(
      "updates.source",
      template,
      lock.access?.variables ?? [],
      env,
    );
  } catch (error) {
    throw new PiShipError("CONFIG_UNAVAILABLE", (error as Error).message, {
      component: "update",
    });
  }
}

/** Copy preferences and user policy (never credentials) before activation. */
function snapshotState(
  stateDir: string,
  from: string,
  to: string,
  now: Date,
): string | null {
  if (!existsSync(stateDir)) return null;
  const root = join(stateDir, "migration", "snapshots");
  const name = `${now.toISOString().replace(/[:.]/g, "-")}-${from}-to-${to}`;
  const target = join(root, name);
  const files: string[] = [];
  for (const path of ["config/preferences.json", "config/policy.json"]) {
    const source = join(stateDir, ...path.split("/"));
    if (!existsSync(source)) continue;
    mkdirSync(dirname(join(target, ...path.split("/"))), {
      recursive: true,
      mode: 0o700,
    });
    copyFileSync(source, join(target, ...path.split("/")));
    files.push(path);
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  writeFileSync(
    join(target, "snapshot.json"),
    `${JSON.stringify(
      {
        schema: SNAPSHOT_SCHEMA,
        from,
        to,
        time: now.toISOString(),
        files,
        excluded: STATE_DATA_CLASSES.filter((item) => item.credential).map(
          (item) => item.path,
        ),
      },
      null,
      2,
    )}\n`,
  );
  const snapshots = readdirSync(root).sort();
  for (const old of snapshots.slice(0, -SNAPSHOT_RETENTION))
    rmSync(join(root, old), { recursive: true, force: true });
  return target;
}

function writeStateMarker(stateDir: string, lock: DistributionLock): void {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeFileAtomic(
    join(stateDir, STATE_MARKER_FILE),
    `${JSON.stringify(
      {
        schema: STATE_MARKER_SCHEMA,
        distribution: lock.app.id,
        version: lock.app.version,
        pi: lock.runtime.version,
        piship: lock.runtime.pishipVersion,
      },
      null,
      2,
    )}\n`,
  );
}

/**
 * Repair a state marker that names another release than the active one. An
 * operation interrupted after its receipt commit leaves it behind; the next
 * update or rollback fixes it before comparing state against a target. A
 * missing marker is left alone: the migration check then uses the active
 * release.
 */
function repairStateMarker(id: string, lock: DistributionLock): void {
  const stateDir = runtimeStateDirectory({ value: id });
  const marker = readStateMarker(stateDir);
  if (
    marker &&
    (marker.version !== lock.app.version || marker.pi !== lock.runtime.version)
  )
    writeStateMarker(stateDir, lock);
}

/**
 * Clear credential classes the target cannot read: their metadata files and
 * the secrets they reference. The target signs in or reacquires; an old
 * credential is never restored.
 */
async function clearCredentials(
  stateDir: string,
  report: MigrationReport,
  deleteSecret: LifecycleOptions["deleteSecret"],
): Promise<string[]> {
  const notices: string[] = [];
  for (const item of report.items) {
    if (item.action !== "clear-and-reacquire") continue;
    const path = join(stateDir, ...item.path.split("/"));
    if (existsSync(path) && statSync(path).isFile()) {
      let refs: string[] = [];
      try {
        const value = JSON.parse(readFileSync(path, "utf8")) as Record<
          string,
          unknown
        >;
        refs = [value.credential_ref, value.secretRef].filter(
          (ref): ref is string => typeof ref === "string",
        );
      } catch {
        // Unreadable metadata still gets removed below.
      }
      for (const ref of refs)
        await deleteSecret?.(ref).catch((error: Error) =>
          notices.push(`Could not delete a stored secret: ${error.message}`),
        );
    }
    rmSync(path, { recursive: true, force: true });
    notices.push(
      `${item.name} was cleared because the target cannot read it; sign in again`,
    );
  }
  if (notices.length)
    rmSync(join(stateDir, "secrets"), { recursive: true, force: true });
  return notices;
}

function checkPayload(
  payload: string,
  lock: DistributionLock,
  runCheck: ReleaseTestRunner,
  env: NodeJS.ProcessEnv,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED",
): void {
  const result = runCheck(payload, lock.app.command, ["version"], env);
  if (
    result.status !== 0 ||
    !result.stdout.includes(`Pi ${lock.runtime.version}`)
  )
    throw new PiShipError(
      code,
      `The ${lock.app.version} release failed its launch check: ${(result.stderr || result.stdout).trim().slice(0, 300)}`,
    );
}

export interface UpdateOptions extends LifecycleOptions {
  readonly channel?: string;
  /** Directory or URL overriding `updates.source`. */
  readonly source?: string;
  /** Proceed when the migration check reports `requires-review`. */
  readonly acceptReview?: boolean;
  /** Report what would happen; changes nothing but the last-check record. */
  readonly check?: boolean;
  readonly fetcher?: typeof fetch;
}

export interface UpdateResult {
  readonly status: "up-to-date" | "available" | "updated";
  readonly id: string;
  readonly from: string;
  readonly to?: string;
  readonly channel: string;
  readonly keyId?: string;
  readonly migration?: MigrationReport;
  readonly snapshot?: string | null;
  readonly notices: readonly string[];
}

function newestFor(
  releases: readonly ChannelRelease[],
  target: string,
): ChannelRelease | undefined {
  return releases
    .filter((item) => item.target === target)
    .sort((a, b) => compareVersions(b.version, a.version))[0];
}

/**
 * Verified update: channel policy, signed channel metadata, a newer release
 * for this target, archive digest, release verification, launch check,
 * migration check, non-secret snapshot, then one atomic activation.
 */
export async function updateDistribution(
  id: string,
  options: UpdateOptions = {},
): Promise<UpdateResult> {
  const receipt = readInstallReceipt(id);
  requireManaged(receipt);
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const release = acquireLock(id);
  try {
    recoverInstallation(id);
    const lock = activeLock(receipt);
    if (!options.check) repairStateMarker(id, lock);
    const updates = lock.updates;
    if (!updates)
      throw new PiShipError(
        "UPDATE_FAILED",
        `${lock.app.name} ${lock.app.version} has no update policy (manifest ${lock.manifest.schema}); install a piship/v1alpha4 release`,
      );
    if (!updates.trust.keys.length)
      throw new PiShipError(
        "UPDATE_FAILED",
        `${lock.app.name} trusts no release keys (updates.trust.keys), so no update can be verified`,
      );
    const selection = selectChannel(updates, options.channel, receipt.channel);
    const { channel } = selection;
    const notices = [...selection.notices];
    const source = resolveSource(lock, options.source, env);
    const minSequence = receipt.channelSequences?.[channel] ?? 0;
    const { metadata, keyId } = await readChannel(source, channel, {
      distribution: id,
      trusted: updates.trust.keys,
      minSequence,
      now,
      ...(options.fetcher ? { fetcher: options.fetcher } : {}),
    });
    const record = (result: string, extra: Partial<InstallReceipt> = {}) =>
      writeReceipt({
        ...readInstallReceipt(id),
        ...extra,
        // A check reports on the requested channel without switching to it.
        ...(options.check ? {} : { channel }),
        channelSequences: {
          ...(receipt.channelSequences ?? {}),
          [channel]: metadata.sequence,
        },
        lastCheck: { time: now().toISOString(), channel, result },
      });
    const entry = newestFor(metadata.releases, currentTarget());
    if (!entry)
      notices.push(
        `Channel ${channel} lists no release for ${currentTarget()}; ask the distribution owner whether this platform is still supported`,
      );
    if (!entry || compareVersions(entry.version, receipt.active) === 0) {
      record("up-to-date");
      // Finishes an update interrupted between its commit and the marker.
      const stateDir = runtimeStateDirectory({ value: id });
      if (!options.check && existsSync(stateDir))
        writeStateMarker(stateDir, lock);
      return {
        status: "up-to-date",
        id,
        from: receipt.active,
        channel,
        keyId,
        notices,
      };
    }
    if (compareVersions(entry.version, receipt.active) < 0)
      throw new PiShipError(
        "UPDATE_FAILED",
        `Channel ${channel} offers ${entry.version}, older than the active ${receipt.active}; downgrades are refused (use rollback to return to a retained release)`,
      );
    const apps = appDirectory(id);
    const staging = mkdtempSync(join(apps, ".staging-"));
    try {
      const archive = join(staging, entry.archive);
      await downloadArchive(source, entry, archive, options.fetcher);
      options.faults?.("staged");
      const verified = await verifyRelease(archive, {
        requireTarget: true,
        expectedSha256: entry.sha256,
        extractTo: join(staging, "release"),
      });
      const target = verified.metadata;
      const problems = [
        [target.distribution.id, id, "distribution"],
        [target.distribution.command, receipt.app.command, "command"],
        [target.distribution.version, entry.version, "version"],
        [target.pi.version, entry.pi, "Pi version"],
        [target.lockSha256, entry.lockSha256, "lock"],
      ].filter(([a, b]) => a !== b);
      if (problems.length)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `The ${entry.version} release does not match its signed channel entry: ${problems.map((item) => item[2]).join(", ")}`,
        );
      if (target.pi.compatibility === "unsupported")
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release runs Pi ${target.pi.version}, which it records as unsupported`,
        );
      checkPayload(
        verified.payload,
        verified.lock,
        options.runCheck ?? runPayloadCommand,
        env,
        "UPDATE_FAILED",
      );
      options.faults?.("verified");
      const stateDir = runtimeStateDirectory({ value: id });
      const migration = checkStateMigration(
        stateDir,
        {
          version: entry.version,
          pi: target.pi.version,
          schemas: target.stateSchemas,
        },
        { version: receipt.active, pi: lock.runtime.version },
      );
      if (migration.verdict === "unsupported")
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release cannot use this distribution's local data: ${migration.items
            .filter((item) => item.verdict === "unsupported")
            .map((item) => `${item.name} (${item.reason})`)
            .join("; ")}`,
        );
      if (
        migration.verdict === "requires-review" &&
        !options.acceptReview &&
        !options.check
      )
        throw new PiShipError(
          "UPDATE_FAILED",
          `The ${entry.version} release needs a migration review: ${migration.items
            .filter((item) => item.verdict === "requires-review")
            .map((item) => item.reason)
            .join("; ")}`,
          {
            userAction:
              "Review the migration check, then rerun update with --accept-review",
          },
        );
      if (options.check) {
        if (migration.verdict === "requires-review" && !options.acceptReview)
          notices.push(
            "Updating needs a migration review: rerun update with --accept-review after reading the migration check",
          );
        record(`available ${entry.version}`);
        return {
          status: "available",
          id,
          from: receipt.active,
          to: entry.version,
          channel,
          keyId,
          migration,
          notices,
        };
      }
      const snapshot = snapshotState(
        stateDir,
        receipt.active,
        entry.version,
        now(),
      );
      const destination = join(apps, entry.version);
      rmSync(destination, { recursive: true, force: true });
      renameSync(verified.payload, destination);
      verifyPayload(destination);
      options.faults?.("installed");
      notices.push(
        ...(await clearCredentials(stateDir, migration, options.deleteSecret)),
      );
      const keepPrevious =
        updates.rollback && verified.lock.updates?.rollback !== false;
      const current = readInstallReceipt(id);
      const next: InstallReceipt = {
        ...current,
        app: verified.lock.app,
        payload: destination,
        active: entry.version,
        ...(keepPrevious ? { previous: receipt.active } : {}),
        releases: [
          {
            version: entry.version,
            payload: destination,
            installedAt: now().toISOString(),
            release: releaseInfo(target, entry.sha256),
          },
          ...(keepPrevious
            ? current.releases.filter((item) => item.version === receipt.active)
            : []),
        ],
        channel,
        channelSequences: {
          ...(current.channelSequences ?? {}),
          [channel]: metadata.sequence,
        },
        lastCheck: {
          time: now().toISOString(),
          channel,
          result: `updated ${receipt.active} -> ${entry.version}`,
        },
      };
      if (!keepPrevious) delete (next as { previous?: string }).previous;
      writeReceipt(next);
      options.faults?.("committed");
      writeStateMarker(stateDir, verified.lock);
      verified.cleanup();
      return {
        status: "updated",
        id,
        from: receipt.active,
        to: entry.version,
        channel,
        keyId,
        migration,
        snapshot,
        notices,
      };
    } finally {
      rmSync(staging, { recursive: true, force: true });
      try {
        recoverInstallation(id);
        options.faults?.("cleaned");
      } catch {
        // Recovery runs again before the next operation.
      }
    }
  } finally {
    release();
  }
}

export interface RollbackResult {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly migration: MigrationReport;
  readonly notices: readonly string[];
}

/**
 * Return to the retained known-good release. Only the immutable payload is
 * switched; sessions and settings stay in place, and credentials are never
 * restored: data the target cannot read is cleared and reacquired.
 */
export async function rollbackDistribution(
  id: string,
  options: LifecycleOptions = {},
): Promise<RollbackResult> {
  const receipt = readInstallReceipt(id);
  requireManaged(receipt);
  const env = options.env ?? process.env;
  const release = acquireLock(id, "ROLLBACK_FAILED");
  try {
    recoverInstallation(id);
    const current = activeLock(receipt);
    repairStateMarker(id, current);
    const previous = receipt.releases.find(
      (item) => item.version === receipt.previous,
    );
    if (!receipt.previous || !previous)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `${receipt.app.id} has no retained release to roll back to`,
      );
    if (compareVersions(receipt.previous, receipt.active) > 0)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} is newer than the active ${receipt.active}; use update instead`,
      );
    let target: DistributionLock;
    try {
      target = verifyPayload(previous.payload);
    } catch (error) {
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} failed verification: ${(error as Error).message}`,
        {
          userAction:
            "Reinstall a trusted release; the damaged one is not activated",
        },
      );
    }
    if (target.app.command !== receipt.app.command)
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release uses command ${target.app.command}; reinstall instead`,
      );
    checkPayload(
      previous.payload,
      target,
      options.runCheck ?? runPayloadCommand,
      env,
      "ROLLBACK_FAILED",
    );
    options.faults?.("verified");
    const stateDir = runtimeStateDirectory({ value: id });
    const migration = checkStateMigration(
      stateDir,
      {
        version: target.app.version,
        pi: target.runtime.version,
        schemas: payloadStateSchemas(target),
      },
      { version: receipt.active, pi: current.runtime.version },
    );
    if (migration.verdict === "unsupported")
      throw new PiShipError(
        "ROLLBACK_FAILED",
        `The retained release ${receipt.previous} cannot read this distribution's local data: ${migration.items
          .filter((item) => item.verdict === "unsupported")
          .map((item) => `${item.name} (${item.reason})`)
          .join("; ")}`,
      );
    const notices = migration.items
      .filter((item) => item.verdict === "requires-review")
      .map((item) => item.reason);
    notices.push(
      ...(await clearCredentials(stateDir, migration, options.deleteSecret)),
    );
    writeReceipt({
      ...readInstallReceipt(id),
      app: target.app,
      payload: previous.payload,
      active: receipt.previous,
      previous: receipt.active,
      lastCheck: {
        time: (options.now ?? (() => new Date()))().toISOString(),
        channel: receipt.channel ?? current.updates?.channel ?? "stable",
        result: `rolled back ${receipt.active} -> ${receipt.previous}`,
      },
    });
    options.faults?.("committed");
    writeStateMarker(stateDir, target);
    return {
      id,
      from: receipt.active,
      to: receipt.previous,
      migration,
      notices,
    };
  } finally {
    release();
  }
}

export interface LifecycleStatus {
  readonly installed: boolean;
  readonly tracked: boolean;
  readonly active?: string;
  readonly previous?: string;
  readonly channel?: string;
  readonly channels?: readonly string[];
  readonly source?: string;
  readonly trustedKeys?: number;
  readonly rollback?: boolean;
  readonly fromRelease?: boolean;
  readonly lastCheck?: InstallReceipt["lastCheck"];
  readonly leftovers: readonly string[];
}

/** Update status for doctor; never fetches anything. */
export function lifecycleStatus(
  id: string,
  lock: DistributionLock,
): LifecycleStatus {
  let receipt: InstallReceipt;
  try {
    receipt = readInstallReceipt(id);
  } catch {
    return { installed: false, tracked: false, leftovers: [] };
  }
  const apps = appDirectory(id);
  const known = new Set([
    ...receipt.releases.map((item) => item.version),
    "launch.mjs",
    ".lifecycle.lock",
  ]);
  const leftovers = existsSync(apps)
    ? readdirSync(apps).filter((name) => !known.has(name))
    : [];
  const active = receipt.releases.find(
    (item) => item.version === receipt.active,
  );
  return {
    installed: true,
    tracked: !!receipt.launcher,
    active: receipt.active,
    ...(receipt.previous ? { previous: receipt.previous } : {}),
    ...(lock.updates
      ? {
          channel:
            receipt.channel &&
            (lock.updates.channels as readonly string[]).includes(
              receipt.channel,
            )
              ? receipt.channel
              : lock.updates.channel,
          channels: lock.updates.channels,
          ...(lock.updates.source ? { source: lock.updates.source } : {}),
          trustedKeys: lock.updates.trust.keys.length,
          rollback: lock.updates.rollback,
        }
      : {}),
    fromRelease: !!active?.release,
    ...(receipt.lastCheck ? { lastCheck: receipt.lastCheck } : {}),
    leftovers,
  };
}
