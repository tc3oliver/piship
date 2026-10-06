// Install a payload or a verified release for the current user: the owned
// release directory, the launcher, the command shim, and the first receipt.
import {
  existsSync,
  mkdirSync,
  rmSync,
  statSync,
  writeFileSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { PiShipError, stopwatch, systemError } from "@piship/contracts";
import { extractArchive } from "../archive.js";
import {
  assertDisjointRoots,
  installHome,
  isTestCreatedState,
  runtimeStateDirectory,
  testStateMarker,
  verifyPayloadContents,
  type DistributionLock,
} from "../index.js";
import { verifyRelease } from "../release/index.js";
import { channelTrustFromLock } from "../lock.js";
import { keyFingerprint } from "../signing.js";
import { createStagingDirectory } from "../temporary-directories.js";
import {
  initialTrustState,
  removeTrustState,
  writeTrustState,
} from "./trust-state.js";
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
import { copyTree, renameWithRetry } from "./files.js";
import { launcherSource, ownsCommandShim, writeShim } from "./launcher.js";

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

/** Checks an installer asks for before anything is installed. */
export interface InstallChecks {
  /** The release archive's SHA-256, obtained out of band from its publisher. */
  readonly expectedSha256?: string;
  /**
   * Update-key fingerprints (`sha256:<hex>`) the release lock must pin. Each
   * given key must be among the lock's channel trust keys
   * (`channelTrustFromLock`); the lock may pin others.
   */
  readonly expectedKeys?: readonly string[];
}

function invalidCheck(message: string, userAction: string): PiShipError {
  return new PiShipError("CONFIG_INVALID", message, {
    component: "install",
    userAction,
  });
}

/**
 * Install a payload directory, a verified release directory, or a verified
 * release archive for the current user. Collisions fail; state is adopted
 * only with `useExistingState`. `checks` pin the archive digest and update
 * keys the installer expects; a mismatch installs nothing.
 */
export async function installDistribution(
  artifact: string,
  useExistingState = false,
  checks: InstallChecks = {},
): Promise<InstallReceipt> {
  const expectedSha256 = checks.expectedSha256?.toLowerCase();
  if (expectedSha256 !== undefined && !/^[0-9a-f]{64}$/.test(expectedSha256))
    throw invalidCheck(
      "The expected archive SHA-256 must be 64 hexadecimal characters",
      "Pass the digest the publisher printed for the release archive",
    );
  const expectedKeys = (checks.expectedKeys ?? []).map((key) =>
    key.toLowerCase(),
  );
  for (const key of checks.expectedKeys ?? [])
    if (!/^sha256:[0-9a-f]{64}$/i.test(key))
      throw invalidCheck(
        `Expected key fingerprint ${key} is not sha256:<64 hexadecimal characters>`,
        "Pass the fingerprint piship keygen printed for the publisher's key",
      );
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
  if (expectedSha256 !== undefined && !isArchive)
    throw invalidCheck(
      `--sha256 checks a release archive, but ${source} is a directory and has no archive digest`,
      "Install the release .tar.gz archive with --sha256, or omit --sha256 for a release or payload directory",
    );
  const isRelease = isArchive || existsSync(join(source, "release.json"));
  const lap = stopwatch();
  assertDisjointRoots();
  mkdirSync(installHome(), { recursive: true });
  const temporary = createStagingDirectory(installHome());
  const staging = temporary.path;
  try {
    let payload = source;
    let lock: DistributionLock;
    let info: InstalledRelease["release"];
    if (isRelease) {
      // For an archive: its digest, from the one read that also unpacks the
      // few metadata files, and the checks that bind them to the release.
      const verified = await verifyRelease(source, {
        requireTarget: true,
        extractTo: staging,
        fastClient: true,
        metadataOnly: isArchive,
        ...(expectedSha256 ? { expectedSha256 } : {}),
      });
      payload = verified.payload;
      lock = verified.lock;
      info = releaseInfo(verified.metadata, verified.archiveSha256);
      lap("install digest and release metadata");
    } else {
      lock = verifyPayloadContents(source, {
        requireTarget: true,
        verifyContents: false,
      });
      lap("install payload metadata");
    }
    const pinned = new Set(
      channelTrustFromLock(lock).map((key) => keyFingerprint(key.publicKey)),
    );
    const unpinned = expectedKeys.filter((key) => !pinned.has(key));
    if (unpinned.length)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Install check: ${lock.app.id}@${lock.app.version} does not pin the expected update key ${unpinned.join(", ")}`,
        {
          component: "install",
          userAction:
            "Do not install this artifact; obtain it again from the trusted source, or confirm the fingerprint with its publisher",
        },
      );
    const { id, command, version } = lock.app;
    if (!VERSION_NAME.test(version))
      throw new Error(`Unsupported distribution version ${version}`);
    // Reject a malformed bootstrap before creating or extracting app files.
    const trust = initialTrustState(lock, id, new Date());
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
            verifyPayloadContents(committed.payload, {
              requireTarget: true,
              verifyContents: false,
            });
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
        ) {
          // Preserve a failed install for explicit maintenance. Moving it
          // under an owned staging directory avoids thousands of deletes
          // before this retry can begin extracting the new payload.
          const abandoned = createStagingDirectory(installHome());
          renameWithRetry(apps, join(abandoned.path, "initial-app"));
        }
        if (existsSync(receiptPath(id))) {
          // The branded command has no uninstall, so name the installed
          // release's own CLI. A damaged receipt names no release.
          let active: string | undefined;
          try {
            active = readInstallReceipt(id).active;
          } catch {}
          throw new Error(
            active
              ? `Install collision for ${id}/${command}; ${active} is already installed. Run ${command} update --from <signed update source> to upgrade without removing installed versions`
              : `Install collision for ${id}/${command}; uninstall the existing distribution first`,
          );
        }
        // No receipt and no marker: PiShip did not create it, so it is never
        // removed here, and uninstall has nothing recorded to remove.
        for (const path of [apps, commandPath])
          if (existsSync(path))
            throw new Error(
              `Install collision for ${id}/${command}: ${path} exists but no PiShip installation of ${id} is recorded; move it aside if it is not in use, then install again`,
            );
        // State that `piship test` or `dev` created for this distribution
        // before its first install is adopted; any other state is not.
        if (
          !useExistingState &&
          existsSync(runtimeStateDirectory({ value: id })) &&
          !isTestCreatedState({ value: id })
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
        renameWithRetry(pending, apps);
        syncDirectory(dirname(apps));
        mkdirSync(dirname(commandPath), { recursive: true });
        lap("install preflight");
        try {
          // The version directory is not referenced until the receipt is
          // written, so the payload is written straight into it: no second
          // move of thousands of files, and an interruption leaves only an
          // unreferenced directory.
          if (isArchive) {
            const expectedRoot = basename(source).replace(/\.tar\.gz$/, "");
            await extractArchive(source, target, {
              expectedRoot,
              hash: false,
              mapEntry: (name) =>
                name.startsWith(`${expectedRoot}/payload/`)
                  ? name.slice(`${expectedRoot}/payload/`.length)
                  : undefined,
            });
          } else if (payload.startsWith(`${staging}`))
            renameWithRetry(payload, target);
          else await copyTree(payload, target);
          lap("install extract payload");
          writeFileSync(launcher, launcherSource(id));
          syncDirectory(dirname(apps));
          // A fresh install is the one point where a release lock sets the
          // installation's update trust; a leftover state of an earlier
          // install is replaced, never merged.
          if (trust) writeTrustState(trust);
          else removeTrustState(id);
          lap("install launcher and trust state");
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
            ...(trust ? { trustState: true } : {}),
          };
          if (!hold.stillHeld())
            throw new Error(`Initial install lock for ${id} was lost; retry`);
          writeReceipt(receipt);
          lap("install receipt");
          writeShim(commandPath, launcher);
          syncDirectory(dirname(commandPath));
          lap("install command shim");
          rmSync(installMarker(apps), { force: true });
          // The state belongs to this install now: installing again after an
          // uninstall must adopt it explicitly.
          rmSync(testStateMarker({ value: id }), { force: true });
          return receipt;
        } catch (error) {
          if (!existsSync(receiptPath(id))) {
            if (ownsCommandShim(commandPath, launcher))
              rmSync(commandPath, { force: true });
            // The ownership marker lets a retry move this aside in O(1).
            // Explicit maintenance reclaims abandoned payloads.
            removeTrustState(id);
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
    lap("install cleanup");
  }
}
