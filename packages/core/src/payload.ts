import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { uptime } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  COMMAND_NAME,
  explicitProjectTrust,
  legacyProjectDimensions,
  type Manifest,
  parseManifestSource,
  readManifestSource,
} from "@piship/schema";
import { hash } from "./digest.js";
import { hashFilesInParallel, workerCount } from "./parallel-files.js";
import { readInstallReceipt } from "./install/receipt.js";
import { manifestDigest } from "./lock.js";
import type { DistributionLock } from "./lock-schema.js";
import { installHome, runtimeStateDirectory } from "./state-paths.js";

/** SHA-256 of every payload file except the inventory itself, by `/` path. */
export function payloadInventory(root: string): Record<string, string> {
  return inventory(root);
}
const byName = (a: { name: string }, b: { name: string }) =>
  a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
/**
 * The inventory of `root`. `known` carries digests a verified source (a cache
 * entry that was hashed when it was created) already holds; a file listed
 * there is not read again. Every other file is hashed from its bytes, by
 * several threads when there are many.
 */
export function inventory(
  root: string,
  known: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const files: string[] = [];
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      byName,
    )) {
      const key = `${prefix}${entry.name}`;
      if (entry.isSymbolicLink())
        throw new Error(`Payload symlink is not allowed: ${key}`);
      if (entry.isDirectory()) visit(join(directory, entry.name), `${key}/`);
      else if (entry.isFile() && key !== "metadata/inventory.json")
        files.push(key);
      else if (!entry.isFile())
        throw new Error(`Unsupported payload entry: ${key}`);
    }
  };
  visit(root, "");
  const unknown = files.filter((key) => !Object.hasOwn(known, key));
  const threads = workerCount(unknown.length);
  const hashed = new Map<string, string>();
  if (threads > 1)
    hashFilesInParallel(threads, root, unknown).forEach((digest, index) => {
      hashed.set(unknown[index] as string, digest);
    });
  const output: Record<string, string> = {};
  for (const key of files)
    output[key] = Object.hasOwn(known, key)
      ? (known[key] as string)
      : (hashed.get(key) ?? hash(readFileSync(join(root, ...key.split("/")))));
  return output;
}
export function removeNpmBins(directory: string): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.name === ".bin") rmSync(path, { recursive: true, force: true });
    else if (entry.isDirectory()) removeNpmBins(path);
  }
}
/**
 * Remove optional packages whose npm lock `os`/`cpu` exclude this target.
 * npm skips them for ordinary dependencies but installs every platform build
 * inside a shrinkwrapped dependency (Pi shipped one up to 1.0.0), which put
 * all 26 esbuild binaries into each payload. Returns the removed lock paths.
 */
export function removeForeignPlatformPackages(
  root: string,
  platform: string = process.platform,
  arch: string = process.arch,
): string[] {
  const lock = JSON.parse(
    readFileSync(join(root, "package-lock.json"), "utf8"),
  ) as {
    packages?: Record<
      string,
      { optional?: boolean; os?: string[]; cpu?: string[] }
    >;
  };
  const removed: string[] = [];
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path.startsWith("node_modules/") || entry.optional !== true) continue;
    if (supports(entry.os, platform) && supports(entry.cpu, arch)) continue;
    rmSync(join(root, ...path.split("/")), { recursive: true, force: true });
    removed.push(path);
  }
  return removed;
}
/** npm's `os`/`cpu` rule: `!value` excludes; any plain value must match. */
function supports(values: readonly string[] | undefined, value: string) {
  if (!values?.length) return true;
  if (values.includes(`!${value}`)) return false;
  const allowed = values.filter((item) => !item.startsWith("!"));
  return allowed.length === 0 || allowed.includes(value);
}
/** JS source maps and TypeScript declaration files, by file name. */
const RUNTIME_IRRELEVANT = /\.(?:map|d\.ts|d\.mts|d\.cts)$/;
export const isRuntimeIrrelevant = (name: string): boolean =>
  RUNTIME_IRRELEVANT.test(name);
/**
 * Remove files a running Node process never reads — JS source maps and
 * TypeScript declaration files — before the payload inventory is computed.
 * A PiShip payload ships ~17k files and over half are exactly these; on
 * Windows Defender real-time-scans every extracted file, so stripping them
 * roughly halves first-install extraction time and shrinks the download.
 * Markdown is deliberately kept: Pi embeds `.md` prompt templates at run time.
 * Returns the removed paths, `/`-separated and relative to `root`.
 */
export function stripRuntimeIrrelevant(root: string): string[] {
  const removed: string[] = [];
  /** Returns whether `directory` itself was removed, having been emptied. */
  const visit = (directory: string, prefix: string): boolean => {
    let changed = false;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (visit(path, `${prefix}${entry.name}/`)) changed = true;
      } else if (entry.isFile() && isRuntimeIrrelevant(entry.name)) {
        rmSync(path);
        removed.push(`${prefix}${entry.name}`);
        changed = true;
      }
    }
    // A directory only declarations lived in is left out, as a build from a
    // runtime cache never creates it.
    if (!changed || !prefix || readdirSync(directory).length > 0) return false;
    rmdirSync(directory);
    return true;
  };
  visit(root, "");
  return removed;
}
/**
 * One of a payload's own JSON files, named by its inventory path (always with
 * `/`, so the message reads the same on every system). A file that is missing, not JSON, or not
 * the shape every reader expects is a damaged payload, reported with the file
 * and the repair, not as a parser or type error.
 */
function payloadJson<T>(
  root: string,
  file: string,
  valid: (value: unknown) => value is T,
  /** The file's text, when the caller has read it already. */
  text?: string,
): T {
  const path = join(root, file);
  let reason: string;
  try {
    const value: unknown = JSON.parse(text ?? readFileSync(path, "utf8"));
    if (valid(value)) return value;
    reason = "does not have the expected content";
  } catch (error) {
    reason =
      error instanceof SyntaxError
        ? "is not valid JSON"
        : (error as NodeJS.ErrnoException).code === "ENOENT"
          ? "is missing"
          : `cannot be read (${(error as NodeJS.ErrnoException).code ?? "error"})`;
  }
  throw new PiShipError("INTEGRITY_FAILED", `${file} in ${root} ${reason}`, {
    component: "payload",
    userAction: repairAction(root),
  });
}
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isTarget = (
  value: unknown,
): value is { platform: string; arch: string } =>
  isRecord(value) &&
  typeof value.platform === "string" &&
  typeof value.arch === "string";
export function verifyPayload(directory: string): DistributionLock {
  return verifyPayloadContents(directory, {
    requireTarget: true,
    verifyContents: true,
  });
}
/**
 * Inventory, manifest, lock, and npm lock verification of a payload. Without
 * `requireTarget`, a consumer on another OS/CPU can still verify it. Set
 * `verifyContents: false` to skip the per-file content hash and keep only the
 * manifest/lock/npm-lock bindings and the target check; install, update,
 * rollback, and doctor never do.
 */
export function verifyPayloadContents(
  directory: string,
  options: {
    readonly requireTarget?: boolean;
    readonly verifyContents?: boolean;
    /** Warn about, rather than fail on, files the inventory does not list. */
    readonly tolerateAdded?: boolean;
  } = {},
): DistributionLock {
  const started = process.hrtime.bigint();
  const root = resolve(directory);
  let fileCount = 0;
  if (options.verifyContents !== false) {
    const expected = payloadJson(
      root,
      "metadata/inventory.json",
      (value): value is Record<string, string> =>
        isRecord(value) &&
        Object.values(value).every((entry) => typeof entry === "string"),
    );
    const actual = inventory(root);
    fileCount = Object.keys(actual).length;
    const added = Object.keys(actual).filter((key) => !(key in expected));
    const missing = Object.keys(expected).filter((key) => !(key in actual));
    const modified = Object.keys(actual).filter(
      (key) => key in expected && expected[key] !== actual[key],
    );
    // Only names Node never loads: anything else added (a .js beside a
    // directory, a nested node_modules) could shadow the release's code.
    if (
      added.length &&
      !missing.length &&
      !modified.length &&
      options.tolerateAdded &&
      added.every((name) =>
        /^(\.DS_Store|Thumbs\.db|desktop\.ini|\._.*)$/.test(
          name.slice(name.lastIndexOf("/") + 1),
        ),
      )
    ) {
      console.error(
        `Warning: ${root} has files that are not part of the release (${added.slice(0, 5).join(", ")}${added.length > 5 ? `, and ${added.length - 5} more` : ""}); continuing. Remove them or run \`piship doctor\` for details.`,
      );
    } else if (added.length || missing.length || modified.length)
      throw payloadIntegrityError(root, { added, modified, missing });
  }
  const target = payloadJson(root, "metadata/target.json", isTarget);
  if (
    options.requireTarget &&
    (target.platform !== process.platform || target.arch !== process.arch)
  )
    throw new Error(
      `Payload target ${target.platform}/${target.arch} does not match this machine ${process.platform}/${process.arch}; use an artifact built for this target`,
    );
  const lock = payloadJson(
    root,
    "piship.lock",
    (value): value is DistributionLock =>
      isRecord(value) &&
      isRecord(value.manifest) &&
      isRecord(value.app) &&
      isRecord(value.runtime),
  );
  // A payload built before a limit on names existed still verifies.
  const path = join(root, "piship.yaml");
  const source = readManifestSource(path);
  const manifest = parseManifestSource(source, path, { existing: true });
  if (
    !manifestMatchesLock(source, manifest, lock) ||
    JSON.stringify(manifest.app) !== JSON.stringify(lock.app)
  )
    throw new PiShipError(
      "LOCK_INVALID",
      `Installed manifest and lock mismatch in ${root}`,
      { component: "payload", userAction: repairAction(root) },
    );
  if (
    lock.runtime.npmLockSha256 !==
    hash(readFileSync(join(root, "package-lock.json")))
  )
    throw new PiShipError(
      "LOCK_INVALID",
      `Installed npm lock mismatch in ${root}`,
      { component: "payload", userAction: repairAction(root) },
    );
  if (process.env.PISHIP_DEBUG_TIMING === "1")
    process.stderr.write(
      `verifyPayload: ${Number(process.hrtime.bigint() - started) / 1e6} ms (${fileCount} files${options.verifyContents === false ? ", content hash skipped" : ""})\n`,
    );
  return lock;
}
/**
 * Whether the payload manifest is the one its lock digest records. A lock
 * written by PiShip 0.13 or earlier digested an undeclared projectTrust
 * dimension under that release's defaults, so for such a lock the manifest is
 * also checked with those defaults written in. Either way the digest is of
 * the manifest's own content: a change to what it declares fails both.
 */
function manifestMatchesLock(
  source: string,
  manifest: Manifest,
  lock: DistributionLock,
): boolean {
  const recorded = lock.manifest.sha256;
  if (manifestDigest(manifest) === recorded) return true;
  if (!writtenBy013(lock)) return false;
  const legacy = explicitProjectTrust(source, legacyProjectDimensions);
  return (
    legacy !== source &&
    manifestDigest(
      parseManifestSource(legacy, "piship.yaml", { existing: true }),
    ) === recorded
  );
}
/**
 * Whether PiShip 0.13 or earlier wrote this lock. Unreleased builds after it
 * still report 0.13.0, but they pin Pi 1.5.0, and 0.13 pinned Pi 1.1.0.
 */
function writtenBy013(lock: DistributionLock): boolean {
  const atMost = (version: unknown, limit: string): boolean => {
    if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version))
      return false;
    const left = version.split(".").map(Number);
    const right = limit.split(".").map(Number);
    const index = left.findIndex((part, at) => part !== right[at]);
    return index === -1 || (left[index] as number) < (right[index] as number);
  };
  return (
    atMost(lock.runtime.pishipVersion, "0.13.0") &&
    atMost(lock.runtime.version, "1.1.0")
  );
}
/**
 * Load the metadata required to boot. By default a launch never walks the
 * payload or reads its inventory, manifest, or npm lock, but it does hash the
 * one small file that carries the distribution's policy, `piship.lock`,
 * against the digest recorded when the release was installed: an edited lock
 * (a relaxed `policy.enforced`, a changed capability) is refused, and costs
 * one hash of a file of tens of kilobytes however large the payload is. A
 * distribution that declares `runtime.verifyAtLaunch: true` (recorded in its
 * lock) opts into the full verification of the payload, inventory included,
 * at every launch. The target check is constant-cost and prevents a
 * wrong-platform installation from trying to load its native runtime.
 */
export function verifyLaunchPayload(directory: string): DistributionLock {
  const root = resolve(directory);
  const target = payloadJson(
    root,
    "metadata/target.json",
    isTarget,
    readPayloadFile(root, "metadata/target.json").toString("utf8"),
  );
  if (target.platform !== process.platform || target.arch !== process.arch)
    throw new Error(
      `Payload target ${target.platform}/${target.arch} does not match this machine ${process.platform}/${process.arch}; use an artifact built for this target`,
    );
  const bytes = readPayloadFile(root, "piship.lock");
  checkInstalledLock(root, bytes);
  const lock = JSON.parse(bytes.toString("utf8")) as DistributionLock;
  if (lock.verifyAtLaunch === true)
    return verifyPayloadContents(root, {
      requireTarget: true,
      verifyContents: true,
      tolerateAdded: true,
    });
  checkFilesPresent(root);
  return lock;
}

/**
 * A file every launch reads. One that is missing or empty (a power loss or
 * a crash can leave a file of a recent write at length zero) is an
 * integrity failure with the repair command, not a raw ENOENT or a JSON
 * parse error.
 */
function readPayloadFile(root: string, relative: string): Buffer {
  let bytes: Buffer;
  try {
    bytes = readFileSync(join(root, relative));
  } catch (error) {
    if (
      ["ENOENT", "ENOTDIR"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      )
    )
      throw payloadIntegrityError(root, {
        added: [],
        modified: [],
        missing: [relative],
      });
    throw error;
  }
  if (bytes.length === 0)
    throw payloadIntegrityError(root, {
      added: [],
      modified: [`${relative} (empty)`],
      missing: [],
    });
  return bytes;
}

const EMPTY_SHA256 = hash("");

/**
 * Whether the installed payload at `root` of this install home is checked
 * once per boot: every file the inventory names must exist and, unless the
 * inventory records the empty file, be non-empty. This stats the files and
 * hashes nothing; it finds what a power loss leaves (missing or zero-length
 * files) in about a hundred milliseconds, so it is not repeated at every
 * launch. A marker in the distribution's cache directory records the boot it
 * ran in; without that directory (the first launch) it runs again.
 */
function checkFilesPresent(root: string): void {
  const id = basename(dirname(root));
  if (!sameDirectory(dirname(dirname(root)), join(installHome(), "apps")))
    return;
  let marker: string | undefined;
  const boot = Math.round(Date.now() - uptime() * 1000);
  try {
    const cache = join(runtimeStateDirectory({ value: id }), "cache");
    if (existsSync(cache)) marker = join(cache, "payload-files.json");
  } catch {
    return;
  }
  if (marker) {
    try {
      const seen = JSON.parse(readFileSync(marker, "utf8")) as {
        boot?: number;
        payload?: string;
      };
      if (
        seen.payload === root &&
        typeof seen.boot === "number" &&
        Math.abs(seen.boot - boot) < 120_000
      )
        return;
    } catch {
      // No marker yet.
    }
  }
  let expected: Record<string, string>;
  try {
    const value: unknown = JSON.parse(
      readFileSync(join(root, "metadata", "inventory.json"), "utf8"),
    );
    if (
      !isRecord(value) ||
      !Object.values(value).every((entry) => typeof entry === "string")
    )
      throw new TypeError("not an inventory");
    expected = value as Record<string, string>;
  } catch {
    throw payloadIntegrityError(root, {
      added: [],
      modified: ["metadata/inventory.json (empty or unreadable)"],
      missing: [],
    });
  }
  const missing: string[] = [];
  const modified: string[] = [];
  for (const [path, digest] of Object.entries(expected)) {
    const stat = lstatSync(join(root, path), { throwIfNoEntry: false });
    if (!stat) missing.push(path);
    else if (stat.size === 0 && digest !== EMPTY_SHA256)
      modified.push(`${path} (empty)`);
  }
  if (missing.length || modified.length)
    throw payloadIntegrityError(root, { added: [], modified, missing });
  if (marker)
    try {
      writeFileSync(marker, JSON.stringify({ boot, payload: root }));
    } catch {
      // Checked again at the next launch.
    }
}

function sameDirectory(a: string, b: string): boolean {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
}

/**
 * An installed release's lock must be the file that was installed: its
 * digest is recorded in the install receipt, from the signed release
 * metadata (`release.lockSha256`) or, for a payload directory, from the
 * install itself. Only a payload at `apps/<id>/<version>` of this install
 * home is bound; a build directory, a release the receipt does not list, a
 * receipt that cannot be read (the installed launcher would not have started
 * it), and an installation from before the digest was recorded have nothing
 * to compare with and are not refused here.
 */
function checkInstalledLock(root: string, bytes: Buffer): void {
  const id = basename(dirname(root));
  if (!sameDirectory(dirname(dirname(root)), join(installHome(), "apps")))
    return;
  let expected: string | undefined;
  let version: string | undefined;
  try {
    const entry = readInstallReceipt(id).releases.find((item) =>
      sameDirectory(item.payload, root),
    );
    expected = entry?.release?.lockSha256 ?? entry?.lockSha256;
    version = entry?.version;
  } catch {
    return;
  }
  if (!expected) return;
  const actual = hash(bytes);
  if (actual !== expected)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `The installed piship.lock of ${id} ${version} is not the one that was installed (SHA-256 ${actual.slice(0, 12)}, recorded ${expected.slice(0, 12)}); its policy cannot be trusted`,
      {
        component: "payload",
        userAction: repairAction(root),
        sanitizedDetail: { payload: root, expected, actual },
      },
    );
}
// Doctor only needs the command name here. Full integrity verification belongs
// to explicit diagnostics and release qualification.
export function payloadApp(directory: string): DistributionLock["app"] {
  try {
    const lock = JSON.parse(
      readFileSync(join(resolve(directory), "piship.lock"), "utf8"),
    ) as DistributionLock;
    const command = lock.app?.command;
    if (command && COMMAND_NAME.test(command)) return lock.app;
  } catch {
    // Malformed metadata cannot identify this distribution.
  }
  throw payloadIntegrityError();
}
// A payload that differs from its inventory: the same INTEGRITY_FAILED a
// release artifact reports, naming each offending path as unexpected (not in
// the inventory), modified, or missing. A lock that no longer describes the
// payload's manifest or npm lock is LOCK_INVALID, as at the release gate.
function payloadIntegrityError(
  root?: string,
  diff?: Readonly<Record<"added" | "modified" | "missing", string[]>>,
): PiShipError {
  const shown = (label: string, paths: readonly string[]) =>
    paths.length
      ? `${label}: ${paths.slice(0, 5).join(", ")}${paths.length > 5 ? ` and ${paths.length - 5} more` : ""}`
      : undefined;
  const parts = diff
    ? [
        shown("unexpected (not in the inventory)", diff.added),
        shown("modified", diff.modified),
        shown("missing", diff.missing),
      ].filter(Boolean)
    : [];
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Installed payload integrity mismatch${root ? ` in ${root}` : ""}${parts.length ? `; ${parts.join("; ")}` : ""}`,
    {
      component: "payload",
      userAction: repairAction(
        root,
        diff && !diff.modified.length && !diff.missing.length,
      ),
      ...(diff
        ? {
            sanitizedDetail: {
              payload: root,
              added: diff.added.slice(0, 50),
              modified: diff.modified.slice(0, 50),
              missing: diff.missing.slice(0, 50),
            },
          }
        : {}),
    },
  );
}
/** Whether the receipt records `version` of `id` as composed from a Company Pack, which has no release archive. */
export function installedFromPack(id: string, version: string): boolean {
  try {
    return Boolean(
      readInstallReceipt(id).releases.find((item) => item.version === version)
        ?.release?.pack,
    );
  } catch {
    return false;
  }
}
/** How to restore a release installed from a Company Pack: from that pack and the runtime archive it pins. */
export function packRepairAction(id: string, version: string): string {
  return `download the ${version} pack and the runtime archive it pins from the distribution's update source (its channel file names both), then run: piship repair ${id} <pack archive> --runtime <runtime archive> (--runtime may be omitted when the runtime archive is beside the pack)`;
}
/**
 * How to recover a payload that fails verification without running it. The
 * id is named when the payload is an installed release, `apps/<id>/<version>`.
 * A personal user may have no PiShip CLI, so the copy inside the downloaded
 * release is named too; only unexpected files can also just be removed.
 */
function repairAction(root?: string, onlyUnexpected = false): string {
  const id = root && basename(dirname(root));
  const installed =
    root &&
    basename(dirname(dirname(root))) === "apps" &&
    COMMAND_NAME.test(id as string);
  const name = installed ? id : "<id>";
  if (installed && installedFromPack(id as string, basename(root)))
    return `Do not run it. ${onlyUnexpected ? "Remove the unexpected files it names, or restore" : "Restore"} it from the same version's Company Pack: ${packRepairAction(id as string, basename(root))} (repair does not run this payload; never run its piship.mjs)`;
  return `Do not run it. ${onlyUnexpected ? "Remove the unexpected files it names, or restore" : "Restore"} it from a trusted release of the same version: download that version's release archive for this computer from the distribution's update source (its channel file names the archive), extract it, and run: node <extracted release>/payload/piship.mjs repair ${name} <extracted release>; with the PiShip CLI: piship repair ${name} <release archive> (repair does not run this payload; never run its piship.mjs). A payload that is not installed must be rebuilt or downloaded again`;
}
/**
 * Compare the SHA-256 of every payload file, computed from the bytes as they
 * were written (an archive extraction or a directory copy), with the payload's
 * own inventory: no file modified, none missing, none the inventory does not
 * name. The inventory file itself is bound separately, by the digest the
 * release records for it. Names the first offending paths with the expected
 * and the actual digest.
 */
export function verifyWrittenPayload(
  digests: ReadonlyMap<string, string>,
  expected: Readonly<Record<string, string>>,
  where: string,
): void {
  const written = new Map(
    [...digests].filter(([path]) => path !== "metadata/inventory.json"),
  );
  const problems: string[] = [];
  for (const [path, actual] of written) {
    const wanted = expected[path];
    if (wanted === undefined) problems.push(`unexpected: ${path}`);
    else if (wanted !== actual)
      problems.push(
        `modified: ${path} (expected ${wanted.slice(0, 16)}, actual ${actual.slice(0, 16)})`,
      );
  }
  for (const path of Object.keys(expected))
    if (!written.has(path)) problems.push(`missing: ${path}`);
  if (problems.length > 0)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Payload integrity mismatch in ${where}; ${problems.slice(0, 5).join("; ")}${problems.length > 5 ? `; and ${problems.length - 5} more` : ""}`,
      {
        component: "payload",
        userAction:
          "Do not install this artifact; obtain it again from the trusted source",
      },
    );
}
