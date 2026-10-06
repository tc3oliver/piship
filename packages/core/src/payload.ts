import { readdirSync, readFileSync, rmdirSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { readManifest } from "@piship/schema";
import { hash } from "./digest.js";
import { manifestDigest } from "./lock.js";
import type { DistributionLock } from "./lock-schema.js";

/** SHA-256 of every payload file except the inventory itself, by `/` path. */
export function payloadInventory(root: string): Record<string, string> {
  return inventory(root);
}
const byName = (a: { name: string }, b: { name: string }) =>
  a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
/**
 * The inventory of `root`. `known` carries digests a verified source (a cache
 * entry that was hashed when it was created) already holds; a file listed
 * there is not read again. Every other file is hashed from its bytes.
 */
export function inventory(
  root: string,
  known: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const output: Record<string, string> = {};
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      byName,
    )) {
      const key = `${prefix}${entry.name}`;
      if (entry.isSymbolicLink())
        throw new Error(`Payload symlink is not allowed: ${key}`);
      if (entry.isDirectory()) visit(join(directory, entry.name), `${key}/`);
      else if (entry.isFile() && key !== "metadata/inventory.json")
        output[key] = Object.hasOwn(known, key)
          ? (known[key] as string)
          : hash(readFileSync(join(directory, entry.name)));
      else if (!entry.isFile())
        throw new Error(`Unsupported payload entry: ${key}`);
    }
  };
  visit(root, "");
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
  } = {},
): DistributionLock {
  const started = process.hrtime.bigint();
  const root = resolve(directory);
  const inventoryPath = join(root, "metadata", "inventory.json");
  let fileCount = 0;
  if (options.verifyContents !== false) {
    const expected = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
      string,
      string
    >;
    const actual = inventory(root);
    fileCount = Object.keys(actual).length;
    const added = Object.keys(actual).filter((key) => !(key in expected));
    const missing = Object.keys(expected).filter((key) => !(key in actual));
    const modified = Object.keys(actual).filter(
      (key) => key in expected && expected[key] !== actual[key],
    );
    if (added.length || missing.length || modified.length)
      throw payloadIntegrityError(root, { added, modified, missing });
  }
  const target = JSON.parse(
    readFileSync(join(root, "metadata", "target.json"), "utf8"),
  ) as { platform: string; arch: string };
  if (
    options.requireTarget &&
    (target.platform !== process.platform || target.arch !== process.arch)
  )
    throw new Error(
      `Payload target ${target.platform}/${target.arch} does not match this machine ${process.platform}/${process.arch}; use an artifact built for this target`,
    );
  const lock = JSON.parse(
    readFileSync(join(root, "piship.lock"), "utf8"),
  ) as DistributionLock;
  const manifest = readManifest(join(root, "piship.yaml"));
  if (
    manifestDigest(manifest) !== lock.manifest.sha256 ||
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
 * Load the metadata required to boot. Launch never walks the payload or reads
 * its inventory, manifest, or npm lock, including for older manifests that
 * declare verifyAtLaunch. Full verification is an explicit diagnostic/release
 * operation. The target check is constant-cost and prevents a wrong-platform
 * installation from trying to load its native runtime.
 */
export function verifyLaunchPayload(directory: string): DistributionLock {
  const root = resolve(directory);
  const target = JSON.parse(
    readFileSync(join(root, "metadata", "target.json"), "utf8"),
  ) as { platform: string; arch: string };
  if (target.platform !== process.platform || target.arch !== process.arch)
    throw new Error(
      `Payload target ${target.platform}/${target.arch} does not match this machine ${process.platform}/${process.arch}; use an artifact built for this target`,
    );
  return JSON.parse(
    readFileSync(join(root, "piship.lock"), "utf8"),
  ) as DistributionLock;
}
// Doctor only needs the command name here. Full integrity verification belongs
// to explicit diagnostics and release qualification.
export function payloadApp(directory: string): DistributionLock["app"] {
  try {
    const lock = JSON.parse(
      readFileSync(join(resolve(directory), "piship.lock"), "utf8"),
    ) as DistributionLock;
    const command = lock.app?.command;
    if (command && /^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(command))
      return lock.app;
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
    /^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(id as string);
  const name = installed ? id : "<id>";
  return `Do not run it. ${onlyUnexpected ? "Remove the unexpected files it names, or restore" : "Restore"} it from a trusted release of the same version with: piship repair ${name} <release archive>, or without a PiShip CLI: node <extracted release>/payload/piship.mjs repair ${name} <extracted release> (repair does not run this payload; never run its piship.mjs). A payload that is not installed must be rebuilt or downloaded again`;
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
