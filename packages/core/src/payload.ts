import { lstatSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { PiShipError } from "@piship/contracts";
import { readManifest } from "@piship/schema";
import { hash } from "./digest.js";
import { manifestDigest } from "./lock.js";
import type { DistributionLock } from "./lock-schema.js";

/** SHA-256 of every payload file except the inventory itself, by `/` path. */
export function payloadInventory(root: string): Record<string, string> {
  return inventory(root);
}
export function inventory(root: string): Record<string, string> {
  const output: Record<string, string> = {};
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      const key = relative(root, path).split(sep).join("/");
      if (stat.isSymbolicLink())
        throw new Error(`Payload symlink is not allowed: ${key}`);
      if (stat.isDirectory()) visit(path);
      else if (stat.isFile() && key !== "metadata/inventory.json")
        output[key] = hash(readFileSync(path));
      else if (!stat.isFile())
        throw new Error(`Unsupported payload entry: ${key}`);
    }
  };
  visit(root);
  return output;
}
export function removeNpmBins(directory: string): void {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (name === ".bin") rmSync(path, { recursive: true, force: true });
    else if (lstatSync(path).isDirectory()) removeNpmBins(path);
  }
}
/**
 * Remove optional packages whose npm lock `os`/`cpu` exclude this target.
 * npm skips them for ordinary dependencies but installs every platform build
 * inside a shrinkwrapped dependency (Pi ships one), which put all 26 esbuild
 * binaries into each payload. Returns the removed lock paths.
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
export function verifyPayload(directory: string): DistributionLock {
  return verifyPayloadContents(directory, { requireTarget: true });
}
/**
 * Inventory, manifest, lock, and npm lock verification of a payload. Without
 * `requireTarget`, a consumer on another OS/CPU can still verify it.
 */
export function verifyPayloadContents(
  directory: string,
  options: { readonly requireTarget?: boolean } = {},
): DistributionLock {
  const started = process.hrtime.bigint();
  const root = resolve(directory);
  const inventoryPath = join(root, "metadata", "inventory.json");
  const expected = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
    string,
    string
  >;
  const actual = inventory(root);
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    throw payloadIntegrityError();
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
      "Installed manifest and lock mismatch; reinstall this distribution",
      { component: "payload" },
    );
  if (
    lock.runtime.npmLockSha256 !==
    hash(readFileSync(join(root, "package-lock.json")))
  )
    throw new PiShipError(
      "LOCK_INVALID",
      "Installed npm lock mismatch; reinstall this distribution",
      { component: "payload" },
    );
  if (process.env.PISHIP_DEBUG_TIMING === "1")
    process.stderr.write(
      `verifyPayload: ${Number(process.hrtime.bigint() - started) / 1e6} ms (${Object.keys(actual).length} files)\n`,
    );
  return lock;
}
// Doctor only needs the command name here. The launcher performs the complete
// integrity verification before importing Pi, including this lockfile.
export function payloadApp(directory: string): DistributionLock["app"] {
  try {
    const lock = JSON.parse(
      readFileSync(join(resolve(directory), "piship.lock"), "utf8"),
    ) as DistributionLock;
    const command = lock.app?.command;
    if (command && /^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/.test(command))
      return lock.app;
  } catch {
    // The launcher will verify the complete payload for a well-formed lock.
  }
  throw payloadIntegrityError();
}
// A payload file whose digest differs from the inventory: the same
// INTEGRITY_FAILED a release artifact reports. A lock that no longer describes
// the payload's manifest or npm lock is LOCK_INVALID, as at the release gate.
function payloadIntegrityError(): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    "Installed payload integrity mismatch; reinstall this distribution",
    { component: "payload" },
  );
}
