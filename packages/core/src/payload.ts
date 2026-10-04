import { lstatSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
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
  const added = Object.keys(actual).filter((key) => !(key in expected));
  const missing = Object.keys(expected).filter((key) => !(key in actual));
  const modified = Object.keys(actual).filter(
    (key) => key in expected && expected[key] !== actual[key],
  );
  if (added.length || missing.length || modified.length)
    throw payloadIntegrityError(root, { added, modified, missing });
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
