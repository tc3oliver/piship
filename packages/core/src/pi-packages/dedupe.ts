// Shared copies of identical dependencies across the vendored Pi packages.
//
// Every Pi package is installed into its own npm root (`pi-packages/<id>`), so
// a dependency several packages use is on disk once per package. A copy is
// shared only when every copy is the same package: the same name, the same
// version, the same registry integrity, byte-identical content, and nothing
// that depends on the platform or on where the package sits. The real files
// then live once in `pi-packages/.shared/<name>@<version>-<digest>`, and each
// place that had a copy keeps a package-local stand-in: its package.json, its
// license files, and for every file the package's `exports` can reach a one
// line module that forwards to the shared file. Node resolves the dependency
// exactly where it did before (`<id>/node_modules/<name>`), through the same
// `exports` map, and lands in the shared file.
//
// Plain files only: no symlink, junction, or hardlink, so the payload, its
// inventory, and the archive stay what they were (regular files; a link is
// refused), and a zip or tar from Windows needs no privilege to extract.
//
// What is never shared, and keeps its package-local copy: a package that has
// dependencies of its own (they resolve from where the package sits, which a
// shared directory does not reproduce), one without an `exports` map (any
// file in it can be imported by path, so the reachable set is unknown), one
// with native code, WebAssembly, an install script, an `os`/`cpu` field, or
// code that finds files or modules at run time, one whose copies differ in any
// way, and a declared Pi package itself (its files carry locked digests).
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { renameWithRetry } from "../rename-retry.js";
import {
  type EsbuildApi,
  isBuiltin,
  type ModuleInfo,
  relativeTarget,
  runtimeDiscovery,
  type ScanResult,
  scanModulesMany,
} from "./module-scan.js";

/** Where the shared copies live, beside the per-package roots. */
export const SHARED_DIRECTORY = ".shared";

/** Why a package keeps its own copy at every place it is. */
export type RetainedReason =
  | "single-copy"
  | "declared-package"
  | "copies-differ"
  | "no-integrity"
  | "has-dependencies"
  | "no-exports"
  | "unsupported-exports"
  | "bin"
  | "install-script"
  | "platform-specific"
  | "native-or-wasm"
  | "nested-node-modules"
  | "symlink-or-special-file"
  | "unsafe-path"
  | "unparsable"
  | "imports-other-packages"
  | "runtime-discovery"
  | "no-saving";

export interface SharedPackage {
  readonly name: string;
  readonly version: string;
  readonly integrity: string;
  /** Payload-relative, `/`-separated. */
  readonly directory: string;
  /** Payload-relative directories that now hold stand-ins. */
  readonly locations: readonly string[];
  /** Files in the shared directory. */
  readonly files: number;
  /** Files each location keeps. */
  readonly kept: number;
  /** Files no longer on disk. */
  readonly saved: number;
}

export interface RetainedPackage {
  readonly name: string;
  readonly version: string;
  readonly locations: readonly string[];
  readonly reason: RetainedReason;
  readonly detail?: string;
}

export interface DedupeReport {
  readonly shared: readonly SharedPackage[];
  readonly retained: readonly RetainedPackage[];
  readonly filesBefore: number;
  readonly filesAfter: number;
}

export interface DedupeOptions {
  /** Directories that must stay whole: the declared packages' roots. */
  readonly keep?: readonly string[];
  readonly esbuild: EsbuildApi;
}

interface Place {
  readonly id: string;
  readonly directory: string;
  /** Payload-relative to the vendor root, `/`-separated. */
  readonly path: string;
  /** npm lockfile key, `node_modules/a/node_modules/b`. */
  readonly lockKey: string;
  readonly name: string;
  readonly version: string;
}

interface LockEntry {
  readonly integrity?: string;
  readonly os?: unknown;
  readonly cpu?: unknown;
  readonly libc?: unknown;
  readonly optional?: boolean;
  readonly hasInstallScript?: boolean;
  readonly dependencies?: Record<string, string>;
}

const posixPath = (path: string) => path.split(sep).join("/");
const sha256 = (data: Buffer | string) =>
  createHash("sha256").update(data).digest("hex");
const readJson = (path: string): Record<string, unknown> | undefined => {
  try {
    const value = JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
};

/** Every package directory under `<root>/<id>/node_modules`, nested ones too. */
function discover(vendorRoot: string): Place[] {
  const places: Place[] = [];
  const visitModules = (id: string, modules: string, lockPrefix: string) => {
    for (const entry of readdirSync(modules, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      const scoped = entry.name.startsWith("@");
      const names = scoped
        ? readdirSync(join(modules, entry.name), { withFileTypes: true })
            .filter((child) => child.isDirectory())
            .map((child) => `${entry.name}/${child.name}`)
        : [entry.name];
      for (const name of names) {
        const directory = join(modules, ...name.split("/"));
        const manifest = readJson(join(directory, "package.json"));
        const lockKey = `${lockPrefix}node_modules/${name}`;
        if (
          typeof manifest?.name === "string" &&
          typeof manifest.version === "string"
        )
          places.push({
            id,
            directory,
            path: posixPath(relative(vendorRoot, directory)),
            lockKey,
            name: manifest.name,
            version: manifest.version,
          });
        const nested = join(directory, "node_modules");
        if (existsSync(nested)) visitModules(id, nested, `${lockKey}/`);
      }
    }
  };
  for (const entry of readdirSync(vendorRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
    const modules = join(vendorRoot, entry.name, "node_modules");
    if (existsSync(modules)) visitModules(entry.name, modules, "");
  }
  return places.sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
}

/** Every file below `directory`, `/`-separated, or the reason there is none. */
function listFiles(
  directory: string,
): { readonly files: string[] } | { readonly reason: RetainedReason } {
  const files: string[] = [];
  let reason: RetainedReason | undefined;
  const visit = (current: string, prefix: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (reason) return;
      const path = join(current, entry.name);
      if (entry.isSymbolicLink()) reason = "symlink-or-special-file";
      else if (entry.isDirectory()) {
        if (entry.name === "node_modules") reason = "nested-node-modules";
        else visit(path, `${prefix}${entry.name}/`);
      } else if (entry.isFile()) files.push(`${prefix}${entry.name}`);
      else reason = "symlink-or-special-file";
    }
  };
  visit(directory, "");
  return reason ? { reason } : { files: files.sort() };
}

function digestOf(directory: string, files: readonly string[]): string {
  const hash = createHash("sha256");
  for (const file of files) {
    const path = join(directory, ...file.split("/"));
    const mode = lstatSync(path).mode & 0o111 ? "x" : "-";
    hash.update(`${file}\0${mode}\0${sha256(readFileSync(path))}\n`);
  }
  return hash.digest("hex");
}

/** A path segment that survives being written in an ESM specifier unchanged. */
const SAFE_SEGMENT = /^[A-Za-z0-9._@+~-]+$/;

const CODE = /\.(?:js|mjs|cjs)$/;
const DECLARATION = /\.d\.[cm]?ts$/;
const NATIVE = /\.(?:node|wasm|so|dylib|dll|exe|a|o)$/i;
const LICENSE = /^(licen[cs]e|copying|notice)/i;

/** What Node matches under its own conditions; anything else needs a flag nobody passes. */
const ACTIVE_CONDITIONS = new Set([
  "node",
  "import",
  "require",
  "default",
  "module-sync",
  "node-addons",
]);

interface ExportTarget {
  readonly path: string;
  /** Under a condition Node does not set (`@zod/source`, `types`, `browser`). */
  readonly inert: boolean;
}

/** Every string target of an `exports` value, or undefined when its shape is not understood. */
function exportTargets(value: unknown): ExportTarget[] | undefined {
  const targets: ExportTarget[] = [];
  const visit = (item: unknown, inert: boolean): boolean => {
    if (item === null) return true;
    if (typeof item === "string") {
      if (
        !item.startsWith("./") ||
        item.split("/").some((part) => part === ".." || part === "node_modules")
      )
        return false;
      targets.push({ path: item, inert });
      return true;
    }
    if (Array.isArray(item)) return item.every((entry) => visit(entry, inert));
    if (typeof item === "object")
      return Object.entries(item as Record<string, unknown>).every(
        ([key, entry]) =>
          // A folder mapping (`"./features/": "./src/features/"`) is gone from
          // Node, and a null pattern carves an exception out of another one.
          !key.endsWith("/") &&
          !(entry === null && key.includes("*")) &&
          visit(
            entry,
            inert || (!key.startsWith(".") && !ACTIVE_CONDITIONS.has(key)),
          ),
      );
    return false;
  };
  return visit(value, false) ? targets : undefined;
}

/** The files of `files` an `exports` target (a `*` pattern too) names. */
function expandTarget(target: string, files: readonly string[]): string[] {
  const path = target.slice(2);
  if (!path.includes("*")) return files.includes(path) ? [path] : [];
  const pattern = new RegExp(
    `^${path
      .split("*")
      .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".+")}$`,
  );
  return files.filter((file) => pattern.test(file));
}

type Entry =
  | { readonly kind: "copy" }
  | { readonly kind: "cjs" }
  | { readonly kind: "esm"; readonly hasDefault: boolean };

interface Plan {
  /** What each location keeps, by path relative to the package directory. */
  readonly entries: ReadonlyMap<string, Entry>;
  readonly files: readonly string[];
}

type Refusal = { readonly reason: RetainedReason; readonly detail?: string };

/**
 * What the copy at `place` needs before it can be shared: a refusal from what
 * is already known (its files, its package.json, its lockfile entry), or the
 * JavaScript to scan and what to conclude from the scan. The scans of every
 * candidate run together.
 */
interface Pending {
  readonly scan: readonly string[];
  readonly finish: (scan: ScanResult) => Plan | Refusal;
}

function inspect(place: Place, lock: LockEntry | undefined): Pending | Refusal {
  const manifest = readJson(join(place.directory, "package.json")) ?? {};
  const listed = listFiles(place.directory);
  if ("reason" in listed) return { reason: listed.reason };
  const { files } = listed;
  const own = (field: string) => {
    const value = manifest[field];
    return value && typeof value === "object"
      ? Object.keys(value as object).length > 0
      : false;
  };
  if (
    own("dependencies") ||
    own("peerDependencies") ||
    own("optionalDependencies") ||
    own("bundledDependencies") ||
    Array.isArray(manifest.bundledDependencies) ||
    Array.isArray(manifest.bundleDependencies) ||
    (lock?.dependencies && Object.keys(lock.dependencies).length > 0)
  )
    return { reason: "has-dependencies" };
  if (manifest.bin !== undefined) return { reason: "bin" };
  const scripts = (manifest.scripts ?? {}) as Record<string, unknown>;
  if (
    lock?.hasInstallScript ||
    ["preinstall", "install", "postinstall"].some((name) => name in scripts) ||
    files.includes("binding.gyp")
  )
    return { reason: "install-script" };
  if (
    manifest.os !== undefined ||
    manifest.cpu !== undefined ||
    manifest.libc !== undefined ||
    lock?.os !== undefined ||
    lock?.cpu !== undefined ||
    lock?.libc !== undefined ||
    lock?.optional === true
  )
    return { reason: "platform-specific" };
  if (files.some((file) => NATIVE.test(file)))
    return { reason: "native-or-wasm" };
  if (
    !place.name.split("/").every((part) => SAFE_SEGMENT.test(part)) ||
    !place.version.split("/").every((part) => SAFE_SEGMENT.test(part)) ||
    files.some(
      (file) => !file.split("/").every((part) => SAFE_SEGMENT.test(part)),
    )
  )
    return { reason: "unsafe-path" };
  if (manifest.exports === undefined) return { reason: "no-exports" };
  const targets = exportTargets(manifest.exports);
  if (!targets) return { reason: "unsupported-exports" };
  for (const field of ["main", "module"]) {
    const value = manifest[field];
    if (typeof value === "string") {
      const path = posix.normalize(value.replace(/^\.\//, ""));
      if (files.includes(path))
        targets.push({ path: `./${path}`, inert: false });
    }
  }
  const reachable = new Map<string, boolean>();
  for (const target of targets)
    for (const file of expandTarget(target.path, files))
      reachable.set(file, (reachable.get(file) ?? true) && target.inert);
  const entries = new Map<string, Entry>();
  const packageJson = files.filter(
    (file) => posix.basename(file) === "package.json",
  );
  for (const file of packageJson) entries.set(file, { kind: "copy" });
  for (const file of files)
    if (LICENSE.test(file) && !file.includes("/"))
      entries.set(file, { kind: "copy" });
  const code: string[] = [];
  for (const [file, inert] of [...reachable].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    if (entries.has(file)) continue;
    if (file.endsWith(".json") || DECLARATION.test(file)) {
      entries.set(file, { kind: "copy" });
    } else if (CODE.test(file)) code.push(file);
    // A source file only a condition Node does not set reaches is left out.
    else if (!inert) return { reason: "unsupported-exports", detail: file };
  }
  // The package's own scripts: every JavaScript file is scanned, reachable or
  // not, because anything in it is loaded from the shared directory.
  const scripted = files.filter((file) => CODE.test(file));
  const finish = (scan: ScanResult): Plan | Refusal => {
    const failed = [...scan.failed][0];
    if (failed) return { reason: "unparsable", detail: failed[0] };
    for (const [file, info] of scan.modules) {
      const found = runtimeDiscovery(info.source);
      if (found)
        return { reason: "runtime-discovery", detail: `${file}: ${found}` };
      for (const item of info.imports) {
        const spec = item.specifier;
        if (spec.startsWith(".")) {
          if (!relativeTarget(file, spec))
            return {
              reason: "imports-other-packages",
              detail: `${file}: ${spec}`,
            };
        } else if (
          !isBuiltin(spec) &&
          !spec.startsWith("#") &&
          spec !== place.name &&
          !spec.startsWith(`${place.name}/`)
        )
          return {
            reason: "imports-other-packages",
            detail: `${file}: ${spec}`,
          };
      }
    }
    for (const file of code) {
      const info = scan.modules.get(file) as ModuleInfo;
      const nearest = (() => {
        for (
          let directory = posix.dirname(file);
          ;
          directory = posix.dirname(directory)
        ) {
          const candidate =
            directory === "." ? "package.json" : `${directory}/package.json`;
          if (files.includes(candidate)) {
            const type = readJson(
              join(place.directory, ...candidate.split("/")),
            )?.type;
            return type;
          }
          if (directory === ".") return undefined;
        }
      })();
      const esm =
        file.endsWith(".mjs") ||
        (file.endsWith(".js") &&
          (nearest === "module" ||
            (nearest !== "commonjs" && info.format === "esm")));
      entries.set(
        file,
        esm
          ? { kind: "esm", hasDefault: info.exports.includes("default") }
          : { kind: "cjs" },
      );
    }
    return { entries, files };
  };
  return { scan: scripted, finish };
}

const specifier = (from: string, to: string): string => {
  const path = posix.relative(posix.dirname(from), to);
  return path.startsWith(".") ? path : `./${path}`;
};

function stubSource(entry: Entry, target: string): string {
  const quoted = JSON.stringify(target);
  if (entry.kind === "cjs") return `module.exports = require(${quoted});\n`;
  if (entry.kind === "esm")
    return `export * from ${quoted};\n${entry.hasDefault ? `export { default } from ${quoted};\n` : ""}`;
  return "";
}

/**
 * Share every dependency the vendored packages hold identical copies of, under
 * `vendorRoot` (`<payload>/pi-packages`). Idempotent only for a fresh tree: a
 * second run finds stand-ins, which differ from one another and are kept.
 */
export function dedupePiPackages(
  vendorRoot: string,
  options: DedupeOptions,
): DedupeReport {
  const keep = new Set((options.keep ?? []).map((path) => resolve(path)));
  const places = discover(vendorRoot).filter(
    (place) => !keep.has(resolve(place.directory)),
  );
  const lockfiles = new Map<string, Record<string, LockEntry>>();
  const lockEntry = (place: Place): LockEntry | undefined => {
    let packages = lockfiles.get(place.id);
    if (!packages) {
      packages =
        (readJson(join(vendorRoot, place.id, "package-lock.json"))?.packages as
          | Record<string, LockEntry>
          | undefined) ?? {};
      lockfiles.set(place.id, packages);
    }
    return packages[place.lockKey];
  };
  const countFiles = (directory: string): number => {
    let total = 0;
    for (const entry of readdirSync(directory, { withFileTypes: true }))
      total += entry.isDirectory()
        ? countFiles(join(directory, entry.name))
        : 1;
    return total;
  };
  const filesBefore = countFiles(vendorRoot);
  const shared: SharedPackage[] = [];
  const retained: RetainedPackage[] = [];
  const candidates: { same: Place[]; pending: Pending }[] = [];
  const retain = (
    group: readonly Place[],
    reason: RetainedReason,
    detail?: string,
  ) =>
    retained.push({
      name: (group[0] as Place).name,
      version: (group[0] as Place).version,
      locations: group.map((place) => place.path),
      reason,
      ...(detail ? { detail } : {}),
    });
  for (const group of byNameVersion(places)) {
    const [first] = group;
    if (!first) continue;
    if (group.length < 2) {
      retain(group, "single-copy");
      continue;
    }
    // The registry's integrity first, then the bytes themselves.
    const identical = new Map<string, Place[]>();
    const unlocked: Place[] = [];
    for (const place of group) {
      const integrity = lockEntry(place)?.integrity;
      if (!integrity) {
        unlocked.push(place);
        continue;
      }
      const listed = listFiles(place.directory);
      if ("reason" in listed) {
        retain([place], listed.reason);
        continue;
      }
      const key = `${integrity}\0${digestOf(place.directory, listed.files)}`;
      identical.set(key, [...(identical.get(key) ?? []), place]);
    }
    if (unlocked.length) retain(unlocked, "no-integrity");
    const sets = [...identical.values()];
    for (const same of sets) {
      if (same.length < 2) {
        retain(same, sets.length > 1 ? "copies-differ" : "single-copy");
        continue;
      }
      const representative = same[0] as Place;
      const inspected = inspect(representative, lockEntry(representative));
      if ("reason" in inspected)
        retain(same, inspected.reason, inspected.detail);
      else candidates.push({ same, pending: inspected });
    }
  }
  // Every candidate's JavaScript is read in one pass, before any file moves.
  const scans = scanModulesMany(
    options.esbuild,
    candidates.map(({ same, pending }) => ({
      root: (same[0] as Place).directory,
      files: pending.scan,
    })),
  );
  candidates.forEach(({ same, pending }, index) => {
    const representative = same[0] as Place;
    const verdict = pending.finish(scans[index] as ScanResult);
    if ("reason" in verdict) {
      retain(same, verdict.reason, verdict.detail);
      return;
    }
    const kept = verdict.entries.size;
    const saved = (same.length - 1) * verdict.files.length - same.length * kept;
    if (saved <= 0) {
      retain(same, "no-saving");
      return;
    }
    const integrity = lockEntry(representative)?.integrity as string;
    // The name carries the registry integrity as well as the bytes: the same
    // bytes under two integrities are two sets and need two directories.
    const digest = sha256(
      `${integrity}\0${digestOf(representative.directory, verdict.files)}`,
    ).slice(0, 12);
    const directory = `${SHARED_DIRECTORY}/${representative.name.replace("/", "+")}@${representative.version}-${digest}`;
    const target = join(vendorRoot, ...directory.split("/"));
    // A name another set already took (a prefix collision) is never mixed
    // into: this set keeps its package-local copies.
    if (existsSync(target)) {
      retain(same, "copies-differ", `${directory} is another set's`);
      return;
    }
    mkdirSync(dirname(target), { recursive: true });
    renameWithRetry(representative.directory, target);
    for (const place of same) {
      if (place !== representative)
        rmSync(place.directory, { recursive: true, force: true });
      mkdirSync(place.directory, { recursive: true });
      for (const [file, entry] of verdict.entries) {
        const destination = join(place.directory, ...file.split("/"));
        mkdirSync(dirname(destination), { recursive: true });
        if (entry.kind === "copy")
          copyFileSync(join(target, ...file.split("/")), destination);
        else
          writeFileSync(
            destination,
            stubSource(
              entry,
              specifier(`${place.path}/${file}`, `${directory}/${file}`),
            ),
          );
      }
    }
    shared.push({
      name: representative.name,
      version: representative.version,
      integrity,
      directory: `pi-packages/${directory}`,
      locations: same.map((place) => `pi-packages/${place.path}`),
      files: verdict.files.length,
      kept,
      saved,
    });
  });
  const sortedRetained = retained
    .map((item) => ({
      ...item,
      locations: item.locations.map((path) => `pi-packages/${path}`),
    }))
    .sort((a, b) =>
      `${a.name}@${a.version}${a.reason}` < `${b.name}@${b.version}${b.reason}`
        ? -1
        : 1,
    );
  return {
    shared: shared.sort((a, b) => (a.directory < b.directory ? -1 : 1)),
    retained: sortedRetained,
    filesBefore,
    filesAfter: countFiles(vendorRoot),
  };
}

function byNameVersion(places: readonly Place[]): Place[][] {
  const groups = new Map<string, Place[]>();
  for (const place of places) {
    const key = `${place.name}@${place.version}`;
    groups.set(key, [...(groups.get(key) ?? []), place]);
  }
  return [...groups.values()];
}
