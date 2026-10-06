// An immutable store for the runtime a release assembles: the npm-installed
// dependency tree and, for a bundled release, its bundled form. Entries are
// content-addressed by everything that decides their bytes, published whole
// by one directory rename, and never modified afterwards, so concurrent
// builds cannot corrupt one another. The store lives under PiShip's user
// cache directory, outside any project or output tree a sandboxed command may
// write.
//
// Only runtime bytes are cached. A release always regenerates its audit,
// SBOM, notices, signature check, smoke tests, and archive from the payload it
// assembles.
import {
  constants,
  copyFileSync,
  type Dirent,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { buildInputDigest, safePath } from "./build-cache.js";
import { canonicalJson, hash } from "./digest.js";
import type { DistributionLock } from "./lock-schema.js";
import { isRuntimeIrrelevant } from "./payload.js";
import { buildInput } from "./runtime-dependencies.js";
import { searchToolCacheDirectory } from "./search-tools/index.js";

const SCHEMA = "piship-runtime-cache/v1";
const RECORD = "entry.json";
/** Entries kept per kind; older ones are evicted when a new one is published. */
const KEEP = { install: 3, bundle: 6 } as const;
const ABANDONED_MS = 24 * 60 * 60 * 1000;
/** What a build spends deleting evicted entries after it published one, and after a hit. */
const DISCARD_BUDGET_MS = { published: 2000, hit: 500 } as const;

export interface RuntimeCache {
  /** Directory holding every entry. */
  readonly root: string;
  /**
   * What decides the installed tree's bytes: the PiShip build input digest,
   * the distribution lock's runtime section (Pi version and the npm lock),
   * the platform and CPU, and Node's major.minor.
   */
  readonly key: string;
  /** `release.strip`: the payload leaves out maps and declarations. */
  readonly strip: boolean;
}

/** The runtime cache a build of `lock` on this machine reads and fills. */
export function runtimeCacheFor(
  lock: DistributionLock,
  env: NodeJS.ProcessEnv = process.env,
): RuntimeCache {
  const [major, minor] = process.versions.node.split(".");
  return {
    root: join(dirname(searchToolCacheDirectory(env)), "runtime"),
    key: hash(
      canonicalJson({
        schema: SCHEMA,
        input: buildInputDigest(buildInput),
        runtime: hash(canonicalJson(lock.runtime)),
        platform: process.platform,
        arch: process.arch,
        node: `${major}.${minor}`,
      }),
    ),
    strip: lock.release?.strip === true,
  };
}

/** A name short enough for Windows paths: the key's first 20 hex digits. */
const entryPath = (cache: RuntimeCache, kind: "i" | "b", key: string) =>
  join(cache.root, `${kind}-${key.slice(0, 20)}`);

const code = (error: unknown) => (error as NodeJS.ErrnoException).code;
function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Rename, retrying where Windows briefly refuses it: Defender or the search
 * indexer holds a handle on a file just written, and the rename of its
 * directory fails with EPERM, EBUSY, or EACCES until the handle closes.
 * Every other error, EXDEV included, is immediate.
 */
export function renameWithRetry(from: string, to: string, delayMs = 50): void {
  for (let attempt = 0; ; attempt++) {
    try {
      renameSync(from, to);
      return;
    } catch (error) {
      if (
        process.platform !== "win32" ||
        attempt >= 10 ||
        !["EPERM", "EBUSY", "EACCES"].includes(code(error) ?? "")
      )
        throw error;
      sleep(delayMs * (attempt + 1));
    }
  }
}

/** Regular files under `root`, as `/`-separated relative paths. */
function listFiles(root: string): string[] {
  const found: string[] = [];
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory())
        visit(join(directory, entry.name), `${prefix}${entry.name}/`);
      else if (entry.isFile()) found.push(`${prefix}${entry.name}`);
      else throw new Error(`Unsupported runtime entry: ${prefix}${entry.name}`);
    }
  };
  visit(root, "");
  return found;
}

const inside = (root: string, path: string) => join(root, ...path.split("/"));

function readRecord<T>(entry: string): T | undefined {
  try {
    return JSON.parse(readFileSync(join(entry, RECORD), "utf8")) as T;
  } catch {
    return undefined;
  }
}

/** Mark an entry as recently used, so eviction keeps what builds still need. */
function touch(entry: string): void {
  try {
    const now = new Date();
    utimesSync(join(entry, RECORD), now, now);
  } catch {}
}

function sameNames(
  listed: readonly string[],
  record: Readonly<Record<string, unknown>>,
): boolean {
  const names = Object.keys(record);
  return (
    listed.length === names.length &&
    listed.every((name) => Object.hasOwn(record, name))
  );
}

/** Write `path` whole, or not at all: a concurrent reader never sees half of it. */
function writeOnce(path: string, text: string): void {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(temporary, text);
    renameWithRetry(temporary, path);
  } catch {
    // The derived file is an optimisation; the next build writes it again.
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * Delete `path` until `deadline` (epoch ms), leaving the rest for a later call.
 * Deleting thousands of files takes minutes on Windows, so no build waits for
 * it. Links are removed, never followed. Returns whether `path` is gone.
 */
function removeUntil(path: string, deadline: number): boolean {
  let entries: Dirent[];
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return !existsSync(path);
  }
  for (const entry of entries) {
    if (Date.now() > deadline) return false;
    const child = join(path, entry.name);
    try {
      if (entry.isDirectory()) {
        if (!removeUntil(child, deadline)) return false;
      } else rmSync(child, { force: true });
    } catch {
      return false;
    }
  }
  try {
    rmdirSync(path);
    return true;
  } catch {
    return false;
  }
}

/** Rename an entry out of sight (to a name builds never look up) and report whether it went. */
function hide(path: string): string | undefined {
  const hidden = `${path}.${Date.now().toString(36)}.d`;
  try {
    renameWithRetry(path, hidden);
    return hidden;
  } catch {
    return undefined;
  }
}

/**
 * Hide the entries beyond what the cache keeps (one rename each, so a build
 * that races finds a clean miss), then delete hidden and abandoned
 * directories for a bounded time.
 */
function prune(cache: RuntimeCache, budget: number): void {
  const modified = (path: string): number => {
    try {
      return statSync(path).mtimeMs;
    } catch {
      return 0;
    }
  };
  try {
    const names = readdirSync(cache.root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
    for (const [prefix, keep] of [
      ["i-", KEEP.install],
      ["b-", KEEP.bundle],
    ] as const)
      for (const entry of names
        .filter((name) => name.startsWith(prefix) && !name.endsWith(".d"))
        .map((name) => ({
          name,
          used: modified(join(cache.root, name, RECORD)),
        }))
        .sort((a, b) => b.used - a.used)
        .slice(keep)) {
        const hidden = hide(join(cache.root, entry.name));
        if (hidden) names.push(basename(hidden));
      }
    const deadline = Date.now() + budget;
    for (const name of names)
      if (
        name.endsWith(".d") ||
        (name.startsWith(".t") &&
          Date.now() - modified(join(cache.root, name)) > ABANDONED_MS)
      )
        removeUntil(join(cache.root, name), deadline);
  } catch {
    // Housekeeping never fails a build.
  }
}

/** Take a directory out of the way now and delete as much of it as the budget allows. */
function discard(path: string): void {
  const deadline = Date.now() + DISCARD_BUDGET_MS.published;
  removeUntil(hide(path) ?? path, deadline);
}

/**
 * Publish a fully written directory under `destination`. A lost race is not
 * an error: when `usable` accepts what is already there, that wins and the
 * new directory is discarded. Anything else in the way is replaced.
 */
function publish(
  holding: string,
  destination: string,
  usable: () => boolean,
): "published" | "existing" {
  // Windows cannot rename onto a directory that exists, and retries that
  // refusal, so a name that is already taken is not attempted.
  if (!existsSync(destination))
    try {
      renameWithRetry(holding, destination);
      return "published";
    } catch (error) {
      if (!existsSync(destination)) throw error;
    }
  if (usable()) {
    discard(holding);
    return "existing";
  }
  const stale = hide(destination);
  renameWithRetry(holding, destination);
  if (stale) discard(stale);
  return "published";
}

// --- The installed dependency tree ----------------------------------------

interface InstallRecord {
  readonly schema: string;
  readonly kind: "install";
  readonly key: string;
  readonly platform: string;
  readonly arch: string;
  /** Every file of `tree`, with its size. */
  readonly files: Readonly<Record<string, number>>;
}

export interface InstallTree {
  readonly path: string;
  readonly tree: string;
  readonly files: Readonly<Record<string, number>>;
}

/**
 * The cached tree for `cache.key`, or undefined when there is none or it does
 * not match its record: wrong key, schema, or target, or a file set that
 * differs from the one recorded when it was created.
 */
export function lookupInstallTree(
  cache: RuntimeCache,
): InstallTree | undefined {
  const path = entryPath(cache, "i", cache.key);
  const record = readRecord<InstallRecord>(path);
  if (
    record?.schema !== SCHEMA ||
    record.kind !== "install" ||
    record.key !== cache.key ||
    record.platform !== process.platform ||
    record.arch !== process.arch ||
    !record.files ||
    typeof record.files !== "object" ||
    Array.isArray(record.files) ||
    Object.entries(record.files).some(
      ([name, size]) => !safePath(name) || !Number.isSafeInteger(size),
    )
  )
    return undefined;
  const tree = join(path, "tree");
  try {
    if (!sameNames(listFiles(tree), record.files)) return undefined;
  } catch {
    return undefined;
  }
  touch(path);
  prune(cache, DISCARD_BUDGET_MS.hit);
  return { path, tree, files: record.files };
}

/**
 * Take the entry for `cache.key` out of use. A build calls this for an entry
 * that matches its record but cannot be placed, so the tree it installs
 * instead is published in its place.
 */
export function discardInstallTree(cache: RuntimeCache): void {
  hide(entryPath(cache, "i", cache.key));
}

const ROOT_FILES = ["package.json", "package-lock.json"];

/**
 * Move the installed dependency tree out of `stage` into a new entry, in one
 * rename, and publish it. `stage` then holds none of `node_modules`,
 * `package.json`, or `package-lock.json`: place them again with
 * `materializeInstallTree`. Where the tree cannot be adopted (the cache is on
 * another volume, the rename is refused, or the tree holds a link) `stage` is
 * left as it was and the result is undefined.
 */
export function adoptInstallTree(
  cache: RuntimeCache,
  stage: string,
): InstallTree | undefined {
  let holding: string;
  try {
    mkdirSync(cache.root, { recursive: true });
    holding = mkdtempSync(join(cache.root, ".t"));
  } catch {
    return undefined;
  }
  const destination = entryPath(cache, "i", cache.key);
  const names = ["node_modules", ...ROOT_FILES];
  // Where the moved tree is now, so a failure can put it back.
  let location = join(holding, "tree");
  const moved: string[] = [];
  let given = false;
  try {
    mkdirSync(location);
    for (const name of names) {
      renameWithRetry(join(stage, name), join(location, name));
      moved.push(name);
    }
    const files: Record<string, number> = {};
    for (const name of listFiles(location).sort())
      files[name] = lstatSync(inside(location, name)).size;
    const record: InstallRecord = {
      schema: SCHEMA,
      kind: "install",
      key: cache.key,
      platform: process.platform,
      arch: process.arch,
      files,
    };
    writeFileSync(join(holding, RECORD), JSON.stringify(record));
    const outcome = publish(
      holding,
      destination,
      () => lookupInstallTree(cache) !== undefined,
    );
    // Another build's entry stands in for ours, which is gone.
    if (outcome === "published") location = join(destination, "tree");
    else given = true;
    const adopted = lookupInstallTree(cache);
    if (!adopted) throw new Error("The runtime cache entry is not readable");
    prune(cache, DISCARD_BUDGET_MS.published);
    return adopted;
  } catch (error) {
    // The tree was handed over and cannot be put back.
    if (given) throw error;
    for (const name of moved.reverse())
      try {
        renameWithRetry(join(location, name), join(stage, name));
      } catch {}
    discard(location === join(holding, "tree") ? holding : destination);
    return undefined;
  }
}

/**
 * Place `from` at `to`. A hardlink creates no new bytes and no new content
 * for Windows Defender to scan, and shares them with the cache entry, so
 * nothing may write through the new name; where it is refused (another
 * volume, a file system without links, a link limit) the file is copied
 * instead, as a copy-on-write clone where the volume has them. A copy never
 * replaces an existing file, which could be a link into the cache. Returns
 * whether links are still worth trying.
 */
function place(from: string, to: string, link: boolean): boolean {
  if (link)
    try {
      linkSync(from, to);
      return true;
    } catch {}
  copyFileSync(from, to, constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
  return false;
}

/**
 * Place the cached tree under `target`. With `strip` the maps and
 * declarations are left behind, which is the strip itself: no file is
 * created and then deleted. Every file placed must have the size recorded when
 * the entry was created.
 *
 * With `link` (by default on Windows only) the files are hardlinked from the
 * entry. There every created file is read and scanned by Defender, which makes
 * a link an order of magnitude cheaper than a copy, while macOS and Linux
 * clone or copy a file about as fast as they link it. A linked file shares its
 * bytes with the entry: nothing may write through it, and deleting it only
 * removes the name.
 */
export function materializeInstallTree(
  tree: InstallTree,
  target: string,
  options: { readonly strip: boolean; readonly link?: boolean },
): void {
  const made = new Set<string>();
  let link = options.link ?? process.platform === "win32";
  for (const [name, size] of Object.entries(tree.files)) {
    if (options.strip && isRuntimeIrrelevant(basename(name))) continue;
    const to = inside(target, name);
    const parent = dirname(to);
    if (!made.has(parent)) {
      mkdirSync(parent, { recursive: true });
      made.add(parent);
    }
    link = place(inside(tree.tree, name), to, link);
    if (lstatSync(to).size !== size)
      throw new Error(`The runtime cache entry is damaged: ${name}`);
  }
}

/**
 * The SHA-256 of every file `materializeInstallTree` places, hashed from the
 * entry's bytes once and kept beside it. A payload assembled from the entry
 * takes these instead of reading its files again.
 */
export function plainInventory(
  tree: InstallTree,
  cache: RuntimeCache,
): Record<string, string> {
  const sidecar = join(
    tree.path,
    `plain-${cache.strip ? "stripped" : "full"}.json`,
  );
  const names = Object.keys(tree.files).filter(
    (name) => !cache.strip || !isRuntimeIrrelevant(basename(name)),
  );
  try {
    const record = JSON.parse(readFileSync(sidecar, "utf8")) as {
      schema?: string;
      key?: string;
      strip?: boolean;
      inventory?: Record<string, string>;
    };
    if (
      record.schema === SCHEMA &&
      record.key === cache.key &&
      record.strip === cache.strip &&
      record.inventory &&
      sameNames(names, record.inventory) &&
      Object.values(record.inventory).every((digest) =>
        /^[0-9a-f]{64}$/.test(digest),
      )
    )
      return record.inventory;
  } catch {}
  const inventory: Record<string, string> = {};
  for (const name of names)
    inventory[name] = hash(readFileSync(inside(tree.tree, name)));
  writeOnce(
    sidecar,
    JSON.stringify({
      schema: SCHEMA,
      key: cache.key,
      strip: cache.strip,
      inventory,
    }),
  );
  return inventory;
}

// --- The bundled runtime ---------------------------------------------------

interface BundleRecord {
  readonly schema: string;
  readonly kind: "bundle";
  readonly key: string;
  readonly files: Readonly<Record<string, { size: number; sha256: string }>>;
}

export interface BundleTree {
  readonly tree: string;
  /** SHA-256 of every file, as verified when the entry was read. */
  readonly inventory: Readonly<Record<string, string>>;
}

/**
 * The bundled runtime stored under `key`, with every file's size and content
 * checked against the record made when it was created. These are the bytes
 * that ship, and they are few.
 */
export function lookupBundle(
  cache: RuntimeCache,
  key: string,
): BundleTree | undefined {
  const path = entryPath(cache, "b", key);
  const record = readRecord<BundleRecord>(path);
  if (
    record?.schema !== SCHEMA ||
    record.kind !== "bundle" ||
    record.key !== key ||
    !record.files ||
    typeof record.files !== "object" ||
    Array.isArray(record.files)
  )
    return undefined;
  const tree = join(path, "tree");
  const inventory: Record<string, string> = {};
  try {
    if (!sameNames(listFiles(tree), record.files)) return undefined;
    for (const [name, file] of Object.entries(record.files)) {
      if (!safePath(name)) return undefined;
      const bytes = readFileSync(inside(tree, name));
      if (bytes.length !== file.size || hash(bytes) !== file.sha256)
        return undefined;
      inventory[name] = file.sha256;
    }
  } catch {
    return undefined;
  }
  touch(path);
  return { tree, inventory };
}

/** Publish the bundled files of `payload` (`names`, hashed as `inventory`). */
export function storeBundle(
  cache: RuntimeCache,
  key: string,
  payload: string,
  inventory: Readonly<Record<string, string>>,
  names: readonly string[],
): void {
  let holding: string;
  try {
    mkdirSync(cache.root, { recursive: true });
    holding = mkdtempSync(join(cache.root, ".t"));
  } catch {
    return;
  }
  try {
    const tree = join(holding, "tree");
    const files: Record<string, { size: number; sha256: string }> = {};
    for (const name of names) {
      const to = inside(tree, name);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(inside(payload, name), to);
      files[name] = {
        size: lstatSync(to).size,
        sha256: inventory[name] as string,
      };
    }
    const record: BundleRecord = {
      schema: SCHEMA,
      kind: "bundle",
      key,
      files,
    };
    writeFileSync(join(holding, RECORD), JSON.stringify(record));
    publish(
      holding,
      entryPath(cache, "b", key),
      () => lookupBundle(cache, key) !== undefined,
    );
    prune(cache, DISCARD_BUDGET_MS.published);
  } catch {
    discard(holding);
  }
}

/** Copy the bundled files into `payload`. */
export function placeBundle(bundle: BundleTree, payload: string): void {
  for (const name of Object.keys(bundle.inventory)) {
    const to = inside(payload, name);
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(
      inside(bundle.tree, name),
      to,
      constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE,
    );
  }
}

export const bundleEntryKey = (cache: RuntimeCache, esbuild: string): string =>
  hash(
    canonicalJson({
      schema: SCHEMA,
      install: cache.key,
      strip: cache.strip,
      esbuild,
    }),
  );
