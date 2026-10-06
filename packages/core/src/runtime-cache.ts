// An immutable store for the runtime a release assembles: the npm-installed
// dependency tree and, for a bundled release, its bundled form. Entries are
// content-addressed by everything that decides their bytes, published whole
// by one directory rename, and never modified afterwards, so concurrent
// builds cannot corrupt one another.
//
// Trust boundary. The store lives under PiShip's user cache directory, outside
// any project or output tree a sandboxed command may write, and has the same
// trust as the owner's home directory: whoever can write there can already
// replace the PiShip install and every key. Within that boundary:
//
// - a bundled runtime, which is what ships, is size- and content-hashed on
//   every lookup against the record made when it was stored;
// - the installed dependency tree is too large to hash on every hit (that is
//   the cost the cache removes), so a hit checks its key, schema, target, a
//   digest over its recorded (path, size) list, the complete file set, and the
//   size of every file it places; the digests a payload inventory takes for
//   it were computed from its bytes when the entry was first used;
// - a release reports whether it came from the cache, and which entry, in the
//   timing output, on one stderr line of `piship release`, and in
//   `<out>/releases/<name>.build-info.json` beside the archive; never in the
//   archive, checksums.txt, or release.json, so a release's bytes are the same
//   with the cache, without it, and from a cold one;
// - `piship release --rebuild` or PISHIP_RELEASE_NO_CACHE=1 builds cold;
// - release qualification runs on a fresh machine, so it always starts cold.
//
// Only runtime bytes are cached. A release always regenerates its audit,
// SBOM, notices, signature check, smoke tests, and archive from the payload it
// assembles.
import { execFileSync } from "node:child_process";
import {
  constants,
  copyFileSync,
  cpSync,
  type Dirent,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  rmdirSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { releaseOptions } from "@piship/schema";
import { buildInputDigest, safePath } from "./build-cache.js";
import { canonicalJson, hash } from "./digest.js";
import type { DistributionLock } from "./lock-schema.js";
import {
  hashFilesInParallel,
  placeFilesInParallel,
  WorkerFailure,
  workerCount,
} from "./parallel-files.js";
import { isRuntimeIrrelevant } from "./payload.js";
import { renameWithRetry } from "./rename-retry.js";
import { buildInput, workspacePackages } from "./runtime-dependencies.js";
import { searchToolCacheDirectory } from "./search-tools/index.js";
import { windowsNpmInvocation } from "./windows-npm.js";

const SCHEMA = "piship-runtime-cache/v3";
const ROOT_FILES = ["package.json", "package-lock.json"];
const RECORD = "entry.json";
/** Entries kept per kind; older ones are evicted when a new one is published. */
const KEEP = { install: 3, framework: 3, bundle: 6 } as const;
const ABANDONED_MS = 24 * 60 * 60 * 1000;
/** What a build spends deleting evicted entries after it published one, and after a hit. */
const DISCARD_BUDGET_MS = { published: 2000, hit: 500 } as const;

export interface RuntimeCache {
  /** Directory holding every entry. */
  readonly root: string;
  /**
   * What decides the third-party tree's bytes: the distribution lock's
   * dependency set (Pi version, the npm lock and the packages it pins), the
   * platform, CPU, and libc family, and the major.minor of Node and npm. It
   * does not depend on PiShip's own compiled output, so a change to PiShip
   * does not install again.
   */
  readonly key: string;
  /** What decides PiShip's own layer: the build input digest. */
  readonly framework: string;
  /** `release.strip`: the payload leaves out maps and declarations. */
  readonly strip: boolean;
}

/** `major.minor` of a version line, or `unknown` for anything else. */
export function majorMinor(text: string): string {
  const [major, minor] = text.trim().split(".");
  return /^\d+$/.test(major ?? "") && /^\d+$/.test(minor ?? "")
    ? `${major}.${minor}`
    : "unknown";
}

let npmLine: string | undefined;
/** The npm that installs the tree, as major.minor; its resolution rules shape the tree. */
function npmVersion(): string {
  if (npmLine === undefined)
    try {
      const invocation =
        process.platform === "win32"
          ? windowsNpmInvocation(["--version"])
          : { file: "npm", args: ["--version"] };
      npmLine = majorMinor(
        execFileSync(invocation.file, [...invocation.args], {
          encoding: "utf8",
          timeout: 30_000,
          stdio: ["ignore", "pipe", "ignore"],
        }),
      );
    } catch {
      npmLine = "unknown";
    }
  return npmLine;
}

/**
 * glibc or musl on Linux, where native packages differ by it; nothing
 * elsewhere. `report` is Node's diagnostic report: only glibc builds name
 * their runtime version in its header.
 */
export function libcFamily(
  platform: string,
  report: () => unknown,
): string | undefined {
  if (platform !== "linux") return undefined;
  try {
    const header = (
      report() as { header?: { glibcVersionRuntime?: string } } | undefined
    )?.header;
    return header?.glibcVersionRuntime ? "glibc" : "musl";
  } catch {
    return "unknown";
  }
}

/** What the key reads from this machine; a caller (a test) may state it instead. */
export interface HostFacts {
  readonly libc?: string | undefined;
  readonly npm?: string;
}

/** The runtime cache a build of `lock` on this machine reads and fills. */
export function runtimeCacheFor(
  lock: DistributionLock,
  env: NodeJS.ProcessEnv = process.env,
  host: HostFacts = {},
): RuntimeCache {
  const [major, minor] = process.versions.node.split(".");
  const { package: pi, version, npmLockSha256, packages } = lock.runtime;
  return {
    root: join(dirname(searchToolCacheDirectory(env)), "runtime"),
    key: hash(
      canonicalJson({
        schema: SCHEMA,
        runtime: { package: pi, version, npmLockSha256, packages },
        platform: process.platform,
        arch: process.arch,
        libc:
          "libc" in host
            ? host.libc
            : libcFamily(process.platform, () => process.report?.getReport()),
        node: `${major}.${minor}`,
        npm: host.npm ?? npmVersion(),
      }),
    ),
    framework: hash(
      canonicalJson({ schema: SCHEMA, input: buildInputDigest(buildInput) }),
    ),
    strip: releaseOptions(lock.manifest.schema, lock.release).strip,
  };
}

/** A name short enough for Windows paths: the key's first 20 hex digits. */
const entryPath = (cache: RuntimeCache, kind: "i" | "f" | "b", key: string) =>
  join(cache.root, `${kind}-${key.slice(0, 20)}`);

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
      ["f-", KEEP.framework],
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

// --- The installed dependency tree and PiShip's own layer ------------------

/**
 * A tree entry is one of two layers: `install`, everything npm installs (the
 * third-party packages, keyed by the lock), and `framework`, PiShip's own
 * compiled output and build input snapshot (keyed by the build input digest).
 * Their paths never overlap, so a payload takes both.
 */
type Layer = "install" | "framework";
const LAYER_DIRECTORY = { install: "i", framework: "f" } as const;

interface TreeRecord {
  readonly schema: string;
  readonly kind: Layer;
  readonly key: string;
  readonly platform: string;
  readonly arch: string;
  /** Every file of `tree`, with its size. */
  readonly files: Readonly<Record<string, number>>;
  /** SHA-256 over the sorted (path, size) list, made when the entry was created. */
  readonly filesSha256: string;
}

export interface InstallTree {
  readonly path: string;
  readonly tree: string;
  readonly files: Readonly<Record<string, number>>;
  /** The entry's identity: the digest over its sorted (path, size) list. */
  readonly digest: string;
  readonly layer: Layer;
  /** The key the entry is stored under. */
  readonly key: string;
}

/** A digest of a file set as `path NUL size LF` lines in path order. */
function filesDigest(files: Readonly<Record<string, number>>): string {
  return hash(
    Object.keys(files)
      .sort()
      .map((name) => `${name}\0${files[name]}\n`)
      .join(""),
  );
}

const layerKey = (cache: RuntimeCache, layer: Layer): string =>
  layer === "install" ? cache.key : cache.framework;
const layerPath = (cache: RuntimeCache, layer: Layer): string =>
  entryPath(cache, LAYER_DIRECTORY[layer], layerKey(cache, layer));

/**
 * The cached tree of `layer`, or undefined when there is none or it does not
 * match its record: wrong key, schema, or target, a record whose digest is not
 * that of its own file list, or a file set that differs from the one recorded
 * when it was created.
 */
export function lookupTree(
  cache: RuntimeCache,
  layer: Layer,
): InstallTree | undefined {
  const key = layerKey(cache, layer);
  const path = layerPath(cache, layer);
  const record = readRecord<TreeRecord>(path);
  if (
    record?.schema !== SCHEMA ||
    record.kind !== layer ||
    record.key !== key ||
    record.platform !== process.platform ||
    record.arch !== process.arch ||
    !record.files ||
    typeof record.files !== "object" ||
    Array.isArray(record.files) ||
    Object.entries(record.files).some(
      ([name, size]) => !safePath(name) || !Number.isSafeInteger(size),
    ) ||
    record.filesSha256 !== filesDigest(record.files)
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
  return {
    path,
    tree,
    files: record.files,
    digest: record.filesSha256,
    layer,
    key,
  };
}

/** The third-party tree: see `lookupTree`. */
export const lookupInstallTree = (cache: RuntimeCache) =>
  lookupTree(cache, "install");

/**
 * Take a layer's entry out of use. A build calls this for an entry that
 * matches its record but cannot be placed, so the tree it makes instead is
 * published in its place.
 */
export function discardTree(cache: RuntimeCache, layer: Layer): void {
  hide(layerPath(cache, layer));
}
export const discardInstallTree = (cache: RuntimeCache) =>
  discardTree(cache, "install");

const code = (error: unknown) => (error as NodeJS.ErrnoException).code;

export interface AdoptedTree {
  readonly tree: InstallTree;
  /**
   * True when the stage's tree was moved into the entry, so the stage holds
   * none of it and `materializeInstallTree` places it again. False when the
   * entry is on another volume and the tree was copied in: the stage still
   * holds the whole tree.
   */
  readonly moved: boolean;
}

/** Create the files of a new entry in `tree`, a directory that does not exist yet. */
type Fill = (tree: string) => { readonly moved: boolean } | undefined;

/**
 * Publish a new entry of `layer`: `fill` writes its files into a holding
 * directory (and says whether it moved them out of somewhere), the file list
 * and its digest are recorded, and the directory is renamed into place. A lost
 * race adopts the winner's entry. Returns undefined when the cache cannot take
 * it; `undo` then puts back whatever `fill` moved.
 */
function publishTree(
  cache: RuntimeCache,
  layer: Layer,
  fill: Fill,
  undo: (location: string) => void,
): AdoptedTree | undefined {
  let holding: string;
  try {
    mkdirSync(cache.root, { recursive: true });
    holding = mkdtempSync(join(cache.root, ".t"));
  } catch {
    return undefined;
  }
  const destination = layerPath(cache, layer);
  // Where the tree is now, so a failure can put it back.
  let location = join(holding, "tree");
  let given = false;
  let moved = true;
  try {
    mkdirSync(location);
    moved = fill(location)?.moved ?? true;
    const files: Record<string, number> = {};
    for (const name of listFiles(location).sort())
      files[name] = lstatSync(inside(location, name)).size;
    const record: TreeRecord = {
      schema: SCHEMA,
      kind: layer,
      key: layerKey(cache, layer),
      platform: process.platform,
      arch: process.arch,
      files,
      filesSha256: filesDigest(files),
    };
    writeFileSync(join(holding, RECORD), JSON.stringify(record));
    const outcome = publish(
      holding,
      destination,
      () => lookupTree(cache, layer) !== undefined,
    );
    // Another build's entry stands in for ours, which is gone.
    if (outcome === "published") location = join(destination, "tree");
    else given = moved;
    const tree = lookupTree(cache, layer);
    if (!tree) throw new Error("The runtime cache entry is not readable");
    prune(cache, DISCARD_BUDGET_MS.published);
    return { tree, moved };
  } catch (error) {
    // The tree was handed over and cannot be put back.
    if (given) throw error;
    undo(location);
    discard(location === join(holding, "tree") ? holding : destination);
    return undefined;
  }
}

/**
 * Publish the installed third-party tree of `stage` (its `node_modules`) as a
 * new entry: moved in with one rename, or, when the cache is on another volume
 * (EXDEV), copied in once and left in the stage as well. A moved tree leaves
 * the stage without `node_modules`. Where the tree cannot be adopted (the
 * rename is refused, or the tree holds a link) the stage is left as it was and
 * the result is undefined.
 */
export function adoptInstallTree(
  cache: RuntimeCache,
  stage: string,
): AdoptedTree | undefined {
  let movedIn = false;
  return publishTree(
    cache,
    "install",
    (location) => {
      try {
        renameWithRetry(
          join(stage, "node_modules"),
          join(location, "node_modules"),
        );
        movedIn = true;
        return { moved: true };
      } catch (error) {
        if (code(error) !== "EXDEV") throw error;
        cpSync(join(stage, "node_modules"), join(location, "node_modules"), {
          recursive: true,
        });
        return { moved: false };
      }
    },
    (location) => {
      if (!movedIn) return;
      try {
        renameWithRetry(
          join(location, "node_modules"),
          join(stage, "node_modules"),
        );
      } catch {}
    },
  );
}

/**
 * Publish PiShip's own layer from the build input, which is a plain copy of
 * files that are already on this machine: no install. Undefined where the
 * cache cannot take it.
 */
export function publishFrameworkTree(
  cache: RuntimeCache,
): InstallTree | undefined {
  return publishTree(
    cache,
    "framework",
    (location) => {
      writeFrameworkFiles(location);
      return { moved: false };
    },
    () => {},
  )?.tree;
}

/**
 * PiShip's own files of a payload, at their payload paths under `root`: the
 * root manifest and npm lock, each workspace package's manifest and compiled
 * output as a real copy under `node_modules/@piship`, and the build input
 * snapshot that management commands read.
 */
export function writeFrameworkFiles(root: string): void {
  for (const name of ROOT_FILES)
    copyFileSync(join(buildInput, name), inside(root, name));
  for (const name of workspacePackages) {
    const target = join(root, "node_modules", "@piship", name);
    mkdirSync(target, { recursive: true });
    copyFileSync(
      join(buildInput, "packages", name, "package.json"),
      join(target, "package.json"),
    );
    cpSync(join(buildInput, "packages", name, "dist"), join(target, "dist"), {
      recursive: true,
    });
  }
  cpSync(
    buildInput,
    join(root, "node_modules", "@piship", "core", "dist", "build-input"),
    { recursive: true },
  );
}

/**
 * Place `from` at `to`. A hardlink creates no new bytes and no new content
 * for Windows Defender to scan, and shares them with the cache entry, so
 * nothing may write through the new name; where it is refused (another
 * volume, a file system without links, a link limit) the file is copied
 * instead, as a copy-on-write clone where the volume has them. A copy never
 * replaces an existing file, which could be a link into the cache. Returns
 * how the file was placed.
 */
function place(from: string, to: string, link: boolean): "linked" | "copied" {
  if (link)
    try {
      linkSync(from, to);
      return "linked";
    } catch {}
  copyFileSync(from, to, constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
  return "copied";
}

/**
 * Place the cached tree under `target`. With `strip` the maps and
 * declarations are left behind, which is the strip itself: no file is
 * created and then deleted. Every file placed must have the size recorded when
 * the entry was created. Returns how many files were linked and how many
 * copied.
 *
 * With `link` (by default on Windows only) the files are hardlinked from the
 * entry. There every created file is read and scanned by Defender, which makes
 * a link an order of magnitude cheaper than a copy, while macOS and Linux
 * clone or copy a file about as fast as they link it. A linked file shares its
 * bytes with the entry: nothing may write through it, and deleting it only
 * removes the name. When a link is refused (another volume, no link support)
 * the rest are copied, and the count says so.
 */
export function materializeInstallTree(
  tree: InstallTree,
  target: string,
  options: { readonly strip: boolean; readonly link?: boolean },
): { readonly linked: number; readonly copied: number } {
  const entries = Object.entries(tree.files).filter(
    ([name]) => !options.strip || !isRuntimeIrrelevant(basename(name)),
  );
  const link = options.link ?? process.platform === "win32";
  const made = new Set<string>();
  const parents = (name: string) => {
    const parent = dirname(inside(target, name));
    if (made.has(parent)) return;
    mkdirSync(parent, { recursive: true });
    made.add(parent);
  };
  const threads = workerCount(entries.length);
  const sequential = (skipExisting: boolean) => {
    const placed = { linked: 0, copied: 0 };
    let linking = link;
    for (const [name, size] of entries) {
      const to = inside(target, name);
      parents(name);
      // After threads that met a refusal, what they placed already is kept.
      if (skipExisting && existsSync(to) && lstatSync(to).size === size)
        continue;
      const how = place(inside(tree.tree, name), to, linking);
      placed[how]++;
      linking = linking && how === "linked";
      if (lstatSync(to).size !== size)
        throw new Error(`The runtime cache entry is damaged: ${name}`);
    }
    return placed;
  };
  if (threads > 1) {
    // Directories first, then the files by several threads at once.
    for (const [name] of entries) parents(name);
    try {
      return placeFilesInParallel(
        threads,
        tree.tree,
        target,
        entries.map(([name]) => name),
        entries.map(([, size]) => size),
        link,
      );
    } catch (error) {
      // Threads that never ran changed nothing; threads that met a refusal
      // Windows gives while a scanner holds a file left some files placed.
      // Either way one thread finishes the job; any other failure stands.
      if (!(error instanceof WorkerFailure) || error.kind === "failed")
        throw error;
      return sequential(error.kind === "transient");
    }
  }
  return sequential(false);
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
      record.key === tree.key &&
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
  const threads = workerCount(names.length);
  const digests =
    threads > 1 ? hashFilesInParallel(threads, tree.tree, names) : undefined;
  names.forEach((name, index) => {
    inventory[name] =
      digests?.[index] ?? hash(readFileSync(inside(tree.tree, name)));
  });
  writeOnce(
    sidecar,
    JSON.stringify({
      schema: SCHEMA,
      key: tree.key,
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
      framework: cache.framework,
      strip: cache.strip,
      esbuild,
    }),
  );
