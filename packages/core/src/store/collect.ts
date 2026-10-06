// Garbage collection and verification of the shared file store. They run when
// somebody asks for them (`doctor`), never during a launch, an install, or an
// update, and they only ever remove store objects and bookkeeping: an
// installed release is its own files, so nothing here can delete or damage
// one, whatever it decides about an object.
//
// What is kept. An object is pinned by the release that placed it while that
// release is its distribution's active release or its rollback target. The
// store itself does not know which those are: the caller says, from the
// installation's receipts (`liveness`), so there is one record of what is
// installed and none that can disagree with it. Everything else is garbage:
// a release the installation no longer retains, a distribution that was
// uninstalled, an object no release names.
//
// Why it cannot hurt an install in progress. An operation that fills the store
// holds a marker in `inflight/` until it ends, and a collection that finds a
// recent one sweeps nothing. A new object, a new reference, and a leftover
// younger than the grace period are kept in any case, so even a marker lost to
// a crash is waited out, not guessed at.
import {
  existsSync,
  type Dirent,
  lstatSync,
  readdirSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { acquireLifecycleLock } from "../install/lifecycle-lock.js";
import { parseObjectName, REF_SCHEMA, storeLayout } from "./store.js";

/** What the installation says of a recorded release. */
export type Liveness = "live" | "dead" | "unknown";

/** An object younger than this is never collected: an install may be about to use it. */
export const DEFAULT_GRACE_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_BUDGET_MS = 5000;
/** The budget is read after this many files, so a large store stops promptly. */
const CHECK_EVERY = 64;

export interface RecordedRelease {
  readonly id: string;
  readonly version: string;
  /** The install home the release was placed for. */
  readonly home: string;
}

export interface CollectOptions {
  readonly root: string;
  /** Whether the installation still retains the release as active or rollback. */
  readonly liveness: (release: RecordedRelease) => Liveness;
  readonly graceMs?: number;
  readonly budgetMs?: number;
  /** Test seams. */
  readonly now?: () => number;
}

export interface CollectedStore {
  /** Another collection holds the store. */
  readonly busy: boolean;
  /** An install or update is filling the store; nothing was swept. */
  readonly deferred: boolean;
  readonly removedObjects: number;
  readonly freedBytes: number;
  readonly removedReferences: number;
  readonly removedTemporaries: number;
  /** Objects kept because a retained release pins them. */
  readonly pinnedObjects: number;
  /** The budget ran out; the next collection continues. */
  readonly remaining: boolean;
}

const EMPTY: CollectedStore = {
  busy: false,
  deferred: false,
  removedObjects: 0,
  freedBytes: 0,
  removedReferences: 0,
  removedTemporaries: 0,
  pinnedObjects: 0,
  remaining: false,
};

const entries = (directory: string): Dirent[] => {
  try {
    return readdirSync(directory, { withFileTypes: true });
  } catch {
    return [];
  }
};

const modified = (path: string): number => {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return 0;
  }
};

interface Reference extends RecordedRelease {
  readonly path: string;
  readonly objects: readonly string[];
}

function readReference(
  path: string,
  id: string,
  file: string,
): Reference | undefined {
  try {
    const record = JSON.parse(readFileSync(path, "utf8")) as {
      schema?: unknown;
      id?: unknown;
      version?: unknown;
      home?: unknown;
      objects?: unknown;
    } | null;
    if (
      record?.schema !== REF_SCHEMA ||
      record.id !== id ||
      `${String(record.version)}.json` !== file ||
      typeof record.home !== "string" ||
      !Array.isArray(record.objects) ||
      !record.objects.every(
        (name) => typeof name === "string" && parseObjectName(name),
      )
    )
      return undefined;
    return {
      id,
      version: record.version as string,
      home: record.home,
      path,
      objects: record.objects as string[],
    };
  } catch {
    return undefined;
  }
}

/**
 * Collect the store at `options.root`: drop what no retained release pins and
 * is past the grace period, within the time budget. A store that does not
 * exist yields nothing.
 */
export function collectStore(options: CollectOptions): CollectedStore {
  const layout = storeLayout(options.root);
  if (!existsSync(layout.marker)) return EMPTY;
  const now = options.now ?? Date.now;
  const grace = options.graceMs ?? DEFAULT_GRACE_MS;
  const deadline = now() + (options.budgetMs ?? DEFAULT_BUDGET_MS);
  const held = new Error("Another collection holds the store");
  let hold: ReturnType<typeof acquireLifecycleLock>;
  try {
    hold = acquireLifecycleLock(
      layout.lock,
      () => held,
      () => new Error(`Could not lock the store at ${options.root}`),
    );
  } catch (error) {
    if (error === held) return { ...EMPTY, busy: true };
    throw error;
  }
  try {
    const old = (path: string) => now() - modified(path) > grace;
    let deferred = false;
    for (const marker of entries(layout.inflight)) {
      const path = join(layout.inflight, marker.name);
      if (old(path)) rmSync(path, { force: true });
      else deferred = true;
    }
    let removedTemporaries = 0;
    for (const file of entries(layout.temporary)) {
      const path = join(layout.temporary, file.name);
      if (old(path)) {
        rmSync(path, { force: true, recursive: true });
        removedTemporaries++;
      }
    }
    let removedReferences = 0;
    const pinned = new Set<string>();
    for (const distribution of entries(layout.refs)) {
      if (!distribution.isDirectory()) continue;
      const directory = join(layout.refs, distribution.name);
      for (const file of entries(directory)) {
        const path = join(directory, file.name);
        const reference = readReference(path, distribution.name, file.name);
        // A reference that cannot be read names nothing to keep.
        const state = reference ? options.liveness(reference) : "dead";
        if (state === "dead" && old(path) && !deferred) {
          rmSync(path, { force: true });
          removedReferences++;
        } else for (const name of reference?.objects ?? []) pinned.add(name);
      }
      try {
        rmdirSync(directory);
      } catch {
        // Not empty.
      }
    }
    if (deferred)
      return {
        ...EMPTY,
        deferred,
        removedTemporaries,
        pinnedObjects: pinned.size,
      };
    let removedObjects = 0;
    let freedBytes = 0;
    let visited = 0;
    let remaining = false;
    sweep: for (const bucket of entries(layout.objects)) {
      if (!bucket.isDirectory()) continue;
      const directory = join(layout.objects, bucket.name);
      for (const file of entries(directory)) {
        if (++visited % CHECK_EVERY === 0 && now() > deadline) {
          remaining = true;
          break sweep;
        }
        if (pinned.has(file.name)) continue;
        const path = join(directory, file.name);
        if (!parseObjectName(file.name) || !old(path)) continue;
        try {
          const info = lstatSync(path);
          rmSync(path, { force: true });
          removedObjects++;
          // A file an installation still links to keeps its bytes.
          if (info.nlink <= 1) freedBytes += info.size;
        } catch {
          // Left for the next collection.
        }
      }
      try {
        rmdirSync(directory);
      } catch {
        // Not empty.
      }
    }
    return {
      busy: false,
      deferred: false,
      removedObjects,
      freedBytes,
      removedReferences,
      removedTemporaries,
      pinnedObjects: pinned.size,
      remaining,
    };
  } finally {
    hold.release();
  }
}

export interface VerifyStoreOptions {
  readonly root: string;
  /** Remove a damaged object; the next install that needs its bytes writes it again. */
  readonly repair?: boolean;
  readonly budgetMs?: number;
  /**
   * Which bucket to begin at (default: a different one each call), so a store
   * larger than the budget is covered by successive runs, not by the first
   * buckets every time.
   */
  readonly start?: number;
  readonly now?: () => number;
}

export interface VerifiedStore {
  readonly checked: number;
  /** Objects whose bytes are not their name's digest, or that are not regular files. */
  readonly damaged: readonly string[];
  readonly repaired: number;
  readonly remaining: boolean;
}

/** Hash every object against its name. */
export function verifyStore(options: VerifyStoreOptions): VerifiedStore {
  const layout = storeLayout(options.root);
  const now = options.now ?? Date.now;
  const deadline = now() + (options.budgetMs ?? DEFAULT_BUDGET_MS);
  const damaged: string[] = [];
  let checked = 0;
  let repaired = 0;
  let remaining = false;
  const buckets = entries(layout.objects).sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  const begin = buckets.length
    ? (options.start ?? Math.floor(Math.random() * buckets.length)) %
      buckets.length
    : 0;
  sweep: for (const bucket of [
    ...buckets.slice(begin),
    ...buckets.slice(0, begin),
  ]) {
    if (!bucket.isDirectory()) continue;
    for (const file of entries(join(layout.objects, bucket.name))) {
      const parsed = parseObjectName(file.name);
      if (!parsed) continue;
      if (checked > 0 && checked % CHECK_EVERY === 0 && now() > deadline) {
        remaining = true;
        break sweep;
      }
      checked++;
      const path = join(layout.objects, bucket.name, file.name);
      let intact = false;
      try {
        intact =
          lstatSync(path).isFile() &&
          createHash("sha256").update(readFileSync(path)).digest("hex") ===
            parsed.digest;
      } catch {
        // Unreadable counts as damaged.
      }
      if (intact) continue;
      damaged.push(file.name);
      if (options.repair) {
        rmSync(path, { force: true, recursive: true });
        repaired++;
      }
    }
  }
  return { checked, damaged, repaired, remaining };
}
