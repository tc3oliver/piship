// File work shared by several threads. A payload has thousands of small files
// and each costs a round trip to the file system (on Windows, one Defender
// scans), so doing them one after another leaves the machine idle between
// calls. A build is a synchronous function, so the work goes to worker threads
// that this thread waits for with `Atomics.wait`: no event loop is needed, and
// the caller still gets its result as a return value.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, rmSync } from "node:fs";
import { availableParallelism } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

/** Below this many files the cost of starting threads is not worth it. */
export const PARALLEL_MIN_FILES = 500;
const MAX_WORKERS = 8;
const FILES_PER_WORKER = 250;
/** A hung worker must not hang a build for ever. */
const WAIT_LIMIT_MS = 15 * 60_000;
const MESSAGE_BYTES = 2048;
/** Slots of the shared state: threads finished, linked, copied, failed, message length. */
const DONE = 0;
const LINKED = 1;
const COPIED = 2;
const FAILED = 3;
const MESSAGE_LENGTH = 4;
/** Set by each worker as its first act, so a worker that cannot run is noticed. */
const STARTED = 5;
/** The shared state's slots, for a test that stands in for a worker. */
export const SLOTS = { DONE, FAILED, MESSAGE_LENGTH, STARTED };
/** How long workers may take to start before the work is given up. */
const START_LIMIT_MS = 60_000;

/**
 * How many threads `files` files are worth, one meaning do it here.
 * PISHIP_FILE_WORKERS=<n> sets the number for any size (1 turns threads off).
 */
export function workerCount(files: number): number {
  const forced = Number(process.env.PISHIP_FILE_WORKERS);
  if (Number.isInteger(forced) && forced >= 1)
    return Math.min(forced, MAX_WORKERS, Math.max(1, files));
  if (files < PARALLEL_MIN_FILES) return 1;
  return Math.max(
    1,
    Math.min(
      MAX_WORKERS,
      availableParallelism(),
      Math.ceil(files / FILES_PER_WORKER),
    ),
  );
}

// Runs in a worker. Everything it does is inside one try: a failure is
// reported through the shared state, and the thread always says it is done, so
// the waiting thread never waits for a crash it cannot see.
const WORKER = `
const { workerData } = require("node:worker_threads");
const state = new Int32Array(workerData.state);
const message = new Uint8Array(workerData.message);
Atomics.add(state, ${STARTED}, 1);
let linked = 0;
let copied = 0;
try {
  const { constants, copyFileSync, linkSync, lstatSync, readFileSync } = require("node:fs");
  const { join } = require("node:path");
  const { createHash } = require("node:crypto");
  const { job, source, target, names, sizes, from, digests } = workerData;
  let link = workerData.link;
  for (let index = 0; index < names.length; index++) {
    if (Atomics.load(state, ${FAILED}) !== 0) break;
    const name = names[index];
    const parts = name.split("/");
    if (job === "hash") {
      const digest = createHash("sha256").update(readFileSync(join(source, ...parts))).digest();
      new Uint8Array(digests).set(digest, (from + index) * 32);
      continue;
    }
    const origin = join(source, ...parts);
    const destination = join(target, ...parts);
    let linkedNow = false;
    if (link) {
      try {
        linkSync(origin, destination);
        linkedNow = true;
      } catch {
        link = false;
      }
    }
    if (!linkedNow) copyFileSync(origin, destination, constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
    if (linkedNow) linked++; else copied++;
    if (lstatSync(destination).size !== sizes[index])
      throw new Error("The runtime cache entry is damaged: " + name);
  }
} catch (error) {
  if (Atomics.compareExchange(state, ${FAILED}, 0, 1) === 0) {
    const bytes = new TextEncoder().encode(String(error && error.message ? error.message : error));
    const length = Math.min(bytes.length, message.length);
    message.set(bytes.subarray(0, length));
    Atomics.store(state, ${MESSAGE_LENGTH}, length);
  }
} finally {
  Atomics.add(state, ${LINKED}, linked);
  Atomics.add(state, ${COPIED}, copied);
  Atomics.add(state, ${DONE}, 1);
  Atomics.notify(state, ${DONE});
}
`;

interface Shared {
  readonly state: Int32Array;
  readonly message: Uint8Array;
}

/**
 * Why threads could not do the work. `startup`: none ran, so nothing was
 * done. `transient`: a thread met a refusal Windows gives while a scanner holds
 * a file (EPERM, EBUSY, EACCES) after some of the work was done. `failed`:
 * anything else. Callers fall back to one thread for the first two.
 */
export class WorkerFailure extends Error {
  constructor(
    message: string,
    readonly kind: "startup" | "transient" | "failed",
  ) {
    super(message);
  }
}
const TRANSIENT = /\b(?:EPERM|EBUSY|EACCES)\b/;

/**
 * Start a worker running `code` (not a file) with `workerData`. A worker
 * inherits the flags of this process, and `--input-type=module` (how a script
 * given with `node -e` is often run) would make its code a module without
 * `require`, so it starts with none.
 */
export function startWorker(
  code: string,
  workerData: Record<string, unknown>,
): Worker {
  return new Worker(code, { eval: true, workerData, execArgv: [] });
}

/** Start `count` workers running `code` over contiguous slices of `names`, and wait for them all. */
function runWorkers(
  code: string,
  count: number,
  names: readonly string[],
  data: (slice: { from: number; to: number }) => Record<string, unknown>,
  shared: Shared,
  buffers: { state: SharedArrayBuffer; message: SharedArrayBuffer },
): void {
  const size = Math.ceil(names.length / count);
  const workers: Worker[] = [];
  let started = 0;
  let refused: unknown;
  for (let from = 0; from < names.length; from += size) {
    const to = Math.min(names.length, from + size);
    try {
      workers.push(
        startWorker(code, {
          ...buffers,
          names: names.slice(from, to),
          from,
          ...data({ from, to }),
        }),
      );
      started++;
    } catch (error) {
      refused = error;
      break;
    }
  }
  const startedBy = Date.now() + START_LIMIT_MS;
  const deadline = Date.now() + WAIT_LIMIT_MS;
  try {
    for (;;) {
      const done = Atomics.load(shared.state, DONE);
      if (done >= started) break;
      if (Atomics.load(shared.state, STARTED) === 0 && Date.now() > startedBy)
        throw new WorkerFailure("Worker threads did not start", "startup");
      if (Date.now() > deadline)
        throw new WorkerFailure("Worker threads did not finish", "failed");
      Atomics.wait(shared.state, DONE, done, 1000);
    }
  } finally {
    for (const worker of workers) void worker.terminate();
  }
  if (refused !== undefined)
    throw new WorkerFailure(
      `Worker threads could not be started: ${(refused as Error)?.message ?? refused}`,
      started === 0 ? "startup" : "transient",
    );
  if (Atomics.load(shared.state, FAILED) !== 0) {
    const text = new TextDecoder().decode(
      shared.message.slice(0, Atomics.load(shared.state, MESSAGE_LENGTH)),
    );
    throw new WorkerFailure(
      text,
      TRANSIENT.test(text) ? "transient" : "failed",
    );
  }
}

function shared(): {
  readonly view: Shared;
  readonly buffers: { state: SharedArrayBuffer; message: SharedArrayBuffer };
} {
  const state = new SharedArrayBuffer(8 * 4);
  const message = new SharedArrayBuffer(MESSAGE_BYTES);
  return {
    view: { state: new Int32Array(state), message: new Uint8Array(message) },
    buffers: { state, message },
  };
}

/**
 * Place `names` from `source` into `target` (whose directories exist) by
 * `count` threads, checking each file's size. A file is hardlinked while
 * `link` holds and links work; otherwise it is copied without ever replacing
 * an existing file. Throws the first failure.
 */
export function placeFilesInParallel(
  count: number,
  source: string,
  target: string,
  names: readonly string[],
  sizes: readonly number[],
  link: boolean,
): { readonly linked: number; readonly copied: number } {
  const { view, buffers } = shared();
  runWorkers(
    WORKER,
    count,
    names,
    ({ from, to }) => ({
      job: "place",
      source,
      target,
      sizes: sizes.slice(from, to),
      link,
    }),
    view,
    buffers,
  );
  return {
    linked: Atomics.load(view.state, LINKED),
    copied: Atomics.load(view.state, COPIED),
  };
}

/** The SHA-256 of each of `names` under `source`, in order, as hex. */
export function hashFilesInParallel(
  count: number,
  source: string,
  names: readonly string[],
): string[] {
  const { view, buffers } = shared();
  const digests = new SharedArrayBuffer(names.length * 32);
  try {
    runWorkers(
      WORKER,
      count,
      names,
      () => ({ job: "hash", source, digests }),
      view,
      buffers,
    );
  } catch (error) {
    // Reading is safe to repeat: do it here, one file at a time.
    if (!(error instanceof WorkerFailure) || error.kind === "failed")
      throw error;
    return names.map((name) =>
      createHash("sha256")
        .update(readFileSync(join(source, ...name.split("/"))))
        .digest("hex"),
    );
  }
  const bytes = Buffer.from(digests);
  return names.map((_, index) =>
    bytes.subarray(index * 32, index * 32 + 32).toString("hex"),
  );
}

// Runs in a worker: removes the files it is given, each retried by `rmSync`
// where Windows holds one open for a moment, and never follows a link.
const REMOVER = `
const { workerData } = require("node:worker_threads");
const state = new Int32Array(workerData.state);
const message = new Uint8Array(workerData.message);
Atomics.add(state, ${STARTED}, 1);
try {
  const { rmSync } = require("node:fs");
  const { join } = require("node:path");
  const { source, names, attempts, delay } = workerData;
  for (const name of names) {
    if (Atomics.load(state, ${FAILED}) !== 0) break;
    rmSync(join(source, ...name.split("/")), { force: true, maxRetries: attempts, retryDelay: delay });
  }
} catch (error) {
  if (Atomics.compareExchange(state, ${FAILED}, 0, 1) === 0) {
    const bytes = new TextEncoder().encode(String(error && error.message ? error.message : error));
    const length = Math.min(bytes.length, message.length);
    message.set(bytes.subarray(0, length));
    Atomics.store(state, ${MESSAGE_LENGTH}, length);
  }
} finally {
  Atomics.add(state, ${DONE}, 1);
  Atomics.notify(state, ${DONE});
}
`;

/**
 * Delete the directory tree at `root`: its files by several threads when there
 * are many, then its directories, deepest first. Links are removed, never
 * followed. A missing `root` is not an error. `attempts` and `delay` are
 * `rmSync`'s retries for a file a scanner still has open.
 */
export function removeTree(
  root: string,
  options: { readonly attempts?: number; readonly delay?: number } = {},
): void {
  const attempts = options.attempts ?? 0;
  const delay = options.delay ?? 100;
  const files: string[] = [];
  const directories: string[] = [];
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const name = `${prefix}${entry.name}`;
      if (entry.isDirectory()) {
        directories.push(name);
        visit(join(directory, entry.name), `${name}/`);
      } else files.push(name);
    }
  };
  try {
    visit(root, "");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const count = workerCount(files.length);
  if (count <= 1) {
    rmSync(root, {
      recursive: true,
      force: true,
      maxRetries: attempts,
      retryDelay: delay,
    });
    return;
  }
  const { view, buffers } = shared();
  try {
    runWorkers(
      REMOVER,
      count,
      files,
      () => ({ source: root, attempts, delay }),
      view,
      buffers,
    );
  } catch (error) {
    // Removing is safe to repeat: what is left goes the single-thread way.
    if (!(error instanceof WorkerFailure) || error.kind === "failed")
      throw error;
    rmSync(root, {
      recursive: true,
      force: true,
      maxRetries: attempts,
      retryDelay: delay,
    });
    return;
  }
  for (const directory of directories.reverse())
    rmSync(join(root, ...directory.split("/")), {
      recursive: true,
      force: true,
      maxRetries: attempts,
      retryDelay: delay,
    });
  rmSync(root, {
    recursive: true,
    force: true,
    maxRetries: attempts,
    retryDelay: delay,
  });
}
