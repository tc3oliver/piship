import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  futimesSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  chmod,
  type FileHandle,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import {
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  type AuditBatch,
  type AuditCapture,
  type AuditEmitter,
  type AuditEvent,
  type AuditSink,
  isLoopbackHost,
  isPrivateNetworkHost,
  NO_CONTENT_CAPTURE,
  PiShipError,
} from "@piship/contracts";
import {
  AUDIT_CONTENT_CLASSES,
  type AuditContentClass,
  type AuditEventInput,
  sanitizeEvent,
  scrubText,
} from "./sanitize.js";

/** Structurally identical to `@piship/schema` AuditSinkConfig. */
export interface AuditSinkConfig {
  readonly id: string;
  readonly type: "file" | "http";
  /** HTTP sinks: endpoint URL or `${NAME}` runtime reference. */
  readonly url?: string;
  readonly required: boolean;
  /** `https` forbids plain HTTP beyond loopback; otherwise it is allowed to a private or internal host. */
  readonly httpTransport?: "https" | "http-allowed";
}

/** Structurally identical to `@piship/schema` AuditConfig. */
export interface AuditConfig {
  readonly enabled: boolean;
  readonly sinks: readonly AuditSinkConfig[];
  readonly buffer: {
    readonly maxEvents: number;
    readonly flushIntervalMs: number;
  };
  readonly capture: AuditCapture;
}

export type AuditLogState = "disabled" | "ok" | "degraded" | "failed";
export type AuditSinkState = "ok" | "degraded" | "failed";

export interface AuditSinkStatus {
  readonly id: string;
  readonly type: "file" | "http";
  readonly required: boolean;
  readonly state: AuditSinkState;
  readonly delivered: number;
  readonly dropped: number;
  readonly pending: number;
  /** Redacted description of the most recent delivery failure. */
  readonly lastError?: string;
  /** Of `pending`, events replayed from crashed processes' spools. */
  readonly replayed?: number;
  /** Replayed events the collector kept refusing, set aside as rejected. */
  readonly rejected?: number;
  /** The sink's spool directory under the state directory, when either is set. */
  readonly spool?: string;
}

export interface AuditStatus {
  readonly state: AuditLogState;
  readonly sinks: readonly AuditSinkStatus[];
  /** Emissions refused by the sanitizer (unknown type, malformed input). */
  readonly rejected: number;
}

export type AuditFetch = (
  url: string | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface AuditLogOptions {
  readonly config: AuditConfig;
  /** Distribution ID stamped on every event. */
  readonly distribution: string;
  /** Distribution state directory; the file sink writes `logs/audit.jsonl`. */
  readonly stateDir: string;
  /** Injected (managed) fetch used by HTTP sinks. */
  readonly fetch?: AuditFetch;
  /**
   * For a sink not set to `httpTransport: https` whose URL is plain HTTP
   * to a private or internal host: a managed fetch that also admits plain
   * HTTP to that URL's origin, and to nothing else. Without it such a sink
   * is not opened.
   */
  readonly plainHttpFetch?: (url: URL) => AuditFetch;
  /** Resolves `${NAME}` references in HTTP sink URLs. */
  readonly resolveUrl?: (template: string) => string;
  readonly now?: () => Date;
  readonly onStateChange?: (state: AuditLogState, status: AuditStatus) => void;
  /** Per-request timeout for HTTP sinks. Default 10 s. */
  readonly requestTimeoutMs?: number;
  /**
   * File sink retention. Fixed size defaults (AUDIT_ROTATION), plus the
   * manifest's `data.audit.retention` as `minimumRetentionMs`. Tests pass
   * smaller limits.
   */
  readonly rotation?: AuditRotation;
  /** Cap on a required HTTP sink's spool. Default AUDIT_SPOOL_MAX_BYTES. */
  readonly spoolMaxBytes?: number;
  /**
   * Claim and replay the spools crashed processes left: a session (launch or
   * doctor) passes true. A short command that only records its own events
   * leaves them to the next session and never waits behind a backlog.
   */
  readonly replaySpool?: boolean;
}

/** Size-based retention of the file sink: `audit.jsonl` plus `.1`..`.<files>`. */
export interface AuditRotation {
  /** Rotate before an append would grow `audit.jsonl` past this size. */
  readonly maxBytes: number;
  /**
   * Rotated files kept (`audit.jsonl.1` is the newest); older ones are
   * deleted, unless `minimumRetentionMs` keeps them.
   */
  readonly files: number;
  /**
   * The audit retention minimum (`data.audit.retention`): a rotated file
   * modified more recently than this is never deleted by rotation, so the
   * chain grows past `files` (`.6`, `.7`, ...) instead. Local audit is then
   * bounded by how much is written within the minimum, not by
   * `maxBytes * (files + 1)`; the retention sweep deletes what has aged out.
   */
  readonly minimumRetentionMs?: number;
  /**
   * How long (monotonic) a rotation lock must be seen unchanged before it is
   * taken over as abandoned. Default 30 s.
   */
  readonly lockStaleMs?: number;
}

/** 10 MiB per file, five rotated files: at most about 60 MiB of local audit. */
export const AUDIT_ROTATION: AuditRotation = Object.freeze({
  maxBytes: 10 * 1024 * 1024,
  files: 5,
});

/** Input accepted by `emit`; distribution and schema are filled by the log. */
export type AuditEmitInput = Omit<AuditEventInput, "distribution">;

export const AUDIT_LOG_FILE = join("logs", "audit.jsonl");
/**
 * A rotation lock seen unchanged (same holder token, same mtime) for this
 * long on the monotonic clock is treated as abandoned by a crashed process.
 */
const ROTATION_LOCK_STALE_MS = 30_000;
/**
 * A rotation takes milliseconds, so a lock whose mtime is more than an hour
 * old by the wall clock was left by a rotator that died, and its process ID
 * belongs to an unrelated process now (or to another host). A short-lived
 * command cannot watch a lock for the stale interval, so this is how such a
 * lock is recovered when its holder's process cannot be shown to be gone. No
 * live rotator holds a lock that long; a clock that jumps forward makes one
 * look this old only inside those milliseconds.
 */
const ROTATION_LOCK_LEASE_MS = 60 * 60_000;
/**
 * Rotation locks this process found held: what it saw (token and mtime) and
 * since when, on the monotonic clock. Ownership never depends on how old an
 * mtime looks against the wall clock alone, which can jump.
 */
const rotationLocksSeen = new Map<string, { state: string; since: number }>();
/** Names this host in a lock token: a process ID means something only here. */
const HOST_ID = createHash("sha256")
  .update(hostname())
  .digest("hex")
  .slice(0, 12);

/** Whether a process with this ID exists (EPERM: it exists, not ours). */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * The process a rotation lock token names, and whether it is on this host:
 * `<pid>-<host id>-<random>`, or `<pid>-<random>` from an earlier PiShip
 * (whose state directory was this host's too).
 */
function tokenOwner(
  token: string,
): { pid: number; sameHost: boolean } | undefined {
  const match = /^(\d+)-(?:([0-9a-f]{12})-)?/.exec(token);
  const pid = Number(match?.[1]);
  if (!match || !Number.isSafeInteger(pid) || pid <= 0) return undefined;
  return { pid, sameHost: match[2] === undefined || match[2] === HOST_ID };
}

/** What one look at a rotation lock showed. */
interface RotationLock {
  /** The holder's token; undefined when the content cannot be read. */
  readonly token: string | undefined;
  readonly mtimeMs: number;
  /** False for a directory or symlink at the lock's path. */
  readonly regular: boolean;
  /**
   * Token and mtime together, compared only for equality with an earlier
   * look; a lock that cannot be read is described by its mtime alone.
   */
  readonly state: string;
}

/** Look at a rotation lock; undefined when it is gone. */
async function observeRotationLock(
  lock: string,
): Promise<RotationLock | undefined> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(lock, "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    // Present but not openable (a root-owned file, or a directory on
    // Windows): describe it by what its entry says.
    try {
      const entry = await lstat(lock);
      return {
        token: undefined,
        mtimeMs: entry.mtimeMs,
        regular: entry.isFile(),
        state: `?\n${entry.mtimeMs}`,
      };
    } catch {
      return undefined;
    }
  }
  try {
    const stat = await handle.stat();
    const token = await handle.readFile("utf8").catch(() => undefined);
    return {
      token,
      mtimeMs: stat.mtimeMs,
      regular: stat.isFile(),
      state: `${token ?? "?"}\n${stat.mtimeMs}`,
    };
  } catch {
    return undefined;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/**
 * Whether the rotator that made `held` is gone: its process no longer exists
 * on this host (at once), its mtime is over an hour old (a reused process
 * ID), or this process has watched it unchanged for `staleMs` on the
 * monotonic clock (`unchangedMs`).
 */
function rotationAbandoned(
  held: RotationLock,
  unchangedMs: number,
  staleMs: number,
): boolean {
  const owner = held.token === undefined ? undefined : tokenOwner(held.token);
  if (owner?.sameHost && owner.pid !== process.pid && !processAlive(owner.pid))
    return true;
  if (Date.now() - held.mtimeMs > ROTATION_LOCK_LEASE_MS) return true;
  return unchangedMs > staleMs;
}

/**
 * The file sink's files that exist, newest first: `logs/audit.jsonl`, then
 * `logs/audit.jsonl.1` and so on. Readers that need the newest event use the
 * first non-empty one; a rotation leaves `audit.jsonl` briefly absent or empty.
 */
export function auditLogFiles(
  stateDir: string,
  rotation: AuditRotation = AUDIT_ROTATION,
): string[] {
  const base = join(stateDir, AUDIT_LOG_FILE);
  const paths = [base];
  // Past `files`, the files a retention minimum kept, while they continue.
  for (
    let index = 1;
    index <= rotation.files || existsSync(`${base}.${index}`);
    index += 1
  )
    paths.push(`${base}.${index}`);
  return paths.filter((path) => existsSync(path));
}
/** Events per write (one HTTP POST or one file append). */
const BATCH_LIMIT = 500;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_CLOSE_DEADLINE_MS = 5_000;
/** Pause between delivery attempts of a required sink while closing. */
const CLOSE_RETRY_MS = 200;

const DISABLED_CONFIG: AuditConfig = {
  enabled: false,
  sinks: [],
  buffer: { maxEvents: 0, flushIntervalMs: 0 },
  capture: NO_CONTENT_CAPTURE,
};

class FileSinkWriter implements AuditSink {
  readonly path: string;

  constructor(
    readonly stateDir: string,
    readonly rotation: AuditRotation = AUDIT_ROTATION,
  ) {
    this.path = join(stateDir, AUDIT_LOG_FILE);
  }

  /** Create `logs/` (0700) and the log file (0600) and prove it is writable. */
  async prepare(): Promise<void> {
    await this.append("");
  }

  async write(batch: AuditBatch): Promise<void> {
    await this.append(
      batch.events.map((event) => `${JSON.stringify(event)}\n`).join(""),
    );
  }

  private async append(data: string): Promise<void> {
    const directory = join(this.stateDir, "logs");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const bytes = Buffer.byteLength(data, "utf8");
    // Read the generation before opening: if a rotation happens in between,
    // the generation no longer matches and this writer does not rotate.
    const generation = bytes > 0 ? await this.generation() : "";
    let handle = await this.open();
    try {
      let { size } = await handle.stat();
      if (bytes > 0 && size > 0 && size + bytes > this.rotation.maxBytes) {
        await handle.close();
        await this.rotate(generation, bytes);
        handle = await this.open();
        ({ size } = await handle.stat());
      }
      if (process.platform !== "win32") await handle.chmod(0o600);
      // A crash mid-append can leave a final line without its newline. Start
      // on a fresh line so the next event is not glued onto the fragment; the
      // fragment itself is kept as is. Checked on the handle that is appended
      // to, so a writer still on a rotated file checks that file.
      if (data)
        await handle.appendFile(
          (await endsMidLine(handle, size)) ? `\n${data}` : data,
          "utf8",
        );
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  private open() {
    // O_NOFOLLOW refuses a planted symlink; it is 0 where unsupported.
    const flags =
      constants.O_RDWR |
      constants.O_APPEND |
      constants.O_CREAT |
      (constants.O_NOFOLLOW ?? 0);
    return open(this.path, flags, 0o600);
  }

  /**
   * Shift `audit.jsonl` to `.1` (and `.1` to `.2`, …), deleting the oldest.
   * Only renames are used: a process still appending through an open handle
   * keeps writing into the renamed file, so no line is lost. One process
   * rotates at a time; the others append to the current file and retry on a
   * later write. Best effort: a failed rotation never fails the append.
   */
  private async rotate(measured: string, bytes: number): Promise<void> {
    const lock = `${this.path}.rotate.lock`;
    const token = `${process.pid}-${HOST_ID}-${randomBytes(8).toString("hex")}\n`;
    if (!(await this.acquireRotationLock(lock, token))) return;
    try {
      // Another process may have taken over a lock this one held too long.
      if ((await readFile(lock, "utf8").catch(() => "")) !== token) return;
      // Another writer may have rotated since this one read the generation.
      // File identity (inode) is not used: it is not reliable on Windows.
      if ((await this.generation()) !== measured) return;
      // The generation advances before the file moves, so a writer can read
      // the new generation yet have measured the old file. Under the lock,
      // re-measure the current file and rotate only if it is still full.
      const current = await statOpen(this.path).catch(() => undefined);
      if (
        !current ||
        current.size === 0 ||
        current.size + bytes <= this.rotation.maxBytes
      )
        return;
      // Advance the generation before moving any file: a crash in between
      // can only make another writer skip one rotation, never repeat one.
      await this.writeGeneration(String(Number(measured) + 1));
      const files = Math.max(1, Math.floor(this.rotation.files));
      // The oldest file is the highest index: `files`, or past it when a
      // retention minimum kept older ones. Delete from the oldest end what
      // is beyond the count and older than the minimum; keep the rest.
      let top = files;
      while (
        await lstat(`${this.path}.${top + 1}`).then(
          () => true,
          () => false,
        )
      )
        top += 1;
      while (top >= files && (await this.expired(`${this.path}.${top}`))) {
        await rm(`${this.path}.${top}`, { force: true });
        top -= 1;
      }
      for (let index = top; index >= 1; index -= 1)
        await rename(
          `${this.path}.${index}`,
          `${this.path}.${index + 1}`,
        ).catch((error: NodeJS.ErrnoException) => {
          if (error.code !== "ENOENT") throw error;
        });
      await rename(this.path, `${this.path}.1`);
    } catch {
      // Keep appending to the current file; rotation is retried later.
    } finally {
      // Release only a lock this process still owns.
      if ((await readFile(lock, "utf8").catch(() => "")) === token)
        await rm(lock, { force: true }).catch(() => undefined);
    }
  }

  /** Whether rotation may delete a rotated file: no minimum keeps it. */
  private async expired(path: string): Promise<boolean> {
    const minimum = this.rotation.minimumRetentionMs;
    if (minimum === undefined) return true;
    const stats = await lstat(path).catch(() => undefined);
    if (!stats) return true;
    return Date.now() - stats.mtimeMs >= minimum;
  }

  /**
   * The generation of the current `audit.jsonl`: a counter in
   * `audit.jsonl.generation` that each rotation advances under the rotation
   * lock. A missing or unreadable file is generation 0.
   */
  private async generation(): Promise<string> {
    const value = await readFile(`${this.path}.generation`, "utf8").catch(
      () => "",
    );
    return /^\d+$/.test(value.trim()) ? String(Number(value.trim())) : "0";
  }

  /** Replace the generation file atomically (write a temporary, rename). */
  private async writeGeneration(value: string): Promise<void> {
    const target = `${this.path}.generation`;
    const temporary = `${target}.${randomBytes(6).toString("hex")}.tmp`;
    await writeFile(temporary, `${value}\n`, { flag: "wx", mode: 0o600 });
    try {
      await rename(temporary, target);
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  /**
   * Create the rotation lock holding `token`. A held lock is taken over when
   * its holder is gone: its process no longer exists on this host (a crashed
   * rotator, recovered by the very next writer, however short-lived), its
   * mtime is over an hour old by the wall clock (a reused process ID), or
   * this process has seen it unchanged (the same holder's token and mtime)
   * for the stale interval, measured on the monotonic clock across its later
   * appends. A live holder is never judged by how old its mtime looks
   * within the hour, so a wall clock that jumps forward does not make a live
   * rotation look abandoned. The takeover renames the lock to a unique name
   * first, so only one process's rename of that file succeeds; a lock that
   * changed in between is put back and given up, not reused. A directory or
   * symlink at the lock's path is never touched.
   *
   * Limit: if a third process creates the lock between that rename and the
   * put-back, the put-back fails and the rotator that was moved aside carries
   * on without its lock. Two rotations can then overlap; the worst outcome is
   * one rotated file dropped before its retention is up, never a torn or
   * duplicated line (every step is a rename, and a rotator re-reads its
   * token and the generation before it starts).
   */
  private async acquireRotationLock(
    lock: string,
    token: string,
  ): Promise<boolean> {
    const create = async () => {
      await writeFile(lock, token, { flag: "wx", mode: 0o600 });
      rotationLocksSeen.delete(lock);
      return true;
    };
    try {
      return await create();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
    }
    try {
      const held = await observeRotationLock(lock);
      if (held === undefined || !held.regular) return false;
      const now = performance.now();
      const seen = rotationLocksSeen.get(lock);
      const unchanged = seen?.state === held.state;
      if (!unchanged)
        rotationLocksSeen.set(lock, { state: held.state, since: now });
      if (
        !rotationAbandoned(
          held,
          unchanged && seen ? now - seen.since : 0,
          this.rotation.lockStaleMs ?? ROTATION_LOCK_STALE_MS,
        )
      )
        return false;
      rotationLocksSeen.delete(lock);
      const taken = `${lock}.${randomBytes(6).toString("hex")}.stale`;
      await rename(lock, taken);
      const moved = await observeRotationLock(taken);
      if (moved?.state !== held.state) {
        await link(taken, lock).catch(() => undefined);
        await rm(taken, { force: true });
        return false;
      }
      await rm(taken, { force: true });
      return await create();
    } catch {
      return false;
    }
  }
}

/** Where required HTTP sinks spool: `<dir>/<sink key>/<owner>.jsonl`. */
export const AUDIT_SPOOL_DIRECTORY = join("logs", "audit-spool");
/** 16 MiB per spool; an append or rewrite past it fails closed. */
export const AUDIT_SPOOL_MAX_BYTES = 16 * 1024 * 1024;
/**
 * A spool not touched for this long is claimable whatever its name says. Its
 * owner touches it on every flush and every SPOOL_HEARTBEAT_MS, so only a gone
 * owner leaves one this old: its process ID now names an unrelated process,
 * or its host ID changed with the hostname (macOS renames the host with the
 * network). Taking a live owner's spool (a process stopped, or a machine
 * asleep, past the lease) only duplicates events: the owner's in-memory queue
 * stays authoritative, and its next touch writes its spool again.
 */
export const AUDIT_SPOOL_LEASE_MS = 10 * 60_000;
const SPOOL_HEARTBEAT_MS = 60_000;
/**
 * Spool files this process owns. Any other file named with this process's ID
 * belongs to an earlier process that had the same ID and is gone. Shared
 * through globalThis, so a second bundled copy of this module sees it too.
 */
const OWNED_SPOOLS = Symbol.for("piship.audit.ownedSpools");
const registry = globalThis as { [OWNED_SPOOLS]?: Set<string> };
registry[OWNED_SPOOLS] ??= new Set<string>();
const ownedSpools = registry[OWNED_SPOOLS];
/** 4xx refusals of the same replayed event before it is set aside as rejected. */
const REPLAY_REFUSALS = 3;

/** `<pid>-<host id>-<random>`, the owner a spool file is named after. */
function ownerToken(): string {
  return `${process.pid}-${HOST_ID}-${randomBytes(8).toString("hex")}`;
}

/** The directory of a sink's spools: a digest, so a sink ID never names a path. */
export function auditSpoolKey(sinkId: string): string {
  return createHash("sha256").update(sinkId).digest("hex").slice(0, 16);
}

/** O_NOFOLLOW refuses a planted symlink; it is 0 where unsupported. */
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
/** O_NONBLOCK keeps a planted FIFO from blocking the open; 0 where unsupported. */
const NONBLOCK = constants.O_NONBLOCK ?? 0;

/**
 * The durable copy of a required HTTP sink's undelivered events. Each process
 * writes its own file, so writers never interleave; a file whose owner is gone
 * (a crash) is claimed by the next launch with one rename, which only one
 * process can win, replayed, and deleted. Every write is synchronous, so the
 * file is never behind the in-memory queue:
 *
 * - `append` (each emitted event) is one O_APPEND write, which is in the
 *   file as soon as it returns: a crash of the process loses nothing, and can
 *   leave only the last line torn, which a reader drops.
 * - `sync` (once per flush, before the batch is sent) fsyncs those appends,
 *   so an event is on disk before the collector can have it. An fsync per
 *   event costs about 8 ms on macOS (F_FULLFSYNC); an operating system crash
 *   or power loss can lose what was emitted since the last flush.
 * - `replace` (once per flush that delivered something, at close, and at
 *   launch) writes the queue to a temporary, fsyncs it, and renames it over
 *   the file, so a crash leaves the old or the new content, never a mix.
 *
 * An event is in the spool before it is sent and leaves it only after the
 * collector acknowledged it, so a crash can resend an event (each keeps its
 * `id`, which the collector de-duplicates) but never lose one it had taken in.
 */
class HttpSpool {
  readonly key: string;
  readonly directory: string;
  readonly path: string;
  #size = 0;
  /** A failed append whose bytes could not be removed: only `replace` repairs it. */
  #torn = false;

  constructor(
    readonly stateDir: string,
    sinkId: string,
    readonly maxBytes: number,
  ) {
    this.key = auditSpoolKey(sinkId);
    this.directory = join(stateDir, AUDIT_SPOOL_DIRECTORY, this.key);
    this.path = join(this.directory, `${ownerToken()}.jsonl`);
  }

  /**
   * Create this process's spool (proving it writable). With `replay`, also
   * claim the spools whose owner is gone and return their events:
   * de-duplicated by `id`, in time order, without content `capture` no
   * longer admits. A claimed spool with a corrupt line is set aside as
   * `<name>.corrupt` once its valid lines are taken, and so is one over the
   * cap, unread. Throws when the spool cannot be written, or, with `replay`,
   * while a spool is set aside in the directory.
   */
  open(capture: AuditCapture, replay: boolean): AuditEvent[] {
    for (const directory of [
      join(this.stateDir, "logs"),
      join(this.stateDir, AUDIT_SPOOL_DIRECTORY),
      this.directory,
    ]) {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      if (process.platform !== "win32") chmodSync(directory, 0o700);
    }
    ownedSpools.add(this.path);
    if (!replay) {
      try {
        this.replace([]);
      } catch (error) {
        ownedSpools.delete(this.path);
        throw error;
      }
      return [];
    }
    const claimed: { path: string; name: string }[] = [];
    try {
      const now = Date.now();
      let bytes = 0;
      for (const name of readdirSync(this.directory).sort()) {
        const path = join(this.directory, name);
        if (ownedSpools.has(path)) continue;
        // Only a regular file: a FIFO or a directory in its place is never opened.
        const entry = lstatSync(path, { throwIfNoEntry: false });
        if (!entry?.isFile() || !spoolAbandoned(name, entry.mtimeMs, now))
          continue;
        if (name.endsWith(".tmp")) {
          rmSync(path, { force: true });
          continue;
        }
        if (!name.endsWith(".jsonl")) continue;
        // Never written this large: set aside unread.
        if (entry.size > this.maxBytes) {
          claimRename(path, join(this.directory, `${name}.corrupt`));
          continue;
        }
        // Within the cap, so neither this replay nor a later rewrite exceeds
        // it; the rest waits for the next launch.
        if (bytes + entry.size > this.maxBytes) continue;
        // Renamed to a name this process owns: a second launcher's rename of
        // the same file fails, so no file is replayed twice.
        const claim = join(this.directory, `${ownerToken()}.jsonl`);
        ownedSpools.add(claim);
        if (claimRename(path, claim)) {
          claimed.push({ path: claim, name });
          bytes += entry.size;
        } else ownedSpools.delete(claim);
      }
      const ids = new Set<string>();
      const events: AuditEvent[] = [];
      const corrupt = new Set<string>();
      for (const { path } of claimed) {
        const spool = readSpool(path);
        if (spool.corrupt) corrupt.add(path);
        for (const event of spool.events)
          if (!ids.has(event.id as string)) {
            ids.add(event.id as string);
            events.push(withCapture(event, capture));
          }
      }
      // Files are named by owner, not age: order by event time (a stable sort
      // keeps each file's own order for equal times).
      events.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
      // Written here before the claimed files go: a crash in between leaves
      // duplicates, which the next replay drops by id.
      this.replace(events);
      for (const { path, name } of claimed) {
        if (corrupt.has(path))
          renameSync(path, join(this.directory, `${name}.corrupt`));
        else rmSync(path, { force: true });
        ownedSpools.delete(path);
      }
      syncDirectory(this.directory);
      const quarantined = readdirSync(this.directory)
        .filter((name) => name.endsWith(".corrupt"))
        .sort();
      if (quarantined.length)
        throw new Error(
          `${this.directory} holds a spool set aside as corrupt or over the cap, ${quarantined.join(", ")}; its valid events are kept but not sent while it is there; remove it, or repair it and rename it back to .jsonl (one over the cap, ${this.maxBytes} bytes, split into files under it)`,
        );
      return events;
    } catch (error) {
      // Left for the next launch, which fails the same way until it is fixed.
      ownedSpools.delete(this.path);
      for (const { path } of claimed) ownedSpools.delete(path);
      throw error;
    }
  }

  append(event: AuditEvent): void {
    if (this.#torn) throw new Error("audit spool has a partial write");
    const line = `${JSON.stringify(event)}\n`;
    const bytes = Buffer.byteLength(line, "utf8");
    if (this.#size + bytes > this.maxBytes)
      throw new Error(`audit spool is full (${this.maxBytes} bytes)`);
    const fd = openSync(
      this.path,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | NOFOLLOW,
      0o600,
    );
    try {
      writeFileSync(fd, line, "utf8");
      this.#size += bytes;
    } catch (error) {
      // A short write (a full disk) must not leave a fragment that the next
      // line is glued onto.
      try {
        ftruncateSync(fd, this.#size);
      } catch {
        this.#torn = true;
      }
      throw error;
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Renew the lease (touch) and, with `durable`, fsync. A spool that no
   * longer holds what this process wrote (taken by a launch past the lease,
   * or swept) is written again from `queue`.
   */
  sync(queue: readonly AuditEvent[], durable = true): void {
    // Windows flushes only through a handle that can write.
    const fd = openSync(
      this.path,
      constants.O_RDWR | constants.O_CREAT | NOFOLLOW,
      0o600,
    );
    let intact: boolean;
    try {
      intact = fstatSync(fd).size === this.#size;
      if (intact) {
        const now = new Date();
        futimesSync(fd, now, now);
        if (durable) fsyncSync(fd);
      }
    } finally {
      closeSync(fd);
    }
    if (!intact) this.replace(queue);
  }

  /**
   * Atomically make the spool hold `events`, or as many of the oldest as fit
   * in `limit` bytes; throws once written when not all of them fit, so the
   * rest are only in memory.
   */
  replace(events: readonly AuditEvent[], limit = this.maxBytes): void {
    const lines: string[] = [];
    let bytes = 0;
    for (const event of events) {
      const line = `${JSON.stringify(event)}\n`;
      const size = Buffer.byteLength(line, "utf8");
      if (bytes + size > limit) break;
      lines.push(line);
      bytes += size;
    }
    const temporary = `${this.path}.tmp`;
    const fd = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | NOFOLLOW,
      0o600,
    );
    try {
      if (process.platform !== "win32") fchmodSync(fd, 0o600);
      writeFileSync(fd, lines.join(""), "utf8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    // No handle stays open on the spool, so the rename also works on Windows.
    renameSync(temporary, this.path);
    syncDirectory(this.directory);
    this.#size = bytes;
    this.#torn = false;
    if (lines.length < events.length)
      throw new Error(`audit spool is full (${this.maxBytes} bytes)`);
  }

  /**
   * Set aside an event the collector keeps refusing in `<spool>.rejected`
   * (0600, at most the cap), never to be sent again. Throws when it cannot be
   * written or is full; the event then stays queued.
   */
  reject(event: AuditEvent): void {
    const path = `${this.path}.rejected`;
    const line = `${JSON.stringify(event)}\n`;
    const fd = openSync(
      path,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | NOFOLLOW,
      0o600,
    );
    try {
      if (fstatSync(fd).size + Buffer.byteLength(line, "utf8") > this.maxBytes)
        throw new Error(
          `audit spool rejected file is full (${this.maxBytes} bytes)`,
        );
      writeFileSync(fd, line, "utf8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  /** At close: delete the spool when `queue` is empty, else leave it holding `queue` for the next launch. */
  release(queue: readonly AuditEvent[]): void {
    try {
      if (queue.length) this.replace(queue);
      else rmSync(this.path, { force: true });
    } finally {
      ownedSpools.delete(this.path);
    }
  }
}

/** One sink directory of the spool, as `doctor` reports it. */
export interface AuditSpoolReport {
  /** `logs/audit-spool/<key>` under the state directory. */
  readonly directory: string;
  /** The required HTTP sink it belongs to; absent for one no longer configured. */
  readonly sink?: string;
  /** Spool files (`*.jsonl`): undelivered events. */
  readonly files: number;
  readonly bytes: number;
  /** Spool files not touched within AUDIT_SPOOL_LEASE_MS: no live owner. */
  readonly stale: number;
  /** Corrupt spools set aside (`*.corrupt`), by name. */
  readonly quarantined: readonly string[];
  /** Replayed events the collector refused, set aside (`*.rejected`), by name. */
  readonly rejected: readonly string[];
}

/**
 * Every sink directory of the spool that holds a file, with `sinkIds` (the
 * required HTTP sinks configured now) naming the ones still in use. A
 * directory of no configured sink (renamed or removed) is never replayed.
 */
export function auditSpools(
  stateDir: string,
  sinkIds: readonly string[],
  now = Date.now(),
): AuditSpoolReport[] {
  const root = join(stateDir, AUDIT_SPOOL_DIRECTORY);
  const sinks = new Map(sinkIds.map((id) => [auditSpoolKey(id), id]));
  const reports: AuditSpoolReport[] = [];
  for (const key of safeReaddir(root).sort()) {
    let files = 0;
    let bytes = 0;
    let stale = 0;
    const quarantined: string[] = [];
    const rejected: string[] = [];
    for (const name of safeReaddir(join(root, key)).sort()) {
      const entry = lstatSync(join(root, key, name), { throwIfNoEntry: false });
      if (!entry?.isFile()) continue;
      if (name.endsWith(".corrupt")) quarantined.push(name);
      if (name.endsWith(".rejected")) rejected.push(name);
      if (!name.endsWith(".jsonl")) continue;
      files += 1;
      bytes += entry.size;
      if (now - entry.mtimeMs > AUDIT_SPOOL_LEASE_MS) stale += 1;
    }
    if (!files && !quarantined.length && !rejected.length) continue;
    const sink = sinks.get(key);
    reports.push({
      directory: join(AUDIT_SPOOL_DIRECTORY, key),
      ...(sink === undefined ? {} : { sink }),
      files,
      bytes,
      stale,
      quarantined,
      rejected,
    });
  }
  return reports;
}

function safeReaddir(directory: string): string[] {
  try {
    return readdirSync(directory);
  } catch {
    return [];
  }
}

/**
 * Whether a spool file's owner is gone: another process on this host that no
 * longer exists, an earlier process with this one's ID, or any owner that has
 * not touched it within the lease. A spool another host touches (a shared
 * home directory) is never taken: its owner's process cannot be seen here.
 */
function spoolAbandoned(name: string, mtimeMs: number, now: number): boolean {
  const owner = tokenOwner(name);
  if (!owner || !/^\d+-[0-9a-f]{12}-/.test(name)) return false;
  // An mtime far in the future (a clock set back since) never keeps a spool.
  if (now - mtimeMs > AUDIT_SPOOL_LEASE_MS || mtimeMs - now > 5 * 60_000)
    return true;
  return (
    owner.sameHost && (owner.pid === process.pid || !processAlive(owner.pid))
  );
}

/**
 * Rename a spool another launcher may take first: false when it is gone
 * (ENOENT), or, on Windows, open or locked by another process (EPERM,
 * EBUSY); the file is then skipped, and `doctor` still lists it.
 */
function claimRename(from: string, to: string): boolean {
  try {
    renameSync(from, to);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "EPERM" || code === "EBUSY") return false;
    throw error;
  }
}

/**
 * 400, 413, or 422: the collector will not take what the batch holds. Any
 * other 4xx (401, 403, 404, ...) says nothing about the events, and is
 * retried like a 5xx.
 */
function refused(error: unknown): boolean {
  const status = (error as { status?: unknown }).status;
  return status === 400 || status === 413 || status === 422;
}

/** Content of a replayed event, filtered again by the current `audit.capture`. */
function withCapture(event: AuditEvent, capture: AuditCapture): AuditEvent {
  if (!event.content) return event;
  const { content, ...rest } = event;
  const kept = Object.entries(content).filter(
    ([name]) =>
      Object.hasOwn(AUDIT_CONTENT_CLASSES, name) &&
      capture[AUDIT_CONTENT_CLASSES[name as AuditContentClass]] === true,
  );
  return kept.length ? { ...rest, content: Object.fromEntries(kept) } : rest;
}

/**
 * Read a spool's events. A last line without its newline was torn by a crash
 * mid-append: it is kept if it is still a whole event, and dropped otherwise.
 * Any other line that is not an event, or a file that is not a regular file,
 * makes the spool corrupt; its valid lines are still returned.
 */
function readSpool(path: string): { events: AuditEvent[]; corrupt: boolean } {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK);
  } catch (error) {
    // Deleted since it was claimed (a sweep run by another release): empty.
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return { events: [], corrupt: false };
    throw error;
  }
  let text: string;
  try {
    if (!fstatSync(fd).isFile()) return { events: [], corrupt: true };
    text = readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
  const lines = text.split("\n");
  const tail = lines.pop() as string;
  const events: AuditEvent[] = [];
  let corrupt = false;
  for (const line of lines) {
    const event = spooledEvent(line);
    if (event) events.push(event);
    else corrupt = true;
  }
  const last = tail && spooledEvent(tail);
  if (last) events.push(last);
  return { events, corrupt };
}

function spooledEvent(line: string): AuditEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  const event = value as Partial<AuditEvent> | null;
  return typeof event === "object" &&
    event !== null &&
    !Array.isArray(event) &&
    event.schema === AUDIT_EVENT_SCHEMA &&
    typeof event.id === "string" &&
    typeof event.event === "string" &&
    typeof event.time === "string"
    ? (event as AuditEvent)
    : undefined;
}

/** Make a created, renamed, or deleted entry durable. Directories cannot be opened on Windows. */
function syncDirectory(directory: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(directory, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * The `http` sink's delivery: one POST of a `piship-audit-batch/v1` batch,
 * settled by the collector's answer. `AuditLog` owns queueing and retries;
 * this is exported so the audit conformance kit can run against it.
 */
export class HttpSinkWriter implements AuditSink {
  constructor(
    readonly url: URL,
    readonly fetch: AuditFetch,
    readonly timeoutMs: number,
  ) {}

  async write(batch: AuditBatch, signal: AbortSignal): Promise<void> {
    const response = await this.fetch(this.url.toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(batch),
      redirect: "manual",
      signal: AbortSignal.any([signal, AbortSignal.timeout(this.timeoutMs)]),
    });
    await response.body?.cancel().catch(() => undefined);
    if (response.status < 200 || response.status > 299)
      throw Object.assign(
        new Error(`collector answered HTTP ${response.status}`),
        { status: response.status },
      );
  }
}

function resolveHttpUrl(
  sink: AuditSinkConfig,
  resolveUrl: ((template: string) => string) | undefined,
): URL {
  if (!sink.url) throw new Error("HTTP sink has no url");
  const value = resolveUrl ? resolveUrl(sink.url) : sink.url;
  if (value.includes("${"))
    throw new Error("HTTP sink url has an unresolved reference");
  const url = new URL(value);
  if (url.username || url.password)
    throw new Error("HTTP sink url must not embed credentials");
  if (
    sink.httpTransport !== "https" &&
    url.protocol === "http:" &&
    !isLoopbackHost(url.hostname) &&
    !isPrivateNetworkHost(url.hostname)
  )
    throw new Error(
      `HTTP sink url is plain HTTP to ${url.hostname}, which is public; plain HTTP is accepted only to a private or internal host`,
    );
  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      (isLoopbackHost(url.hostname) || sink.httpTransport !== "https")
    )
  )
    throw new Error(
      "HTTP sink url must use https (plain http only for loopback, or for a private or internal host unless the sink sets httpTransport: https)",
    );
  return url;
}

/** Plain HTTP beyond loopback, which only a sink not set to https reaches. */
function plainHttpSink(url: URL): boolean {
  return url.protocol === "http:" && !isLoopbackHost(url.hostname);
}

class Sink {
  readonly queue: AuditEvent[] = [];
  state: AuditSinkState = "ok";
  delivered = 0;
  dropped = 0;
  lastError: string | undefined;
  /** A required HTTP sink's durable copy of `queue`. */
  spool: HttpSpool | undefined;
  /** The spool could not take an event or the queue: governed actions fail closed. */
  spoolFailed = false;
  /** Replayed events still at the head of `queue`: not counted against `maxEvents`. */
  replayed = 0;
  /** Events per batch: narrowed while the collector refuses a replayed batch. */
  batchLimit = BATCH_LIMIT;
  /** The replayed head event the collector refused, and how many times in a row. */
  refusedId: string | undefined;
  refusals = 0;
  rejected = 0;

  constructor(
    readonly config: AuditSinkConfig,
    readonly writer: AuditSink | undefined,
    readonly endpoint: string | undefined,
  ) {}

  status(): AuditSinkStatus {
    return {
      id: this.config.id,
      type: this.config.type,
      required: this.config.required,
      state: this.state,
      delivered: this.delivered,
      dropped: this.dropped,
      pending: this.queue.length,
      ...(this.lastError ? { lastError: this.lastError } : {}),
      ...(this.replayed ? { replayed: this.replayed } : {}),
      ...(this.rejected ? { rejected: this.rejected } : {}),
      ...(this.spool && (this.replayed || this.rejected)
        ? { spool: join(AUDIT_SPOOL_DIRECTORY, this.spool.key) }
        : {}),
    };
  }

  describeError(error: unknown): string {
    let message = error instanceof Error ? error.message : String(error);
    const cause = (error as { cause?: { code?: unknown } })?.cause?.code;
    if (typeof cause === "string") message = `${message} (${cause})`;
    // Never echo the full endpoint: its path or query may carry routing secrets.
    if (this.endpoint) message = message.split(this.endpoint).join("<sink>");
    return scrubText(message).slice(0, 300);
  }
}

function unavailable(sink: AuditSinkConfig, reason: string): PiShipError {
  return new PiShipError(
    "AUDIT_UNAVAILABLE",
    `Required audit sink ${sink.id} (${sink.type}) is unavailable: ${reason}`,
    {
      component: "audit",
      userAction:
        "Restore the audit sink or contact the distribution administrator; governed actions stay blocked until it is reachable",
    },
  );
}

/**
 * Buffered audit log with per-sink bounded queues. See AUDIT_FAILURE_MATRIX
 * for the behavior on sink failures. Emission never throws; callers that
 * perform governed actions call `assertAvailable()` to fail closed.
 */
export class AuditLog implements AuditEmitter {
  readonly #sinks: Sink[];
  readonly #config: AuditConfig;
  readonly #distribution: string;
  readonly #now: () => Date;
  readonly #onStateChange: AuditLogOptions["onStateChange"];
  readonly #abort = new AbortController();
  #timer: NodeJS.Timeout | undefined;
  #heartbeat: NodeJS.Timeout | undefined;
  #flushing: Promise<void> = Promise.resolve();
  #flushQueued = false;
  #closed = false;
  #rejected = 0;
  #state: AuditLogState;

  private constructor(
    config: AuditConfig,
    distribution: string,
    sinks: Sink[],
    options: AuditLogOptions,
  ) {
    this.#config = config;
    this.#distribution = distribution;
    this.#sinks = sinks;
    this.#now = options.now ?? (() => new Date());
    this.#onStateChange = options.onStateChange;
    this.#state = this.#computeState();
    if (this.#state !== "disabled" && config.buffer.flushIntervalMs > 0) {
      this.#timer = setInterval(() => {
        void this.flush();
      }, config.buffer.flushIntervalMs);
      this.#timer.unref();
    }
    // Renews each spool's lease even when flushes are rare or off.
    if (sinks.some((sink) => sink.spool)) {
      this.#heartbeat = setInterval(() => {
        for (const sink of this.#sinks)
          if (sink.spool)
            try {
              sink.spool.sync(sink.queue, false);
            } catch (error) {
              this.#spoolFailure(sink, error);
            }
        this.#update();
      }, SPOOL_HEARTBEAT_MS);
      this.#heartbeat.unref();
    }
  }

  /** A log that records nothing and reports `disabled`. */
  static disabled(distribution = "unknown"): AuditLog {
    return new AuditLog(DISABLED_CONFIG, distribution, [], {
      config: DISABLED_CONFIG,
      distribution,
      stateDir: "",
    });
  }

  /**
   * Open every configured sink. A required file sink must be writable and a
   * required HTTP sink must accept an empty batch (2xx) or this throws
   * AUDIT_UNAVAILABLE. Optional sinks that fail to open start `degraded`.
   */
  static async open(options: AuditLogOptions): Promise<AuditLog> {
    const { config } = options;
    if (!config.enabled || config.sinks.length === 0)
      return AuditLog.disabled(options.distribution);
    const ids = new Set<string>();
    const sinks: Sink[] = [];
    for (const sinkConfig of config.sinks) {
      if (ids.has(sinkConfig.id))
        throw new PiShipError(
          "CONFIG_INVALID",
          `Duplicate audit sink id ${sinkConfig.id}`,
          { component: "audit" },
        );
      ids.add(sinkConfig.id);
      sinks.push(await openSink(sinkConfig, options));
    }
    const log = new AuditLog(config, options.distribution, sinks, options);
    // Deliver what a crashed process spooled before anything new.
    if (sinks.some((sink) => sink.queue.length)) void log.flush();
    return log;
  }

  get capture(): AuditCapture {
    return this.#config.capture;
  }

  emit(input: AuditEmitInput): void {
    try {
      if (this.#state === "disabled") return;
      if (this.#closed) {
        // Nothing delivers after close: count the event as lost everywhere.
        for (const sink of this.#sinks) {
          sink.dropped += 1;
          sink.state = sink.config.required ? "failed" : "degraded";
        }
        this.#update();
        return;
      }
      // One ID per emission, shared by every sink and kept across retries.
      const event: AuditEvent = {
        ...sanitizeEvent(
          { ...input, distribution: this.#distribution },
          this.#config.capture,
          this.#now,
        ),
        id: randomUUID(),
      };
      const limit = this.#config.buffer.maxEvents;
      let flushSoon = false;
      for (const sink of this.#sinks) {
        if (sink.queue.length - sink.replayed >= limit) {
          sink.dropped += 1;
          if (sink.config.required) sink.state = "failed";
          else sink.state = "degraded";
          continue;
        }
        if (sink.spool)
          try {
            sink.spool.append(event);
          } catch (error) {
            this.#spoolFailure(sink, error);
          }
        sink.queue.push(event);
        // Early flush at half capacity, but not while a sink is retrying.
        if ((sink.queue.length - sink.replayed) * 2 >= limit && !sink.lastError)
          flushSoon = true;
      }
      this.#update();
      if (flushSoon) void this.flush();
    } catch {
      this.#rejected += 1;
    }
  }

  /** Throws AUDIT_UNAVAILABLE while a required sink has lost events to backpressure. */
  assertAvailable(): void {
    if (this.#state !== "failed") return;
    const sink = this.#sinks.find(
      (item) => item.config.required && item.state === "failed",
    );
    throw new PiShipError(
      "AUDIT_UNAVAILABLE",
      `Audit is unavailable: required sink ${sink?.config.id ?? "unknown"} is failing and ${sink?.spoolFailed ? "its audit spool cannot keep its events" : "the audit buffer is full"}${sink?.replayed && sink.spool ? `, holding ${sink.replayed} event(s) replayed from ${sink.spool.directory}` : ""}`,
      {
        component: "audit",
        userAction:
          "Restore the required audit sink; governed actions fail closed until audit recovers",
        ...(sink?.lastError
          ? { sanitizedDetail: { lastError: sink.lastError } }
          : {}),
      },
    );
  }

  /** Deliver pending events to every sink. Never rejects. */
  flush(): Promise<void> {
    if (this.#state === "disabled" || this.#closed) return this.#flushing;
    return this.#flush();
  }

  #flush(): Promise<void> {
    if (this.#flushQueued) return this.#flushing;
    this.#flushQueued = true;
    this.#flushing = this.#flushing.then(async () => {
      this.#flushQueued = false;
      await Promise.all(this.#sinks.map((sink) => this.#flushSink(sink)));
      this.#update();
    });
    return this.#flushing;
  }

  /**
   * Stop the timer and flush, retrying a required sink until it has taken
   * every event or `deadlineMs` passes; then abort any delivery still
   * running. Undelivered events stay counted as pending in the returned
   * status: check it with `requiredAuditLoss`, since a required sink must
   * never lose events silently.
   */
  async close(deadlineMs = DEFAULT_CLOSE_DEADLINE_MS): Promise<AuditStatus> {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    clearInterval(this.#heartbeat);
    if (this.#state !== "disabled" && !this.#closed) {
      this.#closed = true;
      const final = this.#finalFlush();
      let timer: NodeJS.Timeout | undefined;
      const deadline = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, Math.max(0, deadlineMs));
        timer.unref();
      });
      await Promise.race([final, deadline]);
      clearTimeout(timer);
      this.#abort.abort();
      // Undelivered events, including any only in memory, stay spooled (up
      // to the cap) for the next launch to replay.
      for (const sink of this.#sinks)
        try {
          sink.spool?.release(sink.queue);
        } catch {
          // A spool left behind is claimed by the next launch; what did not
          // fit is still counted as pending.
        }
    }
    this.#closed = true;
    return this.status();
  }

  async #finalFlush(): Promise<void> {
    const signal = this.#abort.signal;
    await this.#flush();
    while (
      !signal.aborted &&
      this.#sinks.some((sink) => sink.config.required && sink.queue.length)
    ) {
      // A referenced timer: an unreferenced one could let the process exit
      // with the retry, and the events, still pending.
      await new Promise<void>((resolve) => {
        const timer = setTimeout(done, CLOSE_RETRY_MS);
        signal.addEventListener("abort", done, { once: true });
        function done() {
          clearTimeout(timer);
          signal.removeEventListener("abort", done);
          resolve();
        }
      });
      if (!signal.aborted) await this.#flush();
    }
  }

  status(): AuditStatus {
    return {
      state: this.#state,
      sinks: this.#sinks.map((sink) => sink.status()),
      rejected: this.#rejected,
    };
  }

  async #flushSink(sink: Sink): Promise<void> {
    // Deliver only what was queued when the flush started, in bounded
    // batches, removing each batch as soon as it is acknowledged.
    let remaining = sink.queue.length;
    if (sink.spool && remaining > 0)
      try {
        sink.spool.sync(sink.queue);
      } catch (error) {
        this.#spoolFailure(sink, error);
      }
    let changed = false;
    while (remaining > 0) {
      const batch = sink.queue.slice(0, Math.min(remaining, sink.batchLimit));
      try {
        if (!sink.writer) throw new Error(sink.lastError ?? "sink is not open");
        if (this.#abort.signal.aborted) throw new Error("audit log closed");
        await sink.writer.write(
          { schema: AUDIT_BATCH_SCHEMA, events: batch },
          this.#abort.signal,
        );
      } catch (error) {
        sink.lastError = sink.describeError(error);
        if (sink.config.required) {
          if (sink.replayed > 0 && refused(error)) {
            // A replayed event the collector will not take (forged, or an
            // older schema) must not wedge the queue: narrow the batch down
            // to it, then set it aside once refused alone REPLAY_REFUSALS
            // times in a row while the collector takes another event.
            if (batch.length > 1) {
              sink.batchLimit = Math.ceil(batch.length / 2);
              continue;
            }
            const head = batch[0] as AuditEvent;
            sink.refusals = sink.refusedId === head.id ? sink.refusals + 1 : 1;
            sink.refusedId = head.id;
            if (sink.refusals >= REPLAY_REFUSALS && sink.spool) {
              // The last event of this flush, alone: a collector that
              // refuses it too refuses everything (misconfigured, not this
              // event), and the head stays queued.
              const probe = sink.queue[remaining - 1] as AuditEvent;
              if (remaining < 2 || !(await this.#deliverAlone(sink, probe))) {
                if (sink.state !== "failed") sink.state = "degraded";
                break;
              }
              sink.queue.splice(remaining - 1, 1);
              if (remaining - 1 < sink.replayed) sink.replayed -= 1;
              sink.delivered += 1;
              remaining -= 1;
              changed = true;
              try {
                sink.spool.reject(head);
              } catch (rejectError) {
                this.#spoolFailure(sink, rejectError);
                break;
              }
              sink.queue.splice(0, 1);
              sink.replayed -= 1;
              sink.rejected += 1;
              remaining -= 1;
              sink.refusedId = undefined;
              sink.refusals = 0;
              sink.batchLimit = BATCH_LIMIT;
              changed = true;
              continue;
            }
          }
          // Retain for retry; the queue bound turns sustained failure into `failed`.
          if (sink.state !== "failed") sink.state = "degraded";
          break;
        }
        sink.queue.splice(0, remaining);
        sink.dropped += remaining;
        sink.state = "degraded";
        return;
      }
      sink.queue.splice(0, batch.length);
      sink.replayed = Math.max(0, sink.replayed - batch.length);
      sink.delivered += batch.length;
      remaining -= batch.length;
      sink.state = "ok";
      sink.lastError = undefined;
      sink.refusedId = undefined;
      sink.refusals = 0;
      // Widen again after narrowing down to a refused event.
      sink.batchLimit = Math.min(BATCH_LIMIT, sink.batchLimit * 2);
      changed = true;
    }
    // Once per flush, not per batch: a rewrite costs the whole queue (bounded
    // by the cap) and two fsyncs.
    if (sink.spool && changed)
      try {
        sink.spool.replace(sink.queue);
        sink.spoolFailed = false;
      } catch (error) {
        this.#spoolFailure(sink, error);
      }
  }

  /** Send one event on its own; whether the collector took it. */
  async #deliverAlone(sink: Sink, event: AuditEvent): Promise<boolean> {
    try {
      await sink.writer?.write(
        { schema: AUDIT_BATCH_SCHEMA, events: [event] },
        this.#abort.signal,
      );
      return sink.writer !== undefined;
    } catch {
      return false;
    }
  }

  #spoolFailure(sink: Sink, error: unknown): void {
    sink.spoolFailed = true;
    sink.state = "failed";
    sink.lastError = sink.describeError(error);
  }

  #computeState(): AuditLogState {
    if (!this.#config.enabled || this.#sinks.length === 0) return "disabled";
    if (this.#sinks.some((sink) => sink.state === "failed")) return "failed";
    if (this.#sinks.some((sink) => sink.state === "degraded"))
      return "degraded";
    return "ok";
  }

  #update(): void {
    const next = this.#computeState();
    if (next === this.#state) return;
    this.#state = next;
    try {
      this.#onStateChange?.(next, this.status());
    } catch {
      // Observers must not break emission.
    }
  }
}

async function openSink(
  config: AuditSinkConfig,
  options: AuditLogOptions,
): Promise<Sink> {
  if (config.type === "file") {
    const writer = new FileSinkWriter(options.stateDir, options.rotation);
    const sink = new Sink(config, writer, undefined);
    try {
      await writer.prepare();
    } catch (error) {
      markOpenFailure(sink, error);
    }
    return sink;
  }
  let url: URL;
  try {
    url = resolveHttpUrl(config, options.resolveUrl);
  } catch (error) {
    return markOpenFailure(new Sink(config, undefined, undefined), error);
  }
  const fetch = plainHttpSink(url)
    ? options.plainHttpFetch?.(url)
    : options.fetch;
  if (!fetch)
    return markOpenFailure(
      new Sink(config, undefined, url.href),
      new Error(
        plainHttpSink(url)
          ? "no plain-HTTP fetch was provided"
          : "no fetch was provided",
      ),
    );
  const writer = new HttpSinkWriter(
    url,
    fetch,
    options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
  );
  const sink = new Sink(config, writer, url.href);
  // Readiness probe: required HTTP sinks must accept an empty batch.
  if (config.required)
    try {
      await writer.write(
        { schema: AUDIT_BATCH_SCHEMA, events: [] },
        new AbortController().signal,
      );
    } catch (error) {
      throw unavailable(config, sink.describeError(error));
    }
  if (config.required) {
    // Only a required sink spools: an optional one drops what it cannot send.
    const spool = new HttpSpool(
      options.stateDir,
      config.id,
      options.spoolMaxBytes ?? AUDIT_SPOOL_MAX_BYTES,
    );
    try {
      const replayed = spool.open(
        options.config.capture,
        options.replaySpool === true,
      );
      // One at a time: spreading a large replay passes V8's argument limit.
      for (const event of replayed) sink.queue.push(event);
      sink.replayed = replayed.length;
    } catch (error) {
      throw unavailable(
        config,
        `its spool under ${AUDIT_SPOOL_DIRECTORY} cannot be used: ${sink.describeError(error)}`,
      );
    }
    sink.spool = spool;
  }
  return sink;
}

/**
 * AUDIT_UNAVAILABLE when a required sink ended with events it did not take
 * (still pending, or dropped because its buffer was full or the log was
 * closed); otherwise undefined. `prefix` says what happened to the operation
 * those events describe. The message holds counts, sink IDs, and the
 * already-redacted last error only.
 */
export function requiredAuditLoss(
  status: AuditStatus,
  prefix = "Audit events were lost",
): PiShipError | undefined {
  const lost = status.sinks.filter(
    (sink) => sink.required && (sink.pending > 0 || sink.dropped > 0),
  );
  if (!lost.length) return undefined;
  const sinks = lost
    .map(
      (sink) =>
        `${sink.id} (${sink.pending} pending, ${sink.dropped} dropped${sink.lastError ? `; last error: ${sink.lastError}` : ""})`,
    )
    .join(", ");
  return new PiShipError(
    "AUDIT_UNAVAILABLE",
    `${prefix}: ${lost.reduce((sum, sink) => sum + sink.pending + sink.dropped, 0)} audit event(s) were not delivered to required audit sink ${sinks}`,
    {
      component: "audit",
      userAction:
        "Restore the required audit sink and report the unrecorded activity to the distribution administrator",
      sanitizedDetail: {
        sinks: lost.map((sink) => ({
          id: sink.id,
          pending: sink.pending,
          dropped: sink.dropped,
        })),
      },
    },
  );
}

/** Required sinks fail launch; optional sinks start degraded. */
function markOpenFailure(sink: Sink, error: unknown): Sink {
  const reason = sink.describeError(error);
  if (sink.config.required) throw unavailable(sink.config, reason);
  sink.state = "degraded";
  sink.lastError = reason;
  return sink;
}

/** Whether a file of `size` bytes is non-empty and does not end with a newline. */
async function endsMidLine(handle: FileHandle, size: number): Promise<boolean> {
  if (size === 0) return false;
  const last = Buffer.alloc(1);
  const { bytesRead } = await handle.read(last, 0, 1, size - 1);
  return bytesRead === 1 && last[0] !== 0x0a;
}

/**
 * Stat a file through an open read handle rather than by path, so the check
 * describes the file that was opened and no later path lookup depends on it.
 */
async function statOpen(path: string) {
  const handle = await open(path, "r");
  try {
    return await handle.stat();
  } finally {
    await handle.close();
  }
}
