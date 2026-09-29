import { randomBytes, randomUUID } from "node:crypto";
import { constants, existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
  AUDIT_BATCH_SCHEMA,
  type AuditBatch,
  type AuditCapture,
  type AuditEmitter,
  type AuditEvent,
  type AuditSink,
  isLoopbackHost,
  NO_CONTENT_CAPTURE,
  PiShipError,
} from "@piship/contracts";
import { type AuditEventInput, sanitizeEvent, scrubText } from "./sanitize.js";

/** Structurally identical to `@piship/schema` AuditSinkConfig. */
export interface AuditSinkConfig {
  readonly id: string;
  readonly type: "file" | "http";
  /** HTTP sinks: endpoint URL or `${NAME}` runtime reference. */
  readonly url?: string;
  readonly required: boolean;
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
  /** Resolves `${NAME}` references in HTTP sink URLs. */
  readonly resolveUrl?: (template: string) => string;
  readonly now?: () => Date;
  readonly onStateChange?: (state: AuditLogState, status: AuditStatus) => void;
  /** Per-request timeout for HTTP sinks. Default 10 s. */
  readonly requestTimeoutMs?: number;
  /**
   * File sink retention. Fixed defaults (AUDIT_ROTATION); not a manifest
   * setting. Tests pass smaller limits.
   */
  readonly rotation?: AuditRotation;
}

/** Size-based retention of the file sink: `audit.jsonl` plus `.1`..`.<files>`. */
export interface AuditRotation {
  /** Rotate before an append would grow `audit.jsonl` past this size. */
  readonly maxBytes: number;
  /** Rotated files kept (`audit.jsonl.1` is the newest); older ones are deleted. */
  readonly files: number;
}

/** 10 MB per file, five rotated files: at most about 60 MB of local audit. */
export const AUDIT_ROTATION: AuditRotation = Object.freeze({
  maxBytes: 10 * 1024 * 1024,
  files: 5,
});

/** Input accepted by `emit`; distribution and schema are filled by the log. */
export type AuditEmitInput = Omit<AuditEventInput, "distribution">;

export const AUDIT_LOG_FILE = join("logs", "audit.jsonl");
/** A rotation older than this is treated as abandoned by a crashed process. */
const ROTATION_LOCK_STALE_MS = 30_000;

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
  for (let index = 1; index <= rotation.files; index += 1)
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
      const { size } = await handle.stat();
      if (bytes > 0 && size > 0 && size + bytes > this.rotation.maxBytes) {
        await handle.close();
        await this.rotate(generation, bytes);
        handle = await this.open();
      }
      if (process.platform !== "win32") await handle.chmod(0o600);
      if (data) await handle.appendFile(data, "utf8");
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  private open() {
    // O_NOFOLLOW refuses a planted symlink; it is 0 where unsupported.
    const flags =
      constants.O_WRONLY |
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
    const token = `${process.pid}-${randomBytes(8).toString("hex")}\n`;
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
      await rm(`${this.path}.${files}`, { force: true });
      for (let index = files - 1; index >= 1; index -= 1)
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
   * Create the rotation lock holding `token`. A lock older than the stale
   * limit is taken over by renaming it to a unique name first: only one
   * process's rename of that file succeeds, and a lock that turns out to be
   * fresh (another process took over in between) is given up, not reused.
   */
  private async acquireRotationLock(
    lock: string,
    token: string,
  ): Promise<boolean> {
    const create = async () => {
      await writeFile(lock, token, { flag: "wx", mode: 0o600 });
      return true;
    };
    try {
      return await create();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
    }
    try {
      if (Date.now() - (await statOpen(lock)).mtimeMs <= ROTATION_LOCK_STALE_MS)
        return false;
      const taken = `${lock}.${randomBytes(6).toString("hex")}.stale`;
      await rename(lock, taken);
      const age = Date.now() - (await statOpen(taken)).mtimeMs;
      await rm(taken, { force: true });
      if (age <= ROTATION_LOCK_STALE_MS) return false;
      return await create();
    } catch {
      return false;
    }
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
      throw new Error(`collector answered HTTP ${response.status}`);
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
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && isLoopbackHost(url.hostname))
  )
    throw new Error(
      "HTTP sink url must use https (plain http only for loopback)",
    );
  return url;
}

class Sink {
  readonly queue: AuditEvent[] = [];
  state: AuditSinkState = "ok";
  delivered = 0;
  dropped = 0;
  lastError: string | undefined;

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
    return new AuditLog(config, options.distribution, sinks, options);
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
        if (sink.queue.length >= limit) {
          sink.dropped += 1;
          if (sink.config.required) sink.state = "failed";
          else sink.state = "degraded";
          continue;
        }
        sink.queue.push(event);
        // Early flush at half capacity, but not while a sink is retrying.
        if (sink.queue.length * 2 >= limit && !sink.lastError) flushSoon = true;
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
      `Audit is unavailable: required sink ${sink?.config.id ?? "unknown"} is failing and the audit buffer is full`,
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
    while (remaining > 0) {
      const batch = sink.queue.slice(0, Math.min(remaining, BATCH_LIMIT));
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
          // Retain for retry; the queue bound turns sustained failure into `failed`.
          if (sink.state !== "failed") sink.state = "degraded";
          return;
        }
        sink.queue.splice(0, remaining);
        sink.dropped += remaining;
        sink.state = "degraded";
        return;
      }
      sink.queue.splice(0, batch.length);
      sink.delivered += batch.length;
      remaining -= batch.length;
      sink.state = "ok";
      sink.lastError = undefined;
    }
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
  if (!options.fetch)
    return markOpenFailure(
      new Sink(config, undefined, url.href),
      new Error("no fetch was provided"),
    );
  const writer = new HttpSinkWriter(
    url,
    options.fetch,
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
