import { constants } from "node:fs";
import { chmod, mkdir, open } from "node:fs/promises";
import { join } from "node:path";
import {
  type AuditCapture,
  type AuditEmitter,
  type AuditEvent,
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
}

/** Input accepted by `emit`; distribution and schema are filled by the log. */
export type AuditEmitInput = Omit<AuditEventInput, "distribution">;

export const AUDIT_BATCH_SCHEMA = "piship-audit-batch/v1" as const;
export const AUDIT_LOG_FILE = join("logs", "audit.jsonl");
/** Events per write (one HTTP POST or one file append). */
const BATCH_LIMIT = 500;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_CLOSE_DEADLINE_MS = 5_000;

const DISABLED_CONFIG: AuditConfig = {
  enabled: false,
  sinks: [],
  buffer: { maxEvents: 0, flushIntervalMs: 0 },
  capture: NO_CONTENT_CAPTURE,
};

interface SinkWriter {
  /** Deliver a batch; throws on failure. */
  write(events: readonly AuditEvent[], signal: AbortSignal): Promise<void>;
}

class FileSinkWriter implements SinkWriter {
  readonly path: string;

  constructor(readonly stateDir: string) {
    this.path = join(stateDir, AUDIT_LOG_FILE);
  }

  /** Create `logs/` (0700) and the log file (0600) and prove it is writable. */
  async prepare(): Promise<void> {
    await this.append("");
  }

  async write(events: readonly AuditEvent[]): Promise<void> {
    await this.append(
      events.map((event) => `${JSON.stringify(event)}\n`).join(""),
    );
  }

  private async append(data: string): Promise<void> {
    const directory = join(this.stateDir, "logs");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    // O_NOFOLLOW refuses a planted symlink; it is 0 where unsupported.
    const flags =
      constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      (constants.O_NOFOLLOW ?? 0);
    const handle = await open(this.path, flags, 0o600);
    try {
      if (process.platform !== "win32") await handle.chmod(0o600);
      if (data) await handle.appendFile(data, "utf8");
    } finally {
      await handle.close();
    }
  }
}

class HttpSinkWriter implements SinkWriter {
  constructor(
    readonly url: URL,
    readonly fetch: AuditFetch,
    readonly timeoutMs: number,
  ) {}

  async write(
    events: readonly AuditEvent[],
    signal: AbortSignal,
  ): Promise<void> {
    await this.post(events, signal);
  }

  async post(events: readonly AuditEvent[], signal: AbortSignal) {
    const response = await this.fetch(this.url.toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ schema: AUDIT_BATCH_SCHEMA, events }),
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
  if (/\$\{[^}]*\}/.test(value))
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
    readonly writer: SinkWriter | undefined,
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
      if (this.#state === "disabled" || this.#closed) return;
      const event = sanitizeEvent(
        { ...input, distribution: this.#distribution },
        this.#config.capture,
        this.#now,
      );
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
   * Stop the timer, run a final flush bounded by `deadlineMs`, and abort any
   * delivery still running at the deadline. Undelivered events stay counted
   * as pending in the returned status.
   */
  async close(deadlineMs = DEFAULT_CLOSE_DEADLINE_MS): Promise<AuditStatus> {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    if (this.#state !== "disabled" && !this.#closed) {
      const final = this.flush();
      this.#closed = true;
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
        await sink.writer.write(batch, this.#abort.signal);
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
    const writer = new FileSinkWriter(options.stateDir);
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
      await writer.post([], new AbortController().signal);
    } catch (error) {
      throw unavailable(config, sink.describeError(error));
    }
  return sink;
}

/** Required sinks fail launch; optional sinks start degraded. */
function markOpenFailure(sink: Sink, error: unknown): Sink {
  const reason = sink.describeError(error);
  if (sink.config.required) throw unavailable(sink.config, reason);
  sink.state = "degraded";
  sink.lastError = reason;
  return sink;
}
