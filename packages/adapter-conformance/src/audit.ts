// The audit sink conformance kit. It checks an `AuditSink` against the
// `piship-audit-batch/v1` contract (docs/enterprise-integration.md, "Audit
// collector") by connecting it to a collector the kit controls: the kit
// writes batches, makes the collector fail, hold, or store and then fail, and
// reads back what was stored. It imports only @piship/adapter-sdk.
import {
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  type AuditBatch,
  type AuditEvent,
  type AuditSink,
  isPiShipError,
  type ManagedFetch,
} from "@piship/adapter-sdk";
import type { ConformanceReport, ConformanceResult } from "./index.js";
import { Finding } from "./shared.js";

/** What `testAuditSink` checks, in report order. */
export const AUDIT_SINK_BEHAVIORS = [
  "metadata-only defaults",
  "secret redaction",
  "identity attribution",
  "session correlation",
  "event id stability",
  "delivery failure",
  "buffer behavior",
  "fail-closed policy",
  "shutdown flush",
  "duplicate handling",
] as const;
export type AuditSinkBehavior = (typeof AUDIT_SINK_BEHAVIORS)[number];

/** What the kit hands the sink it builds for each check. */
export interface AuditSinkEnvironment {
  /** The kit's collector. POST `piship-audit-batch/v1` batches here. */
  readonly url: string;
  /** Reaches the kit's collector; use it in place of the managed fetch. */
  readonly fetch: ManagedFetch;
  /**
   * A fake credential for the sink's own downstream, such as an ingest
   * token. It may appear in a request header; never in an event or an error.
   */
  readonly credential: string;
  /** Whether the sink is required: losing an event is then an error. */
  readonly required: boolean;
  /** The most events a buffering sink may hold. */
  readonly maxEvents: number;
}

/** Counts a buffering sink reports; `lastError` is redacted. */
export interface AuditSinkCounts {
  readonly delivered: number;
  readonly pending: number;
  readonly dropped: number;
  readonly lastError?: string;
}

/**
 * A sink that holds events before the collector has them. `write` queues the
 * batch (an empty batch is still the readiness probe and asks the collector
 * at once), `flush` delivers what is queued and never rejects, `status`
 * reports counts, and `close` delivers what it can within `deadlineMs` and
 * returns what was not taken.
 */
export interface BufferedAuditSink extends AuditSink {
  flush(): Promise<void>;
  status(): AuditSinkCounts;
  close(deadlineMs: number): Promise<AuditSinkCounts>;
}

export type AuditSinkFactory = (
  environment: AuditSinkEnvironment,
) => AuditSink | Promise<AuditSink>;

export interface AuditSinkKitOptions {
  /** Longest one check may take before it fails. Default 10 s. */
  readonly timeoutMs?: number;
  /** Deadline the kit passes to `close()`. Default 250 ms. */
  readonly closeDeadlineMs?: number;
}

// ---------------------------------------------------------------- fixtures

const COLLECTOR_URL = "https://audit-collector.conformance.invalid/v1/batches";
const DISTRIBUTION = "conformance";
const PROMPT_TEXT = "conformance prompt sentinel: summarize fixture.txt";
const COMMAND_TEXT = "conformance command sentinel: cat fixture.txt";
const BASE_TIME = Date.UTC(2026, 0, 1);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EVENT_TYPES = new Set<string>(AUDIT_EVENT_TYPES);
const LIFECYCLE = ["flush", "status", "close"] as const;
let credentials = 0;

/** Fixture event `n`: its `time` is unique, so the kit finds it by time. */
function fixture(n: number, fields: Partial<AuditEvent> = {}): AuditEvent {
  return {
    schema: AUDIT_EVENT_SCHEMA,
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`,
    event: "tool.request",
    time: new Date(BASE_TIME + n * 1000).toISOString(),
    user: "subject-alice",
    session: "session-a",
    distribution: DISTRIBUTION,
    resource: "bash",
    decision: "allowed",
    enforcement: "control-plane",
    detail: { bytes: 42 },
    ...fields,
  };
}

const batchOf = (events: readonly AuditEvent[]): AuditBatch => ({
  schema: AUDIT_BATCH_SCHEMA,
  events,
});
const PROBE = batchOf([]);

/** JSON with object keys sorted, the comparison form of an event. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

// ---------------------------------------------------------------- collector

type Answer = "store" | "unavailable" | "redirect" | "network" | "store-fail";
type Mode = Answer | "hold";

interface CollectorRequest {
  readonly events: readonly Record<string, unknown>[];
  readonly body: string;
}

/**
 * A `piship-audit-batch/v1` collector: it checks the batch shape, stores an
 * event only if its `id` is new, keeps an event whose `id` returns with
 * different content as a conflict, and answers as the kit tells it.
 */
class Collector {
  mode: Mode = "store";
  /** Answers for the next requests, before `mode` applies again. */
  readonly next: Mode[] = [];
  readonly requests: CollectorRequest[] = [];
  readonly stored: Record<string, unknown>[] = [];
  readonly conflicts: string[] = [];
  readonly invalid: string[] = [];
  readonly #forms = new Map<string, string>();
  readonly #held = new Set<(answer: Answer) => void>();

  readonly fetch: ManagedFetch = (url, init) => {
    // Synchronous up to the answer, so a request is visible as soon as the
    // sink has made it.
    try {
      return this.#receive(String(url), init);
    } catch (error) {
      return Promise.reject(error);
    }
  };

  get held(): number {
    return this.#held.size;
  }

  /** Answer every held request with `answer` and stop holding new ones. */
  release(answer: Answer = "store"): void {
    this.mode = answer;
    for (const resolve of [...this.#held]) resolve(answer);
  }

  /** Requests that carried events; the readiness probe is left out. */
  get deliveries(): CollectorRequest[] {
    return this.requests.filter((request) => request.events.length > 0);
  }

  #receive(url: string, init: RequestInit | undefined): Promise<Response> {
    const signal = init?.signal ?? undefined;
    signal?.throwIfAborted();
    if (url !== COLLECTOR_URL) return answer(404);
    if ((init?.method ?? "GET").toUpperCase() !== "POST") return answer(405);
    const body = typeof init?.body === "string" ? init.body : undefined;
    if (body === undefined) return this.#refuse("the body is not JSON text");
    let batch: unknown;
    try {
      batch = JSON.parse(body);
    } catch {
      return this.#refuse("the body is not JSON");
    }
    const problem = batchProblem(batch);
    if (problem) return this.#refuse(problem);
    const events = (batch as { events: Record<string, unknown>[] }).events;
    this.requests.push({ events, body });
    const mode = this.next.shift() ?? this.mode;
    if (mode !== "hold") return this.#answer(mode, events);
    return new Promise<Response>((resolve, reject) => {
      const settle = (next: Answer) => {
        this.#held.delete(settle);
        signal?.removeEventListener("abort", onAbort);
        this.#answer(next, events).then(resolve, reject);
      };
      const onAbort = () => {
        this.#held.delete(settle);
        reject(signal?.reason ?? new Error("aborted"));
      };
      this.#held.add(settle);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  #refuse(reason: string): Promise<Response> {
    this.invalid.push(reason);
    return answer(400);
  }

  #answer(
    mode: Answer,
    events: readonly Record<string, unknown>[],
  ): Promise<Response> {
    if (mode === "network")
      return Promise.reject(new TypeError("fetch failed"));
    if (mode === "unavailable") return answer(503);
    if (mode === "redirect") return answer(302, `${COLLECTOR_URL}/moved`);
    for (const event of events) this.#store(event);
    return answer(mode === "store-fail" ? 503 : 200);
  }

  #store(event: Record<string, unknown>): void {
    const id = event.id as string;
    const form = canonical(event);
    const known = this.#forms.get(id);
    if (known === form) return;
    // A different event under a known id is kept in full and flagged.
    if (known !== undefined) this.conflicts.push(id);
    else this.#forms.set(id, form);
    this.stored.push(event);
  }

  /** Stored events for the fixture sent at `time`. */
  storedAt(time: string): Record<string, unknown>[] {
    return this.stored.filter((event) => event.time === time);
  }
}

function answer(status: number, location?: string): Promise<Response> {
  return Promise.resolve(
    new Response(null, {
      status,
      ...(location ? { headers: { location } } : {}),
    }),
  );
}

/** Why a request body is not a `piship-audit-batch/v1` batch, if it is not. */
function batchProblem(batch: unknown): string | undefined {
  if (!batch || typeof batch !== "object") return "the body is not an object";
  const { schema, events } = batch as { schema?: unknown; events?: unknown };
  if (schema !== AUDIT_BATCH_SCHEMA)
    return `schema is not ${AUDIT_BATCH_SCHEMA}`;
  if (!Array.isArray(events)) return "events is not an array";
  if (events.length > 500) return "a batch holds more than 500 events";
  for (const event of events) {
    if (!event || typeof event !== "object") return "an event is not an object";
    const item = event as Record<string, unknown>;
    if (item.schema !== AUDIT_EVENT_SCHEMA)
      return `an event's schema is not ${AUDIT_EVENT_SCHEMA}`;
    if (typeof item.id !== "string" || !UUID.test(item.id))
      return "an event has no UUID id";
    if (typeof item.event !== "string" || !EVENT_TYPES.has(item.event))
      return "an event has an unknown type";
    if (typeof item.time !== "string") return "an event has no time";
    for (const field of ["user", "session"])
      if (item[field] !== null && typeof item[field] !== "string")
        return `an event's ${field} is neither a string nor null`;
    if (typeof item.distribution !== "string")
      return "an event has no distribution";
  }
  return undefined;
}

// ---------------------------------------------------------------- harness

/** Fail the check with `reason`. */
function fail(reason: string): never {
  throw new Finding(reason);
}

interface Outcome {
  readonly ok: boolean;
  readonly error?: unknown;
}

function isBuffered(sink: AuditSink): sink is BufferedAuditSink {
  return LIFECYCLE.every(
    (name) =>
      typeof (sink as unknown as Record<string, unknown>)[name] === "function",
  );
}

/** The lifecycle members a sink declares, or undefined when it declares none. */
function partialLifecycle(sink: AuditSink): string | undefined {
  const record = sink as unknown as Record<string, unknown>;
  const present = LIFECYCLE.filter(
    (name) => typeof record[name] === "function",
  );
  if (present.length === 0 || present.length === LIFECYCLE.length)
    return undefined;
  const missing = LIFECYCLE.filter((name) => !present.includes(name));
  return `The sink declares ${present.join(" and ")} but not ${missing.join(" and ")}: a buffering sink needs flush, status, and close together`;
}

function message(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/** Everything about an error the sink reported that a reader could see. */
function errorText(error: unknown): string {
  let text = error instanceof Error ? `${error.name}: ${error.message}` : "";
  try {
    text += ` ${JSON.stringify(error)}`;
  } catch {
    text += ` ${String(error)}`;
  }
  return text;
}

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** Wait until `condition` holds or `ms` pass; returns whether it held. */
async function until(condition: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > end) return false;
    await tick();
  }
  return true;
}

/** Tracks whether a promise has settled, and how. */
function track<T>(promise: Promise<T>) {
  const state: { settled: boolean; rejected: boolean; error?: unknown } = {
    settled: false,
    rejected: false,
  };
  const done = promise.then(
    () => {
      state.settled = true;
    },
    (error: unknown) => {
      state.settled = true;
      state.rejected = true;
      state.error = error;
    },
  );
  return { state, done };
}

class Harness {
  readonly collector = new Collector();
  readonly environment: AuditSinkEnvironment;
  sink: AuditSink | undefined;

  constructor(
    readonly create: AuditSinkFactory,
    readonly closeDeadlineMs: number,
    settings: { required: boolean; maxEvents: number },
  ) {
    credentials += 1;
    this.environment = Object.freeze({
      url: COLLECTOR_URL,
      fetch: this.collector.fetch,
      credential: `fake-conformance-credential-${credentials.toString().padStart(4, "0")}`,
      ...settings,
    });
  }

  async open(): Promise<AuditSink> {
    try {
      this.sink = await Promise.resolve().then(() =>
        this.create(this.environment),
      );
    } catch (error) {
      fail(`Creating the sink failed: ${message(error)}`);
    }
    if (!this.sink || typeof this.sink.write !== "function")
      fail("The factory did not return an object with a write function");
    return this.sink;
  }

  get buffered(): BufferedAuditSink | undefined {
    return this.sink && isBuffered(this.sink) ? this.sink : undefined;
  }

  /** The sink's write; a synchronous throw counts as a rejection. */
  write(
    batch: AuditBatch,
    signal = new AbortController().signal,
  ): Promise<void> {
    try {
      return Promise.resolve((this.sink as AuditSink).write(batch, signal));
    } catch (error) {
      return Promise.reject(error);
    }
  }

  /**
   * Hand `batch` to the sink and report whether the collector took it: the
   * write's answer for a plain sink; for a buffering sink, whether a flush
   * moved every event to `delivered`.
   */
  async deliver(batch: AuditBatch): Promise<Outcome> {
    const buffered = this.buffered;
    if (!buffered) {
      try {
        await this.write(batch);
        return { ok: true };
      } catch (error) {
        return { ok: false, error };
      }
    }
    try {
      await this.write(batch);
    } catch (error) {
      return { ok: false, error };
    }
    return this.flush(batch.events.length);
  }

  /** Send `batch` again: a plain sink is written again, a buffering one flushed. */
  retry(batch: AuditBatch): Promise<Outcome> {
    return this.buffered
      ? this.flush(batch.events.length)
      : this.deliver(batch);
  }

  async flush(count: number): Promise<Outcome> {
    const sink = this.buffered as BufferedAuditSink;
    const before = sink.status().delivered;
    try {
      await sink.flush();
    } catch (error) {
      return { ok: false, error };
    }
    const after = sink.status();
    return after.delivered - before >= count && after.pending === 0
      ? { ok: true }
      : { ok: false, error: after.lastError };
  }

  /** Free held requests and close a buffering sink, never failing the check. */
  async dispose(): Promise<void> {
    this.collector.release("unavailable");
    const sink = this.buffered;
    if (!sink) return;
    await Promise.race([
      Promise.resolve()
        .then(() => sink.close(0))
        .catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 1_000).unref?.()),
    ]);
  }
}

type Check = (
  open: (
    settings?: Partial<{ required: boolean; maxEvents: number }>,
  ) => Promise<Harness>,
) => Promise<string | undefined>;

// ---------------------------------------------------------------- checks

const PLAIN_SKIP =
  "The sink has no flush, status, or close, so it holds no events of its own: each write settles with the collector's answer and PiShip's audit log buffer applies";

function describeFailure(outcome: Outcome): string {
  return outcome.error === undefined ? "no error" : message(outcome.error);
}

/** Deliver to a healthy collector, or fail with what the sink said. */
async function mustDeliver(harness: Harness, batch: AuditBatch, what: string) {
  const outcome = await harness.deliver(batch);
  if (!outcome.ok)
    fail(
      `The sink did not deliver ${what} to a healthy collector: ${describeFailure(outcome)}${invalidNote(harness)}`,
    );
}

function invalidNote(harness: Harness): string {
  const [first] = harness.collector.invalid;
  return first ? ` (the collector refused a request: ${first})` : "";
}

/** The single stored event for the fixture sent as `sent`, or a failure. */
function storedOnce(harness: Harness, sent: AuditEvent) {
  const [stored] = harness.collector.storedAt(sent.time);
  if (!stored) fail(`The event sent at ${sent.time} was not stored`);
  return stored;
}

const metadataOnly: Check = async (open) => {
  const harness = await open();
  const plain = fixture(1);
  const withContent = fixture(2, {
    event: "model.request",
    resource: "model-a",
    content: { prompt: PROMPT_TEXT, command: COMMAND_TEXT },
  });
  const another = fixture(3, { event: "tool.allowed" });
  await mustDeliver(harness, batchOf([plain, withContent, another]), "a batch");
  for (const sent of [plain, another]) {
    const stored = storedOnce(harness, sent);
    if ("content" in stored)
      fail(
        `The event sent at ${sent.time} carried no content but was stored with a content property`,
      );
    const text = canonical(stored);
    if (text.includes(PROMPT_TEXT) || text.includes(COMMAND_TEXT))
      fail(
        `The event sent at ${sent.time} carried no content but was stored with another event's prompt or command text`,
      );
  }
  const stored = storedOnce(harness, withContent);
  if (canonical(stored.content) !== canonical(withContent.content))
    fail(
      "An event's opted-in content was not stored exactly as it arrived under content",
    );
  const outside = canonical({ ...stored, content: undefined });
  if (outside.includes(PROMPT_TEXT) || outside.includes(COMMAND_TEXT))
    fail("Opted-in content was copied outside the event's content property");
  return undefined;
};

const secretRedaction: Check = async (open) => {
  const healthy = await open();
  const { credential } = healthy.environment;
  const batch = batchOf([
    fixture(1, { detail: { apiKey: "[REDACTED]", status: 401 } }),
    fixture(2, { event: "credential.acquire", resource: "gateway" }),
  ]);
  await mustDeliver(healthy, batch, "a batch");
  if (
    healthy.collector.stored.some((event) =>
      canonical(event).includes(credential),
    )
  )
    fail("A stored event holds the sink's downstream credential");
  if (
    healthy.collector.requests.some((request) =>
      request.body.includes(credential),
    )
  )
    fail("A request body holds the sink's downstream credential");
  const failing = await open();
  failing.collector.mode = "unavailable";
  const outcome = await failing.deliver(batch);
  const reported = [
    outcome.error === undefined ? "" : errorText(outcome.error),
    failing.buffered ? JSON.stringify(failing.buffered.status()) : "",
  ].join(" ");
  if (reported.includes(failing.environment.credential))
    fail(
      "The error the sink reported for a failed delivery holds its downstream credential",
    );
  return undefined;
};

const identityAttribution: Check = async (open) => {
  const harness = await open();
  const sent = [
    fixture(1, {
      event: "identity.login",
      user: "subject-alice",
      session: null,
    }),
    fixture(2, { event: "runtime.update", user: null, session: null }),
    fixture(3, { user: "subject-bob", session: "session-b" }),
    fixture(4, { user: "subject-alice" }),
  ];
  await mustDeliver(harness, batchOf(sent), "a batch");
  for (const event of sent) {
    const stored = storedOnce(harness, event);
    if (stored.user !== event.user)
      fail(
        `The event sent at ${event.time} with user ${JSON.stringify(event.user)} was stored with user ${JSON.stringify(stored.user)}: user is the identity subject as sent, or null`,
      );
  }
  return undefined;
};

const sessionCorrelation: Check = async (open) => {
  const harness = await open();
  const first = [
    fixture(1, { event: "session.start" }),
    fixture(2),
    fixture(3, { event: "identity.login", session: null }),
  ];
  const second = [
    fixture(4, { event: "session.end" }),
    fixture(5, { session: "session-b", user: "subject-bob" }),
  ];
  await mustDeliver(harness, batchOf(first), "a first batch");
  await mustDeliver(harness, batchOf(second), "a second batch");
  for (const event of [...first, ...second]) {
    const stored = storedOnce(harness, event);
    if (stored.session !== event.session)
      fail(
        `The event sent at ${event.time} in session ${JSON.stringify(event.session)} was stored with session ${JSON.stringify(stored.session)}: a session's events must keep one session value across batches`,
      );
  }
  return undefined;
};

/** Every delivered copy of a fixture carries the id it was sent with. */
function checkIds(harness: Harness, sent: readonly AuditEvent[]): void {
  const byTime = new Map(sent.map((event) => [event.time, event]));
  harness.collector.deliveries.forEach((request, index) => {
    for (const event of request.events) {
      const original = byTime.get(event.time as string);
      if (!original) continue;
      if (event.id !== original.id)
        fail(
          `The event sent at ${original.time} reached the collector${index > 0 ? " on a retry" : ""} with id ${String(event.id)} instead of ${original.id}`,
        );
    }
  });
}

const eventIdStability: Check = async (open) => {
  const harness = await open({ required: true });
  const sent = [fixture(1), fixture(2, { event: "tool.denied" }), fixture(3)];
  const batch = batchOf(sent);
  harness.collector.next.push("unavailable");
  await harness.deliver(batch);
  const retried = await harness.retry(batch);
  if (!retried.ok)
    fail(
      `The sink did not deliver the batch once the collector recovered: ${describeFailure(retried)}`,
    );
  checkIds(harness, sent);
  for (const event of sent) storedOnce(harness, event);
  return undefined;
};

const deliveryFailure: Check = async (open) => {
  const batch = batchOf([fixture(1), fixture(2)]);
  const failures: [Answer, string][] = [
    ["unavailable", "HTTP 503"],
    ["redirect", "a redirect (HTTP 302)"],
    ["network", "a network error"],
  ];
  for (const [mode, what] of failures) {
    const harness = await open();
    harness.collector.mode = mode;
    const buffered = harness.buffered;
    if (!buffered) {
      const outcome = await harness.deliver(batch);
      if (outcome.ok)
        fail(`The sink resolved a write the collector answered with ${what}`);
      continue;
    }
    await harness.write(batch).catch(() => undefined);
    await buffered.flush().catch(() => undefined);
    const counts = buffered.status();
    if (counts.delivered > 0)
      fail(
        `The sink counted ${counts.delivered} event(s) as delivered although the collector answered with ${what}`,
      );
    if (counts.pending + counts.dropped < batch.events.length)
      fail(
        `The collector answered with ${what} and the sink lost ${batch.events.length - counts.pending - counts.dropped} event(s) without counting them as pending or dropped`,
      );
  }
  await answersOnlyAfterCollector(await open(), batch);
  const aborting = await open();
  if (!aborting.buffered) await rejectsOnAbort(aborting, batch);
  return undefined;
};

/** A write (or a buffering sink's flush) settles only after the collector answers. */
async function answersOnlyAfterCollector(harness: Harness, batch: AuditBatch) {
  harness.collector.mode = "hold";
  const buffered = harness.buffered;
  if (buffered) await harness.write(batch);
  const pending = track(buffered ? buffered.flush() : harness.write(batch));
  if (!(await until(() => harness.collector.held > 0, 2_000)))
    fail("The sink never sent the batch to the collector");
  for (let index = 0; index < 10; index += 1) await tick();
  if (pending.state.settled)
    fail(
      `The sink ${buffered ? "finished a flush" : "settled a write"} before the collector answered`,
    );
  harness.collector.release("store");
  await pending.done;
  if (!buffered && pending.state.rejected)
    fail(
      `The sink rejected a write the collector accepted: ${message(pending.state.error)}`,
    );
  if (buffered && buffered.status().delivered < batch.events.length)
    fail("The sink did not count a batch the collector accepted as delivered");
}

/** An aborted write rejects instead of resolving or hanging. */
async function rejectsOnAbort(harness: Harness, batch: AuditBatch) {
  harness.collector.mode = "hold";
  const controller = new AbortController();
  const pending = track(harness.write(batch, controller.signal));
  if (
    !(await until(
      () => harness.collector.held > 0 || pending.state.settled,
      2_000,
    ))
  )
    fail("The sink never sent the batch to the collector");
  controller.abort();
  if (!(await until(() => pending.state.settled, 2_000)))
    fail("The sink did not settle a write after its signal aborted");
  if (!pending.state.rejected)
    fail(
      "The sink resolved a write whose signal aborted before the collector answered",
    );
}

const bufferBehavior: Check = async (open) => {
  const probe = await open();
  const partial = partialLifecycle(probe.sink as AuditSink);
  if (partial) fail(partial);
  if (!probe.buffered) return PLAIN_SKIP;
  const limit = 4;
  const sent = Array.from({ length: limit + 2 }, (_, index) =>
    fixture(index + 1),
  );
  for (const required of [false, true]) {
    const kind = required ? "A required sink" : "An optional sink";
    const harness = await open({ required, maxEvents: limit });
    const sink = harness.buffered as BufferedAuditSink;
    harness.collector.mode = "hold";
    for (const event of sent) {
      const outcome = await harness.write(batchOf([event])).then(
        () => undefined,
        (error: unknown) => error,
      );
      if (outcome !== undefined && !required)
        fail(
          `An optional sink refused a write when its buffer was full (${message(outcome)}); it must drop and count instead`,
        );
      const { pending } = sink.status();
      if (pending > limit)
        fail(`${kind} held ${pending} events with maxEvents ${limit}`);
    }
    const full = sink.status();
    const overflow = sent.length - limit;
    harness.collector.release("store");
    for (let round = 0; round < 3 && sink.status().pending > 0; round += 1)
      await sink.flush().catch(() => undefined);
    const end = sink.status();
    const accounted = end.delivered + end.pending + end.dropped;
    if (accounted !== sent.length)
      fail(
        `${kind} took ${sent.length} events with maxEvents ${limit} and accounts for ${accounted} of them as delivered, pending, or dropped; every event must be in exactly one of those counts`,
      );
    if (full.dropped < overflow)
      fail(
        `${kind} counted ${full.dropped} dropped event(s) after ${overflow} did not fit its buffer`,
      );
    const kept = sent.slice(0, limit).map((event) => event.time);
    const times = harness.collector.stored.map((event) => event.time);
    if (canonical(times) !== canonical(kept))
      fail(
        `${kind} with a full buffer must keep the oldest ${limit} events, deliver them oldest first, and drop the newer ones; the collector stored a different sequence of ${times.length} event(s)`,
      );
  }
  return undefined;
};

const failClosed: Check = async (open) => {
  const harness = await open({ required: true });
  harness.collector.mode = "store";
  try {
    await harness.write(PROBE);
  } catch (error) {
    fail(
      `The sink refused the readiness probe while the collector was healthy: ${message(error)}`,
    );
  }
  if (
    !harness.collector.requests.some((request) => request.events.length === 0)
  )
    fail(
      "The sink answered the readiness probe (an empty batch) without asking the collector",
    );
  harness.collector.mode = "unavailable";
  const probed = await harness.write(PROBE).then(
    () => true,
    () => false,
  );
  if (probed)
    fail(
      "The sink resolved the readiness probe while the collector answered HTTP 503, so a required sink could not fail launch with AUDIT_UNAVAILABLE",
    );
  const partial = partialLifecycle(harness.sink as AuditSink);
  if (partial || !harness.buffered) return undefined;
  const limit = 4;
  const full = await open({ required: true, maxEvents: limit });
  const sink = full.buffered as BufferedAuditSink;
  full.collector.mode = "unavailable";
  for (let index = 1; index <= limit; index += 1)
    await full.write(batchOf([fixture(index)])).catch(() => undefined);
  await sink.flush().catch(() => undefined);
  const refusal = await full.write(batchOf([fixture(limit + 1)])).then(
    () => undefined,
    (error: unknown) => error ?? new Error("rejected"),
  );
  if (refusal === undefined)
    fail(
      "A required sink accepted a write while its buffer was full and the collector was down; it must refuse with AUDIT_UNAVAILABLE",
    );
  if (!isPiShipError(refusal) || refusal.code !== "AUDIT_UNAVAILABLE")
    fail(
      `A required sink with a full buffer refused a write with ${isPiShipError(refusal) ? refusal.code : message(refusal)} instead of a PiShipError with code AUDIT_UNAVAILABLE`,
    );
  full.collector.mode = "store";
  for (let round = 0; round < 3 && sink.status().pending > 0; round += 1)
    await sink.flush().catch(() => undefined);
  const recovered = await full.write(batchOf([fixture(limit + 2)])).then(
    () => undefined,
    (error: unknown) => error ?? new Error("rejected"),
  );
  if (recovered !== undefined)
    fail(
      `A required sink kept refusing writes after its buffer drained: ${message(recovered)}`,
    );
  return undefined;
};

const shutdownFlush: Check = async (open) => {
  const probe = await open();
  const partial = partialLifecycle(probe.sink as AuditSink);
  if (partial) fail(partial);
  if (!probe.buffered) return PLAIN_SKIP;
  const deadline = probe.closeDeadlineMs;
  const sent = [fixture(1), fixture(2), fixture(3)];

  const healthy = await open({ required: true });
  const sink = healthy.buffered as BufferedAuditSink;
  await healthy.write(batchOf(sent));
  const closed = await sink.close(deadline);
  const missing = sent.filter(
    (event) => healthy.collector.storedAt(event.time).length === 0,
  );
  if (missing.length)
    fail(
      `close() returned with ${missing.length} of ${sent.length} queued event(s) never sent to a healthy collector`,
    );
  if (closed.pending !== 0 || closed.dropped !== 0)
    fail(
      `close() delivered every event but reported ${closed.pending} pending and ${closed.dropped} dropped`,
    );
  const late = fixture(4);
  const lateRefused = await healthy.write(batchOf([late])).then(
    () => false,
    () => true,
  );
  await sink.flush().catch(() => undefined);
  if (healthy.collector.storedAt(late.time).length)
    fail("The sink delivered an event written after close()");
  if (!lateRefused && sink.status().dropped <= closed.dropped)
    fail(
      "An event written after close() was neither refused nor counted as dropped",
    );

  const down = await open({ required: true });
  const downSink = down.buffered as BufferedAuditSink;
  down.collector.mode = "unavailable";
  await down.write(batchOf(sent)).catch(() => undefined);
  const report = await downSink.close(deadline);
  if (report.pending + report.dropped < sent.length)
    fail(
      `close() reported ${report.pending} pending and ${report.dropped} dropped while the collector took none of ${sent.length} events: what was not taken must be reported`,
    );
  if (report.delivered > 0)
    fail(
      `close() reported ${report.delivered} delivered while the collector took none`,
    );
  return undefined;
};

const duplicateHandling: Check = async (open) => {
  const harness = await open({ required: true });
  const sent = [
    fixture(1, { event: "session.start" }),
    fixture(2),
    fixture(3, { event: "session.end" }),
  ];
  const batch = batchOf(sent);
  // The collector stores the batch, then its answer is lost.
  harness.collector.next.push("store-fail");
  await harness.deliver(batch);
  const retried = await harness.retry(batch);
  const [first, second] = harness.collector.deliveries;
  if (!first || !second)
    fail(
      "The sink did not resend the batch after the collector's answer was lost",
    );
  const expected = sent.map((event) => event.id);
  const ids = (request: CollectorRequest) =>
    request.events.map((event) => event.id);
  if (canonical(ids(first)) !== canonical(expected))
    fail(
      "The first delivery did not carry the events' ids in the order they were sent",
    );
  if (canonical(ids(second)) !== canonical(ids(first)))
    fail(
      "The resent batch did not carry the same ids in the same order as the first delivery",
    );
  const [conflict] = harness.collector.conflicts;
  if (conflict)
    fail(
      `The sink resent event ${conflict} with content different from its first delivery, so a collector cannot tell it is a retry`,
    );
  if (harness.collector.stored.length !== sent.length)
    fail(
      `A collector that stores each id once stored ${harness.collector.stored.length} events for ${sent.length} sent`,
    );
  if (!retried.ok)
    fail(
      `The sink did not accept the collector's 2xx for a batch it had already stored: ${describeFailure(retried)}`,
    );
  return undefined;
};

const CHECKS: Record<AuditSinkBehavior, Check> = {
  "metadata-only defaults": metadataOnly,
  "secret redaction": secretRedaction,
  "identity attribution": identityAttribution,
  "session correlation": sessionCorrelation,
  "event id stability": eventIdStability,
  "delivery failure": deliveryFailure,
  "buffer behavior": bufferBehavior,
  "fail-closed policy": failClosed,
  "shutdown flush": shutdownFlush,
  "duplicate handling": duplicateHandling,
};

// ---------------------------------------------------------------- runner

/** Replace every credential a harness handed out, then cap the length. */
function scrub(reason: string, harnesses: readonly Harness[]): string {
  let text = reason;
  for (const harness of harnesses)
    text = text.split(harness.environment.credential).join("[credential]");
  return text.length > 400 ? `${text.slice(0, 397)}...` : text;
}

async function runCheck(
  behavior: AuditSinkBehavior,
  create: AuditSinkFactory,
  timeoutMs: number,
  closeDeadlineMs: number,
): Promise<ConformanceResult> {
  const harnesses: Harness[] = [];
  const open = async (
    settings: Partial<{ required: boolean; maxEvents: number }> = {},
  ) => {
    const harness = new Harness(create, closeDeadlineMs, {
      required: settings.required ?? false,
      maxEvents: settings.maxEvents ?? 100,
    });
    harnesses.push(harness);
    await harness.open();
    return harness;
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new Finding(
            `The sink did not settle within ${timeoutMs} ms (a write, flush, or close never answered)`,
          ),
        ),
      timeoutMs,
    );
  });
  let result: ConformanceResult;
  try {
    const skipped = await Promise.race([CHECKS[behavior](open), timeout]);
    result =
      skipped === undefined
        ? { behavior, status: "passed" }
        : { behavior, status: "skipped", reason: skipped };
  } catch (error) {
    const reason =
      error instanceof Finding
        ? error.message
        : `The check stopped on an unexpected error: ${message(error)}`;
    result = { behavior, status: "failed", reason: scrub(reason, harnesses) };
  } finally {
    clearTimeout(timer);
    await Promise.all(harnesses.map((harness) => harness.dispose()));
  }
  return result;
}

/**
 * Check an audit sink against `piship-audit-batch/v1`. `create` builds a new
 * sink for each check, connected to the kit's collector through the
 * environment it is given. Behaviors that need a buffering sink are
 * `skipped` for a sink without `flush`, `status`, and `close`.
 */
export async function testAuditSink(
  create: AuditSinkFactory,
  options: AuditSinkKitOptions = {},
): Promise<ConformanceReport> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const closeDeadlineMs = options.closeDeadlineMs ?? 250;
  const results: ConformanceResult[] = [];
  for (const behavior of AUDIT_SINK_BEHAVIORS)
    results.push(await runCheck(behavior, create, timeoutMs, closeDeadlineMs));
  return { kind: "audit-sink", results };
}
