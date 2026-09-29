// The audit kit must pass a correct sink and fail a sink seeded with one
// defect, for every behavior it checks. The reference sinks below follow the
// `piship-audit-batch/v1` contract: the plain one forwards each batch to the
// collector as PiShip's `http` sink does, the buffered one also owns a
// bounded queue with the audit log's failure policy. Each seeded-bad sink
// changes exactly one thing about a reference sink.
import {
  AUDIT_BATCH_SCHEMA,
  type AuditBatch,
  type AuditEvent,
  type AuditSink,
  defineAuditSink,
  PiShipError,
} from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
import {
  AUDIT_SINK_BEHAVIORS,
  type AuditSinkBehavior,
  type AuditSinkCounts,
  type AuditSinkEnvironment,
  type BufferedAuditSink,
  testAuditSink,
} from "./audit.js";

type Status = "passed" | "failed" | "skipped";
type Statuses = Record<AuditSinkBehavior, Status>;

// ---------------------------------------------------------------- reference sinks

/** Forwards each batch to the collector and settles with its answer. */
function forwardingSink(
  env: AuditSinkEnvironment,
  transform: (batch: AuditBatch) => AuditBatch = (batch) => batch,
): AuditSink {
  return defineAuditSink({
    async write(batch: AuditBatch, signal: AbortSignal): Promise<void> {
      const response = await env.fetch(env.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // A downstream credential belongs in the request, never in an event.
          authorization: `Bearer ${env.credential}`,
        },
        body: JSON.stringify(transform(batch)),
        redirect: "manual",
        signal,
      });
      await response.body?.cancel().catch(() => undefined);
      if (response.status < 200 || response.status > 299)
        throw new Error(`collector answered HTTP ${response.status}`);
    },
  });
}

interface BufferedOptions {
  /** Keep events past `maxEvents` instead of dropping them. */
  readonly unbounded?: boolean;
  /** Drop overflow without counting it. */
  readonly uncounted?: boolean;
  /** A required sink drops overflow but never refuses the write. */
  readonly neverRefuse?: boolean;
  /** close() discards the queue and reports nothing lost. */
  readonly skipCloseFlush?: boolean;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
  });

/**
 * Holds events in a bounded queue and delivers them on flush() and close().
 * A required sink keeps failed events for the next flush and refuses a write
 * with AUDIT_UNAVAILABLE once its queue is full; an optional sink drops and
 * counts them.
 */
function bufferedSink(
  env: AuditSinkEnvironment,
  options: BufferedOptions = {},
): BufferedAuditSink {
  const inner = forwardingSink(env);
  const queue: AuditEvent[] = [];
  const abort = new AbortController();
  let delivered = 0;
  let dropped = 0;
  let lastError: string | undefined;
  let closed = false;
  let flushing: Promise<void> = Promise.resolve();

  async function deliverQueued(): Promise<void> {
    let remaining = queue.length;
    while (remaining > 0) {
      const events = queue.slice(0, Math.min(remaining, 500));
      try {
        if (abort.signal.aborted) throw new Error("sink closed");
        await inner.write({ schema: AUDIT_BATCH_SCHEMA, events }, abort.signal);
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        if (env.required) return;
        queue.splice(0, remaining);
        dropped += remaining;
        return;
      }
      queue.splice(0, events.length);
      delivered += events.length;
      remaining -= events.length;
      lastError = undefined;
    }
  }

  const status = (): AuditSinkCounts => ({
    delivered,
    pending: queue.length,
    dropped,
    ...(lastError ? { lastError } : {}),
  });

  const sink: BufferedAuditSink = {
    async write(batch, signal) {
      // The empty batch is the readiness probe: ask the collector now.
      if (batch.events.length === 0) return inner.write(batch, signal);
      let refused = false;
      for (const event of batch.events) {
        if (closed || (!options.unbounded && queue.length >= env.maxEvents)) {
          if (!options.uncounted) dropped += 1;
          refused = true;
          continue;
        }
        queue.push(event);
      }
      if (refused && env.required && !options.neverRefuse)
        throw new PiShipError(
          "AUDIT_UNAVAILABLE",
          "The audit buffer is full and the collector is not taking events",
          { component: "audit" },
        );
    },
    flush() {
      flushing = flushing.then(deliverQueued);
      return flushing;
    },
    status,
    async close(deadlineMs) {
      closed = true;
      if (options.skipCloseFlush) {
        queue.length = 0;
        return { delivered, pending: 0, dropped: 0 };
      }
      const final = (async () => {
        await sink.flush();
        while (env.required && queue.length > 0 && !abort.signal.aborted) {
          await sleep(20, abort.signal);
          if (!abort.signal.aborted) await sink.flush();
        }
      })();
      await Promise.race([final, sleep(deadlineMs)]);
      abort.abort();
      await final.catch(() => undefined);
      return status();
    },
  };
  return defineAuditSink(sink);
}

// ---------------------------------------------------------------- seeded-bad sinks

let fakeIds = 0;
const freshId = () =>
  `ffffffff-ffff-4fff-8fff-${(++fakeIds).toString(16).padStart(12, "0")}`;

const mapEvents =
  (fn: (event: AuditEvent, batch: AuditBatch) => AuditEvent) =>
  (batch: AuditBatch): AuditBatch => ({
    ...batch,
    events: batch.events.map((event) => fn(event, batch)),
  });

interface BadSink {
  readonly defect: string;
  readonly create: (env: AuditSinkEnvironment) => AuditSink;
  /** Behaviors the defect must fail; every other one keeps its good result. */
  readonly fails: readonly AuditSinkBehavior[];
}

const PLAIN_GOOD: Statuses = {
  "metadata-only defaults": "passed",
  "secret redaction": "passed",
  "identity attribution": "passed",
  "session correlation": "passed",
  "event id stability": "passed",
  "delivery failure": "passed",
  "buffer behavior": "skipped",
  "fail-closed policy": "passed",
  "shutdown flush": "skipped",
  "duplicate handling": "passed",
};
const BUFFERED_GOOD: Statuses = {
  ...PLAIN_GOOD,
  "buffer behavior": "passed",
  "shutdown flush": "passed",
};

const PLAIN_BAD: readonly BadSink[] = [
  {
    defect: "keeps the raw request body with every stored event",
    create: (env) =>
      forwardingSink(
        env,
        mapEvents((event, batch) => ({
          ...event,
          raw: JSON.stringify(batch),
        })),
      ),
    fails: ["metadata-only defaults"],
  },
  {
    defect: "writes its downstream credential into an event",
    create: (env) =>
      forwardingSink(
        env,
        mapEvents((event) => ({
          ...event,
          detail: {
            ...event.detail,
            forwardedWith: `Bearer ${env.credential}`,
          },
        })),
      ),
    fails: ["secret redaction"],
  },
  {
    defect: "quotes its downstream credential in a delivery error",
    create: (env) => {
      const inner = forwardingSink(env);
      return defineAuditSink({
        async write(batch, signal) {
          try {
            await inner.write(batch, signal);
          } catch {
            throw new Error(
              `delivery failed for authorization Bearer ${env.credential}`,
            );
          }
        },
      });
    },
    fails: ["secret redaction"],
  },
  {
    defect: "attributes events without a user to its service account",
    create: (env) =>
      forwardingSink(
        env,
        mapEvents((event) => ({
          ...event,
          user: event.user ?? "svc-forwarder",
        })),
      ),
    fails: ["identity attribution"],
  },
  {
    defect: "replaces the session with a correlation ID taken from each batch",
    create: (env) =>
      forwardingSink(env, (batch) => {
        const correlation = batch.events[0]?.id ?? null;
        return mapEvents((event) => ({ ...event, session: correlation }))(
          batch,
        );
      }),
    fails: ["session correlation"],
  },
  {
    defect: "replaces the session with a new correlation ID on every write",
    create: (env) =>
      forwardingSink(env, (batch) => {
        const correlation = freshId();
        return mapEvents((event) => ({ ...event, session: correlation }))(
          batch,
        );
      }),
    // A retry then differs from the first delivery, which is not a retry.
    fails: ["session correlation", "duplicate handling"],
  },
  {
    defect: "assigns a new event ID on every write",
    create: (env) =>
      forwardingSink(
        env,
        mapEvents((event) => ({ ...event, id: freshId() })),
      ),
    // A resent event with a new ID is a second event to the collector.
    fails: ["event id stability", "duplicate handling"],
  },
  {
    defect: "assigns a new ID to a denied tool event on every write",
    create: (env) =>
      forwardingSink(
        env,
        mapEvents((event) =>
          event.event === "tool.denied" ? { ...event, id: freshId() } : event,
        ),
      ),
    fails: ["event id stability"],
  },
  {
    defect: "counts a redirect as delivered",
    create: (env) =>
      defineAuditSink({
        async write(batch, signal) {
          const response = await env.fetch(env.url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${env.credential}`,
            },
            body: JSON.stringify(batch),
            redirect: "manual",
            signal,
          });
          await response.body?.cancel().catch(() => undefined);
          if (response.status >= 400)
            throw new Error(`collector answered HTTP ${response.status}`);
        },
      }),
    fails: ["delivery failure"],
  },
  {
    defect: "swallows a failed delivery",
    create: (env) => {
      const inner = forwardingSink(env);
      return defineAuditSink({
        async write(batch, signal) {
          await inner.write(batch, signal).catch(() => undefined);
        },
      });
    },
    // A sink that never rejects also answers the readiness probe while the
    // collector is down, so it cannot fail closed either.
    fails: ["delivery failure", "fail-closed policy"],
  },
  {
    defect: "resolves before the collector answers",
    create: (env) => {
      const inner = forwardingSink(env);
      return defineAuditSink({
        async write(batch, signal) {
          void inner.write(batch, signal).catch(() => undefined);
        },
      });
    },
    fails: ["delivery failure", "fail-closed policy"],
  },
  {
    defect: "answers the readiness probe without asking the collector",
    create: (env) => {
      const inner = forwardingSink(env);
      return defineAuditSink({
        async write(batch, signal) {
          if (batch.events.length === 0) return;
          await inner.write(batch, signal);
        },
      });
    },
    fails: ["fail-closed policy"],
  },
  {
    defect: "stamps each delivery attempt into the event",
    create: (env) => {
      let attempt = 0;
      return forwardingSink(env, (batch) => {
        attempt += 1;
        return mapEvents((event) => ({ ...event, forwardAttempt: attempt }))(
          batch,
        );
      });
    },
    fails: ["duplicate handling"],
  },
  {
    defect: "reverses a batch it has sent before",
    create: (env) => {
      const seen = new Set<string>();
      return forwardingSink(env, (batch) => {
        const resent = batch.events.some(
          (event) => event.id && seen.has(event.id),
        );
        for (const event of batch.events) if (event.id) seen.add(event.id);
        return resent
          ? { ...batch, events: [...batch.events].reverse() }
          : batch;
      });
    },
    fails: ["duplicate handling"],
  },
];

const BUFFERED_BAD: readonly BadSink[] = [
  {
    defect: "ignores the buffer bound",
    create: (env) => bufferedSink(env, { unbounded: true }),
    // A buffer that never fills never fails closed.
    fails: ["buffer behavior", "fail-closed policy"],
  },
  {
    defect: "drops overflow without counting it",
    create: (env) => bufferedSink(env, { uncounted: true }),
    fails: ["buffer behavior"],
  },
  {
    defect: "keeps accepting writes while a required buffer is full",
    create: (env) => bufferedSink(env, { neverRefuse: true }),
    fails: ["fail-closed policy"],
  },
  {
    defect: "skips the flush on close",
    create: (env) => bufferedSink(env, { skipCloseFlush: true }),
    fails: ["shutdown flush"],
  },
];

// ---------------------------------------------------------------- helpers

const OPTIONS = { timeoutMs: 8_000, closeDeadlineMs: 300 } as const;

function statuses(report: Awaited<ReturnType<typeof testAuditSink>>) {
  return Object.fromEntries(
    report.results.map((result) => [result.behavior, result.status]),
  ) as Statuses;
}

function expected(good: Statuses, fails: readonly AuditSinkBehavior[]) {
  const result = { ...good };
  for (const behavior of fails) result[behavior] = "failed";
  return result;
}

/** Captures the credential the kit hands the sink, to search reports for it. */
function capturing(create: (env: AuditSinkEnvironment) => AuditSink) {
  const credentials = new Set<string>();
  return {
    credentials,
    create: (env: AuditSinkEnvironment) => {
      credentials.add(env.credential);
      return create(env);
    },
  };
}

// ---------------------------------------------------------------- tests

describe("testAuditSink", () => {
  it("reports every behavior once, in the documented order, as an audit-sink kit", async () => {
    const report = await testAuditSink(forwardingSink, OPTIONS);
    expect(report.kind).toBe("audit-sink");
    expect(report.results.map((result) => result.behavior)).toEqual([
      ...AUDIT_SINK_BEHAVIORS,
    ]);
  });

  it("passes a sink that forwards each batch and skips the checks that need a buffer", async () => {
    const report = await testAuditSink(forwardingSink, OPTIONS);
    expect(statuses(report)).toEqual(PLAIN_GOOD);
    for (const result of report.results)
      if (result.status === "skipped") expect(result.reason).toMatch(/\S/);
  });

  it("passes a sink that buffers events, fails closed when required, and flushes on close", async () => {
    const report = await testAuditSink((env) => bufferedSink(env), OPTIONS);
    expect(
      report.results.filter((result) => result.status !== "passed"),
    ).toEqual([]);
    expect(statuses(report)).toEqual(BUFFERED_GOOD);
  });

  describe.each([
    ...PLAIN_BAD.map((bad) => ({ ...bad, good: PLAIN_GOOD })),
    ...BUFFERED_BAD.map((bad) => ({ ...bad, good: BUFFERED_GOOD })),
  ])("a sink that $defect", ({ create, fails, good }) => {
    it(`fails ${fails.join(" and ")} and nothing else`, async () => {
      const probe = capturing(create);
      const report = await testAuditSink(probe.create, OPTIONS);
      expect(statuses(report)).toEqual(expected(good, fails));
      for (const behavior of fails) {
        const result = report.results.find(
          (item) => item.behavior === behavior,
        );
        expect(result?.reason).toMatch(/\S/);
      }
      // A reason never repeats the credential, even when the sink leaked it.
      const text = JSON.stringify(report);
      for (const credential of probe.credentials)
        expect(text).not.toContain(credential);
    });
  });

  it("fails every behavior alone with at least one seeded defect", () => {
    const alone = [...PLAIN_BAD, ...BUFFERED_BAD]
      .filter((bad) => bad.fails.length === 1)
      .map((bad) => bad.fails[0]);
    expect(new Set(alone)).toEqual(new Set(AUDIT_SINK_BEHAVIORS));
  });

  it("gives every sink a fake credential that names itself as fake", async () => {
    const probe = capturing(forwardingSink);
    await testAuditSink(probe.create, OPTIONS);
    expect(probe.credentials.size).toBeGreaterThan(0);
    for (const credential of probe.credentials)
      expect(credential).toMatch(/fake/i);
  });

  it("fails every check of a sink that never settles instead of hanging", async () => {
    const hanging = () =>
      defineAuditSink({ write: () => new Promise<void>(() => undefined) });
    const started = Date.now();
    const report = await testAuditSink(hanging, {
      timeoutMs: 400,
      closeDeadlineMs: 50,
    });
    expect(Date.now() - started).toBeLessThan(20_000);
    for (const result of report.results) {
      if (result.status === "skipped") continue;
      expect(result.status).toBe("failed");
      expect(result.reason).toMatch(/settle|answer|abort/i);
    }
  });

  it("fails the buffer and shutdown checks of a sink that declares only part of flush, status, and close", async () => {
    const partial = (env: AuditSinkEnvironment) => {
      const { write, flush } = bufferedSink(env);
      return { write, flush } as AuditSink;
    };
    const report = await testAuditSink(partial, OPTIONS);
    const byBehavior = statuses(report);
    expect(byBehavior["buffer behavior"]).toBe("failed");
    expect(byBehavior["shutdown flush"]).toBe("failed");
    expect(
      report.results.find((result) => result.behavior === "buffer behavior")
        ?.reason,
    ).toMatch(/status.*close|close.*status/);
  });

  it("fails every delivery check of a sink that throws while it is created", async () => {
    const report = await testAuditSink(() => {
      throw new Error("cannot start");
    }, OPTIONS);
    for (const result of report.results) {
      expect(result.status).toBe("failed");
      expect(result.reason).toMatch(/cannot start/);
    }
  });
});
