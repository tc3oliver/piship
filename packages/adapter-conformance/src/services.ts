// Service kits: the other direction from the adapter kits. An adapter kit
// runs a company's adapter against a fake service; a service kit sends a
// company's own credential broker or audit collector, usually a staging
// instance, the requests PiShip's `http-broker` provider and `http` audit
// sink send, and holds the answers to the wire contract in
// docs/enterprise-integration.md. It imports only @piship/adapter-sdk and
// Node built-ins, uses no PiShip fixture, and never puts a credential or a
// token in a report.
import { randomUUID } from "node:crypto";
import {
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  type AuditEvent,
} from "@piship/adapter-sdk";
import type { ConformanceReport, ConformanceResult } from "./index.js";
import { check, Finding } from "./shared.js";

type Fetch = typeof globalThis.fetch;

/** What `testCredentialBroker` checks, in report order. */
export const CREDENTIAL_BROKER_BEHAVIORS = [
  "acquire",
  "idempotent replay",
  "key reuse",
  "authentication",
  "revoke",
] as const;
export type CredentialBrokerBehavior =
  (typeof CREDENTIAL_BROKER_BEHAVIORS)[number];

export interface CredentialBrokerKitOptions {
  /** `credential.broker.endpoint` of the broker under test. */
  readonly endpoint: string;
  /** `credential.broker.revokeEndpoint`, when the broker has one. */
  readonly revokeEndpoint?: string;
  /** The distribution's `app.id`, sent as `distribution`. */
  readonly distribution: string;
  /**
   * The identity access token of a test user, as PiShip sends it. Called for
   * each request, so it may sign the user in again.
   */
  readonly identityToken: () => string | Promise<string>;
  /** Reaches the broker. Default: the global `fetch`. */
  readonly fetch?: Fetch;
  /** Longest one request may take. Default 30 s, PiShip's broker timeout. */
  readonly timeoutMs?: number;
}

/** What `testAuditCollector` checks, in report order. */
export const AUDIT_COLLECTOR_BEHAVIORS = [
  "readiness probe",
  "batch",
  "duplicate batch",
  "conflicting id",
  "unknown property",
] as const;
export type AuditCollectorBehavior = (typeof AUDIT_COLLECTOR_BEHAVIORS)[number];

export interface AuditCollectorKitOptions {
  /** The `http` sink's `url`. */
  readonly url: string;
  /** The `distribution` the test events carry. */
  readonly distribution: string;
  /** Reaches the collector. Default: the global `fetch`. */
  readonly fetch?: Fetch;
  /** Longest one request may take. Default 10 s, PiShip's sink timeout. */
  readonly timeoutMs?: number;
  /**
   * Reads back the distinct events the collector kept under `id`. Without
   * it, the kit checks only the collector's answers, not what it stored.
   */
  readonly stored?: (id: string) => Promise<readonly unknown[]>;
}

const CREDENTIAL_TYPES = new Set(["api_key", "bearer", "opaque"]);
const CREDENTIAL_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const VISIBLE_ASCII = /^[\x21-\x7e]{8,}$/;

interface Answer {
  readonly status: number;
  readonly body: unknown;
}

async function send(
  fetch: Fetch,
  url: string,
  timeoutMs: number,
  headers: Record<string, string>,
  body: unknown,
): Promise<Answer> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
      // PiShip never follows a redirect from a broker or a collector.
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new Finding(
      `the request failed without an answer (${error instanceof Error ? error.name : "error"})`,
    );
  }
  check(
    response.status < 300 || response.status > 399,
    `answered HTTP ${response.status}: PiShip never follows a redirect`,
  );
  const text = await response.text().catch(() => "");
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  return { status: response.status, body: parsed };
}

async function run(
  behavior: string,
  body: () => Promise<"passed" | { skipped: string }>,
): Promise<ConformanceResult> {
  try {
    const outcome = await body();
    return outcome === "passed"
      ? { behavior, status: "passed" }
      : { behavior, status: "skipped", reason: outcome.skipped };
  } catch (error) {
    return {
      behavior,
      status: "failed",
      reason:
        error instanceof Finding
          ? error.message
          : `the kit failed: ${error instanceof Error ? error.name : "error"}`,
    };
  }
}

interface Issued {
  readonly credential: string;
  readonly id?: string | undefined;
}

/** Holds an acquire answer to the response contract; never quotes a value. */
function issued(answer: Answer, what: string): Issued {
  check(
    answer.status >= 200 && answer.status <= 299,
    `${what} answered HTTP ${answer.status}, not 2xx`,
  );
  const body = answer.body as Record<string, unknown> | undefined;
  check(
    typeof body === "object" && body !== null,
    `${what}: the body is not a JSON object`,
  );
  check(
    typeof body.credential_type === "string" &&
      CREDENTIAL_TYPES.has(body.credential_type),
    `${what}: credential_type is not api_key, bearer, or opaque`,
  );
  check(
    typeof body.credential === "string" && VISIBLE_ASCII.test(body.credential),
    `${what}: credential is not at least 8 visible ASCII characters`,
  );
  const id = body.credential_id ?? undefined;
  check(
    id === undefined || (typeof id === "string" && CREDENTIAL_ID.test(id)),
    `${what}: credential_id does not match ${CREDENTIAL_ID}`,
  );
  const expires = body.expires_at ?? undefined;
  check(
    expires === undefined ||
      (typeof expires === "string" && Date.parse(expires) > Date.now()),
    `${what}: expires_at is not a future ISO 8601 time`,
  );
  const models = body.models ?? undefined;
  check(
    models === undefined ||
      (Array.isArray(models) &&
        models.every((model) => typeof model === "string")),
    `${what}: models is not an array of model IDs`,
  );
  return { credential: body.credential, id: id as string | undefined };
}

/**
 * Checks a company's credential broker against the `http-broker` contract,
 * sending what PiShip sends. Each credential it obtains is revoked at the end
 * when `revokeEndpoint` is given; otherwise it stays valid until it expires.
 */
export async function testCredentialBroker(
  options: CredentialBrokerKitOptions,
): Promise<ConformanceReport> {
  const fetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const body = { distribution: options.distribution, purpose: "inference" };
  const key = randomUUID();
  const acquire = async (
    idempotencyKey: string,
    requestBody: unknown = body,
    authorization?: string,
  ) =>
    send(
      fetch,
      options.endpoint,
      timeoutMs,
      {
        accept: "application/json",
        "idempotency-key": idempotencyKey,
        authorization:
          authorization ?? `Bearer ${await options.identityToken()}`,
      },
      requestBody,
    );
  let first: Issued | undefined;
  const obtained: Issued[] = [];
  const results: ConformanceResult[] = [];

  results.push(
    await run("acquire", async () => {
      first = issued(await acquire(key), "an acquire");
      obtained.push(first);
      return "passed";
    }),
  );
  results.push(
    await run("idempotent replay", async () => {
      if (!first) return { skipped: "the first acquire failed" };
      const again = issued(
        await acquire(key),
        "the same request with the same Idempotency-Key",
      );
      if (again.credential !== first.credential) obtained.push(again);
      check(
        again.credential === first.credential && again.id === first.id,
        "the same request with the same Idempotency-Key issued a second credential instead of returning the first",
      );
      return "passed";
    }),
  );
  results.push(
    await run("key reuse", async () => {
      if (!first) return { skipped: "the first acquire failed" };
      // The same principal and distribution with one more body property:
      // "same input" is the principal and the whole body, so this is a
      // different request a broker can still accept.
      const answer = await acquire(key, {
        ...body,
        piship_conformance: "key-reuse",
      });
      if (answer.status >= 200 && answer.status <= 299) {
        const other = (answer.body as { credential?: unknown } | undefined)
          ?.credential;
        if (typeof other === "string" && other !== first.credential)
          obtained.push({ credential: other });
        throw new Finding(
          `a different request with a used Idempotency-Key answered HTTP ${answer.status}; the contract asks for 422, or 409 with {"error":"idempotency_key_reused"}`,
        );
      }
      const conflict =
        answer.status === 422 ||
        (answer.status === 409 &&
          (answer.body as { error?: unknown } | undefined)?.error ===
            "idempotency_key_reused");
      if (conflict) return "passed";
      check(
        answer.status !== 409,
        'a different request with a used Idempotency-Key answered 409 without {"error":"idempotency_key_reused"}, which PiShip reads as a request still in progress and retries',
      );
      return {
        skipped: `the broker refused the changed request with HTTP ${answer.status} before checking the key; PiShip treats that as final, which is safe`,
      };
    }),
  );
  results.push(
    await run("authentication", async () => {
      for (const [what, authorization] of [
        ["without a bearer", ""],
        ["with an invalid bearer", "Bearer piship-conformance-invalid-token"],
      ] as const) {
        const answer = await acquire(randomUUID(), body, authorization);
        if (answer.status >= 200 && answer.status <= 299) {
          const other = (answer.body as { credential?: unknown } | undefined)
            ?.credential;
          if (typeof other === "string") obtained.push({ credential: other });
        }
        check(
          answer.status === 401,
          `an acquire ${what} answered HTTP ${answer.status}; PiShip expects 401 for an identity it must refresh`,
        );
      }
      return "passed";
    }),
  );
  results.push(
    await run("revoke", async () => {
      const revokeEndpoint = options.revokeEndpoint;
      if (!revokeEndpoint) return { skipped: "no revokeEndpoint was given" };
      if (obtained.length === 0) return { skipped: "nothing was issued" };
      let failure: string | undefined;
      for (const credential of obtained) {
        const answer = await send(
          fetch,
          revokeEndpoint,
          timeoutMs,
          { authorization: `Bearer ${credential.credential}` },
          {
            credential_id: credential.id ?? null,
            distribution: options.distribution,
          },
        );
        if (
          !(answer.status >= 200 && answer.status <= 299) &&
          answer.status !== 401 &&
          answer.status !== 404
        )
          failure ??= `a revoke answered HTTP ${answer.status}; PiShip counts only 2xx, 401, and 404 as revoked`;
      }
      check(failure === undefined, failure ?? "");
      return "passed";
    }),
  );
  return { kind: "credential", results };
}

/**
 * Checks a company's audit collector against `piship-audit-batch/v1`,
 * sending what PiShip's `http` sink sends. Each test event has the user
 * `piship-conformance` and `detail.conformance: true`, so it can be told
 * apart from real events in the collector's store.
 */
export async function testAuditCollector(
  options: AuditCollectorKitOptions,
): Promise<ConformanceReport> {
  const fetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const session = `piship-conformance-${randomUUID()}`;
  const event = (
    fields: Partial<AuditEvent> = {},
  ): AuditEvent & { readonly id: string } => ({
    schema: AUDIT_EVENT_SCHEMA,
    id: randomUUID(),
    event: "policy.loaded",
    time: new Date().toISOString(),
    user: "piship-conformance",
    session,
    distribution: options.distribution,
    detail: { conformance: true },
    ...fields,
  });
  const post = async (events: readonly unknown[], what: string) => {
    const answer = await send(
      fetch,
      options.url,
      timeoutMs,
      {},
      {
        schema: AUDIT_BATCH_SCHEMA,
        events,
      },
    );
    check(
      answer.status >= 200 && answer.status <= 299,
      `${what} answered HTTP ${answer.status}; any other status than 2xx makes PiShip send it again`,
    );
  };
  const kept = async (id: string, count: number, what: string) => {
    if (!options.stored) return;
    const found = await options.stored(id);
    check(
      found.length === count,
      `${what}: the collector kept ${found.length} distinct events under the ID, not ${count}`,
    );
  };
  const results: ConformanceResult[] = [];
  results.push(
    await run("readiness probe", async () => {
      await post(
        [],
        "the empty batch PiShip sends before a required sink opens",
      );
      return "passed";
    }),
  );
  const stored = event();
  results.push(
    await run("batch", async () => {
      await post([stored], "a batch of one event");
      await kept(stored.id, 1, "a batch of one event");
      return "passed";
    }),
  );
  results.push(
    await run("duplicate batch", async () => {
      await post([stored], "a batch sent again with the same events");
      await kept(stored.id, 1, "a batch sent again");
      return "passed";
    }),
  );
  results.push(
    await run("conflicting id", async () => {
      const conflict = { ...stored, detail: { conformance: true, changed: 1 } };
      await post([conflict], "an event that reuses an ID with other content");
      await kept(
        stored.id,
        2,
        "an event that reuses an ID with other content must be kept beside the first",
      );
      return "passed";
    }),
  );
  results.push(
    await run("unknown property", async () => {
      const extended = { ...event(), conformanceExtension: "optional" };
      await post(
        [extended],
        "an event with an optional property the collector does not know",
      );
      await kept(extended.id, 1, "an event with an unknown property");
      return "passed";
    }),
  );
  return { kind: "audit-sink", results };
}
