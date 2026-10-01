// The credential conformance kit. It runs a credential adapter against a fake
// credential broker the kit owns, answering through the adapter's managed
// fetch, so a run needs no network, no PiShip internals, and no real broker.
// Every check is a contract statement an adapter author can read; the kit
// judges only what the adapter returns, throws, and sends.
import { randomBytes } from "node:crypto";
import {
  type AdapterContext,
  type AdapterFactory,
  type CredentialContext,
  type CredentialProvider,
  type IdentitySession,
  type ManagedFetch,
  PiShipError,
  type PiShipErrorCode,
  type ResolvedEndpoints,
  type RuntimeCredential,
  SecretValue,
} from "@piship/adapter-sdk";
import type { ConformanceReport, ConformanceResult } from "./index.js";
import {
  answer,
  check,
  codeOf,
  expectError,
  expiryOf,
  Finding,
  type Outcome,
  RETRY_AFTER_SECONDS,
  rejection,
  requestText,
  revealed,
  secretsIn,
  settle,
} from "./shared.js";

/**
 * What the credential kit checks, in report order, each with the contract
 * statement it holds the adapter to.
 */
export const CREDENTIAL_CONTRACT = [
  {
    behavior: "acquire",
    statement:
      "acquire() sends its request through the context's managed fetch and returns the credential the broker issued: a kind of api_key, bearer, or opaque, the secret as a SecretValue, and the broker's credential ID; mode is `adapter` (or the built-in `http-broker`)",
  },
  {
    behavior: "refresh",
    statement:
      "refresh() (or acquire() when the adapter has no refresh) asks the broker again and returns the newly issued credential, never the current one",
  },
  {
    behavior: "expiry",
    statement:
      "expiresAt is the broker's expiry, on acquire and refresh; a credential that has already expired is refused with CREDENTIAL_EXPIRED or CREDENTIAL_ACQUIRE_FAILED, never returned",
  },
  {
    behavior: "revoke",
    statement:
      "revoke() sends a request that names the credential (its ID or secret) and resolves once the broker accepted it",
  },
  {
    behavior: "401",
    statement:
      "an acquire the broker answers with 401 fails with IDENTITY_EXPIRED, not retryable, so PiShip refreshes the sign-in",
  },
  {
    behavior: "403",
    statement:
      "a 403 is an authorization denial, CREDENTIAL_DENIED and not retryable, for acquire and revoke, decided from the status even when the body never arrives",
  },
  {
    behavior: "429",
    statement:
      "a 429 is retryable, CREDENTIAL_ACQUIRE_FAILED (acquire) or CREDENTIAL_REVOKED (revoke), with Retry-After (seconds or HTTP-date) kept as retryAfterMs",
  },
  {
    behavior: "5xx",
    statement:
      "a 5xx is retryable, CREDENTIAL_ACQUIRE_FAILED (acquire) or CREDENTIAL_REVOKED (revoke), with any Retry-After kept as retryAfterMs",
  },
  {
    behavior: "timeout",
    statement:
      "a broker that never answers ends in a retryable CREDENTIAL_ACQUIRE_FAILED (acquire) or CREDENTIAL_REVOKED (revoke) after the adapter's own timeout, also when the caller passed a signal: the signal composes with the timeout and never replaces it",
  },
  {
    behavior: "abort",
    statement:
      "the caller's signal cancels the request in flight; a cancellation, including one before anything was sent, fails with CREDENTIAL_ACQUIRE_FAILED (acquire) or CREDENTIAL_REVOKED (revoke) and is not retryable",
  },
  {
    behavior: "redaction",
    statement:
      "no identity token, credential, or broker answer body appears in any error's message, stack, detail, action, cause, or rendering, and the returned credential never renders its secret",
  },
  {
    behavior: "concurrent refresh",
    statement:
      "concurrent refreshes of one credential each resolve, and no result carries a field of the credential issued to the other call",
  },
  {
    behavior: "retry behavior",
    statement:
      "the adapter never re-sends a request by itself: after a timeout, a connection reset, a 5xx, a 429, or a 401 it has sent no more requests than one successful acquire sends; a transport failure is retryable; a network or TLS policy refusal from the managed fetch keeps its code and is not retryable",
  },
  {
    behavior: "idempotency",
    statement:
      "CredentialContext.idempotencyKey is sent as the Idempotency-Key header on every acquire and refresh request, and a failure reports it as detail.idempotencyKey, so a caller retrying a timed-out acquire with that key receives the credential the broker already issued",
  },
] as const;

export type CredentialBehavior =
  (typeof CREDENTIAL_CONTRACT)[number]["behavior"];

/** The behaviors the credential kit reports, in report order. */
export const CREDENTIAL_BEHAVIORS: readonly CredentialBehavior[] =
  CREDENTIAL_CONTRACT.map((entry) => entry.behavior);

/** A credential the fake broker issued. Fake values only, never a real secret. */
export interface IssuedCredential {
  readonly kind: "api_key";
  readonly secret: string;
  readonly credentialId: string;
  readonly expiresAt: Date;
}

export interface CredentialKitOptions {
  /**
   * The request timeout the adapter applies, in milliseconds. The kit waits
   * several times this long for a stalled request to end before it reports a
   * hang, so build the adapter under test with a short timeout (such as
   * 200 ms) to keep a run fast. Default 30 000.
   */
  readonly requestTimeoutMs?: number;
  /**
   * The fake broker's success answer to an acquire or refresh. The default
   * is the `http-broker` wire format: `{credential_type, credential,
   * credential_id, expires_at}`. An adapter for another service encodes the
   * issued credential the way that service does.
   */
  readonly issue?: (credential: IssuedCredential) => Response;
  /** The fake broker's success answer to a revoke. Default: 204. */
  readonly revoked?: () => Response;
  /**
   * `false` when the adapter's service does not honor idempotency keys: the
   * `idempotency` behavior is then `skipped`, never `passed`.
   */
  readonly idempotency?: boolean;
  /** Merged over the kit's placeholder endpoints in the adapter's context. */
  readonly endpoints?: Partial<ResolvedEndpoints>;
  readonly distributionId?: string;
}

// ------------------------------------------------------------- fake broker

/** Which provider method the kit is calling. */
type Operation = "acquire" | "refresh" | "revoke";

interface BrokerRequest {
  readonly operation: Operation;
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string;
  readonly idempotencyKey: string | null;
  /** The abort reason when the request's signal ended it. */
  cancelledBy?: unknown;
}

/** How the broker answers one delivered request. */
type Handler = (
  request: BrokerRequest,
  index: number,
  signal: AbortSignal | undefined,
) => Response | Promise<Response>;

const HOUR_MS = 3_600_000;

class FakeBroker {
  readonly requests: BrokerRequest[] = [];
  readonly issued: IssuedCredential[] = [];
  readonly #byKey = new Map<string, IssuedCredential>();
  readonly #pending = new Set<(error: unknown) => void>();
  operation: Operation = "acquire";
  /** Called as a request arrives, before it is answered. */
  onDeliver: ((request: BrokerRequest) => void) | undefined;
  handler: Handler = () => this.issue();

  constructor(
    readonly run: string,
    readonly options: CredentialKitOptions,
  ) {}

  readonly fetch: ManagedFetch = async (input, init = {}) => {
    const signal = init.signal ?? undefined;
    // Like a real fetch, a signal that is already aborted sends nothing.
    if (signal?.aborted) throw signal.reason;
    const headers = new Headers(init.headers);
    const request: BrokerRequest = {
      operation: this.operation,
      url: String(input),
      method: (init.method ?? "GET").toUpperCase(),
      headers,
      body:
        typeof init.body === "string"
          ? init.body
          : init.body
            ? await new Response(init.body).text()
            : "",
      idempotencyKey: headers.get("idempotency-key"),
    };
    this.requests.push(request);
    this.onDeliver?.(request);
    return this.handler(request, this.requests.length - 1, signal);
  };

  /** Issue a new credential, or replay the one already issued for the key. */
  issue(
    request?: BrokerRequest,
    expiresAt = new Date(
      Math.floor(Date.now() / 1000) * 1000 +
        HOUR_MS +
        this.issued.length * 60_000,
    ),
  ): Response {
    const key = request?.idempotencyKey;
    const replay = key ? this.#byKey.get(key) : undefined;
    const credential = replay ?? this.#newCredential(expiresAt);
    if (key && !replay) this.#byKey.set(key, credential);
    return (this.options.issue ?? httpBrokerAnswer)(credential);
  }

  #newCredential(expiresAt: Date): IssuedCredential {
    const n = this.issued.length + 1;
    const credential: IssuedCredential = {
      kind: "api_key",
      secret: `conformance-credential-${n}-${this.run}`,
      credentialId: `conformance-id-${n}-${this.run.slice(0, 8)}`,
      expiresAt,
    };
    this.issued.push(credential);
    return credential;
  }

  revoked(): Response {
    return this.options.revoked?.() ?? new Response(null, { status: 204 });
  }

  status(
    status: number,
    headers: Record<string, string> = {},
    body = "",
  ): Response {
    return answer(status, headers, body);
  }

  /** An answer whose body never arrives; it ends only with the request. */
  stalledBody(status: number, signal: AbortSignal | undefined): Response {
    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        const end = (error: unknown) => {
          try {
            controller.error(error);
          } catch {
            // Already ended.
          }
        };
        this.#pending.add(end);
        signal?.addEventListener("abort", () => end(signal.reason), {
          once: true,
        });
      },
    });
    return new Response(stream, { status });
  }

  /** No answer at all: it ends only when the request's signal aborts. */
  stall(
    request: BrokerRequest,
    signal: AbortSignal | undefined,
  ): Promise<Response> {
    return new Promise((_resolve, reject) => {
      const end = (reason: unknown) => {
        request.cancelledBy = reason;
        this.#pending.delete(end);
        reject(reason);
      };
      if (signal?.aborted) return end(signal.reason);
      this.#pending.add(end);
      signal?.addEventListener("abort", () => end(signal.reason), {
        once: true,
      });
    });
  }

  /** End every stalled request, so a hung adapter call settles. */
  release(): void {
    for (const end of [...this.#pending])
      end(new TypeError("fetch failed: the conformance broker closed"));
    this.#pending.clear();
  }
}

/** The `http-broker` success answer. */
function httpBrokerAnswer(credential: IssuedCredential): Response {
  return Response.json({
    credential_type: credential.kind,
    credential: credential.secret,
    credential_id: credential.credentialId,
    expires_at: credential.expiresAt.toISOString(),
  });
}

// ------------------------------------------------------------ the harness

class Harness {
  readonly run = randomBytes(8).toString("hex");
  readonly token = `conformance-identity-token-${this.run}`;
  readonly bodySentinel = `conformance-broker-body-${this.run}`;
  readonly identity: IdentitySession;
  readonly timeoutMs: number;
  /** How long the kit waits for a stalled call to end before calling it hung. */
  readonly boundMs: number;
  broker: FakeBroker;
  #baseline: number | undefined;

  constructor(
    readonly factory: AdapterFactory<CredentialProvider>,
    readonly options: CredentialKitOptions,
  ) {
    this.timeoutMs = options.requestTimeoutMs ?? 30_000;
    this.boundMs = this.timeoutMs * 3 + 2_000;
    this.identity = {
      subject: "conformance-user",
      issuer: "https://issuer.conformance.invalid",
      accessToken: new SecretValue(this.token),
      expiresAt: new Date(Date.now() + HOUR_MS),
    };
    this.broker = new FakeBroker(this.run, options);
  }

  /** A fresh broker and a fresh provider built against it. */
  async provider(): Promise<CredentialProvider> {
    this.broker.release();
    this.broker = new FakeBroker(this.run, this.options);
    const context: AdapterContext = {
      distributionId: this.distributionId,
      fetch: this.broker.fetch,
      endpoints: {
        issuer: "https://issuer.conformance.invalid",
        brokerEndpoint: "https://broker.conformance.invalid/v1/credential",
        brokerRevokeEndpoint: "https://broker.conformance.invalid/v1/revoke",
        baseUrl: "https://gateway.conformance.invalid/v1",
        additionalCA: [],
        ...this.options.endpoints,
      },
    };
    // Bounded like every call into the adapter: a hung factory fails the
    // check instead of hanging the kit.
    const made = await settle(() => this.factory(context), this.boundMs);
    check(
      made.kind !== "hung",
      "the adapter factory did not end within the kit's bound",
    );
    if (made.kind === "rejected") throw made.error;
    const provider = made.value;
    check(
      provider && typeof provider.acquire === "function",
      "the adapter factory returned no credential provider",
    );
    return provider;
  }

  get distributionId(): string {
    return this.options.distributionId ?? "conformance";
  }

  ctx(extra: Partial<CredentialContext> = {}): CredentialContext {
    return { distributionId: this.distributionId, ...extra };
  }

  /** Settle a call, or report it hung after the bound and release it. */
  async call<T>(
    operation: Operation,
    call: () => Promise<T>,
  ): Promise<Outcome<T>> {
    this.broker.operation = operation;
    return settle(call, this.boundMs, () => this.broker.release());
  }

  /** A credential acquired through the adapter with the broker's success answer. */
  async acquired(provider: CredentialProvider): Promise<RuntimeCredential> {
    const handler = this.broker.handler;
    this.broker.handler = (request) => this.broker.issue(request);
    const outcome = await this.call("acquire", () =>
      provider.acquire(this.identity, this.ctx()),
    );
    this.broker.handler = handler;
    check(
      outcome.kind === "resolved" && outcome.value,
      "a successful acquire, needed to set up this check, did not return a credential",
    );
    return outcome.value;
  }

  /** How many requests one successful acquire sends. */
  async baseline(): Promise<number> {
    if (this.#baseline === undefined) {
      const provider = await this.provider();
      await this.acquired(provider);
      this.#baseline = this.broker.requests.length;
    }
    return this.#baseline;
  }

  /** Renew as PiShip does: refresh() when present, else a new acquire. */
  renew(
    provider: CredentialProvider,
    current: RuntimeCredential,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential | null> {
    return provider.refresh
      ? provider.refresh(this.identity, current, ctx)
      : provider.acquire(this.identity, ctx);
  }
}

/** A credential's fields must all come from `issued`. */
function matchesIssue(
  credential: RuntimeCredential | null | undefined,
  issued: IssuedCredential,
): boolean {
  return (
    !!credential &&
    revealed(credential.secret) === issued.secret &&
    credential.credentialId === issued.credentialId
  );
}

const ACQUIRE_FAILED: readonly PiShipErrorCode[] = [
  "CREDENTIAL_ACQUIRE_FAILED",
];
const REVOKE_FAILED: readonly PiShipErrorCode[] = ["CREDENTIAL_REVOKED"];

// ---------------------------------------------------------------- checks

type Check = (h: Harness) => Promise<string | undefined>;

const checks: Record<CredentialBehavior, Check> = {
  async acquire(h) {
    const provider = await h.provider();
    check(
      provider.mode === "adapter" || provider.mode === "http-broker",
      `mode is ${String(provider.mode)}; a credential adapter declares mode "adapter"`,
    );
    h.broker.handler = (request) => h.broker.issue(request);
    const outcome = await h.call("acquire", () =>
      provider.acquire(h.identity, h.ctx()),
    );
    check(
      outcome.kind !== "hung",
      "acquire did not end within the kit's bound",
    );
    check(
      outcome.kind === "resolved",
      `acquire failed against a broker that issued a credential (${codeOf(outcome.kind === "rejected" ? outcome.error : undefined)})`,
    );
    check(
      h.broker.requests.length > 0,
      "acquire sent no request through the context's managed fetch",
    );
    const credential = outcome.value;
    const issued = h.broker.issued.at(-1);
    check(credential && issued, "acquire returned no credential");
    check(
      ["api_key", "bearer", "opaque"].includes(credential.kind),
      "the credential kind is not api_key, bearer, or opaque",
    );
    check(
      typeof (credential.secret as { reveal?: unknown })?.reveal === "function",
      "the credential secret is not a SecretValue",
    );
    check(
      revealed(credential.secret) === issued.secret,
      "the credential secret is not the one the broker issued",
    );
    check(
      credential.credentialId === issued.credentialId,
      "the credential ID is not the one the broker issued",
    );
    return undefined;
  },

  async refresh(h) {
    const provider = await h.provider();
    const current = await h.acquired(provider);
    const before = h.broker.requests.length;
    const issuedBefore = h.broker.issued.length;
    h.broker.handler = (request) => h.broker.issue(request);
    const outcome = await h.call("refresh", () =>
      h.renew(provider, current, h.ctx()),
    );
    check(
      outcome.kind !== "hung",
      "refresh did not end within the kit's bound",
    );
    check(
      outcome.kind === "resolved",
      "refresh failed against a broker that issued a credential",
    );
    check(
      h.broker.requests.length > before,
      "refresh sent no request to the broker",
    );
    const next = h.broker.issued.slice(issuedBefore);
    check(
      revealed(outcome.value?.secret) !== revealed(current.secret),
      "refresh returned the current secret instead of the new one",
    );
    check(
      next.some((issued) => revealed(outcome.value?.secret) === issued.secret),
      "the refreshed secret is not the one the broker issued",
    );
    check(
      next.some((issued) => matchesIssue(outcome.value, issued)),
      "the refreshed credential ID does not belong to the refreshed secret",
    );
    return undefined;
  },

  async expiry(h) {
    const provider = await h.provider();
    const credential = await h.acquired(provider);
    const issued = h.broker.issued.at(-1);
    const expiry = expiryOf(credential);
    check(
      issued &&
        expiry !== undefined &&
        Math.abs(expiry - issued.expiresAt.getTime()) < 1_000,
      "the acquired credential's expiresAt is not the broker's expiry",
    );
    h.broker.handler = (request) => h.broker.issue(request);
    const renewed = await h.call("refresh", () =>
      h.renew(provider, credential, h.ctx()),
    );
    const next = h.broker.issued.at(-1);
    check(
      renewed.kind === "resolved" && renewed.value && next,
      "refresh failed, so the refreshed expiry could not be checked",
    );
    const renewedExpiry = expiryOf(renewed.value);
    check(
      renewedExpiry !== undefined &&
        Math.abs(renewedExpiry - next.expiresAt.getTime()) < 1_000,
      "the refreshed credential's expiresAt is not the broker's new expiry",
    );
    h.broker.handler = (request) =>
      h.broker.issue(
        request,
        new Date(Math.floor(Date.now() / 1000) * 1000 - 60_000),
      );
    const expired = await h.call("acquire", () =>
      provider.acquire(h.identity, h.ctx()),
    );
    expectError(
      rejection(expired, "a credential that had already expired"),
      "a credential that had already expired",
      { codes: ["CREDENTIAL_EXPIRED", "CREDENTIAL_ACQUIRE_FAILED"] },
    );
    return undefined;
  },

  async revoke(h) {
    const provider = await h.provider();
    if (!provider.revoke)
      return "skipped: the adapter has no revoke(); a credential stays valid until it expires";
    const credential = await h.acquired(provider);
    const before = h.broker.requests.length;
    h.broker.handler = () => h.broker.revoked();
    const outcome = await h.call(
      "revoke",
      () => provider.revoke?.(credential, h.ctx()) ?? Promise.resolve(),
    );
    check(outcome.kind !== "hung", "revoke did not end within the kit's bound");
    check(
      outcome.kind === "resolved",
      "revoke failed although the broker accepted it",
    );
    const sent = h.broker.requests.slice(before);
    check(sent.length > 0, "revoke sent no request to the broker");
    const secret = revealed(credential.secret) ?? "";
    const id = credential.credentialId ?? "";
    check(
      sent.some((request) => {
        const text = requestText(request);
        return (id && text.includes(id)) || (secret && text.includes(secret));
      }),
      "the revoke request names neither the credential ID nor the credential",
    );
    return undefined;
  },

  async "401"(h) {
    const provider = await h.provider();
    h.broker.handler = () => h.broker.status(401);
    const outcome = await h.call("acquire", () =>
      provider.acquire(h.identity, h.ctx()),
    );
    expectError(
      rejection(outcome, "acquire answered 401"),
      "acquire answered 401",
      {
        codes: ["IDENTITY_EXPIRED"],
        retryable: false,
      },
    );
    return undefined;
  },

  async "403"(h) {
    const provider = await h.provider();
    h.broker.handler = () =>
      h.broker.status(
        403,
        { "content-type": "application/json" },
        '{"error":"denied"}',
      );
    expectError(
      rejection(
        await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
        "acquire answered 403",
      ),
      "acquire answered 403",
      { codes: ["CREDENTIAL_DENIED"], retryable: false },
    );
    h.broker.handler = (_request, _index, signal) =>
      h.broker.stalledBody(403, signal);
    expectError(
      rejection(
        await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
        "acquire answered 403 with a body that never arrives",
      ),
      "acquire answered 403 with a body that never arrives",
      { codes: ["CREDENTIAL_DENIED"], retryable: false },
    );
    if (provider.revoke) {
      const credential = await h.acquired(provider);
      h.broker.handler = () => h.broker.status(403);
      expectError(
        rejection(
          await h.call(
            "revoke",
            () => provider.revoke?.(credential, h.ctx()) ?? Promise.resolve(),
          ),
          "revoke answered 403",
        ),
        "revoke answered 403",
        { codes: ["CREDENTIAL_DENIED"], retryable: false },
      );
    }
    return undefined;
  },

  async "429"(h) {
    const provider = await h.provider();
    const wait = { "retry-after": String(RETRY_AFTER_SECONDS) };
    h.broker.handler = () => h.broker.status(429, wait);
    expectError(
      rejection(
        await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
        "acquire answered 429",
      ),
      "acquire answered 429",
      {
        codes: ACQUIRE_FAILED,
        retryable: true,
        retryAfterMs: RETRY_AFTER_SECONDS * 1000,
      },
    );
    const date = new Date(Date.now() + 30_000).toUTCString();
    h.broker.handler = () => h.broker.status(429, { "retry-after": date });
    expectError(
      rejection(
        await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
        "acquire answered 429 with an HTTP-date",
      ),
      "acquire answered 429 with an HTTP-date",
      {
        codes: ACQUIRE_FAILED,
        retryable: true,
        retryAfterMs: [15_000, 30_000],
      },
    );
    if (provider.revoke) {
      const credential = await h.acquired(provider);
      h.broker.handler = () => h.broker.status(429, wait);
      expectError(
        rejection(
          await h.call(
            "revoke",
            () => provider.revoke?.(credential, h.ctx()) ?? Promise.resolve(),
          ),
          "revoke answered 429",
        ),
        "revoke answered 429",
        {
          codes: REVOKE_FAILED,
          retryable: true,
          retryAfterMs: RETRY_AFTER_SECONDS * 1000,
        },
      );
    }
    return undefined;
  },

  async "5xx"(h) {
    const provider = await h.provider();
    for (const status of [500, 502, 503]) {
      const what = `acquire answered ${status}`;
      h.broker.handler = () =>
        status === 503
          ? h.broker.status(503, { "retry-after": "5" })
          : h.broker.status(
              status,
              { "content-type": "text/html" },
              "<html>unavailable</html>",
            );
      expectError(
        rejection(
          await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
          what,
        ),
        what,
        {
          codes: ACQUIRE_FAILED,
          retryable: true,
          ...(status === 503 ? { retryAfterMs: 5_000 } : {}),
        },
      );
    }
    if (provider.revoke) {
      const credential = await h.acquired(provider);
      h.broker.handler = () => h.broker.status(503, { "retry-after": "5" });
      expectError(
        rejection(
          await h.call(
            "revoke",
            () => provider.revoke?.(credential, h.ctx()) ?? Promise.resolve(),
          ),
          "revoke answered 503",
        ),
        "revoke answered 503",
        { codes: REVOKE_FAILED, retryable: true, retryAfterMs: 5_000 },
      );
    }
    return undefined;
  },

  async timeout(h) {
    const provider = await h.provider();
    h.broker.handler = (request, _index, signal) =>
      h.broker.stall(request, signal);
    expectError(
      rejection(
        await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
        "acquire to a broker that never answers",
      ),
      "acquire to a broker that never answers",
      { codes: ACQUIRE_FAILED, retryable: true },
    );
    // A caller signal that never fires must not remove the timeout.
    const quiet = new AbortController();
    expectError(
      rejection(
        await h.call("acquire", () =>
          provider.acquire(h.identity, h.ctx({ signal: quiet.signal })),
        ),
        "acquire with a caller signal to a broker that never answers",
      ),
      "acquire with a caller signal to a broker that never answers",
      { codes: ACQUIRE_FAILED, retryable: true },
    );
    if (provider.revoke) {
      const credential = await h.acquired(provider);
      h.broker.handler = (request, _index, signal) =>
        h.broker.stall(request, signal);
      expectError(
        rejection(
          await h.call(
            "revoke",
            () =>
              provider.revoke?.(credential, h.ctx({ signal: quiet.signal })) ??
              Promise.resolve(),
          ),
          "revoke to a broker that never answers",
        ),
        "revoke to a broker that never answers",
        { codes: REVOKE_FAILED, retryable: true },
      );
    }
    return undefined;
  },

  async abort(h) {
    const provider = await h.provider();
    const credential = provider.revoke ? await h.acquired(provider) : undefined;
    const operations: [
      Operation,
      (ctx: CredentialContext) => Promise<unknown>,
      readonly PiShipErrorCode[],
    ][] = [
      ["acquire", (ctx) => provider.acquire(h.identity, ctx), ACQUIRE_FAILED],
    ];
    if (provider.revoke && credential)
      operations.push([
        "revoke",
        (ctx) => provider.revoke?.(credential, ctx) ?? Promise.resolve(),
        REVOKE_FAILED,
      ]);
    for (const [operation, run, codes] of operations) {
      // Cancelled while the broker holds the request.
      const controller = new AbortController();
      const reason = new DOMException(
        "cancelled by the conformance kit",
        "AbortError",
      );
      h.broker.handler = (request, _index, signal) =>
        h.broker.stall(request, signal);
      h.broker.onDeliver = () => controller.abort(reason);
      const before = h.broker.requests.length;
      const what = `${operation} cancelled in flight`;
      const outcome = await h.call(operation, () =>
        run(h.ctx({ signal: controller.signal })),
      );
      h.broker.onDeliver = undefined;
      expectError(rejection(outcome, what), what, { codes, retryable: false });
      const sent = h.broker.requests.slice(before);
      check(
        sent.length > 0 &&
          sent.every((request) => request.cancelledBy === reason),
        `${what}: the request was not ended by the caller's signal`,
      );
      // Cancelled before anything was sent.
      const early = `${operation} with a signal that was already aborted`;
      expectError(
        rejection(
          await h.call(operation, () =>
            run(h.ctx({ signal: AbortSignal.abort() })),
          ),
          early,
        ),
        early,
        { codes, retryable: false },
      );
    }
    return undefined;
  },

  async redaction(h) {
    const provider = await h.provider();
    const credential = await h.acquired(provider);
    const credentialSecret = revealed(credential.secret) ?? "";
    const secrets = [h.token, h.bodySentinel, credentialSecret].filter(Boolean);
    check(
      !secretsIn(credential, [credentialSecret]),
      "the returned credential renders its secret; wrap it in a SecretValue",
    );
    const body = JSON.stringify({ error: "failure", detail: h.bodySentinel });
    const cases: [string, Operation, Handler][] = [
      [
        "a 403 whose body holds a sentinel",
        "acquire",
        () =>
          h.broker.status(403, { "content-type": "application/json" }, body),
      ],
      [
        "a 502 whose HTML body holds a sentinel",
        "acquire",
        () =>
          h.broker.status(
            502,
            { "content-type": "text/html" },
            `<html><body>${h.bodySentinel}</body></html>`,
          ),
      ],
      [
        "a 400 whose body holds a sentinel",
        "acquire",
        () =>
          h.broker.status(400, { "content-type": "application/json" }, body),
      ],
      [
        "a 200 whose body is not the expected answer",
        "acquire",
        () =>
          h.broker.status(
            200,
            { "content-type": "application/json" },
            `<html>${h.bodySentinel}</html>`,
          ),
      ],
      [
        "a transport error that quotes the identity token",
        "acquire",
        () => {
          throw new TypeError(
            `Invalid value "Bearer ${h.token}" for header "authorization"`,
          );
        },
      ],
    ];
    if (provider.revoke) {
      cases.push(
        [
          "a revoke 502 whose body holds a sentinel",
          "revoke",
          () => h.broker.status(502, {}, h.bodySentinel),
        ],
        [
          "a revoke transport error that quotes the credential",
          "revoke",
          () => {
            throw new TypeError(
              `Invalid value "Bearer ${credentialSecret}" for header "authorization"`,
            );
          },
        ],
      );
    }
    for (const [what, operation, handler] of cases) {
      h.broker.handler = handler;
      const outcome = await h.call(
        operation,
        async (): Promise<unknown> =>
          operation === "revoke"
            ? provider.revoke?.(credential, h.ctx())
            : provider.acquire(h.identity, h.ctx()),
      );
      check(
        outcome.kind !== "hung",
        `${what}: the call did not end within the kit's bound`,
      );
      if (outcome.kind === "rejected")
        check(
          !secretsIn(outcome.error, secrets),
          `${what}: the error shows a token, credential, or answer body`,
        );
    }
    return undefined;
  },

  async "concurrent refresh"(h) {
    const provider = await h.provider();
    const current = await h.acquired(provider);
    const before = h.broker.requests.length;
    const issuedBefore = h.broker.issued.length;
    // Hold the first answer until the second request arrives (or briefly, for
    // an adapter that serializes refreshes), then answer both at once.
    let release: () => void = () => {};
    const both = new Promise<void>((resolve) => {
      release = resolve;
    });
    const hold = Math.min(250, h.timeoutMs / 2);
    h.broker.onDeliver = () => {
      if (h.broker.requests.length - before >= 2) release();
    };
    h.broker.handler = async (request) => {
      await Promise.race([both, new Promise((r) => setTimeout(r, hold))]);
      return h.broker.issue(request);
    };
    const outcome = await h.call("refresh", () =>
      Promise.allSettled([
        h.renew(
          provider,
          current,
          h.ctx({ idempotencyKey: `conformance-a-${h.run}` }),
        ),
        h.renew(
          provider,
          current,
          h.ctx({ idempotencyKey: `conformance-b-${h.run}` }),
        ),
      ]),
    );
    h.broker.onDeliver = undefined;
    check(
      outcome.kind === "resolved",
      "concurrent refreshes did not end within the kit's bound",
    );
    const [first, second] = outcome.value;
    check(
      first?.status === "fulfilled" && second?.status === "fulfilled",
      "a concurrent refresh failed",
    );
    const issued = h.broker.issued.slice(issuedBefore);
    const results = [first.value, second.value];
    for (const [index, result] of results.entries()) {
      check(result, "a concurrent refresh returned no credential");
      const own = issued.find(
        (item) => item.secret === revealed(result.secret),
      );
      check(
        own,
        "a concurrent refresh returned a secret the broker did not issue to it",
      );
      const others = issued.filter((item) => item !== own);
      check(
        !others.some(
          (other) =>
            result.credentialId === other.credentialId ||
            expiryOf(result) === other.expiresAt.getTime(),
        ),
        `concurrent refresh ${index + 1} carries the ID or expiry of the credential issued to the other call`,
      );
    }
    return undefined;
  },

  async "retry behavior"(h) {
    const allowed = await h.baseline();
    const cases: [
      string,
      (
        request: BrokerRequest,
        index: number,
        signal: AbortSignal | undefined,
      ) => Response | Promise<Response>,
    ][] = [
      [
        "a timeout",
        (request, index, signal) =>
          index < allowed
            ? h.broker.stall(request, signal)
            : h.broker.issue(request),
      ],
      [
        "a connection reset after the request was sent",
        (request, index) => {
          if (index < allowed)
            throw new TypeError("fetch failed", {
              cause: { code: "ECONNRESET" },
            });
          return h.broker.issue(request);
        },
      ],
      [
        "a 503",
        (request, index) =>
          index < allowed
            ? h.broker.status(503, { "retry-after": "1" })
            : h.broker.issue(request),
      ],
      [
        "a 502",
        (request, index) =>
          index < allowed ? h.broker.status(502) : h.broker.issue(request),
      ],
      [
        "a 429",
        (request, index) =>
          index < allowed
            ? h.broker.status(429, { "retry-after": "1" })
            : h.broker.issue(request),
      ],
      [
        "a 401",
        (request, index) =>
          index < allowed ? h.broker.status(401) : h.broker.issue(request),
      ],
    ];
    for (const [what, handler] of cases) {
      const fresh = await h.provider();
      h.broker.handler = handler;
      const outcome = await h.call("acquire", () =>
        fresh.acquire(h.identity, h.ctx()),
      );
      check(
        outcome.kind !== "hung",
        `after ${what}: the call did not end within the kit's bound`,
      );
      check(
        h.broker.requests.length <= allowed,
        `after ${what}: the adapter sent ${h.broker.requests.length} requests where one acquire sends ${allowed}`,
      );
      check(
        outcome.kind === "rejected",
        `after ${what}: the adapter retried and succeeded instead of failing`,
      );
    }
    // A transport failure, before or after sending, is retryable.
    const provider = await h.provider();
    for (const code of ["ECONNREFUSED", "ECONNRESET"]) {
      const what = `a transport failure (${code})`;
      h.broker.handler = () => {
        throw new TypeError("fetch failed", { cause: { code } });
      };
      expectError(
        rejection(
          await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
          what,
        ),
        what,
        { codes: ACQUIRE_FAILED, retryable: true },
      );
    }
    // A policy refusal is invalid configuration, never a transient failure.
    for (const code of ["NETWORK_DENIED", "TLS_POLICY_VIOLATION"] as const) {
      const what = `a ${code} refusal from the managed fetch`;
      h.broker.handler = () => {
        throw new PiShipError(code, "refused by the network policy", {
          component: "network",
        });
      };
      expectError(
        rejection(
          await h.call("acquire", () => provider.acquire(h.identity, h.ctx())),
          what,
        ),
        what,
        { codes: [code], retryable: false },
      );
    }
    return undefined;
  },

  async idempotency(h) {
    if (h.options.idempotency === false)
      return "skipped: the adapter declares that its service does not honor idempotency keys";
    const provider = await h.provider();
    const key = (name: string) => `conformance-${name}-${h.run}`;
    h.broker.handler = (request) => h.broker.issue(request);
    const acquired = await h.call("acquire", () =>
      provider.acquire(h.identity, h.ctx({ idempotencyKey: key("acquire") })),
    );
    check(
      acquired.kind === "resolved" && acquired.value,
      "an acquire with an idempotency key failed",
    );
    check(
      h.broker.requests.every(
        (request) => request.idempotencyKey === key("acquire"),
      ),
      "an acquire request did not carry CredentialContext.idempotencyKey as Idempotency-Key",
    );
    const before = h.broker.requests.length;
    const renewed = await h.call("refresh", () =>
      h.renew(
        provider,
        acquired.value as RuntimeCredential,
        h.ctx({ idempotencyKey: key("refresh") }),
      ),
    );
    check(
      renewed.kind === "resolved",
      "a refresh with an idempotency key failed",
    );
    check(
      h.broker.requests
        .slice(before)
        .every((request) => request.idempotencyKey === key("refresh")),
      "a refresh request did not carry CredentialContext.idempotencyKey as Idempotency-Key",
    );
    // The broker issues the credential, then the answer is lost.
    const lost = key("lost");
    const issuedBefore = h.broker.issued.length;
    h.broker.handler = (request, _index, signal) => {
      h.broker.issue(request);
      return h.broker.stall(request, signal);
    };
    const error = expectError(
      rejection(
        await h.call("acquire", () =>
          provider.acquire(h.identity, h.ctx({ idempotencyKey: lost })),
        ),
        "an acquire whose answer was lost",
      ),
      "an acquire whose answer was lost",
      { codes: ACQUIRE_FAILED },
    );
    check(
      error.sanitizedDetail?.idempotencyKey === lost,
      "the timed-out acquire does not report its key as detail.idempotencyKey",
    );
    const issuedForLost = h.broker.issued.slice(issuedBefore);
    check(
      issuedForLost.length === 1,
      "the broker issued no single credential for the lost answer",
    );
    // The caller retries the same acquire with the reported key.
    h.broker.handler = (request) => h.broker.issue(request);
    const retried = await h.call("acquire", () =>
      provider.acquire(
        h.identity,
        h.ctx({
          idempotencyKey: String(error.sanitizedDetail?.idempotencyKey),
        }),
      ),
    );
    check(
      retried.kind === "resolved",
      "retrying the lost acquire with its key failed",
    );
    check(
      issuedForLost[0] && matchesIssue(retried.value, issuedForLost[0]),
      "retrying the lost acquire with its key did not return the credential the broker already issued",
    );
    return undefined;
  },
};

/**
 * Run a credential adapter against the kit's fake broker and report each
 * behavior of `CREDENTIAL_CONTRACT` as passed, failed, or skipped, with a
 * reason for anything but passed. `adapter` is the adapter module's default
 * export, as `defineCredentialAdapter` returns it; the kit calls it with a
 * context whose `fetch` reaches only the fake broker.
 */
export async function testCredentialAdapter(
  adapter: AdapterFactory<CredentialProvider>,
  options: CredentialKitOptions = {},
): Promise<ConformanceReport> {
  const timeout = options.requestTimeoutMs;
  if (timeout !== undefined && !(Number.isFinite(timeout) && timeout > 0))
    throw new RangeError("requestTimeoutMs must be a positive number");
  const harness = new Harness(adapter, options);
  const results: ConformanceResult[] = [];
  for (const behavior of CREDENTIAL_BEHAVIORS) {
    try {
      const outcome = await checks[behavior](harness);
      results.push(
        outcome?.startsWith("skipped: ")
          ? {
              behavior,
              status: "skipped",
              reason: outcome.slice("skipped: ".length),
            }
          : { behavior, status: "passed" },
      );
    } catch (error) {
      results.push({
        behavior,
        status: "failed",
        reason:
          error instanceof Finding
            ? error.message
            : `the check ended unexpectedly with ${codeOf(error)}`,
      });
    } finally {
      harness.broker.onDeliver = undefined;
      harness.broker.release();
    }
  }
  return { kind: "credential", results };
}
