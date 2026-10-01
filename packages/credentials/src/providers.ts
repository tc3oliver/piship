import {
  type CredentialContext,
  type CredentialProvider,
  type IdentitySession,
  type ManagedFetch,
  PiShipError,
  parseRetryAfter,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  SecretValue,
  trimTrailingSlashes,
} from "@piship/contracts";

export interface HttpBrokerOptions {
  readonly endpoint: string;
  readonly revokeEndpoint?: string;
  readonly fetch: ManagedFetch;
  /** Declared gateway; a broker-returned base_url must match it. */
  readonly expectedBaseUrl?: string;
  readonly timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/** Which broker call failed. */
export type BrokerOperation = "acquire" | "revoke";

/**
 * Why a broker call failed, carried as `sanitizedDetail.reason` (with
 * `operation` and, for an HTTP answer, `status`) so callers can tell the
 * retry classes apart where they share an error code. Never secret.
 *
 * - `unreachable`: transport failure; no answer was received
 * - `timeout`: no complete answer within the timeout
 * - `cancelled`: the caller's signal aborted the call
 * - `authentication` (401), `denied` (403), `rate-limited` (429),
 *   `unavailable` (5xx), `rejected` (any other non-2xx)
 * - `contract`: a 2xx answer that breaks the http-broker contract
 * - `idempotency-conflict` (409 or 422 to an acquire that carried an
 *   idempotency key): the broker already used the key for other input
 *
 * A failure without an answer (`unreachable`, `timeout`, `cancelled`) also
 * carries `outcome`: `not-sent` when the request never reached the broker,
 * `unknown` when the broker may have received it and acted on it. An acquire
 * that carried an idempotency key reports it as `idempotencyKey`, so a caller
 * that retries the same acquire can send the same key.
 */
export type BrokerFailureReason =
  | "unreachable"
  | "timeout"
  | "cancelled"
  | "authentication"
  | "denied"
  | "rate-limited"
  | "unavailable"
  | "rejected"
  | "contract"
  | "idempotency-conflict";

/** Non-secret detail an acquire adds to every failure: its idempotency key. */
type ExtraDetail = Readonly<Record<string, string>>;

function brokerFailure(
  operation: BrokerOperation,
  reason: BrokerFailureReason,
  message: string,
  options: {
    readonly retryable?: boolean;
    readonly retryAfterMs?: number | undefined;
    readonly status?: number;
    readonly outcome?: "not-sent" | "unknown";
    readonly detail?: ExtraDetail;
    readonly userAction?: string;
  } = {},
): PiShipError {
  const detail = {
    component: "credential",
    retryable: options.retryable ?? false,
    ...(options.retryAfterMs === undefined
      ? {}
      : { retryAfterMs: options.retryAfterMs }),
    ...(options.userAction ? { userAction: options.userAction } : {}),
    sanitizedDetail: {
      operation,
      reason,
      ...(options.status === undefined ? {} : { status: options.status }),
      ...(options.outcome ? { outcome: options.outcome } : {}),
      ...options.detail,
    },
  };
  return operation === "acquire"
    ? new PiShipError("CREDENTIAL_ACQUIRE_FAILED", message, detail)
    : new PiShipError("CREDENTIAL_REVOKED", message, detail);
}

/**
 * Map a broker answer that is not a success to the error contract. A 401 is
 * left to the caller, because acquire and revoke read it differently.
 */
function statusFailure(
  operation: BrokerOperation,
  response: Response,
  detail: ExtraDetail = {},
): PiShipError {
  const status = response.status;
  if (status === 403)
    return new PiShipError(
      "CREDENTIAL_DENIED",
      operation === "acquire"
        ? "The credential broker denied this user or distribution"
        : "The credential broker denied revoking this credential",
      {
        component: "credential",
        userAction: "Ask your administrator for access",
        sanitizedDetail: { operation, reason: "denied", status, ...detail },
      },
    );
  // Only an acquire that sent a key can conflict with an earlier use of it.
  if ((status === 409 || status === 422) && detail.idempotencyKey)
    return brokerFailure(
      operation,
      "idempotency-conflict",
      "The credential broker refused an idempotency key it already used for a different request",
      {
        status,
        detail,
        userAction:
          "Run the command again; a new request uses a new idempotency key",
      },
    );
  const reason: BrokerFailureReason =
    status === 429
      ? "rate-limited"
      : status >= 500
        ? "unavailable"
        : "rejected";
  const retryable = reason !== "rejected";
  const subject =
    operation === "acquire" ? "The credential broker" : "Credential revocation";
  return brokerFailure(
    operation,
    reason,
    status === 429
      ? `${subject} is rate limiting requests`
      : `${subject} returned HTTP ${status}`,
    {
      retryable,
      status,
      // The server's wait is honored for every retryable answer, 5xx included.
      retryAfterMs: retryable
        ? parseRetryAfter(response.headers.get("retry-after"))
        : undefined,
      detail,
    },
  );
}

/** Largest broker answer body read; the http-broker answer is a few hundred bytes. */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Anything but visible ASCII: a token that becomes a header value is refused
 * before it is sent or stored. Beyond CR, LF and NUL, which break the header,
 * any other control character, space, or non-ASCII character makes the
 * request fail in the HTTP client on every use.
 */
const HEADER_BREAKING = /[^\x21-\x7e]/;

/** A broker credential ID: non-secret, shown, audited, and sent back on revoke. */
const CREDENTIAL_ID = /^[A-Za-z0-9._:-]{1,256}$/;

/** Optional broker answer fields, where `null` is read as absent. */
const OPTIONAL_ANSWER_FIELDS = [
  "subject",
  "credential_id",
  "expires_at",
  "models",
  "base_url",
] as const;

/** An idempotency key: 1 to 255 visible ASCII characters, no spaces. */
const IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,255}$/;

/**
 * The system error code behind a transport failure (`ECONNRESET`,
 * `ECONNREFUSED`), or undefined. A raw fetch error carries it as its cause;
 * the managed fetch keeps only the code, at the end of its
 * `GATEWAY_UNREACHABLE` message, after the host it names. Only a bare code is
 * ever taken: never a message, a URL, a header, or a body.
 */
function systemCode(error: unknown): string | undefined {
  if (error instanceof PiShipError)
    return error.code === "GATEWAY_UNREACHABLE"
      ? /: ([A-Z][A-Z0-9_]{0,63})$/.exec(error.message)?.[1]
      : undefined;
  const code = (error as { cause?: { code?: unknown } })?.cause?.code;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)
    ? code
    : undefined;
}

/**
 * A short, fixed description of a transport failure. Never an error message:
 * undici puts an invalid header value, such as a bearer token, into its
 * message. The system error code comes first. The managed fetch reports
 * every transport failure as the gateway's `GATEWAY_UNREACHABLE`, whatever
 * the host, so that code never names a broker failure; another PiShip code,
 * such as `NETWORK_DENIED`, is kept.
 */
function transportCode(error: unknown): string {
  return (
    systemCode(error) ??
    (error instanceof PiShipError && error.code !== "GATEWAY_UNREACHABLE"
      ? error.code
      : "network error")
  );
}

/**
 * System errors raised while connecting, before any request byte reaches the
 * broker: the broker cannot have acted on the request. Any other transport
 * failure may come after the request was sent.
 */
const NOT_SENT_CODES = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
]);

/**
 * Whether a transport failure happened before the request was sent. The
 * managed fetch keeps only the system code, at the end of its message; a
 * message in another shape reads as possibly sent, never as not sent.
 */
function failedBeforeSend(error: unknown): boolean {
  const code = systemCode(error);
  return code !== undefined && NOT_SENT_CODES.has(code);
}

/** Read at most `MAX_BODY_BYTES` of a body; a larger one breaks the contract. */
async function readBounded(
  response: Response,
  operation: BrokerOperation,
  detail: ExtraDetail,
): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      throw brokerFailure(
        operation,
        "contract",
        "The credential broker answer is too large",
        { status: response.status, detail },
      );
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Release an answer whose body is not needed; never fails. */
function discardBody(response: Response): void {
  response.body?.cancel().catch(() => {});
}

/**
 * One broker call under a deadline that a caller's signal can shorten but
 * never remove. The status decides the classification; `body()` reads a
 * bounded body under the same deadline and is called only for a success, so
 * a stalled or huge error body never turns a 403 into a timeout. Transport
 * failures are credential failures, not gateway ones; other PiShip errors
 * from the managed fetch (network or TLS policy) keep their own codes.
 *
 * Nothing is retried here. A failure without an answer says whether the
 * request may have reached the broker (`outcome`), because a broker may have
 * issued a credential for a request whose answer was lost.
 */
async function brokerRequest(
  fetch: ManagedFetch,
  url: string,
  init: RequestInit,
  operation: BrokerOperation,
  options: {
    readonly signal?: AbortSignal;
    readonly timeoutMs?: number;
    readonly detail?: ExtraDetail;
  },
): Promise<{
  readonly response: Response;
  readonly body: () => Promise<string>;
}> {
  const detail = options.detail ?? {};
  const cancelled = (outcome: "not-sent" | "unknown") =>
    brokerFailure(
      operation,
      "cancelled",
      `The credential ${operation === "acquire" ? "request" : "revocation"} was cancelled`,
      { outcome, detail },
    );
  // A signal that is already aborted never reaches the broker.
  if (options.signal?.aborted) throw cancelled("not-sent");
  const deadline = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal
    ? AbortSignal.any([options.signal, deadline])
    : deadline;
  const subject =
    operation === "acquire"
      ? "The credential broker"
      : "The credential revocation endpoint";
  const failure = (error: unknown): unknown => {
    if (options.signal?.aborted) return cancelled("unknown");
    if (error instanceof PiShipError && error.code !== "GATEWAY_UNREACHABLE")
      return error;
    if (
      deadline.aborted ||
      (error as Error)?.name === "AbortError" ||
      (error as Error)?.name === "TimeoutError"
    )
      return brokerFailure(
        operation,
        "timeout",
        `${subject} did not respond in time`,
        { retryable: true, outcome: "unknown", detail },
      );
    const code = systemCode(error);
    return brokerFailure(
      operation,
      "unreachable",
      `${subject} is unreachable (${transportCode(error)})`,
      {
        retryable: true,
        outcome: failedBeforeSend(error) ? "not-sent" : "unknown",
        // The system code, when there is one, so a log or a test sees why.
        detail: { ...detail, ...(code ? { transport: code } : {}) },
      },
    );
  };
  let response: Response;
  try {
    response = await fetch(url, { ...init, signal });
  } catch (error) {
    throw failure(error);
  }
  return {
    response,
    body: async () => {
      try {
        return await readBounded(response, operation, detail);
      } catch (error) {
        throw failure(error);
      }
    },
  };
}

function normalizeUrl(value: string): string {
  const url = new URL(value);
  return `${url.origin}${trimTrailingSlashes(url.pathname)}`;
}

/**
 * Generic organization credential broker (`http-broker`).
 *
 * POST <endpoint> with `Authorization: Bearer <identity access token>` returns
 * `{credential_type, credential, credential_id?, expires_at?, models?, base_url?}`.
 * `CredentialContext.idempotencyKey`, when set, is sent as `Idempotency-Key`;
 * a failed acquire is never re-sent here. Revocation POSTs `{credential_id}`
 * to the optional revoke endpoint with the runtime credential as bearer. Raw
 * responses are never logged or echoed.
 */
export class HttpBrokerCredentialProvider implements CredentialProvider {
  readonly mode = "http-broker" as const;
  readonly requiresIdentity = true;
  constructor(readonly options: HttpBrokerOptions) {}

  /** Remote revocation is available only with a declared revoke endpoint. */
  get revocable(): boolean {
    return !!this.options.revokeEndpoint;
  }

  async acquire(
    identity: IdentitySession | null,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential> {
    if (!identity?.accessToken)
      throw new PiShipError(
        "IDENTITY_REQUIRED",
        "The credential broker requires a signed-in identity",
        {
          component: "credential",
          userAction: "Run login",
        },
      );
    const token = identity.accessToken.reveal();
    if (HEADER_BREAKING.test(token))
      throw new PiShipError(
        "IDENTITY_INVALID",
        "The identity session holds a malformed access token",
        { component: "credential", userAction: "Run login again" },
      );
    const key = ctx.idempotencyKey;
    if (key !== undefined && !IDEMPOTENCY_KEY.test(key))
      throw brokerFailure(
        "acquire",
        "contract",
        "The idempotency key must be 1 to 255 visible ASCII characters",
      );
    // The key is not secret: it rides on every failure so a caller that
    // retries this acquire can send it again.
    const detail: ExtraDetail =
      key === undefined ? {} : { idempotencyKey: key };
    const { response, body: readBody } = await brokerRequest(
      this.options.fetch,
      this.options.endpoint,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          accept: "application/json",
          ...(key === undefined ? {} : { "idempotency-key": key }),
        },
        body: JSON.stringify({
          distribution: ctx.distributionId,
          purpose: "inference",
        }),
      },
      "acquire",
      {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        ...(this.options.timeoutMs
          ? { timeoutMs: this.options.timeoutMs }
          : {}),
        detail,
      },
    );
    if (response.status >= 300) discardBody(response);
    if (response.status === 401)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The credential broker rejected the identity session",
        {
          component: "credential",
          userAction: "Run login again",
          sanitizedDetail: {
            operation: "acquire",
            reason: "authentication",
            status: 401,
            ...detail,
          },
        },
      );
    if (response.status >= 300)
      throw statusFailure("acquire", response, detail);
    const text = await readBody();
    let body: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
        throw new TypeError("not an object");
      body = parsed as Record<string, unknown>;
    } catch {
      throw brokerFailure(
        "acquire",
        "contract",
        "The credential broker returned malformed JSON",
        { status: response.status, detail },
      );
    }
    // Many serializers write `null` for an unset field: an optional field
    // that is `null` means exactly what an absent one means.
    for (const field of OPTIONAL_ANSWER_FIELDS)
      if (body[field] === null) delete body[field];
    // A broker may say whom it authenticated. If it does, it must be the
    // identity PiShip sent: the reuse of a stored credential trusts the
    // principal the identity adapter asserted, and a broker that answers for
    // a different subject means the two disagree about who is asking.
    if (
      body.subject !== undefined &&
      (typeof body.subject !== "string" || body.subject !== identity.subject)
    )
      throw await this.#discardIssued(
        body,
        ctx,
        brokerFailure(
          "acquire",
          "contract",
          "The credential broker issued a credential for another subject",
          { status: response.status, detail },
        ),
      );
    const type = body.credential_type;
    const secret = body.credential;
    // The first field that breaks the contract, named in the error; its
    // value never is.
    const invalid =
      type !== "api_key" && type !== "bearer" && type !== "opaque"
        ? "credential_type"
        : typeof secret !== "string" ||
            secret.length < 8 ||
            HEADER_BREAKING.test(secret)
          ? "credential"
          : body.credential_id !== undefined &&
              (typeof body.credential_id !== "string" ||
                !CREDENTIAL_ID.test(body.credential_id))
            ? "credential_id"
            : body.expires_at !== undefined &&
                (typeof body.expires_at !== "string" ||
                  Number.isNaN(Date.parse(body.expires_at)))
              ? "expires_at"
              : body.models !== undefined &&
                  (!Array.isArray(body.models) ||
                    body.models.some((item) => typeof item !== "string"))
                ? "models"
                : body.base_url !== undefined &&
                    typeof body.base_url !== "string"
                  ? "base_url"
                  : undefined;
    // `typeof secret` repeats the check above only to narrow its type.
    if (invalid !== undefined || typeof secret !== "string") {
      const field = invalid ?? "credential";
      throw brokerFailure(
        "acquire",
        "contract",
        `The credential broker response does not match the http-broker contract: invalid ${field}`,
        { status: response.status, detail: { ...detail, field } },
      );
    }
    if (
      typeof body.base_url === "string" &&
      this.options.expectedBaseUrl &&
      normalizeUrl(body.base_url) !== normalizeUrl(this.options.expectedBaseUrl)
    )
      throw await this.#discardIssued(
        body,
        ctx,
        new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          "The credential broker returned an undeclared gateway base_url",
          {
            component: "credential",
            userAction: "Align the broker with inference.baseUrl",
            sanitizedDetail: {
              operation: "acquire",
              reason: "contract",
              status: response.status,
              ...detail,
            },
          },
        ),
      );
    const value = new SecretValue(secret);
    const expiresAt =
      typeof body.expires_at === "string"
        ? new Date(body.expires_at)
        : undefined;
    if (expiresAt && expiresAt.getTime() <= Date.now())
      throw await this.#discardIssued(
        body,
        ctx,
        new PiShipError(
          "CREDENTIAL_EXPIRED",
          "The credential broker issued an already expired credential",
          {
            component: "credential",
            sanitizedDetail: {
              operation: "acquire",
              reason: "contract",
              status: response.status,
              ...detail,
            },
          },
        ),
      );
    return {
      kind: type as RuntimeCredentialKind,
      secret: value,
      ...(typeof body.credential_id === "string"
        ? { credentialId: body.credential_id }
        : {}),
      ...(expiresAt ? { expiresAt } : {}),
      metadata: {
        ...(Array.isArray(body.models)
          ? { models: body.models as string[] }
          : {}),
        ...(typeof body.base_url === "string"
          ? { baseUrl: body.base_url }
          : {}),
      },
    };
  }

  /**
   * Revoke, best effort, a credential the broker issued in an answer PiShip
   * then refuses, so it does not stay live at the broker with nothing
   * recording it. Returns `error`, the refusal, which is what the caller
   * sees either way; a failed revocation is noted in its detail.
   */
  async #discardIssued(
    body: Record<string, unknown>,
    ctx: CredentialContext,
    error: PiShipError,
  ): Promise<PiShipError> {
    const secret = body.credential;
    const type = body.credential_type;
    if (
      !this.options.revokeEndpoint ||
      (type !== "api_key" && type !== "bearer" && type !== "opaque") ||
      typeof secret !== "string" ||
      secret.length < 8 ||
      HEADER_BREAKING.test(secret)
    )
      return error;
    const issued: RuntimeCredential = {
      kind: type,
      secret: new SecretValue(secret),
      ...(typeof body.credential_id === "string" &&
      CREDENTIAL_ID.test(body.credential_id)
        ? { credentialId: body.credential_id }
        : {}),
      metadata: {},
    };
    try {
      await this.revoke(issued, ctx);
      return error;
    } catch {
      return new PiShipError(
        error.code,
        `${error.message}; revoking the credential it issued failed, so it stays live at the broker until it expires`,
        {
          component: "credential",
          ...(error.userAction ? { userAction: error.userAction } : {}),
          retryable: error.retryable,
          sanitizedDetail: {
            ...error.sanitizedDetail,
            issuedNotRevoked: true,
          },
        },
      );
    }
  }

  refresh(
    identity: IdentitySession | null,
    _current: RuntimeCredential,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential> {
    return this.acquire(identity, ctx);
  }

  async revoke(
    credential: RuntimeCredential,
    ctx: CredentialContext,
  ): Promise<void> {
    if (!this.options.revokeEndpoint) return;
    if (HEADER_BREAKING.test(credential.secret.reveal()))
      throw brokerFailure(
        "revoke",
        "contract",
        "The stored credential is malformed and cannot be revoked",
      );
    const { response } = await brokerRequest(
      this.options.fetch,
      this.options.revokeEndpoint,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${credential.secret.reveal()}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          credential_id: credential.credentialId ?? null,
          distribution: ctx.distributionId,
        }),
      },
      "revoke",
      {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        ...(this.options.timeoutMs
          ? { timeoutMs: this.options.timeoutMs }
          : {}),
      },
    );
    discardBody(response);
    // 401 and 404: the credential is no longer valid there, so it is revoked.
    if (
      response.status >= 300 &&
      response.status !== 404 &&
      response.status !== 401
    )
      throw statusFailure("revoke", response);
  }
}

export interface LocalSecretOptions {
  /** What the prompt asks for. Default `API key`. */
  readonly label?: string;
  /** How the secret is sent. Default `api_key`. */
  readonly kind?: "api_key" | "bearer";
  /** Longest secret accepted; unlimited when absent. */
  readonly maxLength?: number;
  /** The command that stores it, for the error when none is entered. */
  readonly userAction?: string;
}

/**
 * User-owned secret (`local-secret`), such as a personal provider API key or
 * a sandbox service's API key or token, captured interactively and kept in
 * the configured SecretStore. It has no expiry and no remote revocation.
 */
export class LocalSecretCredentialProvider implements CredentialProvider {
  readonly mode = "local-secret" as const;
  readonly requiresIdentity = false;
  constructor(readonly options: LocalSecretOptions = {}) {}
  async acquire(
    _identity: IdentitySession | null,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential> {
    if (!ctx.readSecret)
      throw new PiShipError(
        "CREDENTIAL_REQUIRED",
        "No local secret is stored for this distribution",
        {
          component: "credential",
          userAction:
            this.options.userAction ??
            "Run the branded login command to store it",
        },
      );
    const value = (
      await ctx.readSecret(this.options.label ?? "API key")
    ).trim();
    // At least 8 visible ASCII characters: a space, a control character
    // (CR, LF, NUL), or a non-ASCII character would break the request
    // header it is sent in.
    if (
      value.length < 8 ||
      HEADER_BREAKING.test(value) ||
      (this.options.maxLength !== undefined &&
        value.length > this.options.maxLength)
    )
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The entered secret is empty or malformed",
        {
          component: "credential",
        },
      );
    return {
      kind: this.options.kind ?? "api_key",
      secret: new SecretValue(value),
    };
  }
}

/**
 * Explicit delegation to Pi-native authentication (`pi-native`). PiShip does
 * not read, copy, or store Pi's credential; it only records the delegation.
 */
export class PiNativeCredentialProvider implements CredentialProvider {
  readonly mode = "pi-native" as const;
  readonly requiresIdentity = false;
  async acquire(): Promise<null> {
    return null;
  }
}

/** The selected inference endpoint needs no credential (`none`). */
export class NoCredentialProvider implements CredentialProvider {
  readonly mode = "none" as const;
  readonly requiresIdentity = false;
  async acquire(): Promise<null> {
    return null;
  }
}
