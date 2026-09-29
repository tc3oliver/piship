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
  | "contract";

function brokerFailure(
  operation: BrokerOperation,
  reason: BrokerFailureReason,
  message: string,
  options: {
    readonly retryable?: boolean;
    readonly retryAfterMs?: number | undefined;
    readonly status?: number;
  } = {},
): PiShipError {
  const detail = {
    component: "credential",
    retryable: options.retryable ?? false,
    ...(options.retryAfterMs === undefined
      ? {}
      : { retryAfterMs: options.retryAfterMs }),
    sanitizedDetail: {
      operation,
      reason,
      ...(options.status === undefined ? {} : { status: options.status }),
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
        sanitizedDetail: { operation, reason: "denied", status },
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
    },
  );
}

/**
 * One broker call under a deadline that a caller's signal can shorten but
 * never remove. The body is read under the same deadline. Transport failures
 * are credential failures, not gateway ones; other PiShip errors from the
 * managed fetch (network or TLS policy) keep their own codes.
 */
async function brokerRequest(
  fetch: ManagedFetch,
  url: string,
  init: RequestInit,
  operation: BrokerOperation,
  options: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
): Promise<{ readonly response: Response; readonly text: string }> {
  const deadline = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal
    ? AbortSignal.any([options.signal, deadline])
    : deadline;
  const subject =
    operation === "acquire"
      ? "The credential broker"
      : "The credential revocation endpoint";
  try {
    const response = await fetch(url, { ...init, signal });
    return { response, text: await response.text() };
  } catch (error) {
    if (options.signal?.aborted)
      throw brokerFailure(
        operation,
        "cancelled",
        `The credential ${operation === "acquire" ? "request" : "revocation"} was cancelled`,
      );
    if (error instanceof PiShipError && error.code !== "GATEWAY_UNREACHABLE")
      throw error;
    if (
      deadline.aborted ||
      (error as Error)?.name === "AbortError" ||
      (error as Error)?.name === "TimeoutError"
    )
      throw brokerFailure(
        operation,
        "timeout",
        `${subject} did not respond in time`,
        { retryable: true },
      );
    throw brokerFailure(
      operation,
      "unreachable",
      `${subject} is unreachable${error instanceof Error ? `: ${error.message}` : ""}`,
      { retryable: true },
    );
  }
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
 * Revocation POSTs `{credential_id}` to the optional revoke endpoint with the
 * runtime credential as bearer. Raw responses are never logged or echoed.
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
    const { response, text } = await brokerRequest(
      this.options.fetch,
      this.options.endpoint,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${identity.accessToken.reveal()}`,
          "content-type": "application/json",
          accept: "application/json",
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
      },
    );
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
          },
        },
      );
    if (response.status >= 300) throw statusFailure("acquire", response);
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
        { status: response.status },
      );
    }
    const type = body.credential_type;
    const secret = body.credential;
    if (
      (type !== "api_key" && type !== "bearer" && type !== "opaque") ||
      typeof secret !== "string" ||
      secret.length < 8 ||
      (body.credential_id !== undefined &&
        typeof body.credential_id !== "string") ||
      (body.expires_at !== undefined &&
        (typeof body.expires_at !== "string" ||
          Number.isNaN(Date.parse(body.expires_at)))) ||
      (body.models !== undefined &&
        (!Array.isArray(body.models) ||
          body.models.some((item) => typeof item !== "string"))) ||
      (body.base_url !== undefined && typeof body.base_url !== "string")
    )
      throw brokerFailure(
        "acquire",
        "contract",
        "The credential broker response does not match the http-broker contract",
        { status: response.status },
      );
    if (
      typeof body.base_url === "string" &&
      this.options.expectedBaseUrl &&
      normalizeUrl(body.base_url) !== normalizeUrl(this.options.expectedBaseUrl)
    )
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker returned an undeclared gateway base_url",
        {
          component: "credential",
          userAction: "Align the broker with inference.baseUrl",
          sanitizedDetail: {
            operation: "acquire",
            reason: "contract",
            status: response.status,
          },
        },
      );
    const value = new SecretValue(secret);
    const expiresAt =
      typeof body.expires_at === "string"
        ? new Date(body.expires_at)
        : undefined;
    if (expiresAt && expiresAt.getTime() <= Date.now())
      throw new PiShipError(
        "CREDENTIAL_EXPIRED",
        "The credential broker issued an already expired credential",
        {
          component: "credential",
        },
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
    // 401 and 404: the credential is no longer valid there, so it is revoked.
    if (
      response.status >= 300 &&
      response.status !== 404 &&
      response.status !== 401
    )
      throw statusFailure("revoke", response);
  }
}

/**
 * User-owned secret (`local-secret`), such as a personal provider API key,
 * captured interactively and kept in the configured SecretStore. It has no
 * expiry and no remote revocation.
 */
export class LocalSecretCredentialProvider implements CredentialProvider {
  readonly mode = "local-secret" as const;
  readonly requiresIdentity = false;
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
          userAction: "Run the branded login command to store it",
        },
      );
    const value = (await ctx.readSecret("API key")).trim();
    if (value.length < 8 || /\s/.test(value))
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The entered secret is empty or malformed",
        {
          component: "credential",
        },
      );
    return { kind: "api_key", secret: new SecretValue(value) };
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
