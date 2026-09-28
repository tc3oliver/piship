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

/** Broker transport failures are credential acquisition failures, not gateway ones. */
async function brokerRequest(
  fetch: ManagedFetch,
  url: string,
  init: RequestInit,
): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (error) {
    if (error instanceof PiShipError && error.code === "NETWORK_DENIED")
      throw error;
    if (
      (error as Error)?.name === "AbortError" ||
      (error as Error)?.name === "TimeoutError"
    )
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker did not respond in time",
        {
          component: "credential",
          retryable: true,
        },
      );
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      `The credential broker is unreachable${error instanceof Error ? `: ${error.message}` : ""}`,
      { component: "credential", retryable: true },
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
    const signal =
      ctx.signal ?? AbortSignal.timeout(this.options.timeoutMs ?? 30_000);
    const response = await brokerRequest(
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
        signal,
      },
    );
    if (response.status === 401)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The credential broker rejected the identity session",
        {
          component: "credential",
          userAction: "Run login again",
        },
      );
    if (response.status === 403)
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker denied this user or distribution",
        {
          component: "credential",
          userAction: "Ask your administrator for access",
        },
      );
    if (response.status === 429) {
      const after = parseRetryAfter(response.headers.get("retry-after"));
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker is rate limiting requests",
        {
          component: "credential",
          retryable: true,
          ...(after === undefined ? {} : { retryAfterMs: after }),
        },
      );
    }
    if (response.status >= 300)
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        `The credential broker returned HTTP ${response.status}`,
        { component: "credential", retryable: response.status >= 500 },
      );
    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch {
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker returned malformed JSON",
        {
          component: "credential",
        },
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
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "The credential broker response does not match the http-broker contract",
        {
          component: "credential",
        },
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
    const response = await this.options.fetch(this.options.revokeEndpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${credential.secret.reveal()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        credential_id: credential.credentialId ?? null,
        distribution: ctx.distributionId,
      }),
      signal:
        ctx.signal ?? AbortSignal.timeout(this.options.timeoutMs ?? 30_000),
    });
    if (
      response.status >= 300 &&
      response.status !== 404 &&
      response.status !== 401
    )
      throw new PiShipError(
        "CREDENTIAL_REVOKED",
        `Credential revocation returned HTTP ${response.status}`,
        {
          component: "credential",
          retryable: response.status >= 500,
        },
      );
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
