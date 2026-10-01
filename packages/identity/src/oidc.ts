import * as client from "openid-client";
import {
  type IdentityProvider,
  type IdentitySession,
  isLoopbackHost,
  type LoginContext,
  type ManagedFetch,
  PiShipError,
  parseRetryAfter,
  SecretValue,
} from "@piship/contracts";
import { retainClaims } from "./claims.js";
import { startLoopbackReceiver } from "./loopback.js";

export interface OidcIdentityOptions {
  readonly issuer: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly audience?: string;
  /** Registered loopback redirect; port 0/omitted selects an ephemeral port. */
  readonly redirectUri: string;
  /** Managed fetch honoring proxy, CA, and private-only policy. */
  readonly fetch: ManagedFetch;
  readonly timeoutSeconds?: number;
  readonly clockToleranceSeconds?: number;
}

function mapError(error: unknown, action: string): PiShipError {
  for (
    let current: unknown = error;
    current;
    current = (current as { cause?: unknown }).cause
  )
    if (current instanceof PiShipError) return current;
  // A deadline is an unavailable identity provider, not an invalid identity.
  for (
    let current: unknown = error;
    current;
    current = (current as { cause?: unknown }).cause
  )
    if ((current as Error)?.name === "TimeoutError")
      return new PiShipError(
        "GATEWAY_UNREACHABLE",
        `${action}: the identity provider did not respond in time`,
        {
          component: "identity",
          retryable: true,
          userAction: "Check the network connection, then try again",
        },
      );
  const code = (error as { code?: string })?.code ?? "";
  const cause = (error as { cause?: unknown })?.cause;
  // A provider outage or rate limit, including a proxy's HTML error page in
  // front of it, is retryable with the server's wait. It says nothing about
  // the identity, so it is never IDENTITY_INVALID or IDENTITY_EXPIRED. The
  // managed fetch may return another realm's Response, so match its shape.
  const answer = (
    error instanceof client.ResponseBodyError ? error.response : cause
  ) as Partial<Response> | undefined;
  const status =
    typeof answer?.status === "number" &&
    typeof answer.headers?.get === "function"
      ? answer.status
      : undefined;
  if (
    status !== undefined &&
    (status >= 500 ||
      status === 429 ||
      (error instanceof client.ResponseBodyError &&
        (error.error === "server_error" ||
          error.error === "temporarily_unavailable")))
  ) {
    const limited = status === 429;
    const retryAfterMs = parseRetryAfter(answer?.headers?.get("retry-after"));
    return new PiShipError(
      limited ? "GATEWAY_RATE_LIMITED" : "GATEWAY_UNREACHABLE",
      `${action}: the identity provider ${limited ? "is rate limiting requests" : "is temporarily unavailable"} (HTTP ${status})`,
      {
        component: "identity",
        retryable: true,
        ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
        userAction: "Try again later",
      },
    );
  }
  // oauth4webapi puts the precise failed check (claim, state, signature) in the cause.
  const detail =
    cause instanceof Error && cause.message
      ? cause.message
      : ((error as Error)?.message ?? String(error));
  if (error instanceof client.AuthorizationResponseError) {
    const denied = error.error === "access_denied";
    return new PiShipError(
      "IDENTITY_INVALID",
      `${action}: the identity provider ${denied ? "denied" : "rejected"} the request (${error.error})`,
      {
        component: "identity",
        userAction: "Run login again or contact your administrator",
      },
    );
  }
  if (error instanceof client.ResponseBodyError) {
    const expired = error.error === "invalid_grant";
    return new PiShipError(
      expired ? "IDENTITY_EXPIRED" : "IDENTITY_INVALID",
      `${action}: token endpoint returned ${error.error}`,
      {
        component: "identity",
        userAction: expired ? "Run login again" : "Contact your administrator",
      },
    );
  }
  if (code === "OAUTH_JWT_TIMESTAMP_CHECK_FAILED")
    return new PiShipError("IDENTITY_EXPIRED", `${action}: ${detail}`, {
      component: "identity",
      userAction: "Check the system clock, then run login again",
    });
  return new PiShipError("IDENTITY_INVALID", `${action}: ${detail}`, {
    component: "identity",
    userAction: "Check the configured issuer and client registration",
  });
}

function session(
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
  previous?: IdentitySession,
): IdentitySession {
  const claims = tokens.claims();
  if (!claims) {
    if (!previous)
      throw new PiShipError(
        "IDENTITY_INVALID",
        "The identity provider returned no ID token",
        {
          component: "identity",
        },
      );
  } else if (
    previous &&
    (claims.sub !== previous.subject || claims.iss !== previous.issuer)
  )
    throw new PiShipError(
      "IDENTITY_INVALID",
      "Refreshed identity does not match the signed-in subject",
      { component: "identity" },
    );
  const retained = retainClaims(claims);
  const expiresIn = tokens.expiresIn();
  const displayName =
    (claims?.name as string | undefined) ??
    (claims?.preferred_username as string | undefined) ??
    previous?.displayName;
  const email = (claims?.email as string | undefined) ?? previous?.email;
  const refreshToken = tokens.refresh_token ?? previous?.refreshToken?.reveal();
  return {
    subject: claims?.sub ?? previous?.subject ?? "",
    issuer: claims?.iss ?? previous?.issuer ?? "",
    ...(displayName ? { displayName } : {}),
    ...(email ? { email } : {}),
    accessToken: new SecretValue(tokens.access_token),
    ...(tokens.id_token
      ? { idToken: new SecretValue(tokens.id_token) }
      : previous?.idToken
        ? { idToken: previous.idToken }
        : {}),
    ...(refreshToken ? { refreshToken: new SecretValue(refreshToken) } : {}),
    ...(expiresIn === undefined
      ? {}
      : { expiresAt: new Date(Date.now() + expiresIn * 1000) }),
    claims: Object.keys(retained).length ? retained : (previous?.claims ?? {}),
  };
}

/**
 * Native public-client OIDC login with Authorization Code + PKCE (S256), state,
 * nonce, and ID token issuer/audience/authorized-party/signature/time checks,
 * implemented with the maintained openid-client library.
 */
export class OidcPkceIdentityProvider implements IdentityProvider {
  readonly kind = "oidc";
  #config: Promise<client.Configuration> | undefined;
  constructor(readonly options: OidcIdentityOptions) {
    if (options.scopes.indexOf("openid") < 0)
      throw new PiShipError(
        "CONFIG_INVALID",
        "OIDC login requires the openid scope",
      );
  }

  configuration(): Promise<client.Configuration> {
    this.#config ??= (async () => {
      const issuer = new URL(this.options.issuer);
      const insecureLoopback =
        issuer.protocol === "http:" && isLoopbackHost(issuer.hostname);
      try {
        const config = await client.discovery(
          issuer,
          this.options.clientId,
          {
            redirect_uris: [this.options.redirectUri],
            response_types: ["code"],
            token_endpoint_auth_method: "none",
            [client.clockTolerance]: this.options.clockToleranceSeconds ?? 30,
          },
          client.None(),
          {
            [client.customFetch]: (url, init) =>
              this.options.fetch(url, init as RequestInit),
            timeout: this.options.timeoutSeconds ?? 30,
            execute: [
              client.enableNonRepudiationChecks,
              ...(insecureLoopback ? [client.allowInsecureRequests] : []),
            ],
          },
        );
        const methods =
          config.serverMetadata().code_challenge_methods_supported;
        if (Array.isArray(methods) && !methods.includes("S256"))
          throw new PiShipError(
            "IDENTITY_INVALID",
            "The identity provider does not support PKCE S256",
            { component: "identity" },
          );
        return config;
      } catch (error) {
        this.#config = undefined;
        throw mapError(error, "OIDC discovery failed");
      }
    })();
    return this.#config;
  }

  async login(ctx: LoginContext): Promise<IdentitySession> {
    const config = await this.configuration();
    // The listener refuses a callback without this state and keeps waiting,
    // so a stray request cannot end the sign-in; the state is still checked
    // again below with the code exchange.
    const state = client.randomState();
    const receiver = await startLoopbackReceiver(this.options.redirectUri, {
      state,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
      ...(ctx.timeoutMs ? { timeoutMs: ctx.timeoutMs } : {}),
    });
    try {
      const verifier = client.randomPKCECodeVerifier();
      const nonce = client.randomNonce();
      const parameters: Record<string, string> = {
        redirect_uri: receiver.redirectUri,
        scope: this.options.scopes.join(" "),
        code_challenge: await client.calculatePKCECodeChallenge(verifier),
        code_challenge_method: "S256",
        state,
        nonce,
      };
      if (this.options.audience) parameters.audience = this.options.audience;
      await ctx.openUrl(
        client.buildAuthorizationUrl(config, parameters).toString(),
      );
      const callback = await receiver.callback;
      try {
        const tokens = await client.authorizationCodeGrant(config, callback, {
          pkceCodeVerifier: verifier,
          expectedState: state,
          expectedNonce: nonce,
          idTokenExpected: true,
        });
        return session(tokens);
      } catch (error) {
        throw mapError(error, "Sign-in failed");
      }
    } finally {
      await receiver.close();
    }
  }

  async refresh(current: IdentitySession): Promise<IdentitySession> {
    if (!current.refreshToken)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "Identity session has no refresh token",
        {
          component: "identity",
          userAction: "Run login again",
        },
      );
    const config = await this.configuration();
    try {
      return session(
        await client.refreshTokenGrant(config, current.refreshToken.reveal()),
        current,
      );
    } catch (error) {
      throw mapError(error, "Identity refresh failed");
    }
  }

  async logout(current: IdentitySession): Promise<void> {
    const config = await this.configuration();
    if (!config.serverMetadata().revocation_endpoint) return;
    const failures: string[] = [];
    for (const [hint, token] of [
      ["refresh_token", current.refreshToken],
      ["access_token", current.accessToken],
    ] as const) {
      if (!token) continue;
      try {
        await client.tokenRevocation(config, token.reveal(), {
          token_type_hint: hint,
        });
      } catch (error) {
        failures.push(`${hint}: ${mapError(error, "revocation").message}`);
      }
    }
    if (failures.length)
      throw new PiShipError(
        "IDENTITY_INVALID",
        `Token revocation failed (${failures.join("; ")})`,
        {
          component: "identity",
          retryable: true,
        },
      );
  }
}
