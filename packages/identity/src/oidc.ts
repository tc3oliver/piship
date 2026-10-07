import * as client from "openid-client";
import {
  type IdentityProvider,
  type IdentitySession,
  isLoopbackHost,
  isPrivateNetworkHost,
  type LoginContext,
  type ManagedFetch,
  PiShipError,
  parseRetryAfter,
  SecretValue,
} from "@piship/contracts";
import { retainClaims } from "./claims.js";
import { DEFAULT_LOGIN_TIMEOUT_MS, startLoopbackReceiver } from "./loopback.js";

export interface OidcIdentityOptions {
  readonly issuer: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly audience?: string;
  /** `authorization_code_pkce` (default) or RFC 8628 `device_code`. */
  readonly flow?: "authorization_code_pkce" | "device_code";
  /**
   * Registered loopback redirect; port 0/omitted selects an ephemeral port.
   * Required for `authorization_code_pkce`, unused by `device_code`.
   */
  readonly redirectUri?: string;
  /** Managed fetch honoring proxy, CA, and private-only policy. */
  readonly fetch: ManagedFetch;
  /**
   * `identity.oidc.httpTransport: http-allowed`: the issuer and the
   * endpoints its discovery document names may use plain HTTP to a private
   * or internal host. `fetch` must admit those requests; this provider
   * refuses a plain-HTTP endpoint on any other host, including the
   * authorization endpoint the browser opens.
   */
  readonly plainHttp?: boolean;
  /**
   * With `plainHttp`: called after discovery with the endpoints it names
   * (each `*_endpoint` and `jwks_uri`), so the caller's fetch can admit
   * plain HTTP to exactly those origins.
   */
  readonly onDiscoveredEndpoints?: (urls: readonly string[]) => void;
  readonly timeoutSeconds?: number;
  readonly clockToleranceSeconds?: number;
  /** Replaces the device-flow poll wait; for tests that must not really wait. */
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

/** Never poll faster than this, nor slower than that, whatever the provider asks for. */
const MIN_POLL_INTERVAL_SECONDS = 1;
const MAX_POLL_INTERVAL_SECONDS = 60;
/** `setTimeout` fires after 1 ms for a delay beyond this. */
const MAX_TIMER_MS = 2 ** 31 - 1;
const MAX_VERIFICATION_URI_LENGTH = 2048;
const USER_CODE = /^[A-Za-z0-9 _-]{1,32}$/;
// Control characters: C0, DEL, C1, and the Unicode line and paragraph separators.
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point.
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point.
const UNSAFE_URI_CHARACTER = /[\s\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/**
 * Text from the identity provider, made safe to print to a terminal: no
 * control character (an escape sequence cannot start), at most `max`
 * characters.
 */
export function terminalSafe(text: string, max = 200): string {
  const clean = text.replace(CONTROL, "");
  return clean.length > max ? `${clean.slice(0, max)}...` : clean;
}
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

function sleepFor(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, ms);
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
  });
}

/** Settle with `work`, or reject at once when `signal` aborts. */
function raceAbort<T>(signal: AbortSignal, work: Promise<T>): Promise<T> {
  // An abort can reject `work` after this has settled; that is not unhandled.
  work.catch(() => {});
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    work
      .finally(() => signal.removeEventListener("abort", abort))
      .then(resolve, reject);
  });
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
  const detail = terminalSafe(
    cause instanceof Error && cause.message
      ? cause.message
      : ((error as Error)?.message ?? String(error)),
  );
  if (error instanceof client.AuthorizationResponseError) {
    const errorCode = terminalSafe(error.error, 64);
    const denied = error.error === "access_denied";
    // These name the request PiShip built from the configuration, not the
    // person signing in: a wrong client ID, redirect URI, or scope.
    const registration = [
      "unauthorized_client",
      "invalid_client",
      "invalid_request",
      "invalid_scope",
      "unsupported_response_type",
    ].includes(error.error);
    return new PiShipError(
      "IDENTITY_INVALID",
      `${action}: the identity provider ${denied ? "denied" : "rejected"} the request (${errorCode})`,
      {
        component: "identity",
        userAction: registration
          ? "Ask your administrator to check the configured client ID, its registered redirect URI, and the requested scopes, then run login again"
          : "Run login again or contact your administrator",
      },
    );
  }
  if (error instanceof client.ResponseBodyError) {
    const expired = error.error === "invalid_grant";
    return new PiShipError(
      expired ? "IDENTITY_EXPIRED" : "IDENTITY_INVALID",
      `${action}: token endpoint returned ${terminalSafe(error.error, 64)}`,
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
 * With `http-allowed`, every endpoint the discovery document names is https,
 * or plain HTTP to loopback or a private or internal host. The managed fetch
 * checks the endpoints PiShip requests; this also covers the authorization
 * and end-session endpoints, which the browser opens.
 */
function refusePublicPlainHttp(metadata: client.ServerMetadata): string[] {
  const endpoints: string[] = [];
  for (const [key, value] of Object.entries(metadata)) {
    if (
      typeof value !== "string" ||
      !(key.endsWith("_endpoint") || key === "jwks_uri")
    )
      continue;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      continue;
    }
    if (url.protocol === "http:" && !isPrivateNetworkHost(url.hostname))
      throw new PiShipError(
        "CONFIG_INVALID",
        `The identity provider's ${key} is plain HTTP to ${url.hostname}, which is public; identity.oidc.httpTransport: http-allowed permits plain HTTP only to a private or internal host`,
        { component: "identity" },
      );
    endpoints.push(value);
  }
  return endpoints;
}

/**
 * Native public-client OIDC login with Authorization Code + PKCE (S256), state,
 * nonce, and ID token issuer/audience/authorized-party/signature/time checks,
 * implemented with the maintained openid-client library.
 */
export class OidcPkceIdentityProvider implements IdentityProvider {
  readonly kind = "oidc";
  #config: Promise<client.Configuration> | undefined;
  readonly #device: boolean;
  constructor(readonly options: OidcIdentityOptions) {
    if (options.scopes.indexOf("openid") < 0)
      throw new PiShipError(
        "CONFIG_INVALID",
        "OIDC login requires the openid scope",
      );
    this.#device = options.flow === "device_code";
    if (!this.#device && !options.redirectUri)
      throw new PiShipError(
        "CONFIG_INVALID",
        "OIDC authorization_code_pkce login requires a redirect URI",
      );
  }

  configuration(): Promise<client.Configuration> {
    this.#config ??= (async () => {
      const issuer = new URL(this.options.issuer);
      const plainHttp = this.options.plainHttp === true;
      const insecureLoopback =
        issuer.protocol === "http:" && isLoopbackHost(issuer.hostname);
      try {
        const config = await client.discovery(
          issuer,
          this.options.clientId,
          {
            ...(this.#device
              ? {}
              : {
                  redirect_uris: [this.options.redirectUri ?? ""],
                  response_types: ["code"],
                }),
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
              ...(insecureLoopback || plainHttp
                ? [client.allowInsecureRequests]
                : []),
            ],
          },
        );
        if (plainHttp) {
          // Checked whether or not anyone is told the endpoints.
          const endpoints = refusePublicPlainHttp(config.serverMetadata());
          this.options.onDiscoveredEndpoints?.(endpoints);
        }
        const methods =
          config.serverMetadata().code_challenge_methods_supported;
        // The device flow does not use PKCE.
        if (
          !this.#device &&
          Array.isArray(methods) &&
          !methods.includes("S256")
        )
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

  /**
   * A verification URI is shown to the person and opened in a browser, and it
   * comes from the provider's response: it must be a plain URL on https (plain
   * HTTP only where the manifest allows it for this host), without
   * credentials or control characters, and not oversized. The error never
   * carries the value.
   */
  #verificationUri(value: unknown): string {
    const refuse = () =>
      new PiShipError(
        "IDENTITY_INVALID",
        "The identity provider returned an unusable verification URL",
        { component: "identity", userAction: "Contact your administrator" },
      );
    if (
      typeof value !== "string" ||
      value.length > MAX_VERIFICATION_URI_LENGTH ||
      UNSAFE_URI_CHARACTER.test(value)
    )
      throw refuse();
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw refuse();
    }
    const issuer = new URL(this.options.issuer);
    const plainAllowed =
      (this.options.plainHttp === true && isPrivateNetworkHost(url.hostname)) ||
      (issuer.protocol === "http:" &&
        isLoopbackHost(issuer.hostname) &&
        isLoopbackHost(url.hostname));
    if (
      (url.protocol !== "https:" &&
        !(url.protocol === "http:" && plainAllowed)) ||
      url.username ||
      url.password ||
      url.href.length > MAX_VERIFICATION_URI_LENGTH
    )
      throw refuse();
    return url.href;
  }

  async login(ctx: LoginContext): Promise<IdentitySession> {
    const config = await this.configuration();
    if (this.#device) return this.#deviceLogin(config, ctx);
    // The listener refuses a callback without this state and keeps waiting,
    // so a stray request cannot end the sign-in; the state is still checked
    // again below with the code exchange.
    const state = client.randomState();
    const receiver = await startLoopbackReceiver(
      this.options.redirectUri ?? "",
      {
        state,
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        ...(ctx.timeoutMs ? { timeoutMs: ctx.timeoutMs } : {}),
      },
    );
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

  /**
   * RFC 8628 device authorization. The person enters the user code at the
   * provider from any browser; this process only polls the token endpoint,
   * so no local port is involved. There is no `state` or `nonce`: nothing
   * returns through a browser redirect, and the ID token arrives in the
   * response to PiShip's own token request, bound to this `device_code`.
   * Every other ID token check is the same as the code flow's, because the
   * response goes through the same library validation.
   */
  async #deviceLogin(
    config: client.Configuration,
    ctx: LoginContext,
  ): Promise<IdentitySession> {
    if (!config.serverMetadata().device_authorization_endpoint)
      throw new PiShipError(
        "CONFIG_INVALID",
        "The identity provider does not advertise a device_authorization_endpoint, which identity.oidc.flow: device_code needs",
        {
          component: "identity",
          userAction:
            "Use flow authorization_code_pkce, or ask your administrator to enable the device code flow at the identity provider",
        },
      );
    if (!ctx.presentDeviceCode)
      throw new PiShipError(
        "CONFIG_UNAVAILABLE",
        "This sign-in cannot show a device code, which identity.oidc.flow: device_code needs",
        { component: "identity" },
      );
    // Cancellation and the deadline are one signal; its reason says which.
    const stop = new AbortController();
    const loginMs = Math.min(
      ctx.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS,
      MAX_TIMER_MS,
    );
    const timer = setTimeout(() => stop.abort("timeout"), loginMs);
    const cancel = () => stop.abort("cancel");
    if (ctx.signal?.aborted) cancel();
    ctx.signal?.addEventListener("abort", cancel, { once: true });
    const { signal } = stop;
    const ended = (how: string, retry: string) =>
      new PiShipError("IDENTITY_REQUIRED", `Sign-in ${how}`, {
        component: "identity",
        ...(retry ? { userAction: retry } : {}),
      });
    try {
      signal.throwIfAborted();
      const parameters: Record<string, string> = {
        scope: this.options.scopes.join(" "),
      };
      if (this.options.audience) parameters.audience = this.options.audience;
      const device = await raceAbort(
        signal,
        client.initiateDeviceAuthorization(config, parameters),
      );
      // Nothing the provider sent is shown or opened before it is checked.
      const verificationUri = this.#verificationUri(device.verification_uri);
      const verificationUriComplete =
        device.verification_uri_complete === undefined
          ? undefined
          : this.#verificationUri(device.verification_uri_complete);
      if (!USER_CODE.test(String(device.user_code)))
        throw new PiShipError(
          "IDENTITY_INVALID",
          "The identity provider returned an unusable user code",
          { component: "identity", userAction: "Contact your administrator" },
        );
      // The code is good until the provider's expiry or this login's own
      // deadline, whichever comes first; after the expiry it cannot succeed.
      const expiresMs = Math.min(
        Math.max(0, device.expires_in * 1000),
        MAX_TIMER_MS,
      );
      const expiry = setTimeout(() => stop.abort("expired"), expiresMs);
      try {
        await ctx.presentDeviceCode({
          verificationUri,
          userCode: device.user_code,
          ...(verificationUriComplete ? { verificationUriComplete } : {}),
          expiresInSeconds: Math.min(expiresMs, loginMs) / 1000,
        });
        const clampInterval = (seconds: number) =>
          Math.min(
            Math.max(
              Number.isFinite(seconds) ? seconds : 5,
              MIN_POLL_INTERVAL_SECONDS,
            ),
            MAX_POLL_INTERVAL_SECONDS,
          );
        let interval = clampInterval(device.interval ?? 5);
        const sleep = this.options.sleep ?? sleepFor;
        for (;;) {
          await sleep(interval * 1000, signal);
          try {
            const tokens = await raceAbort(
              signal,
              client.genericGrantRequest(config, DEVICE_GRANT, {
                device_code: device.device_code,
              }),
            );
            return session(tokens);
          } catch (error) {
            if (!(error instanceof client.ResponseBodyError)) throw error;
            if (error.error === "slow_down")
              interval = clampInterval(interval + 5);
            else if (error.error !== "authorization_pending") throw error;
          }
        }
      } finally {
        clearTimeout(expiry);
      }
    } catch (error) {
      if (signal.aborted)
        throw signal.reason === "cancel"
          ? ended("was cancelled", "")
          : ended(
              signal.reason === "expired"
                ? "timed out: the device code expired"
                : "timed out",
              "Run login again and enter the new code promptly",
            );
      if (error instanceof client.ResponseBodyError) {
        if (error.error === "access_denied")
          throw new PiShipError(
            "IDENTITY_INVALID",
            "Sign-in failed: the sign-in request was declined (access_denied)",
            {
              component: "identity",
              userAction: "Run login again or contact your administrator",
            },
          );
        if (error.error === "expired_token")
          throw ended(
            "timed out: the device code expired",
            "Run login again and enter the new code promptly",
          );
      }
      throw mapError(error, "Sign-in failed");
    } finally {
      clearTimeout(timer);
      ctx.signal?.removeEventListener("abort", cancel);
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
