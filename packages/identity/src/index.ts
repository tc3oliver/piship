import {
  ADAPTER_CALL_TIMEOUT_MS,
  ADAPTER_INTERACTIVE_TIMEOUT_MS,
  callWithDeadline,
  type IdentityProvider,
  type IdentitySession,
  PiShipError,
  principalKey,
  SecretValue,
  samePrincipal,
  type WorkloadIdentityProvider,
} from "@piship/contracts";

import { retainClaims } from "./claims.js";

export type { WorkloadIdentityProvider } from "@piship/contracts";
export { RETAINED_CLAIMS, retainClaims } from "./claims.js";
export {
  DEFAULT_LOGIN_TIMEOUT_MS,
  type LoopbackReceiver,
  startLoopbackReceiver,
} from "./loopback.js";
export {
  type OidcIdentityOptions,
  OidcPkceIdentityProvider,
  terminalSafe,
} from "./oidc.js";

export const IDENTITY_METADATA_SCHEMA = "piship-identity-metadata/v1";

/** Non-secret identity state safe to write to ordinary files. */
export interface IdentityMetadata {
  readonly schema: typeof IDENTITY_METADATA_SCHEMA;
  readonly subject: string;
  readonly issuer: string;
  readonly displayName?: string;
  readonly email?: string;
  readonly expiresAt?: string;
  readonly claims: Record<string, unknown>;
  readonly secretRef: string;
}

export function identityMetadata(
  session: IdentitySession,
  secretRef: string,
): IdentityMetadata {
  return {
    schema: IDENTITY_METADATA_SCHEMA,
    subject: session.subject,
    issuer: session.issuer,
    ...(session.displayName ? { displayName: session.displayName } : {}),
    ...(session.email ? { email: session.email } : {}),
    ...(session.expiresAt
      ? { expiresAt: session.expiresAt.toISOString() }
      : {}),
    // Only allowlisted claims reach the plaintext session file.
    claims: retainClaims(session.claims),
    secretRef,
  };
}

/** Bundle token material into one secret for the SecretStore. */
export function identitySecret(session: IdentitySession): SecretValue {
  return new SecretValue(
    JSON.stringify({
      accessToken: session.accessToken?.reveal(),
      idToken: session.idToken?.reveal(),
      refreshToken: session.refreshToken?.reveal(),
    }),
  );
}

function tokenValue(value: unknown, field: string): SecretValue | undefined {
  if (value === undefined || value === null) return undefined;
  if (value instanceof SecretValue) return value;
  let text: unknown = value;
  if (
    typeof value === "object" &&
    typeof (value as { reveal?: unknown }).reveal === "function"
  )
    try {
      text = (value as { reveal: () => unknown }).reveal();
    } catch {
      text = undefined;
    }
  if (typeof text !== "string" || text.length === 0)
    throw new PiShipError(
      "IDENTITY_INVALID",
      `The identity provider returned an unusable ${field}`,
      { component: "identity" },
    );
  return new SecretValue(text);
}

/**
 * Validate an identity session from an adapter and re-wrap its tokens as
 * SecretValues of this contracts copy, so redaction (which relies on
 * `instanceof`) always applies. Plain-string tokens are accepted and wrapped.
 */
export function normalizeIdentitySession(value: unknown): IdentitySession {
  const session = (value ?? {}) as Record<string, unknown>;
  if (
    typeof session.subject !== "string" ||
    !session.subject ||
    typeof session.issuer !== "string" ||
    !session.issuer
  )
    throw new PiShipError(
      "IDENTITY_INVALID",
      "The identity provider returned a session without a subject and issuer",
      { component: "identity" },
    );
  const expiresAt =
    session.expiresAt === undefined
      ? undefined
      : new Date(
          session.expiresAt instanceof Date
            ? session.expiresAt.getTime()
            : typeof session.expiresAt === "string"
              ? Date.parse(session.expiresAt)
              : Number.NaN,
        );
  if (expiresAt && Number.isNaN(expiresAt.getTime()))
    throw new PiShipError(
      "IDENTITY_INVALID",
      "The identity provider returned an invalid session expiry",
      { component: "identity" },
    );
  const accessToken = tokenValue(session.accessToken, "access token");
  const idToken = tokenValue(session.idToken, "ID token");
  const refreshToken = tokenValue(session.refreshToken, "refresh token");
  return {
    subject: session.subject,
    issuer: session.issuer,
    ...(typeof session.displayName === "string" && session.displayName
      ? { displayName: session.displayName }
      : {}),
    ...(typeof session.email === "string" && session.email
      ? { email: session.email }
      : {}),
    ...(accessToken ? { accessToken } : {}),
    ...(idToken ? { idToken } : {}),
    ...(refreshToken ? { refreshToken } : {}),
    ...(expiresAt ? { expiresAt } : {}),
    ...(session.claims && typeof session.claims === "object"
      ? { claims: retainClaims(session.claims as Record<string, unknown>) }
      : {}),
  };
}

/**
 * Refuse a refreshed session whose principal `(iss, sub)` differs from the
 * session it refreshed: a refresh never switches the user.
 */
export function assertSamePrincipal(
  refreshed: IdentitySession,
  previous: IdentitySession,
  refusal: { readonly message: string; readonly userAction: string } = {
    message: "Refreshed identity does not match the signed-in subject",
    userAction: "Run login again",
  },
): IdentitySession {
  if (!samePrincipal(principalKey(refreshed), principalKey(previous)))
    throw new PiShipError("IDENTITY_INVALID", refusal.message, {
      component: "identity",
      userAction: refusal.userAction,
    });
  return refreshed;
}

/** Whether an identity provider declared itself non-interactive (a workload identity). */
export function isWorkloadIdentityProvider(
  provider: IdentityProvider,
): provider is WorkloadIdentityProvider {
  return (provider as { interactive?: unknown }).interactive === false;
}

/** The deadlines `normalizedIdentityProvider` applies (tests shorten them). */
export interface IdentityAdapterDeadlines {
  /** Names the adapter in a timeout, such as its path in the manifest. */
  readonly name?: string;
  /** `refresh()`, `logout()`, and a workload's `login()`. */
  readonly timeoutMs?: number;
  /** An interactive `login()`, unless the caller passed `timeoutMs`. */
  readonly loginTimeoutMs?: number;
}

/**
 * Wrap an adapter so every session it returns is normalized and a refresh
 * keeps the signed-in principal. An `interactive` declaration other than a
 * boolean is refused, so a typo never changes how a session is obtained.
 *
 * Every call has a deadline and receives a signal that aborts at it: a
 * workload `login()`, `refresh()`, and `logout()` have
 * `ADAPTER_CALL_TIMEOUT_MS`, an interactive `login()` the caller's
 * `timeoutMs` or `ADAPTER_INTERACTIVE_TIMEOUT_MS`. A call that runs past it
 * fails retryably with `GATEWAY_UNREACHABLE` naming the adapter and the
 * call, even if the adapter never settles.
 */
export function normalizedIdentityProvider(
  provider: IdentityProvider,
  deadlines: IdentityAdapterDeadlines = {},
): IdentityProvider {
  const interactive = (provider as { interactive?: unknown }).interactive;
  if (interactive !== undefined && typeof interactive !== "boolean")
    throw new PiShipError(
      "CONFIG_INVALID",
      "The identity adapter's interactive declaration must be true or false",
      { component: "identity" },
    );
  const name = deadlines.name ?? "";
  const subject = `The identity adapter${name ? ` ${name}` : ""}`;
  const bounded = <T>(
    phase: "login" | "refresh" | "logout",
    timeoutMs: number,
    signal: AbortSignal | undefined,
    call: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> =>
    callWithDeadline(call, {
      timeoutMs,
      ...(signal ? { signal } : {}),
      timedOut: () =>
        new PiShipError(
          "GATEWAY_UNREACHABLE",
          `${subject} did not answer ${phase}() within ${Math.ceil(timeoutMs / 1000)} s`,
          {
            component: "identity",
            retryable: true,
            userAction:
              "Check the service the identity adapter signs in with, then try again",
            sanitizedDetail: {
              ...(name ? { adapter: name } : {}),
              phase,
              reason: "timeout",
              timeoutMs,
            },
          },
        ),
      cancelled: () =>
        phase === "login"
          ? new PiShipError("IDENTITY_REQUIRED", "Sign-in was cancelled", {
              component: "identity",
            })
          : new PiShipError(
              "GATEWAY_UNREACHABLE",
              `${subject}'s ${phase}() was cancelled`,
              {
                component: "identity",
                sanitizedDetail: {
                  ...(name ? { adapter: name } : {}),
                  phase,
                  reason: "cancelled",
                },
              },
            ),
    });
  const callTimeoutMs = deadlines.timeoutMs ?? ADAPTER_CALL_TIMEOUT_MS;
  const refresh = provider.refresh?.bind(provider);
  const logout = provider.logout?.bind(provider);
  return {
    kind: provider.kind,
    ...(interactive === false ? { interactive } : {}),
    login: async (ctx) =>
      normalizeIdentitySession(
        await bounded(
          "login",
          interactive === false
            ? callTimeoutMs
            : (ctx.timeoutMs ??
                deadlines.loginTimeoutMs ??
                ADAPTER_INTERACTIVE_TIMEOUT_MS),
          ctx.signal,
          (signal) => provider.login({ ...ctx, signal }),
        ),
      ),
    ...(refresh
      ? {
          refresh: async (session: IdentitySession, ctx) =>
            assertSamePrincipal(
              normalizeIdentitySession(
                await bounded("refresh", callTimeoutMs, ctx?.signal, (signal) =>
                  refresh(session, { signal }),
                ),
              ),
              session,
            ),
        }
      : {}),
    ...(logout
      ? {
          logout: (session: IdentitySession, ctx) =>
            bounded("logout", callTimeoutMs, ctx?.signal, (signal) =>
              logout(session, { signal }),
            ),
        }
      : {}),
  };
}

export function parseIdentityMetadata(value: unknown): IdentityMetadata {
  const record = value as Partial<IdentityMetadata> | null;
  if (
    !record ||
    record.schema !== IDENTITY_METADATA_SCHEMA ||
    typeof record.subject !== "string" ||
    typeof record.issuer !== "string" ||
    typeof record.secretRef !== "string"
  )
    throw new PiShipError(
      "IDENTITY_REQUIRED",
      "Stored identity metadata is missing or from an incompatible version",
      { component: "identity", userAction: "Run login again" },
    );
  return record as IdentityMetadata;
}

export function restoreIdentitySession(
  metadata: IdentityMetadata,
  secret: SecretValue | null,
): IdentitySession {
  let tokens: {
    accessToken?: string;
    idToken?: string;
    refreshToken?: string;
  } = {};
  if (secret)
    try {
      tokens = JSON.parse(secret.reveal()) as typeof tokens;
    } catch {
      tokens = {};
    }
  return {
    subject: metadata.subject,
    issuer: metadata.issuer,
    ...(metadata.displayName ? { displayName: metadata.displayName } : {}),
    ...(metadata.email ? { email: metadata.email } : {}),
    ...(tokens.accessToken
      ? { accessToken: new SecretValue(tokens.accessToken) }
      : {}),
    ...(tokens.idToken ? { idToken: new SecretValue(tokens.idToken) } : {}),
    ...(tokens.refreshToken
      ? { refreshToken: new SecretValue(tokens.refreshToken) }
      : {}),
    ...(metadata.expiresAt ? { expiresAt: new Date(metadata.expiresAt) } : {}),
    claims: metadata.claims,
  };
}
