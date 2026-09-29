import {
  type IdentityProvider,
  type IdentitySession,
  PiShipError,
  principalKey,
  SecretValue,
  samePrincipal,
} from "@piship/contracts";

import { retainClaims } from "./claims.js";

export { RETAINED_CLAIMS, retainClaims } from "./claims.js";
export { startLoopbackReceiver, type LoopbackReceiver } from "./loopback.js";
export { OidcPkceIdentityProvider, type OidcIdentityOptions } from "./oidc.js";

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
): IdentitySession {
  if (!samePrincipal(principalKey(refreshed), principalKey(previous)))
    throw new PiShipError(
      "IDENTITY_INVALID",
      "Refreshed identity does not match the signed-in subject",
      { component: "identity", userAction: "Run login again" },
    );
  return refreshed;
}

/**
 * An identity adapter that obtains its session without a person: the
 * identity of a CI job, a scheduled automation, or a managed worker.
 * `login()` must never call `openUrl`; PiShip obtains a session from it at
 * every activation, holds the session in memory only, and never stores it.
 */
export interface WorkloadIdentityProvider extends IdentityProvider {
  readonly interactive: false;
}

/** Whether an identity provider declared itself non-interactive (a workload identity). */
export function isWorkloadIdentityProvider(
  provider: IdentityProvider,
): provider is WorkloadIdentityProvider {
  return (provider as { interactive?: unknown }).interactive === false;
}

/**
 * Wrap an adapter so every session it returns is normalized and a refresh
 * keeps the signed-in principal. An `interactive` declaration other than a
 * boolean is refused, so a typo never changes how a session is obtained.
 */
export function normalizedIdentityProvider(
  provider: IdentityProvider,
): IdentityProvider {
  const interactive = (provider as { interactive?: unknown }).interactive;
  if (interactive !== undefined && typeof interactive !== "boolean")
    throw new PiShipError(
      "CONFIG_INVALID",
      "The identity adapter's interactive declaration must be true or false",
      { component: "identity" },
    );
  const refresh = provider.refresh?.bind(provider);
  const logout = provider.logout?.bind(provider);
  return {
    kind: provider.kind,
    ...(interactive === false ? { interactive } : {}),
    login: async (ctx) => normalizeIdentitySession(await provider.login(ctx)),
    ...(refresh
      ? {
          refresh: async (session: IdentitySession) =>
            assertSamePrincipal(
              normalizeIdentitySession(await refresh(session)),
              session,
            ),
        }
      : {}),
    ...(logout ? { logout } : {}),
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
