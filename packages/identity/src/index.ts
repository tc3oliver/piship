import {
  type IdentitySession,
  PiShipError,
  SecretValue,
} from "@piship/contracts";

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
    claims: session.claims ?? {},
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
