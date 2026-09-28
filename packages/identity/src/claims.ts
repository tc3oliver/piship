/**
 * The only ID-token claims PiShip keeps in session state, which is written to
 * the plaintext `identity/session.json`: identifiers, validity times, and
 * display fields. Anything else an IdP or adapter returns is dropped.
 */
export const RETAINED_CLAIMS: readonly string[] = [
  "sub",
  "iss",
  "aud",
  "azp",
  "exp",
  "iat",
  "auth_time",
  "name",
  "preferred_username",
  "email",
  "email_verified",
  "groups",
];

function claimValue(value: unknown): boolean {
  if (["string", "number", "boolean"].includes(typeof value)) return true;
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

/** Keep allowlisted claims with scalar or string-array values. */
export function retainClaims(
  claims: Readonly<Record<string, unknown>> | undefined | null,
): Record<string, unknown> {
  const retained: Record<string, unknown> = {};
  if (!claims || typeof claims !== "object") return retained;
  for (const name of RETAINED_CLAIMS)
    if (Object.hasOwn(claims, name) && claimValue(claims[name]))
      retained[name] = claims[name];
  return retained;
}
