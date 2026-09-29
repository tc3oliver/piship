// The allowlist lives in @piship/contracts, where adapter authors reach it
// through the SDK; this package keeps exporting it.
import { RETAINED_CLAIMS } from "@piship/contracts";

export { RETAINED_CLAIMS };

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
