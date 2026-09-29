// Validation of the Keycloak access token that PiShip sends to the broker.
//
// Order matters and is the point of this file: the header is read only to
// pick the algorithm and the key; the signature is verified with a key from
// the realm's JWKS; only then is the payload parsed and its claims checked.
// Nothing from an unverified payload is used for anything.
//
// Only RS256 is accepted. `alg: none`, the HS* family (the classic confusion
// where an RSA public key is used as an HMAC secret) and every other
// algorithm are refused before a key is looked up, and the key is always an
// RSA public KeyObject, which node:crypto cannot use as an HMAC secret.
import { createPublicKey, verify as verifySignature } from "node:crypto";

/** Why a token was refused. Non-secret; safe to log. */
export class TokenError extends Error {
  /** @param {string} reason */
  constructor(reason) {
    super(`access token refused: ${reason}`);
    this.name = "TokenError";
    this.reason = reason;
  }
}

/** The JWKS could not be fetched and no usable key is cached: a server-side failure, not the client's. */
export class JwksUnavailableError extends Error {
  constructor() {
    super("identity provider keys unavailable");
    this.name = "JwksUnavailableError";
  }
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_LENGTH = 8192;
const MIN_RSA_BITS = 2048;

function decodeJson(segment, reason) {
  try {
    const value = JSON.parse(
      Buffer.from(segment, "base64url").toString("utf8"),
    );
    if (value && typeof value === "object" && !Array.isArray(value))
      return value;
  } catch {
    // fall through
  }
  throw new TokenError(reason);
}

/**
 * @param {object} options
 * @param {string} options.issuer exact `iss`
 * @param {string} options.audience required member of `aud`
 * @param {string} options.authorizedParty exact `azp` (the PiShip client)
 * @param {string} options.jwksUrl the realm's certs endpoint
 * @param {typeof fetch} [options.fetch]
 * @param {() => number} [options.now] milliseconds
 * @param {number} [options.clockToleranceSeconds] for exp, nbf and iat
 * @param {number} [options.jwksMaxAgeMs] refetch the JWKS after this age
 * @param {number} [options.jwksMinRefreshMs] at most one refetch for an unknown `kid` per interval
 * @param {number} [options.jwksMaxStaleMs] while refetches fail, trust the cached keys at most this long after the last successful fetch
 * @param {number} [options.timeoutMs] JWKS request timeout
 */
export function createTokenVerifier({
  issuer,
  audience,
  authorizedParty,
  jwksUrl,
  fetch = globalThis.fetch,
  now = Date.now,
  clockToleranceSeconds = 30,
  jwksMaxAgeMs = 10 * 60_000,
  jwksMinRefreshMs = 30_000,
  jwksMaxStaleMs = 60 * 60_000,
  timeoutMs = 5_000,
}) {
  /** @type {Map<string, import("node:crypto").KeyObject>} */
  let keys = new Map();
  let fetchedAt = Number.NEGATIVE_INFINITY;
  // Start of the last JWKS request, successful or not: it bounds how often
  // the identity provider is asked, including while it is failing.
  let attemptedAt = Number.NEGATIVE_INFINITY;
  /** @type {Promise<void> | null} */
  let pending = null;

  async function loadJwks() {
    attemptedAt = now();
    const response = await fetch(jwksUrl, {
      headers: { accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error(`JWKS answered ${response.status}`);
    const body = await response.json();
    if (!body || !Array.isArray(body.keys)) throw new Error("JWKS has no keys");
    const next = new Map();
    for (const jwk of body.keys) {
      if (jwk?.kty !== "RSA" || typeof jwk.kid !== "string") continue;
      if (jwk.use !== undefined && jwk.use !== "sig") continue;
      if (jwk.alg !== undefined && jwk.alg !== "RS256") continue;
      try {
        // Only the public members are passed, so a JWKS that wrongly
        // publishes a private key still yields a public KeyObject.
        const key = createPublicKey({
          key: { kty: "RSA", n: jwk.n, e: jwk.e },
          format: "jwk",
        });
        if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS)
          continue;
        next.set(jwk.kid, key);
      } catch {
        // an unusable key is skipped, not fatal
      }
    }
    keys = next;
    fetchedAt = now();
  }

  /** One JWKS request at a time; concurrent callers share it. */
  function refresh() {
    pending ??= loadJwks().finally(() => {
      pending = null;
    });
    return pending;
  }

  async function keyFor(kid) {
    // A request already in flight answers for this caller too.
    if (pending) await pending.catch(() => {});
    const mayAsk = () => now() - attemptedAt >= jwksMinRefreshMs;
    if (now() - fetchedAt > jwksMaxAgeMs && mayAsk()) {
      try {
        await refresh();
      } catch {
        // A stale cache still verifies known keys, for a while; with no
        // cache the provider is unavailable.
      }
    }
    // A key the realm withdrew (rotated out after a compromise) must stop
    // verifying even while the realm cannot be reached: past
    // jwksMaxStaleMs since the last successful fetch, the cache is dropped.
    if (now() - fetchedAt > jwksMaxStaleMs) keys = new Map();
    if (keys.size === 0) throw new JwksUnavailableError();
    let key = keys.get(kid);
    // An unknown kid may be a rotated signing key: refetch, but at most
    // once per jwksMinRefreshMs, so random kids cannot drive a request
    // to the identity provider per call.
    if (!key && mayAsk()) {
      try {
        await refresh();
      } catch {
        if (keys.size === 0) throw new JwksUnavailableError();
      }
      key = keys.get(kid);
    }
    if (!key) throw new TokenError("unknown-kid");
    return key;
  }

  /**
   * Verify a compact JWS access token and return its verified claims.
   * @param {string} token
   * @returns {Promise<Record<string, unknown>>}
   */
  async function verify(token) {
    if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH)
      throw new TokenError("malformed");
    const parts = token.split(".");
    if (parts.length !== 3) throw new TokenError("malformed");
    const [headerPart, payloadPart, signaturePart] = parts;
    if (!SEGMENT.test(headerPart) || !SEGMENT.test(payloadPart))
      throw new TokenError("malformed");
    const header = decodeJson(headerPart, "malformed");
    // Checked before the signature's shape, so `alg: none` (whose signature
    // is empty) is always reported as the algorithm it is.
    if (header.alg !== "RS256") throw new TokenError("algorithm");
    if (!SEGMENT.test(signaturePart)) throw new TokenError("malformed");
    if (header.crit !== undefined) throw new TokenError("malformed");
    if (typeof header.kid !== "string" || header.kid.length === 0)
      throw new TokenError("unknown-kid");

    const key = await keyFor(header.kid);
    const valid = verifySignature(
      "sha256",
      Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
      key,
      Buffer.from(signaturePart, "base64url"),
    );
    if (!valid) throw new TokenError("signature");

    // Verified from here on.
    const claims = decodeJson(payloadPart, "malformed");
    const nowSeconds = now() / 1000;
    if (claims.iss !== issuer) throw new TokenError("issuer");
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(audience)) throw new TokenError("audience");
    if (typeof claims.exp !== "number") throw new TokenError("expired");
    if (nowSeconds >= claims.exp + clockToleranceSeconds)
      throw new TokenError("expired");
    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== "number") throw new TokenError("not-yet-valid");
      if (nowSeconds + clockToleranceSeconds < claims.nbf)
        throw new TokenError("not-yet-valid");
    }
    if (claims.iat !== undefined) {
      if (typeof claims.iat !== "number") throw new TokenError("not-yet-valid");
      if (claims.iat > nowSeconds + clockToleranceSeconds)
        throw new TokenError("not-yet-valid");
    }
    if (claims.azp !== authorizedParty)
      throw new TokenError("authorized-party");
    // Keycloak marks access tokens `typ: Bearer` (ID tokens are `ID`).
    if (claims.typ !== undefined && claims.typ !== "Bearer")
      throw new TokenError("token-type");
    if (
      typeof claims.sub !== "string" ||
      claims.sub.length === 0 ||
      claims.sub.length > 255
    )
      throw new TokenError("subject");
    return claims;
  }

  return { verify };
}
