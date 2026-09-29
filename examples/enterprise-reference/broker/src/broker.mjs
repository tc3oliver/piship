// The reference credential broker: the http-broker contract of
// docs/enterprise-integration.md in front of LiteLLM.
//
//   POST /v1/credential   Bearer <Keycloak access token>  -> LiteLLM virtual key
//   POST /v1/revoke       Bearer <that virtual key>       -> key deleted
//   GET  /health
//
// Every answer is JSON with `cache-control: no-store`. Error bodies are a
// fixed code, never an upstream message. Nothing secret is logged: see log.mjs.
import { createHash, randomBytes } from "node:crypto";
import { JwksUnavailableError, TokenError } from "./token.mjs";
import { ISSUER_MARK, UpstreamError } from "./litellm.mjs";

/**
 * Model entitlement by Keycloak group. A user gets the union over their
 * groups; a group not listed here grants nothing. The README shows this
 * table; keep the two in step.
 */
export const GROUP_MODELS = Object.freeze({
  engineering: Object.freeze(["acme/coder", "acme/general"]),
  support: Object.freeze(["acme/coder"]),
});

/** Models for a verified `groups` claim, in a stable order; empty when none. */
export function modelsForGroups(groups) {
  const models = new Set();
  // Own properties only: a group named `constructor` or `__proto__` grants nothing.
  for (const group of groups)
    if (Object.hasOwn(GROUP_MODELS, group))
      for (const model of GROUP_MODELS[group]) models.add(model);
  return [...models].sort();
}

/**
 * The LiteLLM `user_id` of a principal. Deterministic in (iss, sub) and
 * nothing else, so every key one employee is ever issued, including every
 * rotation, carries the same user and counts against one user budget. It is
 * a hash so that any issuer and subject fit LiteLLM's field; the user's
 * LiteLLM metadata keeps `iss` and `sub` for an operator to read.
 */
export function principalUserId(issuer, subject) {
  const digest = createHash("sha256")
    .update(JSON.stringify([issuer, subject]))
    .digest("hex");
  return `oidc-${digest.slice(0, 40)}`;
}

/**
 * A new `credential_id`, also used as the LiteLLM `key_alias`. It uses only
 * characters both PiShip (`[A-Za-z0-9._:-]`, at most 256) and LiteLLM
 * accept, and is random, so it reveals nothing about the key.
 */
export function newCredentialId() {
  return `pb-${randomBytes(12).toString("hex")}`;
}

export const CREDENTIAL_ID_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[\x21-\x7e]{1,255}$/;
const VISIBLE_ASCII = /^[\x21-\x7e]+$/;
const MAX_BODY_BYTES = 4096;

/**
 * Idempotency records, in memory: a restart forgets them (the reference
 * accepts that; a production broker keeps them in a shared store). A record
 * is keyed by the Idempotency-Key and holds a fingerprint of the input (the
 * principal and the request body, never the token), so a key sent with other
 * input or by another principal never returns the stored credential.
 */
export function createIdempotencyStore({
  now = Date.now,
  pendingTtlMs = 120_000,
  maxEntries = 10_000,
} = {}) {
  /** @type {Map<string, { fingerprint: string, state: "pending" | "done", response?: object, expiresAt: number }>} */
  const entries = new Map();
  const sweep = () => {
    const at = now();
    for (const [key, entry] of entries)
      if (entry.expiresAt <= at) entries.delete(key);
  };
  return {
    /**
     * Look the key up and, if it is new, reserve it, in one synchronous step.
     * `admit` decides whether new work may start (the rate limit); when it
     * returns a refusal the key is not reserved.
     */
    begin(key, fingerprint, admit) {
      sweep();
      const entry = entries.get(key);
      if (entry) {
        if (entry.fingerprint !== fingerprint) return { kind: "conflict" };
        if (entry.state === "pending") return { kind: "in-flight" };
        return { kind: "replay", response: entry.response };
      }
      const refusal = admit();
      if (refusal) return refusal;
      if (entries.size >= maxEntries) {
        // Evict the oldest finished records; pending ones stay.
        for (const [oldKey, old] of entries) {
          if (entries.size < maxEntries) break;
          if (old.state === "done") entries.delete(oldKey);
        }
        if (entries.size >= maxEntries) return { kind: "full" };
      }
      entries.set(key, {
        fingerprint,
        state: "pending",
        expiresAt: now() + pendingTtlMs,
      });
      return { kind: "new" };
    },
    /** Keep the answer until the credential it carries expires. */
    complete(key, response, expiresAtMs) {
      const entry = entries.get(key);
      if (!entry) return;
      entry.state = "done";
      entry.response = response;
      entry.expiresAt = expiresAtMs;
    },
    /** Forget a key whose issuing failed, so it can be sent again. */
    abandon(key) {
      entries.delete(key);
    },
  };
}

/** Acquires per principal per minute, fixed window. */
export function createRateLimiter({ limitPerMinute, now = Date.now }) {
  /** @type {Map<string, { windowStart: number, count: number }>} */
  const windows = new Map();
  return {
    /** @returns {number} 0 when allowed, else seconds until the window resets */
    take(userId) {
      const at = now();
      for (const [id, window] of windows)
        if (at - window.windowStart >= 60_000) windows.delete(id);
      const window = windows.get(userId) ?? { windowStart: at, count: 0 };
      if (window.count >= limitPerMinute)
        return Math.max(
          1,
          Math.ceil((window.windowStart + 60_000 - at) / 1000),
        );
      window.count += 1;
      windows.set(userId, window);
      return 0;
    },
  };
}

function send(res, status, body, headers = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(text),
    ...headers,
  });
  res.end(text);
}

const failure = (status, error, headers) => ({
  status,
  body: { error },
  headers,
});

/** Read at most MAX_BODY_BYTES; null when larger. */
async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function bearer(req) {
  const header = req.headers.authorization;
  if (typeof header !== "string") return null;
  const match = /^Bearer ([\x21-\x7e]+)$/i.exec(header);
  return match ? match[1] : null;
}

function parseJsonObject(text) {
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}

/** JSON with sorted keys, so the fingerprint ignores key order and spacing. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

/**
 * LiteLLM reports expiry as ISO 8601 with `Z` or `+00:00`; anything without
 * an explicit zone is refused rather than guessed.
 */
function parseExpiry(text) {
  if (typeof text !== "string" || !/(Z|[+-]\d{2}:\d{2})$/.test(text))
    return Number.NaN;
  return Date.parse(text);
}

/**
 * @param {object} config see server.mjs for the environment it comes from
 * @param {object} deps
 * @param {{ verify(token: string): Promise<Record<string, unknown>> }} deps.verifier
 * @param {ReturnType<import("./litellm.mjs").createLiteLLMAdmin>} deps.litellm
 * @param {(event: string, fields?: object) => void} deps.log
 * @param {() => number} [deps.now]
 */
export function createBroker(
  config,
  { verifier, litellm, log, now = Date.now },
) {
  const idempotency = createIdempotencyStore({ now });
  const limiter = createRateLimiter({
    limitPerMinute: config.acquireLimitPerMinute,
    now,
  });

  async function acquire(req) {
    const token = bearer(req);
    if (!token)
      return failure(401, "invalid_token", { "www-authenticate": "Bearer" });
    let claims;
    try {
      claims = await verifier.verify(token);
    } catch (error) {
      if (error instanceof JwksUnavailableError)
        return failure(503, "identity_provider_unavailable", {
          "retry-after": "5",
        });
      if (error instanceof TokenError)
        return {
          ...failure(401, "invalid_token", {
            "www-authenticate": 'Bearer error="invalid_token"',
          }),
          reason: error.reason,
        };
      throw error;
    }
    const userId = principalUserId(claims.iss, claims.sub);

    const contentType = String(req.headers["content-type"] ?? "");
    if (!/^application\/json\b/i.test(contentType))
      return { ...failure(415, "unsupported_media_type"), userId };
    const text = await readBody(req);
    if (text === null) return { ...failure(413, "body_too_large"), userId };
    const body = parseJsonObject(text);
    if (body?.purpose !== "inference" || typeof body.distribution !== "string")
      return { ...failure(400, "invalid_request"), userId };
    if (body.distribution !== config.distribution)
      return {
        ...failure(403, "distribution_denied"),
        userId,
        reason: "distribution",
      };

    const groups = claims.groups;
    if (
      !Array.isArray(groups) ||
      !groups.every((group) => typeof group === "string")
    )
      return { ...failure(403, "not_entitled"), userId, reason: "no-groups" };
    const models = modelsForGroups(groups);
    if (models.length === 0)
      return {
        ...failure(403, "not_entitled"),
        userId,
        reason: "no-entitled-group",
      };

    const key = req.headers["idempotency-key"];
    if (
      key !== undefined &&
      (typeof key !== "string" || !IDEMPOTENCY_KEY_PATTERN.test(key))
    )
      return { ...failure(400, "invalid_idempotency_key"), userId };

    // Rate limiting comes after the idempotency lookup, so that a retry of a
    // finished acquire gets its stored answer rather than a 429.
    const admit = () => {
      const wait = limiter.take(userId);
      return wait ? { kind: "rate-limited", wait } : null;
    };
    let reserved = false;
    if (typeof key === "string") {
      const fingerprint = createHash("sha256")
        .update(canonical([claims.iss, claims.sub, body]))
        .digest("hex");
      const outcome = idempotency.begin(key, fingerprint, admit);
      if (outcome.kind === "replay")
        return {
          status: 200,
          body: outcome.response,
          userId,
          idempotency: "replay",
          credentialId: outcome.response.credential_id,
        };
      if (outcome.kind === "conflict")
        return {
          ...failure(422, "idempotency_key_reused"),
          userId,
          idempotency: "conflict",
        };
      if (outcome.kind === "in-flight")
        return {
          ...failure(503, "request_in_progress", { "retry-after": "1" }),
          userId,
          idempotency: "in-flight",
        };
      if (outcome.kind === "full")
        return { ...failure(503, "busy", { "retry-after": "5" }), userId };
      if (outcome.kind === "rate-limited")
        return {
          ...failure(429, "rate_limited", {
            "retry-after": String(outcome.wait),
          }),
          userId,
        };
      reserved = true;
    } else {
      const refusal = admit();
      if (refusal)
        return {
          ...failure(429, "rate_limited", {
            "retry-after": String(refusal.wait),
          }),
          userId,
        };
    }

    const credentialId = newCredentialId();
    try {
      const result = await issue({ claims, userId, models, credentialId });
      if (reserved) idempotency.complete(key, result.body, result.expiresAtMs);
      await retireOldKeys(userId, credentialId);
      return {
        status: 200,
        body: result.body,
        userId,
        credentialId,
        models,
        idempotency: reserved ? "new" : "none",
      };
    } catch (error) {
      if (reserved) idempotency.abandon(key);
      if (!(error instanceof UpstreamError)) throw error;
      if (error.unknownOutcome) {
        // A key may exist that is not being returned: /key/generate's answer
        // was lost, or its expiry was refused. Delete it by its alias; if
        // that is confirmed, nothing was issued.
        try {
          await litellm.deleteKeys({ aliases: [credentialId] });
          return {
            ...failure(503, "gateway_unavailable", { "retry-after": "5" }),
            userId,
            credentialId,
            reason: error.operation,
          };
        } catch {
          return {
            ...failure(502, "gateway_outcome_unknown"),
            userId,
            credentialId,
            reason: error.operation,
          };
        }
      }
      return {
        ...failure(503, "gateway_unavailable", { "retry-after": "5" }),
        userId,
        reason: error.operation,
        upstreamStatus: error.status,
      };
    }
  }

  async function issue({ claims, userId, models, credentialId }) {
    await litellm.ensureUser({
      userId,
      maxBudget: config.userMaxBudget,
      budgetDuration: config.userBudgetDuration,
      tpmLimit: config.userTpmLimit,
      rpmLimit: config.userRpmLimit,
      metadata: { iss: claims.iss, sub: claims.sub },
    });
    const issuedAt = now();
    const { key, expires } = await litellm.generateKey({
      userId,
      models,
      durationSeconds: config.keyTtlSeconds,
      alias: credentialId,
      metadata: { distribution: config.distribution },
      maxParallelRequests: config.keyMaxParallelRequests,
    });
    // The key must expire, and no later than asked. A key LiteLLM would keep
    // longer is not returned: the caller deletes it by its alias, as it does
    // any key whose issue did not complete.
    const expiresAtMs = parseExpiry(expires);
    if (
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= issuedAt ||
      expiresAtMs > issuedAt + (config.keyTtlSeconds + 60) * 1000
    )
      throw new UpstreamError("key-expiry", {
        status: 200,
        unknownOutcome: true,
      });
    return {
      expiresAtMs,
      body: {
        credential_type: "api_key",
        credential: key,
        credential_id: credentialId,
        expires_at: new Date(expiresAtMs).toISOString(),
        models,
        base_url: config.gatewayBaseUrl,
        subject: claims.sub,
      },
    };
  }

  /**
   * Rotation is "generate new, then delete old" (LiteLLM's regenerate is
   * Enterprise-only). After issuing, keep the newest `maxKeysPerUser` keys
   * this broker issued for the user and delete the rest; a failure here only
   * logs, since every key also expires.
   */
  async function retireOldKeys(userId, keepId) {
    try {
      const mine = (await litellm.listUserKeys(userId)).filter(
        (entry) =>
          entry.metadata?.issued_by === ISSUER_MARK &&
          entry.metadata?.distribution === config.distribution &&
          typeof entry.key_alias === "string",
      );
      const retire = mine
        .slice(config.maxKeysPerUser)
        .map((entry) => entry.key_alias)
        .filter((alias) => alias !== keepId);
      if (retire.length === 0) return;
      await litellm.deleteKeys({ aliases: retire });
      log("credential.retired", { user_id: userId, deleted: retire.length });
    } catch (error) {
      log("credential.retire_failed", {
        user_id: userId,
        reason: error instanceof UpstreamError ? error.operation : "error",
      });
    }
  }

  async function revoke(req) {
    const credential = bearer(req);
    if (
      !credential ||
      credential.length < 8 ||
      credential.length > 512 ||
      !VISIBLE_ASCII.test(credential)
    )
      return failure(401, "invalid_credential", {
        "www-authenticate": "Bearer",
      });
    const contentType = String(req.headers["content-type"] ?? "");
    if (!/^application\/json\b/i.test(contentType))
      return failure(415, "unsupported_media_type");
    const text = await readBody(req);
    if (text === null) return failure(413, "body_too_large");
    const body = parseJsonObject(text);
    if (
      !body ||
      typeof body.distribution !== "string" ||
      (body.credential_id !== null && typeof body.credential_id !== "string")
    )
      return failure(400, "invalid_request");
    if (body.distribution !== config.distribution)
      return { ...failure(403, "distribution_denied"), reason: "distribution" };

    try {
      // Holding the key is the proof: LiteLLM describes the key only to its
      // holder. A refusal there does not mean the key is gone (LiteLLM also
      // refuses an expired, over-budget or blocked key that still exists),
      // so it is confirmed under the master key by the key's hash; only a
      // key LiteLLM does not have at all is answered 404 without a delete.
      const info =
        (await litellm.keyInfoAsHolder(credential)) ??
        (await litellm.keyInfoByHash(credential));
      if (!info)
        return { ...failure(404, "not_found"), reason: "unknown-credential" };
      const credentialId =
        typeof info.key_alias === "string" ? info.key_alias : undefined;
      const userId =
        typeof info.user_id === "string" ? info.user_id : undefined;
      // Only keys this broker issued are deleted through it.
      if (
        info.metadata?.issued_by !== ISSUER_MARK ||
        info.metadata?.distribution !== config.distribution
      )
        return {
          ...failure(403, "not_a_broker_credential"),
          userId,
          reason: "foreign-key",
        };
      const deleted = await litellm.deleteKeys({ keys: [credential] });
      if (!deleted)
        return {
          ...failure(404, "not_found"),
          userId,
          credentialId,
          reason: "already-deleted",
        };
      return {
        status: 200,
        body: { revoked: true, credential_id: credentialId ?? null },
        userId,
        credentialId,
        // The id the client sent is informational: the key presented is what
        // is revoked. A mismatch is recorded, not refused.
        reason:
          body.credential_id !== null && body.credential_id !== credentialId
            ? "credential-id-mismatch"
            : undefined,
      };
    } catch (error) {
      if (!(error instanceof UpstreamError)) throw error;
      return {
        ...failure(503, "gateway_unavailable", { "retry-after": "5" }),
        reason: error.operation,
        upstreamStatus: error.status,
      };
    }
  }

  /** The node:http request listener. */
  return async function handle(req, res) {
    const started = now();
    const path = (req.url ?? "").split("?")[0];
    let route = "unknown";
    let result;
    try {
      if (path === "/health" && req.method === "GET") {
        return send(res, 200, { status: "ok" });
      }
      if (path === "/v1/credential") {
        route = "acquire";
        result =
          req.method === "POST"
            ? await acquire(req)
            : failure(405, "method_not_allowed", { allow: "POST" });
      } else if (path === "/v1/revoke") {
        route = "revoke";
        result =
          req.method === "POST"
            ? await revoke(req)
            : failure(405, "method_not_allowed", { allow: "POST" });
      } else {
        result = failure(404, "not_found");
      }
    } catch {
      result = failure(500, "internal_error");
    }
    send(res, result.status, result.body, result.headers);
    log(
      route === "revoke"
        ? "credential.revoke"
        : route === "acquire"
          ? "credential.acquire"
          : "request",
      {
        route,
        status: result.status,
        reason: result.reason,
        user_id: result.userId,
        credential_id: result.credentialId,
        models: result.models,
        idempotency: result.idempotency,
        upstream_status: result.upstreamStatus,
        duration_ms: now() - started,
      },
    );
  };
}
