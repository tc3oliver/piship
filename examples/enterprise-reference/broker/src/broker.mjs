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
import { isIP } from "node:net";
import { ISSUER_MARK, UpstreamError } from "./litellm.mjs";
import { JwksUnavailableError, TokenError } from "./token.mjs";

/**
 * Model entitlement by Keycloak group, keyed by the group's full path. A
 * group name is unique only among its siblings (`/engineering` and
 * `/contractors/engineering` are both `engineering`), so the key must be
 * something unique in the realm: the realm's groups mapper sends full paths.
 * A user gets the union over their groups; a group not listed here grants
 * nothing. The README shows this table; keep the two in step.
 */
export const GROUP_MODELS = Object.freeze({
  "/engineering": Object.freeze(["acme/coder", "acme/general"]),
  "/support": Object.freeze(["acme/coder"]),
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
 * is scoped to the principal: it is keyed by the principal's user id and the
 * Idempotency-Key together, so another principal's use of the same key is a
 * different record and can neither read nor block this one. It holds a
 * fingerprint of the input (the principal and the request body, never the
 * token), so the same key sent by the same principal with another body
 * never returns the stored credential.
 *
 * A principal keeps at most `maxPerPrincipal` records: a new one first
 * drops that principal's oldest finished record, so one busy user never
 * evicts anyone else's. Only past `maxEntries` in all are other principals'
 * oldest finished records dropped.
 *
 * A record in progress has no time limit: it stays until the request that
 * reserved it completes or abandons it, however long that request waits
 * (every LiteLLM call it makes has a timeout, so it ends). Each reservation
 * carries a random token, and complete and abandon act only on the record
 * their own reservation made, never on a later one for the same key.
 */
export function createIdempotencyStore({
  now = Date.now,
  maxEntries = 10_000,
  maxPerPrincipal = 6,
} = {}) {
  /** @type {Map<string, { principal: string, fingerprint: string, token: string, state: "pending" | "done", response?: object, expiresAt: number }>} */
  const entries = new Map();
  /** Each principal's record ids, oldest first. @type {Map<string, Set<string>>} */
  const byPrincipal = new Map();
  const recordId = (principal, key) => `${principal}\n${key}`;
  const remove = (id) => {
    const entry = entries.get(id);
    if (!entry) return;
    entries.delete(id);
    const own = byPrincipal.get(entry.principal);
    own?.delete(id);
    if (own?.size === 0) byPrincipal.delete(entry.principal);
  };
  /** Drop the oldest finished record among `ids`; false when all are pending. */
  const evictOldestDone = (ids) => {
    for (const id of ids)
      if (entries.get(id)?.state === "done") {
        remove(id);
        return true;
      }
    return false;
  };
  const sweep = () => {
    const at = now();
    for (const [id, entry] of entries) if (entry.expiresAt <= at) remove(id);
  };
  return {
    /**
     * Look the key up and, if it is new, reserve it, in one synchronous step.
     * `admit` decides whether new work may start (the rate limit); when it
     * returns a refusal the key is not reserved.
     */
    begin(principal, key, fingerprint, admit) {
      sweep();
      const id = recordId(principal, key);
      const entry = entries.get(id);
      if (entry) {
        if (entry.fingerprint !== fingerprint) return { kind: "conflict" };
        if (entry.state === "pending") return { kind: "in-flight" };
        return { kind: "replay", response: entry.response };
      }
      const refusal = admit();
      if (refusal) return refusal;
      const own = byPrincipal.get(principal) ?? new Set();
      if (own.size >= maxPerPrincipal && !evictOldestDone(own))
        return { kind: "full" };
      if (entries.size >= maxEntries && !evictOldestDone(entries.keys()))
        return { kind: "full" };
      const token = randomBytes(16).toString("hex");
      entries.set(id, {
        principal,
        fingerprint,
        token,
        state: "pending",
        expiresAt: Number.POSITIVE_INFINITY,
      });
      own.add(id);
      byPrincipal.set(principal, own);
      return { kind: "new", token };
    },
    /** Keep the answer until the credential it carries expires. */
    complete(principal, key, token, response, expiresAtMs) {
      const entry = entries.get(recordId(principal, key));
      if (entry?.token !== token) return;
      entry.state = "done";
      entry.response = response;
      entry.expiresAt = expiresAtMs;
    },
    /**
     * Forget a finished record whose stored answer is no longer valid (its
     * credential was revoked, deleted or refused, or the principal's
     * entitlement changed), so the key issues again. Only the record that
     * still holds `response` is dropped: a newer record for the key stays.
     */
    discard(principal, key, response) {
      const id = recordId(principal, key);
      const entry = entries.get(id);
      if (entry?.state === "done" && entry.response === response) remove(id);
    },
    /** Forget a key whose issuing failed, so it can be sent again. */
    abandon(principal, key, token) {
      const id = recordId(principal, key);
      if (entries.get(id)?.token === token) remove(id);
    },
    /** How many records are kept, in all or for one principal. */
    size(principal) {
      return principal === undefined
        ? entries.size
        : (byPrincipal.get(principal)?.size ?? 0);
    },
  };
}

/**
 * Requests per caller per minute, fixed window. At most `maxCallers` windows
 * are kept. Past that, a caller without a window is counted in one shared
 * overflow window limited to `overflowLimitPerMinute` (unlimited by
 * default) rather than refused: someone who fills the table with made-up
 * callers must not lock every other caller out. What protects the upstream
 * then is the caller's own concurrency cap.
 */
export function createRateLimiter({
  limitPerMinute,
  now = Date.now,
  maxCallers = 10_000,
  overflowLimitPerMinute = Number.POSITIVE_INFINITY,
}) {
  /** @type {Map<string, { windowStart: number, count: number }>} */
  const windows = new Map();
  const overflow = { windowStart: Number.NEGATIVE_INFINITY, count: 0 };
  const secondsLeft = (window, at) =>
    Math.max(1, Math.ceil((window.windowStart + 60_000 - at) / 1000));
  const count = (window, limit, at) => {
    if (window.count >= limit) return secondsLeft(window, at);
    window.count += 1;
    return 0;
  };
  return {
    /** @returns {number} 0 when allowed, else seconds until the window resets */
    take(caller) {
      const at = now();
      for (const [id, window] of windows)
        if (at - window.windowStart >= 60_000) windows.delete(id);
      let window = windows.get(caller);
      if (!window) {
        if (windows.size >= maxCallers) {
          if (at - overflow.windowStart >= 60_000) {
            overflow.windowStart = at;
            overflow.count = 0;
          }
          return count(overflow, overflowLimitPerMinute, at);
        }
        window = { windowStart: at, count: 0 };
        windows.set(caller, window);
      }
      return count(window, limitPerMinute, at);
    },
  };
}

/**
 * The rate-limit key of an address: an IPv4 address as it is, an IPv6
 * address by its /64 prefix, since one host or network usually holds a
 * whole /64 and could otherwise count as billions of callers.
 */
export function addressBucket(address) {
  if (isIP(address) !== 6) return address;
  let text = address.split("%")[0].toLowerCase();
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups =
    tail === undefined
      ? left
      : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return `${groups
    .slice(0, 4)
    .map((group) => Number.parseInt(group, 16).toString(16))
    .join(":")}::/64`;
}

/** Strip the IPv4-mapped IPv6 prefix, so one client has one address. */
function normalizeAddress(address) {
  return typeof address === "string" ? address.replace(/^::ffff:/i, "") : "";
}

/**
 * One `X-Forwarded-For` hop as a bare address: a port a proxy appended
 * (`192.0.2.1:443`, `[2001:db8::1]:443`) is dropped. Null when the hop is
 * not an IP address (`unknown`, an obfuscated identifier, garbage).
 */
function forwardedAddress(hop) {
  const text = hop.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(text);
  const withPort = /^(\d+\.\d+\.\d+\.\d+):\d+$/.exec(text);
  const address = normalizeAddress(
    bracketed ? bracketed[1] : withPort ? withPort[1] : text,
  );
  return isIP(address) === 0 ? null : address;
}

/**
 * The address a request came from: the socket's peer, or, when that peer is
 * a configured trusted proxy, the right-most `X-Forwarded-For` entry that is
 * not itself a trusted proxy. The header is ignored from anyone else, since
 * a client can write any value into it. The walk stops at the first hop from
 * the right that is not an address: everything left of it may be the
 * client's own writing, so the peer counts instead.
 */
export function clientAddress(req, trustedProxies) {
  const peer = normalizeAddress(req.socket?.remoteAddress);
  if (!trustedProxies.has(peer)) return peer;
  const header = req.headers["x-forwarded-for"];
  const hops = (
    Array.isArray(header) ? header.join(",") : (header ?? "")
  ).split(",");
  for (let i = hops.length - 1; i >= 0; i--) {
    const address = forwardedAddress(hops[i]);
    if (address === null) return peer;
    if (!trustedProxies.has(address)) return address;
  }
  return peer;
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
  const idempotency = createIdempotencyStore({
    now,
    maxPerPrincipal: 2 * config.maxKeysPerUser,
  });
  const limiter = createRateLimiter({
    limitPerMinute: config.acquireLimitPerMinute,
    now,
  });
  const revokeLimiter = createRateLimiter({
    limitPerMinute: config.revokeLimitPerMinute,
    now,
  });
  const trustedProxies = new Set(config.trustedProxies.map(normalizeAddress));
  // Revokes waiting on LiteLLM, across all callers: each costs one or two
  // /key/info calls, so this caps what revoke can make LiteLLM do at once.
  let revokesInFlight = 0;

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
    let reservation;
    let staleReason;
    if (typeof key === "string") {
      const fingerprint = createHash("sha256")
        .update(canonical([claims.iss, claims.sub, body]))
        .digest("hex");
      let outcome = idempotency.begin(userId, key, fingerprint, admit);
      if (outcome.kind === "replay") {
        let stale;
        try {
          stale = await staleReplay(outcome.response, userId, models);
        } catch (error) {
          if (!(error instanceof UpstreamError)) throw error;
          // The key could not be confirmed: nothing is returned, and the
          // record stays for a retry.
          return {
            ...failure(503, "gateway_unavailable", { "retry-after": "5" }),
            userId,
            idempotency: "replay-unconfirmed",
            reason: error.operation,
            upstreamStatus: error.status,
          };
        }
        if (!stale)
          return {
            status: 200,
            body: outcome.response,
            userId,
            idempotency: "replay",
            credentialId: outcome.response.credential_id,
          };
        // The stored credential must not be handed out again. The record is
        // dropped and the key issues a new credential under the current
        // entitlement, as a new request (rate limited like one).
        staleReason = stale;
        idempotency.discard(userId, key, outcome.response);
        outcome = idempotency.begin(userId, key, fingerprint, admit);
        if (outcome.kind === "replay")
          // Another request already reissued for this key meanwhile.
          return {
            ...failure(503, "request_in_progress", { "retry-after": "1" }),
            userId,
            idempotency: "in-flight",
          };
      }
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
      reservation = outcome.token;
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
      // Issue and retire run one at a time per user, so two acquires of one
      // user cannot each count the keys before the other's new key exists.
      const result = await perUser(userId, async () => {
        const issued = await issue({ claims, userId, models, credentialId });
        if (reserved)
          idempotency.complete(
            userId,
            key,
            reservation,
            issued.body,
            issued.expiresAtMs,
          );
        await retireOldKeys(userId, credentialId);
        return issued;
      });
      return {
        status: 200,
        body: result.body,
        userId,
        credentialId,
        models,
        idempotency: reserved ? (staleReason ? "reissued" : "new") : "none",
        reason: staleReason,
      };
    } catch (error) {
      if (reserved) idempotency.abandon(userId, key, reservation);
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

  /**
   * Why a stored answer may no longer be replayed, or undefined when it may.
   * The caller's token has already been verified and its entitlement
   * recomputed, so a principal without a valid token, or who lost every
   * entitled group, never gets here. What is checked:
   *
   * - entitlement: the models the principal is entitled to now must be
   *   exactly those the stored credential carries; a changed entitlement
   *   issues a new credential rather than replaying the old one.
   * - liveness: LiteLLM must still describe the key to its holder, as this
   *   principal's key under the stored alias (and, when LiteLLM reports
   *   them, with those models). A key revoked through this broker, retired
   *   by rotation, deleted by an administrator, or refused as expired or
   *   blocked fails this.
   *
   * An UpstreamError (LiteLLM unreachable or answering 5xx) propagates: the
   * caller then returns nothing rather than an unconfirmed credential.
   * Residual: a key revoked between this check and the answer reaching the
   * client is returned, as it would be had it been revoked just after its
   * first issue; the gateway refuses it and PiShip renews.
   */
  async function staleReplay(response, userId, models) {
    const sameModels = (list) =>
      Array.isArray(list) &&
      list.length === models.length &&
      [...list].sort().every((model, i) => model === models[i]);
    if (!sameModels(response.models)) return "replay-entitlement-changed";
    const info = await litellm.keyInfoAsHolder(response.credential);
    if (!info) return "replay-credential-refused";
    if (
      info.key_alias !== response.credential_id ||
      info.user_id !== userId ||
      (info.models !== undefined && !sameModels(info.models))
    )
      return "replay-credential-changed";
    return undefined;
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
   * Run `task` after every earlier task of the same user has settled. In
   * process only: several broker instances need a shared lock.
   */
  const userQueues = new Map();
  function perUser(userId, task) {
    const run = (userQueues.get(userId) ?? Promise.resolve()).then(task);
    const settled = run.then(
      () => {},
      () => {},
    );
    userQueues.set(userId, settled);
    settled.then(() => {
      if (userQueues.get(userId) === settled) userQueues.delete(userId);
    });
    return run;
  }

  /**
   * Rotation is "generate new, then delete old" (LiteLLM's regenerate is
   * Enterprise-only). After issuing, keep the new key and the newest
   * `maxKeysPerUser - 1` other keys this broker issued for the user, and
   * delete the rest; a failure here only logs, since every key also
   * expires.
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
        .filter((entry) => entry.key_alias !== keepId)
        .slice(config.maxKeysPerUser - 1)
        .map((entry) => entry.key_alias);
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
    // Revoke is authenticated only by the key it revokes, so it is limited
    // by where it comes from, before anything else is looked at.
    const wait = revokeLimiter.take(
      addressBucket(clientAddress(req, trustedProxies)),
    );
    if (wait)
      return failure(429, "rate_limited", { "retry-after": String(wait) });
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

    if (revokesInFlight >= config.revokeMaxConcurrent)
      return {
        ...failure(503, "busy", { "retry-after": "1" }),
        reason: "revoke-concurrency",
      };
    revokesInFlight += 1;
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
      // Only keys this broker issued are deleted through it. Any other key is
      // answered exactly like an unknown one, so revoke cannot be used to
      // learn whether a string is a working LiteLLM key; the log keeps why.
      if (
        info.metadata?.issued_by !== ISSUER_MARK ||
        info.metadata?.distribution !== config.distribution
      )
        return { ...failure(404, "not_found"), userId, reason: "foreign-key" };
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
    } finally {
      revokesInFlight -= 1;
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
