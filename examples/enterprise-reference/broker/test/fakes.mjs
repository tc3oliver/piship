// Test doubles for the broker contract tests: a Keycloak that publishes a
// JWKS and mints RS256 access tokens, and a LiteLLM admin API with an
// in-memory user and key table. Every secret here is an obvious sentinel.
import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";

export const ISSUER = "http://127.0.0.1:18080/realms/piship-reference";
export const AUDIENCE = "piship-reference-broker";
export const CLIENT = "acmecode";
export const MASTER_KEY = "sk-master-SENTINEL-0000000000000000";
/** Every fake LiteLLM error body carries this, to prove the broker never passes one on. */
export const UPSTREAM_BODY_MARK = "SENTINEL-UPSTREAM-BODY";
const ISSUER_MARK = "piship-reference-broker";

async function listen(handler) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  return { server, url: `http://127.0.0.1:${port}` };
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : undefined;
}

function reply(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** A fake identity provider: JWKS endpoint plus a token minter. */
export async function startFakeKeycloak() {
  const pair = () => generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signing = { k1: pair(), k2: pair() };
  const state = { published: ["k1"], jwksFetches: 0, jwksStatus: 200 };
  const { server, url } = await listen((req, res) => {
    if (req.url !== "/realms/piship-reference/protocol/openid-connect/certs")
      return reply(res, 404, {});
    state.jwksFetches += 1;
    if (state.jwksStatus !== 200) return reply(res, state.jwksStatus, {});
    reply(res, 200, {
      keys: state.published.map((kid) => ({
        ...signing[kid].publicKey.export({ format: "jwk" }),
        kid,
        use: "sig",
        alg: "RS256",
      })),
    });
  });

  /**
   * Mint an access token. `claims` override the defaults; `options` choose
   * the signing key (`kid`, `privateKey`), the header, or a raw algorithm.
   */
  function mint(claims = {}, options = {}) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const payload = {
      iss: ISSUER,
      aud: [AUDIENCE, "account"],
      azp: CLIENT,
      sub: "0f1e2d3c-alice",
      typ: "Bearer",
      iat: nowSeconds,
      nbf: nowSeconds,
      exp: nowSeconds + 300,
      groups: ["/engineering"],
      preferred_username: "alice",
      ...claims,
    };
    for (const [name, value] of Object.entries(payload))
      if (value === undefined) delete payload[name];
    const kid = options.kid ?? "k1";
    const header = {
      alg: options.alg ?? "RS256",
      typ: "JWT",
      kid,
      ...options.header,
    };
    const input = `${b64(header)}.${b64(payload)}`;
    let signature;
    if (options.signature !== undefined) signature = options.signature;
    else if (/^(RS|PS)/.test(header.alg))
      signature = sign(
        "sha256",
        Buffer.from(input),
        options.privateKey ?? signing[kid]?.privateKey ?? signing.k1.privateKey,
      ).toString("base64url");
    else if (header.alg === "HS256")
      signature = createHmac("sha256", options.hmacSecret)
        .update(input)
        .digest("base64url");
    else signature = "";
    return `${input}.${signature}`;
  }

  return {
    url,
    jwksUrl: `${url}/realms/piship-reference/protocol/openid-connect/certs`,
    state,
    mint,
    /** The PEM of a published public key: the secret an HS256 confusion attack would use. */
    publicPem: (kid = "k1") =>
      signing[kid].publicKey.export({ format: "pem", type: "spki" }),
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  };
}

/** A fake LiteLLM with the admin endpoints the broker uses and a model list for key checks. */
export async function startFakeLiteLLM() {
  const users = new Map();
  const keys = new Map();
  const calls = [];
  const issued = [];
  // LiteLLM v1.103.0 still describes a deleted key to a master-key lookup.
  const deletedKeys = [];
  let clock = Date.parse("2026-01-01T00:00:00Z");
  const state = {
    /** path -> { status, count } answered instead of the real handler */
    faults: new Map(),
    /** Delay /key/generate by this many milliseconds. */
    generateDelayMs: 0,
    /** Create the key, then drop the connection without answering. */
    dropAfterGenerate: false,
    /** Answer /key/generate with this `expires` instead of a real one. */
    expiresOverride: undefined,
    /** Answer a holder's /key/info for a live key with this status. */
    holderKeyInfoStatus: undefined,
    /** Answer a master-key /key/info with this status. */
    adminKeyInfoStatus: undefined,
    /** /key/list returns at most this many keys per page. */
    maxPageSize: 100,
    /** Delay /key/info by this many milliseconds. */
    keyInfoDelayMs: 0,
  };
  const hash = (key) => createHash("sha256").update(key).digest("hex");
  const denied = (res, key) =>
    reply(res, 401, {
      error: {
        // Like LiteLLM, quote part of the key in the error.
        message: `Authentication Error, Invalid proxy server token passed. Received API Key = sk-...${String(key).slice(-4)} ${UPSTREAM_BODY_MARK}`,
        type: "token_not_found_in_db",
        code: "401",
      },
    });

  const { server, url } = await listen(async (req, res) => {
    const parsed = new URL(req.url, "http://fake");
    const path = parsed.pathname;
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    const body = await readJson(req);
    const auth =
      bearer === MASTER_KEY ? "master" : keys.has(bearer) ? "key" : "other";
    calls.push({
      method: req.method,
      path,
      auth,
      body,
      query: Object.fromEntries(parsed.searchParams),
    });

    const fault = state.faults.get(path);
    if (fault && fault.count > 0) {
      fault.count -= 1;
      if (fault.status === "drop") return req.socket.destroy();
      return reply(res, fault.status, {
        error: { message: `boom ${MASTER_KEY} ${UPSTREAM_BODY_MARK}` },
      });
    }

    if (path === "/v1/models" && req.method === "GET") {
      const key = keys.get(bearer);
      if (!key) return denied(res, bearer);
      return reply(res, 200, {
        object: "list",
        data: key.models.map((id) => ({ id, object: "model" })),
      });
    }
    if (path === "/key/info" && req.method === "GET") {
      if (state.keyInfoDelayMs)
        await new Promise((resolve) =>
          setTimeout(resolve, state.keyInfoDelayMs),
        );
      const describe = (key) =>
        reply(res, 200, {
          key: key.token,
          info: {
            key_alias: key.key_alias,
            user_id: key.user_id,
            metadata: key.metadata,
            models: key.models,
            expires: key.expires,
          },
        });
      if (auth === "master") {
        if (state.adminKeyInfoStatus !== undefined)
          return reply(res, state.adminKeyInfoStatus, {
            error: { message: `boom ${UPSTREAM_BODY_MARK}` },
          });
        // Like LiteLLM: `key` is a key, hashed here, or already its hash.
        const asked = parsed.searchParams.get("key") ?? "";
        const token = asked.startsWith("sk-") ? hash(asked) : asked;
        const key = [...keys.values(), ...deletedKeys].find(
          (entry) => entry.token === token,
        );
        if (!key)
          return reply(res, 404, {
            error: {
              message: `Key not found in database ${UPSTREAM_BODY_MARK}`,
              code: "404",
            },
          });
        return describe(key);
      }
      const key = keys.get(bearer);
      if (!key) return denied(res, bearer);
      // A key that exists but that LiteLLM refuses here: expired or
      // blocked (401 on v1.103.0), 400 or 403 on other releases.
      if (state.holderKeyInfoStatus !== undefined)
        return reply(res, state.holderKeyInfoStatus, {
          error: {
            message: `refused sk-...${bearer.slice(-4)} ${UPSTREAM_BODY_MARK}`,
          },
        });
      return describe(key);
    }
    if (auth !== "master") return denied(res, bearer);

    if (path === "/user/info" && req.method === "GET") {
      const user = users.get(parsed.searchParams.get("user_id"));
      if (!user)
        return reply(res, 404, {
          error: {
            message: `User not found ${UPSTREAM_BODY_MARK}`,
            code: "404",
          },
        });
      return reply(res, 200, { user_info: user, keys: [] });
    }
    if (path === "/user/new" && req.method === "POST") {
      if (users.has(body.user_id))
        return reply(res, 409, { error: { message: "exists", code: "409" } });
      users.set(body.user_id, { ...body, spend: 0 });
      return reply(res, 200, { ...body, key: "" });
    }
    if (path === "/key/generate" && req.method === "POST") {
      if ([...keys.values()].some((key) => key.key_alias === body.key_alias))
        return reply(res, 400, {
          error: { message: "alias exists", code: "400" },
        });
      if (state.generateDelayMs)
        await new Promise((resolve) =>
          setTimeout(resolve, state.generateDelayMs),
        );
      const key = `sk-issued-SENTINEL-${randomBytes(12).toString("hex")}`;
      clock += 1000;
      const seconds = Number(/^(\d+)s$/.exec(body.duration)?.[1]);
      const expires = new Date(Date.now() + seconds * 1000)
        .toISOString()
        .replace("Z", "123Z");
      const record = {
        token: hash(key),
        key_alias: body.key_alias,
        user_id: body.user_id,
        models: body.models,
        metadata: body.metadata,
        expires,
        created_at: new Date(clock).toISOString(),
      };
      keys.set(key, record);
      issued.push(key);
      if (state.dropAfterGenerate) return req.socket.destroy();
      return reply(res, 200, {
        key,
        expires:
          state.expiresOverride === undefined ? expires : state.expiresOverride,
        key_alias: body.key_alias,
        user_id: body.user_id,
        token: record.token,
      });
    }
    if (path === "/key/list" && req.method === "GET") {
      const userId = parsed.searchParams.get("user_id");
      const all = [...keys.values()].filter((key) => key.user_id === userId);
      const size = Math.min(
        Number(parsed.searchParams.get("size") ?? 10),
        state.maxPageSize,
      );
      const page = Number(parsed.searchParams.get("page") ?? 1);
      return reply(res, 200, {
        keys: all.slice((page - 1) * size, page * size),
        total_count: all.length,
        current_page: page,
        total_pages: Math.ceil(all.length / size),
      });
    }
    if (path === "/key/delete" && req.method === "POST") {
      const deleted = [];
      for (const [key, record] of keys) {
        if (
          body.keys?.includes(key) ||
          body.key_aliases?.includes(record.key_alias)
        ) {
          keys.delete(key);
          deletedKeys.push(record);
          deleted.push(record.key_alias);
        }
      }
      if (deleted.length === 0)
        return reply(res, 404, {
          error: {
            message: `No keys found ${UPSTREAM_BODY_MARK}`,
            code: "404",
          },
        });
      return reply(res, 200, { deleted_keys: deleted });
    }
    reply(res, 404, { error: { message: "no route" } });
  });

  return {
    url,
    users,
    keys,
    calls,
    issued,
    state,
    /** Add a key the broker did not issue, as an administrator would. */
    addForeignKey(userId) {
      const key = `sk-foreign-SENTINEL-${randomBytes(8).toString("hex")}`;
      keys.set(key, {
        token: hash(key),
        key_alias: `admin-${randomBytes(4).toString("hex")}`,
        user_id: userId,
        models: ["acme/coder"],
        metadata: {},
        expires: null,
        created_at: new Date().toISOString(),
      });
      issued.push(key);
      return key;
    },
    /**
     * Add a key that carries the broker's mark, as an earlier broker run
     * would have left it. `fields` override the record (created_at,
     * metadata).
     */
    addBrokerKey(userId, fields = {}) {
      const key = `sk-issued-SENTINEL-${randomBytes(12).toString("hex")}`;
      keys.set(key, {
        token: hash(key),
        key_alias: `pb-${randomBytes(12).toString("hex")}`,
        user_id: userId,
        models: ["acme/coder"],
        metadata: { distribution: "acmecode", issued_by: ISSUER_MARK },
        expires: null,
        // Older than every key the fake issues.
        created_at: "2025-01-01T00:00:00.000Z",
        ...fields,
      });
      issued.push(key);
      return key;
    },
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  };
}
