// Contract test of the reference broker against docs/enterprise-integration.md
// (http-broker: acquire, status table, idempotency, revoke) and the token
// rules in the broker README. No Docker: Keycloak and LiteLLM are fakes.
//
//   node --test test/
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, describe, it } from "node:test";
import {
  CREDENTIAL_ID_PATTERN,
  GROUP_MODELS,
  principalUserId,
} from "../src/broker.mjs";
import { loadConfig } from "../server.mjs";
import { ISSUER, MASTER_KEY, UPSTREAM_BODY_MARK } from "./fakes.mjs";
import { GATEWAY_BASE_URL, startHarness } from "./harness.mjs";

const ALICE = { sub: "0f1e2d3c-alice", groups: ["/engineering"] };
const BOB = {
  sub: "9a8b7c6d-bob",
  groups: ["/support"],
  preferred_username: "bob",
};
const uuid = () => crypto.randomUUID();

/** Every harness started here, so the final test can scan all their logs. */
const harnesses = [];
async function harness(overrides) {
  const h = await startHarness(overrides);
  harnesses.push(h);
  return h;
}
/** Every token minted here: none may appear in a log line. */
const minted = [];
const mint = (h, claims, options) => {
  const token = h.keycloak.mint(claims, options);
  minted.push(token);
  return token;
};
const generateCalls = (h) =>
  h.litellm.calls.filter((call) => call.path === "/key/generate");

after(async () => {
  for (const h of harnesses) await h.close();
});

describe("acquire: success response", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  it("returns every documented field for alice (engineering)", async () => {
    const started = Date.now();
    const res = await h.acquire(mint(h, ALICE));
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /^application\/json/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    const body = res.json;
    assert.deepEqual(Object.keys(body).sort(), [
      "base_url",
      "credential",
      "credential_id",
      "credential_type",
      "expires_at",
      "models",
      "subject",
    ]);
    assert.equal(body.credential_type, "api_key");
    assert.ok(
      body.credential.length >= 8 && /^[\x21-\x7e]+$/.test(body.credential),
    );
    assert.match(body.credential_id, CREDENTIAL_ID_PATTERN);
    assert.match(
      body.expires_at,
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    const expires = Date.parse(body.expires_at);
    assert.ok(expires > started, "expires in the future");
    assert.ok(
      expires <= Date.now() + (h.config.keyTtlSeconds + 1) * 1000,
      "no longer than the configured lifetime",
    );
    assert.deepEqual(body.models, ["acme/coder", "acme/general"]);
    assert.equal(body.base_url, GATEWAY_BASE_URL);
    assert.equal(
      body.subject,
      ALICE.sub,
      "subject echoes the authenticated sub",
    );
  });

  it("gives bob (support) only acme/coder, and LiteLLM enforces it on the key", async () => {
    const res = await h.acquire(mint(h, BOB));
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.models, ["acme/coder"]);
    assert.equal(res.json.subject, BOB.sub);
    assert.deepEqual(h.litellm.keys.get(res.json.credential).models, [
      "acme/coder",
    ]);
  });

  it("mints the key per D-01: user_id is the principal, no team_id, OSS fields only", async () => {
    const res = await h.acquire(mint(h, ALICE));
    const call = generateCalls(h).at(-1);
    assert.equal(call.auth, "master");
    const userId = principalUserId(ISSUER, ALICE.sub);
    assert.deepEqual(Object.keys(call.body).sort(), [
      "duration",
      "key_alias",
      "metadata",
      "models",
      "user_id",
    ]);
    assert.equal(call.body.user_id, userId);
    assert.equal(call.body.key_alias, res.json.credential_id);
    assert.equal(call.body.duration, `${h.config.keyTtlSeconds}s`);
    assert.equal(call.body.metadata.issued_by, "piship-reference-broker");
    const user = h.litellm.users.get(userId);
    assert.equal(user.user_role, "internal_user_viewer");
    assert.equal(user.auto_create_key, false);
    assert.equal(user.max_budget, h.config.userMaxBudget);
    assert.deepEqual(user.metadata, { iss: ISSUER, sub: ALICE.sub });
  });

  it("maps several acquires of one principal to one LiteLLM user, and two principals to two", async () => {
    const aliceUser = principalUserId(ISSUER, ALICE.sub);
    const bobUser = principalUserId(ISSUER, BOB.sub);
    assert.notEqual(aliceUser, bobUser);
    assert.notEqual(
      principalUserId("http://other-issuer", ALICE.sub),
      aliceUser,
      "issuer is part of the principal",
    );
    const creates = h.litellm.calls.filter((call) => call.path === "/user/new");
    assert.equal(
      creates.filter((call) => call.body.user_id === aliceUser).length,
      1,
    );
    assert.equal(
      creates.filter((call) => call.body.user_id === bobUser).length,
      1,
    );
    const aliceKeys = [...h.litellm.keys.values()].filter(
      (key) => key.user_id === aliceUser,
    );
    assert.ok(aliceKeys.length >= 2, "alice holds several keys on one user");
  });

  it("the group table is the one the README documents", () => {
    assert.deepEqual(GROUP_MODELS, {
      "/engineering": ["acme/coder", "acme/general"],
      "/support": ["acme/coder"],
    });
  });
});

describe("acquire: token validation (401, nothing issued)", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  /** 401, nothing issued, nothing echoed, and the logged reason is the expected check. */
  const refused = async (reason, token) => {
    const name = reason ?? "no token";
    const before = generateCalls(h).length;
    const res = await h.acquire(token);
    assert.equal(res.status, 401, name);
    assert.equal(JSON.parse(h.logLines.at(-1)).reason, reason, name);
    assert.match(res.headers.get("www-authenticate"), /^Bearer/, name);
    assert.equal(generateCalls(h).length, before, `${name}: no key generated`);
    assert.doesNotMatch(res.text, /sk-|eyJ/, `${name}: nothing secret echoed`);
  };

  it("no Authorization header", () => refused(undefined, undefined));
  it("a non-Bearer scheme", async () => {
    const token = mint(h, ALICE);
    const res = await fetch(`${h.url}/v1/credential`, {
      method: "POST",
      headers: {
        authorization: `Basic ${token}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    assert.equal(res.status, 401);
  });
  it("a malformed token", () => refused("malformed", "not.a.jwt!"));
  it("wrong issuer", () =>
    refused(
      "issuer",
      mint(h, { ...ALICE, iss: "http://127.0.0.1:18080/realms/other" }),
    ));
  it("wrong audience", () =>
    refused("audience", mint(h, { ...ALICE, aud: ["account"] })));
  it("missing audience", () =>
    refused("audience", mint(h, { ...ALICE, aud: undefined })));
  it("bad signature: payload changed after signing", () => {
    const token = mint(h, ALICE);
    const [header, , signature] = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({
        ...JSON.parse(Buffer.from(token.split(".")[1], "base64url")),
        groups: ["/engineering", "/support"],
        sub: "someone-else",
      }),
    ).toString("base64url");
    return refused("signature", `${header}.${forged}.${signature}`);
  });
  it("bad signature: signed by another key under a published kid", async () => {
    const { generateKeyPairSync } = await import("node:crypto");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    return refused("signature", mint(h, ALICE, { kid: "k1", privateKey }));
  });
  it("expired beyond the 30 s clock tolerance", () => {
    const now = Math.floor(Date.now() / 1000);
    return refused(
      "expired",
      mint(h, { ...ALICE, iat: now - 400, nbf: now - 400, exp: now - 31 }),
    );
  });
  it("accepts a token expired within the clock tolerance", async () => {
    const now = Math.floor(Date.now() / 1000);
    const res = await h.acquire(
      mint(h, { ...ALICE, iat: now - 300, exp: now - 10 }),
    );
    assert.equal(res.status, 200);
  });
  it("no exp claim", () =>
    refused("expired", mint(h, { ...ALICE, exp: undefined })));
  it("not valid yet (nbf beyond tolerance)", () => {
    const now = Math.floor(Date.now() / 1000);
    return refused(
      "not-yet-valid",
      mint(h, { ...ALICE, nbf: now + 120, exp: now + 400 }),
    );
  });
  it("issued in the future (iat beyond tolerance)", () => {
    const now = Math.floor(Date.now() / 1000);
    return refused("not-yet-valid", mint(h, { ...ALICE, iat: now + 120 }));
  });
  it("alg: none with an empty signature", () =>
    refused("algorithm", mint(h, ALICE, { alg: "none" })));
  it("alg: none with a signature", () =>
    refused("algorithm", mint(h, ALICE, { alg: "none", signature: "AAAA" })));
  it("HS256 signed with the published RSA public key (algorithm confusion)", () =>
    refused(
      "algorithm",
      mint(h, ALICE, { alg: "HS256", hmacSecret: h.keycloak.publicPem("k1") }),
    ));
  it("RS512 and PS256 are refused (RS256 only)", async () => {
    await refused("algorithm", mint(h, ALICE, { header: { alg: "RS512" } }));
    await refused("algorithm", mint(h, ALICE, { header: { alg: "PS256" } }));
  });
  it("a crit header", () =>
    refused("malformed", mint(h, ALICE, { header: { crit: ["exp"] } })));
  it("unknown kid", () =>
    refused("unknown-kid", mint(h, ALICE, { kid: "nope" })));
  it("no kid", () =>
    refused("unknown-kid", mint(h, ALICE, { header: { kid: undefined } })));
  it("wrong azp (another client's token)", () =>
    refused("authorized-party", mint(h, { ...ALICE, azp: "other-client" })));
  it("an ID token (typ ID)", () =>
    refused("token-type", mint(h, { ...ALICE, typ: "ID" })));
  it("no sub", () => refused("subject", mint(h, { ...ALICE, sub: undefined })));
});

describe("acquire: JWKS cache", () => {
  it("caches the JWKS and asks at most once per interval for unknown kids", async () => {
    const h = await harness();
    assert.equal((await h.acquire(mint(h, ALICE))).status, 200);
    assert.equal(h.keycloak.state.jwksFetches, 1);
    assert.equal((await h.acquire(mint(h, ALICE))).status, 200);
    assert.equal(h.keycloak.state.jwksFetches, 1, "cached");
    // Within the 30 s interval an unknown kid is refused without a refetch,
    // so random kids cannot drive a JWKS request per call.
    h.keycloak.state.published = ["k1", "k2"];
    assert.equal((await h.acquire(mint(h, ALICE, { kid: "k2" }))).status, 401);
    for (let i = 0; i < 5; i++)
      assert.equal(
        (await h.acquire(mint(h, ALICE, { kid: `random-${i}` }))).status,
        401,
      );
    assert.equal(h.keycloak.state.jwksFetches, 1);
  });

  it("an unknown kid after the interval refetches and accepts a rotated key", async () => {
    const h = await harness();
    // The verifier with a controlled clock, to step past the interval.
    const { createTokenVerifier } = await import("../src/token.mjs");
    let now = Date.now();
    const verifier = createTokenVerifier({
      issuer: ISSUER,
      audience: "piship-reference-broker",
      authorizedParty: "acmecode",
      jwksUrl: h.keycloak.jwksUrl,
      now: () => now,
    });
    await verifier.verify(mint(h, ALICE));
    const fetches = h.keycloak.state.jwksFetches;
    h.keycloak.state.published = ["k2"];
    await assert.rejects(verifier.verify(mint(h, ALICE, { kid: "k2" })), {
      reason: "unknown-kid",
    });
    assert.equal(
      h.keycloak.state.jwksFetches,
      fetches,
      "no refetch inside the interval",
    );
    now += 31_000;
    const claims = await verifier.verify(mint(h, ALICE, { kid: "k2" }));
    assert.equal(claims.sub, ALICE.sub);
    assert.equal(h.keycloak.state.jwksFetches, fetches + 1, "one refetch");
  });

  it("trusts a stale JWKS while the realm fails only up to jwksMaxStaleMs after the last good fetch", async () => {
    const h = await harness();
    const { createTokenVerifier, JwksUnavailableError } = await import(
      "../src/token.mjs"
    );
    let now = Date.now();
    const verifier = createTokenVerifier({
      issuer: ISSUER,
      audience: "piship-reference-broker",
      authorizedParty: "acmecode",
      jwksUrl: h.keycloak.jwksUrl,
      now: () => now,
    });
    const start = now;
    // The verifier's clock moves past an hour, so the token lives three.
    const token = () =>
      mint(h, { ...ALICE, exp: Math.floor(start / 1000) + 3 * 3600 });
    await verifier.verify(token());
    h.keycloak.state.jwksStatus = 500;
    now = start + 11 * 60_000;
    assert.equal(
      (await verifier.verify(token())).sub,
      ALICE.sub,
      "stale but within an hour",
    );
    now = start + 61 * 60_000;
    await assert.rejects(verifier.verify(token()), JwksUnavailableError);
    h.keycloak.state.jwksStatus = 200;
    now += 31_000;
    assert.equal((await verifier.verify(token())).sub, ALICE.sub, "recovers");
  });

  it("BROKER_JWKS_MAX_STALE_SECONDS is 600 to 86400, default 3600", () => {
    const base = {
      BROKER_ISSUER: ISSUER,
      BROKER_JWKS_URL: "https://idp.example.com/certs",
      BROKER_LITELLM_URL: "https://litellm.example.com",
      LITELLM_MASTER_KEY: MASTER_KEY,
      BROKER_GATEWAY_BASE_URL: GATEWAY_BASE_URL,
    };
    assert.equal(loadConfig(base).jwksMaxStaleSeconds, 3600);
    assert.equal(
      loadConfig({ ...base, BROKER_JWKS_MAX_STALE_SECONDS: "86400" })
        .jwksMaxStaleSeconds,
      86_400,
    );
    for (const value of ["599", "86401"])
      assert.throws(() =>
        loadConfig({ ...base, BROKER_JWKS_MAX_STALE_SECONDS: value }),
      );
  });

  it("answers 503 with Retry-After when the JWKS cannot be fetched and nothing is cached", async () => {
    const h = await harness();
    h.keycloak.state.jwksStatus = 500;
    const res = await h.acquire(mint(h, ALICE));
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "5");
  });
});

describe("acquire: request and entitlement", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  const denied = async (name, token, options) => {
    const before = generateCalls(h).length;
    const res = await h.acquire(token, options);
    assert.equal(res.status, 403, name);
    assert.equal(generateCalls(h).length, before, `${name}: no key generated`);
    return res;
  };

  it("403 when the verified token has no groups claim", () =>
    denied("missing groups", mint(h, { ...ALICE, groups: undefined })));
  it("403 when groups is empty", () =>
    denied("empty groups", mint(h, { ...ALICE, groups: [] })));
  it("403 when no group is entitled", () =>
    denied("unknown group", mint(h, { ...ALICE, groups: ["/sales"] })));
  it("403 for a nested group that shares an entitled group's name, and for a bare name", () =>
    denied(
      "same name, other path",
      mint(h, {
        ...ALICE,
        groups: ["/contractors/engineering", "engineering", "support"],
      }),
    ));
  it("403 for group names that are Object prototype members", () =>
    denied(
      "prototype groups",
      mint(h, { ...ALICE, groups: ["constructor", "__proto__", "toString"] }),
    ));
  it("403 when groups is not a string array", () =>
    denied("bad groups", mint(h, { ...ALICE, groups: "/engineering" })));
  it("403 for another distribution", () =>
    denied("distribution", mint(h, ALICE), {
      body: { distribution: "othercode", purpose: "inference" },
    }));
  it("400 for a purpose other than inference", async () => {
    assert.equal(
      (
        await h.acquire(mint(h, ALICE), {
          body: { distribution: "acmecode", purpose: "sandbox" },
        })
      ).status,
      400,
    );
  });
  it("400 for a body that is not a JSON object", async () => {
    assert.equal(
      (await h.acquire(mint(h, ALICE), { body: "[1,2]" })).status,
      400,
    );
    assert.equal(
      (await h.acquire(mint(h, ALICE), { body: "{not json" })).status,
      400,
    );
  });
  it("413 for an oversized body", async () => {
    const res = await h.acquire(mint(h, ALICE), {
      body: {
        distribution: "acmecode",
        purpose: "inference",
        pad: "x".repeat(5000),
      },
    });
    assert.equal(res.status, 413);
  });
  it("415 for a body that is not JSON by content type", async () => {
    assert.equal(
      (
        await h.acquire(mint(h, ALICE), {
          headers: { "content-type": "text/plain" },
        })
      ).status,
      415,
    );
  });
  it("400 for an Idempotency-Key outside 1 to 255 visible ASCII characters", async () => {
    assert.equal(
      (await h.acquire(mint(h, ALICE), { key: "has space" })).status,
      400,
    );
    assert.equal(
      (await h.acquire(mint(h, ALICE), { key: "x".repeat(256) })).status,
      400,
    );
  });
  it("405 and 404 for other methods and paths; /health answers", async () => {
    assert.equal((await fetch(`${h.url}/v1/credential`)).status, 405);
    assert.equal(
      (await fetch(`${h.url}/v1/other`, { method: "POST" })).status,
      404,
    );
    assert.equal((await fetch(`${h.url}/health`)).status, 200);
  });
});

describe("acquire: idempotency (docs: Idempotency and retries)", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  it("new key: issues", async () => {
    const res = await h.acquire(mint(h, ALICE), { key: uuid() });
    assert.equal(res.status, 200);
  });

  it("same key, same input, first finished: the stored answer, no second key", async () => {
    const key = uuid();
    const first = await h.acquire(mint(h, ALICE), { key });
    const count = generateCalls(h).length;
    const second = await h.acquire(mint(h, ALICE), { key });
    assert.equal(second.status, 200);
    assert.deepEqual(second.json, first.json);
    assert.equal(generateCalls(h).length, count, "not issued again");
  });

  it("same input means principal plus body, not the token: a refreshed token replays", async () => {
    const key = uuid();
    const first = await h.acquire(mint(h, ALICE), { key });
    const refreshed = mint(h, {
      ...ALICE,
      iat: Math.floor(Date.now() / 1000) - 1,
      jti: "refreshed",
    });
    const second = await h.acquire(refreshed, { key });
    assert.equal(second.status, 200);
    assert.equal(second.json.credential_id, first.json.credential_id);
  });

  it("body key order and spacing do not change the input", async () => {
    const key = uuid();
    const first = await h.acquire(mint(h, ALICE), {
      key,
      body: '{"distribution":"acmecode","purpose":"inference"}',
    });
    const second = await h.acquire(mint(h, ALICE), {
      key,
      body: '{ "purpose": "inference", "distribution": "acmecode" }',
    });
    assert.equal(second.json.credential_id, first.json.credential_id);
  });

  it("same key, different body: 422, not issued, stored credential never returned", async () => {
    const key = uuid();
    const first = await h.acquire(mint(h, ALICE), { key });
    const count = generateCalls(h).length;
    const res = await h.acquire(mint(h, ALICE), {
      key,
      body: { distribution: "acmecode", purpose: "inference", extra: 1 },
    });
    assert.equal(res.status, 422);
    assert.equal(generateCalls(h).length, count);
    assert.ok(!res.text.includes(first.json.credential));
    assert.ok(!res.text.includes(first.json.credential_id));
  });

  it("same key, another principal: a separate record, so one user's key never returns or blocks another's credential", async () => {
    const key = uuid();
    const alice = await h.acquire(mint(h, ALICE), { key });
    const res = await h.acquire(mint(h, BOB), { key });
    assert.equal(res.status, 200, "bob's acquire issues his own");
    assert.equal(res.json.subject, BOB.sub);
    assert.notEqual(res.json.credential_id, alice.json.credential_id);
    assert.ok(!res.text.includes(alice.json.credential));
    const replay = await h.acquire(mint(h, ALICE), { key });
    assert.deepEqual(replay.json, alice.json, "alice's record is untouched");
    const bobReplay = await h.acquire(mint(h, BOB), { key });
    assert.deepEqual(bobReplay.json, res.json);
  });

  it("records are capped per principal: one user's records never evict another's", async () => {
    const { createIdempotencyStore } = await import("../src/broker.mjs");
    const store = createIdempotencyStore({ maxEntries: 4, maxPerPrincipal: 2 });
    const admit = () => null;
    const far = Date.now() + 3_600_000;
    assert.equal(store.begin("bob", "b1", "fb", admit).kind, "new");
    store.complete("bob", "b1", { id: "bob-1" }, far);
    for (let i = 1; i <= 5; i++) {
      assert.equal(store.begin("alice", `a${i}`, "fa", admit).kind, "new");
      store.complete("alice", `a${i}`, { id: `alice-${i}` }, far);
      assert.ok(store.size("alice") <= 2);
    }
    assert.deepEqual(store.begin("bob", "b1", "fb", admit), {
      kind: "replay",
      response: { id: "bob-1" },
    });
    assert.equal(
      store.begin("alice", "a5", "fa", admit).kind,
      "replay",
      "the newest stays",
    );
    assert.equal(
      store.begin("alice", "a1", "fa", admit).kind,
      "new",
      "alice's oldest was dropped",
    );
  });

  it("a principal whose records are all in progress gets 'full', and others are unaffected", async () => {
    const { createIdempotencyStore } = await import("../src/broker.mjs");
    const store = createIdempotencyStore({ maxPerPrincipal: 2 });
    const admit = () => null;
    assert.equal(store.begin("alice", "a1", "f", admit).kind, "new");
    assert.equal(store.begin("alice", "a2", "f", admit).kind, "new");
    assert.equal(store.begin("alice", "a3", "f", admit).kind, "full");
    assert.equal(store.begin("bob", "a3", "f", admit).kind, "new");
  });

  it("same key while the first is still running: 503 with Retry-After, then the stored answer", async () => {
    const key = uuid();
    h.litellm.state.generateDelayMs = 300;
    const firstPromise = h.acquire(mint(h, ALICE), { key });
    await new Promise((resolve) => setTimeout(resolve, 100));
    const during = await h.acquire(mint(h, ALICE), { key });
    h.litellm.state.generateDelayMs = 0;
    assert.equal(during.status, 503);
    assert.equal(during.headers.get("retry-after"), "1");
    const first = await firstPromise;
    assert.equal(first.status, 200);
    const afterwards = await h.acquire(mint(h, ALICE), { key });
    assert.deepEqual(afterwards.json, first.json);
  });

  it("no answer is stored for a 401, 403, 429 or 503: the same key then issues normally", async () => {
    const key = uuid();
    const now = Math.floor(Date.now() / 1000);
    assert.equal(
      (
        await h.acquire(mint(h, { ...ALICE, exp: now - 100, iat: now - 400 }), {
          key,
        })
      ).status,
      401,
    );
    assert.equal(
      (await h.acquire(mint(h, { ...ALICE, groups: [] }), { key })).status,
      403,
    );
    h.litellm.state.faults.set("/user/info", { status: 500, count: 1 });
    assert.equal((await h.acquire(mint(h, ALICE), { key })).status, 503);
    assert.equal((await h.acquire(mint(h, ALICE), { key })).status, 200);
  });

  it("no key: every request issues a new credential", async () => {
    const a = await h.acquire(mint(h, ALICE));
    const b = await h.acquire(mint(h, ALICE));
    assert.notEqual(a.json.credential_id, b.json.credential_id);
  });
});

describe("acquire: 429 rate limit", () => {
  it("answers 429 with Retry-After in seconds, per principal, and still replays a finished key", async () => {
    const h = await harness({ BROKER_ACQUIRE_LIMIT_PER_MINUTE: "2" });
    const key = uuid();
    const first = await h.acquire(mint(h, ALICE), { key });
    assert.equal(first.status, 200);
    assert.equal((await h.acquire(mint(h, ALICE))).status, 200);
    const count = generateCalls(h).length;
    const limited = await h.acquire(mint(h, ALICE), { key: uuid() });
    assert.equal(limited.status, 429);
    const wait = Number(limited.headers.get("retry-after"));
    assert.ok(Number.isInteger(wait) && wait >= 1 && wait <= 60);
    assert.equal(generateCalls(h).length, count);
    const replay = await h.acquire(mint(h, ALICE), { key });
    assert.equal(
      replay.status,
      200,
      "a retry of a finished acquire is not rate limited",
    );
    assert.equal(replay.json.credential_id, first.json.credential_id);
    assert.equal(
      (await h.acquire(mint(h, BOB))).status,
      200,
      "bob has his own window",
    );
  });
});

describe("acquire: upstream LiteLLM failure (503)", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  it("503 with Retry-After when LiteLLM answers 5xx; its body is never passed on", async () => {
    for (const path of ["/user/info", "/user/new", "/key/generate"]) {
      h.litellm.state.faults.set(path, { status: 500, count: 1 });
      const res = await h.acquire(mint(h, { ...ALICE, sub: `fresh-${path}` }));
      assert.equal(res.status, 503, path);
      assert.equal(res.headers.get("retry-after"), "5");
      assert.ok(!res.text.includes(UPSTREAM_BODY_MARK));
      assert.ok(!res.text.includes(MASTER_KEY));
    }
  });

  it("a key created but whose answer was lost is deleted by alias; the client gets 503", async () => {
    h.litellm.state.dropAfterGenerate = true;
    const before = h.litellm.keys.size;
    const res = await h.acquire(mint(h, ALICE));
    h.litellm.state.dropAfterGenerate = false;
    assert.equal(res.status, 503);
    assert.equal(
      h.litellm.keys.size,
      before,
      "no orphaned key left in LiteLLM",
    );
  });

  it("502 when the lost key cannot be confirmed deleted (outcome unknown)", async () => {
    h.litellm.state.dropAfterGenerate = true;
    h.litellm.state.faults.set("/key/delete", { status: 500, count: 1 });
    const res = await h.acquire(mint(h, ALICE));
    h.litellm.state.dropAfterGenerate = false;
    assert.equal(res.status, 502);
  });

  it("a key LiteLLM reports without an explicit zone, or never expiring, is deleted and not returned", async () => {
    for (const expires of [
      null,
      "2030-01-01T00:00:00",
      "2099-01-01T00:00:00Z",
    ]) {
      h.litellm.state.expiresOverride = expires;
      const before = h.litellm.keys.size;
      const res = await h.acquire(mint(h, ALICE));
      assert.equal(res.status, 503, String(expires));
      assert.equal(h.litellm.keys.size, before);
    }
    h.litellm.state.expiresOverride = undefined;
  });

  it("503 when LiteLLM is unreachable", async () => {
    const h2 = await harness({ BROKER_LITELLM_URL: "http://127.0.0.1:9" });
    const res = await h2.acquire(mint(h2, ALICE));
    assert.equal(res.status, 503);
  });
});

describe("rotation: generate new, then delete old", () => {
  it("keeps the newest keys per user (BROKER_MAX_KEYS_PER_USER) on one user_id and never touches another user's", async () => {
    const h = await harness({ BROKER_MAX_KEYS_PER_USER: "2" });
    const bob = await h.acquire(mint(h, BOB));
    const ids = [];
    for (let i = 0; i < 4; i++)
      ids.push((await h.acquire(mint(h, ALICE))).json.credential_id);
    const aliceUser = principalUserId(ISSUER, ALICE.sub);
    const aliases = [...h.litellm.keys.values()]
      .filter((key) => key.user_id === aliceUser)
      .map((key) => key.key_alias);
    assert.deepEqual(aliases.sort(), ids.slice(-2).sort());
    assert.ok(h.litellm.keys.has(bob.json.credential));
    assert.ok(
      !h.litellm.calls.some((call) => /regenerate/.test(call.path)),
      "no Enterprise regenerate",
    );
  });

  it("serializes issue-then-retire per user: concurrent acquires never count keys at the same time", async () => {
    const h = await harness({ BROKER_MAX_KEYS_PER_USER: "1" });
    h.litellm.state.generateDelayMs = 150;
    const [a, b] = await Promise.all([
      h.acquire(mint(h, ALICE)),
      h.acquire(mint(h, ALICE)),
    ]);
    h.litellm.state.generateDelayMs = 0;
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    const order = h.litellm.calls
      .filter((call) => ["/key/generate", "/key/list"].includes(call.path))
      .map((call) => call.path);
    assert.deepEqual(order, [
      "/key/generate",
      "/key/list",
      "/key/generate",
      "/key/list",
    ]);
    const aliceUser = principalUserId(ISSUER, ALICE.sub);
    const left = [...h.litellm.keys.values()].filter(
      (key) => key.user_id === aliceUser,
    );
    assert.equal(left.length, 1, "the cap holds");
    assert.ok(
      [a.json.credential_id, b.json.credential_id].includes(left[0].key_alias),
    );
  });

  it("reads every /key/list page", async () => {
    const h = await harness({ BROKER_MAX_KEYS_PER_USER: "2" });
    h.litellm.state.maxPageSize = 2;
    const aliceUser = principalUserId(ISSUER, ALICE.sub);
    for (let i = 0; i < 5; i++) h.litellm.addBrokerKey(aliceUser);
    const issued = (await h.acquire(mint(h, ALICE))).json;
    const left = [...h.litellm.keys.values()].filter(
      (key) => key.user_id === aliceUser,
    );
    assert.equal(left.length, 2);
    assert.ok(left.some((key) => key.key_alias === issued.credential_id));
    assert.ok(
      h.litellm.calls.filter((call) => call.path === "/key/list").length >= 3,
    );
  });

  it("retires a key without a readable created_at first, and never the new key", async () => {
    const h = await harness({ BROKER_MAX_KEYS_PER_USER: "2" });
    const aliceUser = principalUserId(ISSUER, ALICE.sub);
    for (const created_at of [undefined, "not a date"]) {
      // An old key with a date, then one without: the one without goes.
      const dated = h.litellm.addBrokerKey(aliceUser);
      const undated = h.litellm.addBrokerKey(aliceUser, { created_at });
      const issued = (await h.acquire(mint(h, ALICE))).json;
      assert.ok(!h.litellm.keys.has(undated), String(created_at));
      assert.ok(h.litellm.keys.has(dated), String(created_at));
      assert.ok(h.litellm.keys.has(issued.credential));
      h.litellm.keys.delete(dated);
      h.litellm.keys.delete(issued.credential);
    }
    // A key dated after the new one (clock skew) does not push the new key
    // out or keep the user over the cap.
    const h1 = await harness({ BROKER_MAX_KEYS_PER_USER: "1" });
    const future = h1.litellm.addBrokerKey(aliceUser, {
      created_at: "2099-01-01T00:00:00.000Z",
    });
    const issued = (await h1.acquire(mint(h1, ALICE))).json;
    assert.ok(h1.litellm.keys.has(issued.credential));
    assert.ok(!h1.litellm.keys.has(future));
  });

  it("never deletes a key it did not issue", async () => {
    const h = await harness({ BROKER_MAX_KEYS_PER_USER: "1" });
    const foreign = h.litellm.addForeignKey(principalUserId(ISSUER, ALICE.sub));
    await h.acquire(mint(h, ALICE));
    await h.acquire(mint(h, ALICE));
    assert.ok(h.litellm.keys.has(foreign));
  });
});

describe("revoke", () => {
  let h;
  before(async () => {
    h = await harness();
  });

  it("deletes the key with the key as the proof; LiteLLM then rejects it", async () => {
    const issued = (await h.acquire(mint(h, ALICE))).json;
    const models = await fetch(`${h.litellm.url}/v1/models`, {
      headers: { authorization: `Bearer ${issued.credential}` },
    });
    assert.equal(models.status, 200);
    const res = await h.revoke(issued.credential, issued.credential_id);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, {
      revoked: true,
      credential_id: issued.credential_id,
    });
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.ok(!h.litellm.keys.has(issued.credential));
    const info = h.litellm.calls
      .filter((call) => call.path === "/key/info")
      .at(-1);
    assert.equal(info.auth, "key", "looked up with the key itself");
    const del = h.litellm.calls
      .filter((call) => call.path === "/key/delete")
      .at(-1);
    assert.equal(del.auth, "master");
    assert.deepEqual(del.body, { keys: [issued.credential] });
    const rejected = await fetch(`${h.litellm.url}/v1/models`, {
      headers: { authorization: `Bearer ${issued.credential}` },
    });
    assert.equal(rejected.status, 401);
  });

  it("an already deleted or unknown key answers 404, which PiShip counts as revoked", async () => {
    const issued = (await h.acquire(mint(h, ALICE))).json;
    assert.equal(
      (await h.revoke(issued.credential, issued.credential_id)).status,
      200,
    );
    const again = await h.revoke(issued.credential, issued.credential_id);
    assert.equal(again.status, 404);
    assert.ok(!again.text.includes(UPSTREAM_BODY_MARK));
    assert.equal(
      (await h.revoke("sk-never-issued-SENTINEL-000", null)).status,
      404,
    );
  });

  it("revokes with credential_id null (a broker that returned none)", async () => {
    const issued = (await h.acquire(mint(h, BOB))).json;
    assert.equal((await h.revoke(issued.credential, null)).status, 200);
    assert.ok(!h.litellm.keys.has(issued.credential));
  });

  it("the presented key is what is revoked, even with a mismatched credential_id", async () => {
    const a = (await h.acquire(mint(h, ALICE))).json;
    const b = (await h.acquire(mint(h, ALICE))).json;
    assert.equal((await h.revoke(a.credential, b.credential_id)).status, 200);
    assert.ok(!h.litellm.keys.has(a.credential));
    assert.ok(h.litellm.keys.has(b.credential), "the other key is untouched");
  });

  it("a key this broker did not issue, or issued for another distribution, gets the same 404 as an unknown key; it stays", async () => {
    const unknown = await h.revoke("sk-never-issued-SENTINEL-002", null);
    assert.equal(unknown.status, 404);
    const foreign = h.litellm.addForeignKey("someone");
    const other = h.litellm.addBrokerKey("someone", {
      metadata: {
        distribution: "othercode",
        issued_by: "piship-reference-broker",
      },
    });
    for (const key of [foreign, other]) {
      const res = await h.revoke(key, null);
      assert.equal(res.status, unknown.status);
      assert.equal(res.text, unknown.text, "same body as an unknown key");
      assert.equal(
        res.headers.get("www-authenticate"),
        unknown.headers.get("www-authenticate"),
      );
      assert.ok(h.litellm.keys.has(key));
      assert.equal(JSON.parse(h.logLines.at(-1)).reason, "foreign-key");
    }
  });

  it("401 without a bearer, 403 for another distribution, 400 for a bad body", async () => {
    assert.equal((await h.revoke(undefined)).status, 401);
    const issued = (await h.acquire(mint(h, ALICE))).json;
    assert.equal(
      (await h.revoke(issued.credential, issued.credential_id, "othercode"))
        .status,
      403,
    );
    assert.ok(h.litellm.keys.has(issued.credential));
    const bad = await fetch(`${h.url}/v1/revoke`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${issued.credential}`,
        "content-type": "application/json",
      },
      body: '{"credential_id": 5}',
    });
    assert.equal(bad.status, 400);
  });

  it("503 with Retry-After when LiteLLM fails", async () => {
    const issued = (await h.acquire(mint(h, ALICE))).json;
    h.litellm.state.faults.set("/key/delete", { status: 500, count: 1 });
    const res = await h.revoke(issued.credential, issued.credential_id);
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "5");
    assert.ok(!res.text.includes(UPSTREAM_BODY_MARK));
  });

  it("a live key whose holder lookup LiteLLM refuses is confirmed by its hash under the master key and deleted", async () => {
    for (const status of [400, 401, 403]) {
      const issued = (await h.acquire(mint(h, ALICE))).json;
      h.litellm.state.holderKeyInfoStatus = status;
      const res = await h.revoke(issued.credential, issued.credential_id);
      h.litellm.state.holderKeyInfoStatus = undefined;
      assert.equal(res.status, 200, `holder lookup ${status}`);
      assert.ok(!h.litellm.keys.has(issued.credential), `${status}: deleted`);
      const lookup = h.litellm.calls
        .filter((call) => call.path === "/key/info")
        .at(-1);
      assert.equal(lookup.auth, "master");
      assert.equal(
        lookup.query.key,
        createHash("sha256").update(issued.credential).digest("hex"),
        "looked up by the key's SHA-256",
      );
    }
    for (const call of h.litellm.calls)
      for (const value of Object.values(call.query))
        assert.ok(!value.startsWith("sk-"), "no key in a query string");
  });

  it("answers 404 only when the master-key lookup also finds no such key", async () => {
    h.litellm.state.holderKeyInfoStatus = 401;
    const res = await h.revoke("sk-never-issued-SENTINEL-001", null);
    h.litellm.state.holderKeyInfoStatus = undefined;
    assert.equal(res.status, 404);
    const lookup = h.litellm.calls
      .filter((call) => call.path === "/key/info")
      .at(-1);
    assert.equal(lookup.auth, "master", "confirmed before answering 404");
  });

  it("503 and the key stays when the holder lookup is refused and the master-key lookup fails", async () => {
    const issued = (await h.acquire(mint(h, ALICE))).json;
    h.litellm.state.holderKeyInfoStatus = 401;
    h.litellm.state.adminKeyInfoStatus = 500;
    const res = await h.revoke(issued.credential, issued.credential_id);
    h.litellm.state.holderKeyInfoStatus = undefined;
    h.litellm.state.adminKeyInfoStatus = undefined;
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "5");
    assert.ok(h.litellm.keys.has(issued.credential));
  });
});

describe("revoke: limits", () => {
  const infoCalls = (h) =>
    h.litellm.calls.filter((call) => call.path === "/key/info").length;

  it("429 with Retry-After past BROKER_REVOKE_LIMIT_PER_MINUTE from one address, before LiteLLM is asked", async () => {
    const h = await harness({ BROKER_REVOKE_LIMIT_PER_MINUTE: "3" });
    for (let i = 0; i < 3; i++)
      assert.equal((await h.revoke(`sk-unknown-SENTINEL-00${i}`)).status, 404);
    const before = infoCalls(h);
    // Any request counts, a malformed one too.
    const limited = await h.revoke(undefined);
    assert.equal(limited.status, 429);
    const wait = Number(limited.headers.get("retry-after"));
    assert.ok(Number.isInteger(wait) && wait >= 1 && wait <= 60);
    assert.equal(
      (await h.revoke("sk-unknown-SENTINEL-009")).status,
      429,
      "still limited",
    );
    assert.equal(infoCalls(h), before, "no lookup once limited");
  });

  it("ignores X-Forwarded-For unless the peer is a configured trusted proxy", async () => {
    const direct = await harness({ BROKER_REVOKE_LIMIT_PER_MINUTE: "1" });
    const spoof = (h, address) =>
      h.revoke("sk-unknown-SENTINEL-010", null, "acmecode", {
        "x-forwarded-for": address,
      });
    assert.equal((await spoof(direct, "10.0.0.1")).status, 404);
    assert.equal(
      (await spoof(direct, "10.0.0.2")).status,
      429,
      "a client cannot pick its own address",
    );

    const proxied = await harness({
      BROKER_REVOKE_LIMIT_PER_MINUTE: "1",
      BROKER_TRUSTED_PROXIES: "127.0.0.1",
    });
    assert.equal((await spoof(proxied, "10.0.0.1")).status, 404);
    assert.equal((await spoof(proxied, "10.0.0.2")).status, 404);
    assert.equal((await spoof(proxied, "10.0.0.1")).status, 429);
    // The right-most untrusted hop counts, not what the client prepended.
    assert.equal((await spoof(proxied, "10.0.0.3, 10.0.0.2")).status, 429);
  });

  it("503 with Retry-After: 1 past BROKER_REVOKE_MAX_CONCURRENT lookups in flight", async () => {
    const h = await harness({ BROKER_REVOKE_MAX_CONCURRENT: "1" });
    h.litellm.state.keyInfoDelayMs = 200;
    const first = h.revoke("sk-unknown-SENTINEL-011");
    await new Promise((resolve) => setTimeout(resolve, 50));
    const second = await h.revoke("sk-unknown-SENTINEL-012");
    h.litellm.state.keyInfoDelayMs = 0;
    assert.equal(second.status, 503);
    assert.equal(second.headers.get("retry-after"), "1");
    assert.equal((await first).status, 404);
    assert.equal(
      (await h.revoke("sk-unknown-SENTINEL-013")).status,
      404,
      "the slot is released",
    );
  });

  it("the rate limiter keeps at most maxCallers windows", async () => {
    const { createRateLimiter } = await import("../src/broker.mjs");
    let now = 0;
    const limiter = createRateLimiter({
      limitPerMinute: 5,
      maxCallers: 2,
      now: () => now,
    });
    assert.equal(limiter.take("a"), 0);
    now = 10_000;
    assert.equal(limiter.take("b"), 0);
    assert.equal(limiter.take("c"), 50, "waits for the oldest window");
    now = 60_000;
    assert.equal(limiter.take("c"), 0, "a's window ended");
  });
});

describe("configuration: back-channel URLs", () => {
  const base = {
    BROKER_ISSUER: ISSUER,
    BROKER_JWKS_URL: "https://idp.example.com/certs",
    BROKER_LITELLM_URL: "https://litellm.example.com",
    LITELLM_MASTER_KEY: MASTER_KEY,
    BROKER_GATEWAY_BASE_URL: GATEWAY_BASE_URL,
  };
  const load = (overrides) => loadConfig({ ...base, ...overrides });

  it("accepts https, and http on a loopback host", () => {
    for (const name of ["BROKER_JWKS_URL", "BROKER_LITELLM_URL"])
      for (const value of [
        "https://idp.example.com/certs",
        "http://127.0.0.1:8080/certs",
        "http://127.8.9.10/certs",
        "http://localhost:4000",
        "http://[::1]:4000",
      ])
        assert.doesNotThrow(() => load({ [name]: value }), `${name} ${value}`);
  });

  it("refuses http to any other host, naming the variable and not the value", () => {
    for (const name of ["BROKER_JWKS_URL", "BROKER_LITELLM_URL"])
      for (const value of [
        "http://keycloak:8080/certs",
        "http://idp.example.com/certs",
        "http://10.0.0.5:4000",
        "http://127.example.com",
      ])
        assert.throws(
          () => load({ [name]: value }),
          (error) =>
            error.message.startsWith(`${name} must be an https URL`) &&
            !error.message.includes(value),
          `${name} ${value}`,
        );
  });

  it("with BROKER_ALLOW_INSECURE_BACKCHANNEL=true, accepts http to a container name only", () => {
    const insecure = { BROKER_ALLOW_INSECURE_BACKCHANNEL: "true" };
    const config = load({
      ...insecure,
      BROKER_JWKS_URL: "http://keycloak:8080/certs",
      BROKER_LITELLM_URL: "http://litellm:4000",
    });
    assert.equal(config.litellmUrl, "http://litellm:4000");
    for (const value of ["http://idp.example.com/certs", "http://10.0.0.5"])
      assert.throws(() => load({ ...insecure, BROKER_JWKS_URL: value }));
    assert.throws(
      () => load({ BROKER_ALLOW_INSECURE_BACKCHANNEL: "yes" }),
      /BROKER_ALLOW_INSECURE_BACKCHANNEL must be true or false/,
    );
  });
});

describe("no Enterprise feature and no secret in any log line", () => {
  it("never calls regenerate, never sends team_id or model_max_budget", () => {
    for (const h of harnesses)
      for (const call of h.litellm.calls) {
        assert.doesNotMatch(call.path, /regenerate/);
        const body = JSON.stringify(call.body ?? {});
        assert.doesNotMatch(body, /team_id|model_max_budget/);
      }
  });

  it("scans every log line of every broker for the master key, issued keys, tokens and planted sentinels", () => {
    let lines = 0;
    for (const h of harnesses) {
      const planted = [MASTER_KEY, ...h.litellm.issued];
      for (const line of h.logLines) {
        lines += 1;
        JSON.parse(line);
        for (const secret of planted)
          assert.ok(!line.includes(secret), "a key reached the log");
        for (const token of minted)
          assert.ok(!line.includes(token), "a token reached the log");
        assert.ok(
          !line.includes("SENTINEL"),
          `a sentinel reached the log: ${line.slice(0, 80)}`,
        );
        assert.doesNotMatch(line, /sk-[A-Za-z0-9]|eyJ/);
      }
    }
    assert.ok(lines > 50, `the scan saw the broker's output (${lines} lines)`);
  });

  it("the logger drops unknown fields and scrubs key and token shapes", async () => {
    const { createLogger } = await import("../src/log.mjs");
    const out = [];
    const log = createLogger({
      write: (line) => out.push(line),
      secrets: ["planted-secret-value"],
    });
    log("x planted-secret-value", {
      reason: "sk-abcdefgh eyJhbGciOi.eyJzdWIiOi.c2ln",
      credential: "sk-should-not-appear",
      body: { a: 1 },
    });
    assert.equal(out.length, 1);
    assert.ok(!out[0].includes("planted-secret-value"));
    assert.ok(!out[0].includes("should-not-appear"));
    assert.doesNotMatch(out[0], /sk-a|eyJh/);
  });
});
