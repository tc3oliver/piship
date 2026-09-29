// The broker against PiShip's own http-broker client: HttpBrokerCredentialProvider
// from packages/credentials, built in this repository (`npm run build` at the
// root first). PISHIP_REPO_ROOT may point at another checkout's root.
//
//   node --test test/
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { after, before, describe, it } from "node:test";
import { CREDENTIAL_ID_PATTERN } from "../src/broker.mjs";
import { ISSUER } from "./fakes.mjs";
import { GATEWAY_BASE_URL, startHarness } from "./harness.mjs";

const root = resolve(
  process.env.PISHIP_REPO_ROOT ??
    join(dirname(fileURLToPath(import.meta.url)), "../../../.."),
);
const credentialsDist = join(root, "packages/credentials/dist/index.js");
const contractsDist = join(root, "packages/contracts/dist/index.js");
if (!existsSync(credentialsDist) || !existsSync(contractsDist))
  throw new Error(
    `PiShip packages are not built under ${root}: run "npm ci && npm run build" at the repository root`,
  );
const { HttpBrokerCredentialProvider } = await import(
  pathToFileURL(credentialsDist).href
);
const { SecretValue } = await import(pathToFileURL(contractsDist).href);

const ALICE = { sub: "0f1e2d3c-alice", groups: ["engineering"] };
const BOB = { sub: "9a8b7c6d-bob", groups: ["support"] };
const ctx = (extra = {}) => ({ distributionId: "acmecode", ...extra });

describe("PiShip HttpBrokerCredentialProvider against the reference broker", () => {
  let h;
  let provider;
  const identity = (claims) => ({
    subject: claims.sub,
    issuer: ISSUER,
    accessToken: new SecretValue(h.keycloak.mint(claims)),
  });
  const code = async (promise) => {
    try {
      await promise;
    } catch (error) {
      return error;
    }
    assert.fail("expected a failure");
  };

  before(async () => {
    h = await startHarness({ BROKER_ACQUIRE_LIMIT_PER_MINUTE: "50" });
    provider = new HttpBrokerCredentialProvider({
      endpoint: `${h.url}/v1/credential`,
      revokeEndpoint: `${h.url}/v1/revoke`,
      fetch: globalThis.fetch,
      expectedBaseUrl: GATEWAY_BASE_URL,
    });
  });
  after(() => h.close());

  it("acquire: a RuntimeCredential with id, expiry, models and the declared base URL", async () => {
    const credential = await provider.acquire(
      identity(ALICE),
      ctx({ idempotencyKey: crypto.randomUUID() }),
    );
    assert.equal(credential.kind, "api_key");
    assert.match(credential.credentialId, CREDENTIAL_ID_PATTERN);
    assert.ok(credential.expiresAt > new Date());
    assert.deepEqual(credential.metadata.models, [
      "acme/coder",
      "acme/general",
    ]);
    assert.equal(credential.metadata.baseUrl, GATEWAY_BASE_URL);
    assert.ok(h.litellm.keys.has(credential.secret.reveal()));
  });

  it("acquire for bob is narrower", async () => {
    const credential = await provider.acquire(identity(BOB), ctx());
    assert.deepEqual(credential.metadata.models, ["acme/coder"]);
  });

  it("a caller retrying with the same idempotency key gets the same credential", async () => {
    const key = crypto.randomUUID();
    const first = await provider.acquire(
      identity(ALICE),
      ctx({ idempotencyKey: key }),
    );
    const second = await provider.acquire(
      identity(ALICE),
      ctx({ idempotencyKey: key }),
    );
    assert.equal(second.credentialId, first.credentialId);
    assert.equal(second.secret.reveal(), first.secret.reveal());
  });

  it("the subject the broker echoes is the identity's subject", async () => {
    const response = await h.acquire(h.keycloak.mint(ALICE));
    assert.equal(response.json.subject, identity(ALICE).subject);
  });

  it("401 (invalid token) is IDENTITY_EXPIRED", async () => {
    const error = await code(
      provider.acquire(
        {
          subject: "x",
          issuer: ISSUER,
          accessToken: new SecretValue(
            h.keycloak.mint({ ...ALICE, iss: "http://evil" }),
          ),
        },
        ctx(),
      ),
    );
    assert.equal(error.code, "IDENTITY_EXPIRED");
    assert.equal(error.sanitizedDetail.reason, "authentication");
  });

  it("403 (not entitled) is CREDENTIAL_DENIED, not retryable", async () => {
    const error = await code(
      provider.acquire(identity({ ...ALICE, groups: ["sales"] }), ctx()),
    );
    assert.equal(error.code, "CREDENTIAL_DENIED");
    assert.equal(error.retryable, false);
  });

  it("403 for another distribution is CREDENTIAL_DENIED", async () => {
    const error = await code(
      provider.acquire(identity(ALICE), { distributionId: "othercode" }),
    );
    assert.equal(error.code, "CREDENTIAL_DENIED");
  });

  it("a reused key with other input is an idempotency conflict", async () => {
    const key = crypto.randomUUID();
    await provider.acquire(identity(ALICE), ctx({ idempotencyKey: key }));
    const error = await code(
      provider.acquire(identity(BOB), ctx({ idempotencyKey: key })),
    );
    assert.equal(error.code, "CREDENTIAL_ACQUIRE_FAILED");
    assert.equal(error.sanitizedDetail.reason, "idempotency-conflict");
    assert.equal(error.retryable, false);
  });

  it("a request still in flight is retryable after 1 s", async () => {
    const key = crypto.randomUUID();
    h.litellm.state.generateDelayMs = 300;
    const first = provider.acquire(
      identity(ALICE),
      ctx({ idempotencyKey: key }),
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    const error = await code(
      provider.acquire(identity(ALICE), ctx({ idempotencyKey: key })),
    );
    h.litellm.state.generateDelayMs = 0;
    assert.equal(error.sanitizedDetail.reason, "unavailable");
    assert.equal(error.retryable, true);
    assert.equal(error.retryAfterMs, 1000);
    await first;
  });

  it("an upstream LiteLLM failure is retryable with Retry-After", async () => {
    h.litellm.state.faults.set("/key/generate", { status: 500, count: 1 });
    const error = await code(provider.acquire(identity(ALICE), ctx()));
    assert.equal(error.code, "CREDENTIAL_ACQUIRE_FAILED");
    assert.equal(error.sanitizedDetail.reason, "unavailable");
    assert.equal(error.retryable, true);
    assert.equal(error.retryAfterMs, 5000);
  });

  it("a rate limit is retryable with Retry-After", async () => {
    const limited = await startHarness({
      BROKER_ACQUIRE_LIMIT_PER_MINUTE: "1",
    });
    try {
      const p = new HttpBrokerCredentialProvider({
        endpoint: `${limited.url}/v1/credential`,
        fetch: globalThis.fetch,
      });
      const id = {
        subject: ALICE.sub,
        issuer: ISSUER,
        accessToken: new SecretValue(limited.keycloak.mint(ALICE)),
      };
      await p.acquire(id, ctx());
      const error = await code(p.acquire(id, ctx()));
      assert.equal(error.sanitizedDetail.reason, "rate-limited");
      assert.equal(error.retryable, true);
      assert.ok(error.retryAfterMs >= 1000);
    } finally {
      await limited.close();
    }
  });

  it("revoke deletes the key, and a second revoke still counts as revoked", async () => {
    const credential = await provider.acquire(identity(ALICE), ctx());
    await provider.revoke(credential, ctx());
    assert.ok(!h.litellm.keys.has(credential.secret.reveal()));
    await provider.revoke(credential, ctx());
  });

  it("a revoke LiteLLM cannot complete is a retryable CREDENTIAL_REVOKED", async () => {
    const credential = await provider.acquire(identity(ALICE), ctx());
    h.litellm.state.faults.set("/key/delete", { status: 500, count: 1 });
    const error = await code(provider.revoke(credential, ctx()));
    assert.equal(error.code, "CREDENTIAL_REVOKED");
    assert.equal(error.retryable, true);
  });
});
