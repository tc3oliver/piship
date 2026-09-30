// The broker against PiShip's own http-broker client: HttpBrokerCredentialProvider
// from packages/credentials, built in this repository (`npm run build` at the
// root first). PISHIP_REPO_ROOT may point at another checkout's root.
//
//   node --test test/
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
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
const { CredentialManager, HttpBrokerCredentialProvider, MemorySecretStore } =
  await import(pathToFileURL(credentialsDist).href);
const { SecretValue } = await import(pathToFileURL(contractsDist).href);

const ALICE = { sub: "0f1e2d3c-alice", groups: ["/engineering"] };
const BOB = { sub: "9a8b7c6d-bob", groups: ["/support"] };
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
    // The same principal, first with a body PiShip would not send: records
    // are per principal, so another user's key is never a conflict.
    const key = crypto.randomUUID();
    const first = await h.acquire(h.keycloak.mint(ALICE), {
      key,
      body: { distribution: "acmecode", purpose: "inference", extra: 1 },
    });
    assert.equal(first.status, 200);
    const error = await code(
      provider.acquire(identity(ALICE), ctx({ idempotencyKey: key })),
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

describe("PiShip CredentialManager against the reference broker: durable idempotency", () => {
  let h;
  let temp;
  const metadataPath = () =>
    join(temp, "credentials-metadata", "inference.json");
  const pendingKey = () => {
    const file = join(temp, "credentials-metadata", "pending-issuance.json");
    return existsSync(file)
      ? JSON.parse(readFileSync(file, "utf8")).idempotency_key
      : null;
  };
  const manager = (fetch, extra = {}) =>
    new CredentialManager({
      distributionId: "acmecode",
      provider: new HttpBrokerCredentialProvider({
        endpoint: `${h.url}/v1/credential`,
        fetch,
        expectedBaseUrl: GATEWAY_BASE_URL,
      }),
      store: new MemorySecretStore(),
      metadataPath: metadataPath(),
      beforeExpirySeconds: 300,
      ...extra,
    });
  const alice = () => ({
    subject: ALICE.sub,
    issuer: ISSUER,
    accessToken: new SecretValue(h.keycloak.mint(ALICE)),
  });

  beforeEach(async () => {
    h = await startHarness({ BROKER_ACQUIRE_LIMIT_PER_MINUTE: "50" });
    temp = mkdtempSync(join(tmpdir(), "piship-broker-issuance-"));
  });
  afterEach(async () => {
    await h.close();
    rmSync(temp, { recursive: true, force: true });
  });

  it("an acquire whose answer was lost is recovered by the next process with the same key: one LiteLLM key", async () => {
    // The broker issues and answers; the answer is lost on the way back.
    const lossy = async (url, init) => {
      const response = await fetch(url, init);
      await response.text();
      throw new TypeError("fetch failed", { cause: { code: "ECONNRESET" } });
    };
    await assert.rejects(
      manager(lossy).ensure(alice(), ctx(), { allowAcquire: true }),
      (error) => error.sanitizedDetail.outcome === "unknown",
    );
    const key = pendingKey();
    assert.ok(key);
    assert.equal(h.litellm.keys.size, 1);
    // A new manager reads the key from disk; a new identity token of the
    // same principal is the same input to the broker.
    const active = await manager(globalThis.fetch).ensure(alice(), ctx(), {
      allowAcquire: true,
    });
    assert.equal(h.litellm.keys.size, 1);
    assert.ok(h.litellm.keys.has(active.secret.reveal()));
    assert.equal(pendingKey(), null);
    assert.ok(
      h.logLines.some((line) => JSON.parse(line).idempotency === "replay"),
    );
  });

  it("a PiShip process killed after the broker answered and before it committed: the next process gets the same credential", async () => {
    const script = join(temp, "acquire.mjs");
    writeFileSync(
      script,
      `import { CredentialManager, HttpBrokerCredentialProvider, MemorySecretStore } from ${JSON.stringify(pathToFileURL(credentialsDist).href)};
import { SecretValue } from ${JSON.stringify(pathToFileURL(contractsDist).href)};
const [url, metadataPath, subject, issuer, token] = process.argv.slice(2);
// The answer arrives, the parent is told, and this process never commits it.
const stalled = async (target, init) => {
  const response = await fetch(target, init);
  await response.text();
  process.stdout.write("answered\\n");
  return new Promise(() => {});
};
setInterval(() => {}, 1000);
await new CredentialManager({
  distributionId: "acmecode",
  provider: new HttpBrokerCredentialProvider({ endpoint: url, fetch: stalled }),
  store: new MemorySecretStore(),
  metadataPath,
  beforeExpirySeconds: 300,
}).ensure({ subject, issuer, accessToken: new SecretValue(token) }, { distributionId: "acmecode" }, { allowAcquire: true });
`,
    );
    // The token is a test token of the fake Keycloak, passed as an argument
    // to the child only.
    const child = spawn(
      process.execPath,
      [
        script,
        `${h.url}/v1/credential`,
        metadataPath(),
        ALICE.sub,
        ISSUER,
        h.keycloak.mint(ALICE),
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const exited = new Promise((done) =>
      child.on("exit", (_code, signal) => done(signal)),
    );
    child.stdout.on("data", (chunk) => {
      if (String(chunk).includes("answered")) child.kill("SIGKILL");
    });
    assert.equal(await exited, "SIGKILL");
    assert.equal(h.litellm.keys.size, 1);
    assert.ok(pendingKey());
    assert.equal(existsSync(metadataPath()), false);

    const active = await manager(globalThis.fetch, {
      // The killed process left its lock: take it over without the
      // production wait.
      lockTiming: { heartbeatMs: 50, staleMs: 300, waitMs: 5000 },
    }).ensure(alice(), ctx(), { allowAcquire: true });
    assert.equal(h.litellm.keys.size, 1);
    assert.ok(h.litellm.keys.has(active.secret.reveal()));
    assert.equal(pendingKey(), null);
  });
});
