import { createHash, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";

// The knobs of the demo-company fixture services, tested at the HTTP level so a
// regression in the fixture is caught here and not as a confusing failure in a
// consumer. Deterministic loopback fixtures; not evidence of a live integration.

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let services: Services;
beforeEach(async () => {
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
});

const REDIRECT = "http://127.0.0.1:8765/callback";
const PAYLOAD = { distribution: "acmecode", purpose: "inference" };

function form(values: Record<string, string>) {
  return {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: services.clientId,
      ...values,
    }).toString(),
  };
}

const tokenEndpoint = (values: Record<string, string>) =>
  fetch(`${services.issuer}/token`, form(values));

const claimsOf = (idToken: string) =>
  JSON.parse(Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString());

/** Act as the browser up to the redirect; the code is not exchanged yet. */
async function authorize() {
  const verifier = randomBytes(32).toString("base64url");
  const url = new URL(`${services.issuer}/authorize`);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: services.clientId,
    redirect_uri: REDIRECT,
    scope: "openid profile email",
    state: "state-1",
    nonce: "nonce-1",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  }).toString();
  const redirect = await fetch(url, { redirect: "manual" });
  const code = new URL(redirect.headers.get("location") ?? "").searchParams.get(
    "code",
  );
  return { code: code ?? "", verifier };
}

const exchange = ({ code, verifier }: { code: string; verifier: string }) =>
  tokenEndpoint({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    redirect_uri: REDIRECT,
  });

async function login() {
  const response = await exchange(await authorize());
  expect(response.status).toBe(200);
  const tokens = await response.json();
  return { tokens, claims: claimsOf(tokens.id_token) };
}

const refresh = (token: string) =>
  tokenEndpoint({ grant_type: "refresh_token", refresh_token: token });

interface AcquireOptions {
  key?: string;
  header?: string;
  body?: unknown;
  signal?: AbortSignal;
}

function acquire(accessToken: string, options: AcquireOptions = {}) {
  return fetch(services.brokerUrl, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
      ...(options.key === undefined
        ? {}
        : { [options.header ?? "Idempotency-Key"]: options.key }),
    },
    body:
      typeof options.body === "string"
        ? options.body
        : JSON.stringify(options.body ?? PAYLOAD),
    ...(options.signal ? { signal: options.signal } : {}),
  });
}

const revoke = (bearer: string, signal?: AbortSignal) =>
  fetch(services.revokeUrl, {
    method: "POST",
    headers: { authorization: `Bearer ${bearer}` },
    body: "{}",
    ...(signal ? { signal } : {}),
  });

const credentialSubjects = () =>
  [...services.state.credentials.values()].map(
    (entry: { subject: string }) => entry.subject,
  );

describe("subject and identity attributes", () => {
  it("signs in as the fictional demo developer by default", async () => {
    const { claims } = await login();
    expect(claims).toMatchObject({
      iss: services.issuer,
      sub: "demo-user-1",
      email: "developer@demo.example",
      name: "Demo Developer",
    });
  });

  it("issues tokens for the chosen subject, Alice and then Bob, from one provider", async () => {
    services.knobs.subject = "alice";
    const alice = await login();
    services.knobs.subject = "bob";
    const bob = await login();
    expect(alice.claims).toMatchObject({ iss: services.issuer, sub: "alice" });
    expect(bob.claims).toMatchObject({ iss: services.issuer, sub: "bob" });
  });

  it("attributes broker credentials to the subject that signed in", async () => {
    services.knobs.subject = "alice";
    const alice = await login();
    services.knobs.subject = "bob";
    const bob = await login();
    await acquire(alice.tokens.access_token);
    await acquire(bob.tokens.access_token);
    expect(credentialSubjects()).toEqual(["alice", "bob"]);
  });

  it("takes email and display name from their own knobs", async () => {
    Object.assign(services.knobs, {
      subject: "alice",
      email: "alice@acme.example",
      displayName: "Alice Example",
    });
    const { claims } = await login();
    expect(claims).toMatchObject({
      sub: "alice",
      email: "alice@acme.example",
      name: "Alice Example",
    });
  });

  it("keeps the demo email and name when only the subject changes", async () => {
    services.knobs.subject = "bob";
    const { claims } = await login();
    expect(claims).toMatchObject({
      sub: "bob",
      email: "developer@demo.example",
      name: "Demo Developer",
    });
  });

  it("uses the subject captured when the browser approved, not the one at code exchange", async () => {
    services.knobs.subject = "alice";
    const pending = await authorize();
    services.knobs.subject = "bob";
    const tokens = await (await exchange(pending)).json();
    expect(claimsOf(tokens.id_token).sub).toBe("alice");
  });

  it("keeps the session subject on refresh unless refreshSubject is set", async () => {
    services.knobs.subject = "alice";
    const { tokens } = await login();
    services.knobs.subject = "bob";
    const refreshed = await (await refresh(tokens.refresh_token)).json();
    expect(claimsOf(refreshed.id_token).sub).toBe("alice");
  });

  it("claims refreshSubject on the refresh grant and carries it to later grants", async () => {
    services.knobs.subject = "alice";
    const { tokens } = await login();
    services.knobs.refreshSubject = "mallory";
    const refreshed = await (await refresh(tokens.refresh_token)).json();
    expect(claimsOf(refreshed.id_token).sub).toBe("mallory");
    await acquire(refreshed.access_token);
    expect(credentialSubjects()).toEqual(["mallory"]);
    services.knobs.refreshSubject = undefined;
    const again = await (await refresh(refreshed.refresh_token)).json();
    expect(claimsOf(again.id_token).sub).toBe("mallory");
  });

  it("issues refreshed tokens under an issuer set after sign-in", async () => {
    const { tokens } = await login();
    services.knobs.idTokenIssuer = "https://other-issuer.example";
    const refreshed = await (await refresh(tokens.refresh_token)).json();
    expect(claimsOf(refreshed.id_token).iss).toBe(
      "https://other-issuer.example",
    );
  });
});

describe("broker idempotency", () => {
  it("is off by default: a repeated key issues a second credential and records nothing", async () => {
    const { tokens } = await login();
    const first = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    const second = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    expect(second.credential).not.toBe(first.credential);
    expect(services.state.credentialCount).toBe(2);
    expect(services.state.idempotencyKeys).toEqual([]);
  });

  it("records every key the client sends, in order, repeats included", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    for (const key of ["key-1", "key-2", "key-1"])
      await acquire(tokens.access_token, { key });
    expect(services.state.idempotencyKeys).toEqual(["key-1", "key-2", "key-1"]);
  });

  it("does not record a key when the client sends none", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    const response = await acquire(tokens.access_token);
    expect(response.status).toBe(200);
    expect(services.state.idempotencyKeys).toEqual([]);
  });

  it("replays the original result for a repeated key with the same input", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    const first = await acquire(tokens.access_token, { key: "key-1" });
    const second = await acquire(tokens.access_token, { key: "key-1" });
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual(await first.json());
    expect(first.headers.get("idempotent-replayed")).toBeNull();
    expect(second.headers.get("idempotent-replayed")).toBe("true");
    expect(services.state.credentialCount).toBe(1);
  });

  it("replays the original result even when the access token was refreshed in between", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    const first = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    const refreshed = await (await refresh(tokens.refresh_token)).json();
    const second = await (
      await acquire(refreshed.access_token, { key: "key-1" })
    ).json();
    expect(second).toEqual(first);
  });

  it("treats a body with the same fields in another order as the same input", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    await acquire(tokens.access_token, {
      key: "key-1",
      body: '{"distribution":"acmecode","purpose":"inference"}',
    });
    const second = await acquire(tokens.access_token, {
      key: "key-1",
      body: '{"purpose":"inference","distribution":"acmecode"}',
    });
    expect(second.status).toBe(200);
    expect(services.state.credentialCount).toBe(1);
  });

  it("rejects a repeated key with different input as 409 and issues nothing", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    const first = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    const conflict = await acquire(tokens.access_token, {
      key: "key-1",
      body: { ...PAYLOAD, distribution: "othercode" },
    });
    expect(conflict.status).toBe(409);
    expect(services.state.credentialCount).toBe(1);
    const replay = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    expect(replay).toEqual(first);
  });

  it("rejects a key first used by another subject as 409", async () => {
    services.knobs.brokerIdempotency = true;
    services.knobs.subject = "alice";
    const alice = await login();
    services.knobs.subject = "bob";
    const bob = await login();
    await acquire(alice.tokens.access_token, { key: "key-1" });
    const conflict = await acquire(bob.tokens.access_token, { key: "key-1" });
    expect(conflict.status).toBe(409);
    expect(credentialSubjects()).toEqual(["alice"]);
  });

  it("issues a new credential for a new key", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    const first = await (
      await acquire(tokens.access_token, { key: "key-1" })
    ).json();
    const second = await (
      await acquire(tokens.access_token, { key: "key-2" })
    ).json();
    expect(second.credential).not.toBe(first.credential);
    expect(services.state.credentialCount).toBe(2);
  });

  it("reads the key from the header named by brokerIdempotencyHeader", async () => {
    Object.assign(services.knobs, {
      brokerIdempotency: true,
      brokerIdempotencyHeader: "X-Request-Id",
    });
    const { tokens } = await login();
    await acquire(tokens.access_token, { key: "key-1" });
    await acquire(tokens.access_token, {
      key: "key-2",
      header: "X-Request-Id",
    });
    await acquire(tokens.access_token, {
      key: "key-2",
      header: "x-request-id",
    });
    expect(services.state.idempotencyKeys).toEqual(["key-2", "key-2"]);
    expect(services.state.credentialCount).toBe(2);
  });

  it("does not consume a key on a request the broker failed", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    services.knobs.brokerStatus = 503;
    expect((await acquire(tokens.access_token, { key: "key-1" })).status).toBe(
      503,
    );
    services.knobs.brokerStatus = undefined;
    const retry = await acquire(tokens.access_token, { key: "key-1" });
    expect(retry.status).toBe(200);
    expect(retry.headers.get("idempotent-replayed")).toBeNull();
    expect(services.state.credentialCount).toBe(1);
  });

  it("does not record a key for an unauthenticated request", async () => {
    services.knobs.brokerIdempotency = true;
    const response = await acquire("not-a-token", { key: "key-1" });
    expect(response.status).toBe(401);
    expect(services.state.idempotencyKeys).toEqual([]);
  });
});

interface Endpoint {
  /** Prefix of the endpoint's knobs: `<prefix>Status`, `<prefix>Faults`, ... */
  prefix: "broker" | "revoke" | "token";
  /** HTTP status the request gets when no fault is armed. */
  normal: number;
  /** Do the prerequisites now, before any fault is armed, and return the request. */
  prepare(): Promise<(signal?: AbortSignal) => Promise<Response>>;
}

const ENDPOINTS: Endpoint[] = [
  {
    prefix: "broker",
    normal: 200,
    async prepare() {
      const { tokens } = await login();
      return (signal) => acquire(tokens.access_token, signal ? { signal } : {});
    },
  },
  {
    prefix: "revoke",
    normal: 204,
    prepare: async () => (signal) => revoke("sk-unknown-credential", signal),
  },
  {
    // A refresh with an unknown token: the fixture's normal answer is 400.
    prefix: "token",
    normal: 400,
    prepare: async () => (signal) =>
      fetch(`${services.issuer}/token`, {
        ...form({ grant_type: "refresh_token", refresh_token: "unknown" }),
        ...(signal ? { signal } : {}),
      }),
  },
];

describe.each(ENDPOINTS)(
  "fault injection on the $prefix endpoint",
  (endpoint) => {
    const knob = (suffix: string) => `${endpoint.prefix}${suffix}`;
    const set = (suffix: string, value: unknown) => {
      services.knobs[knob(suffix)] = value;
    };

    it("serves normally when no fault is armed", async () => {
      const send = await endpoint.prepare();
      expect((await send()).status).toBe(endpoint.normal);
    });

    it("answers the configured status on every request until it is cleared", async () => {
      const send = await endpoint.prepare();
      set("Status", 503);
      expect((await send()).status).toBe(503);
      expect((await send()).status).toBe(503);
      set("Status", undefined);
      expect((await send()).status).toBe(endpoint.normal);
    });

    it("sends Retry-After in seconds when the knob is a number", async () => {
      const send = await endpoint.prepare();
      set("Status", 429);
      set("RetryAfter", 3);
      const response = await send();
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("3");
    });

    it("sends Retry-After as an HTTP-date when the knob is a Date", async () => {
      const send = await endpoint.prepare();
      const at = new Date(Date.now() + 5_000);
      set("Status", 429);
      set("RetryAfter", at);
      const header = (await send()).headers.get("retry-after");
      expect(header).toBe(at.toUTCString());
      expect(Date.parse(header ?? "")).toBe(
        Math.floor(at.getTime() / 1000) * 1000,
      );
    });

    it("sends a string Retry-After verbatim", async () => {
      const send = await endpoint.prepare();
      set("Status", 503);
      set("RetryAfter", "soon");
      expect((await send()).headers.get("retry-after")).toBe("soon");
    });

    it("answers a string Body verbatim as HTML, like a proxy error page", async () => {
      const send = await endpoint.prepare();
      set("Status", 502);
      set("Body", "<html>Bad Gateway</html>");
      const response = await send();
      expect(response.status).toBe(502);
      expect(response.headers.get("content-type")).toContain("text/html");
      expect(await response.text()).toBe("<html>Bad Gateway</html>");
    });

    it("answers an object Body as JSON", async () => {
      const send = await endpoint.prepare();
      set("Status", 503);
      set("Body", { error: "temporarily_unavailable" });
      const response = await send();
      expect(response.headers.get("content-type")).toContain(
        "application/json",
      );
      expect(await response.json()).toEqual({
        error: "temporarily_unavailable",
      });
    });

    it("answers the default JSON error body when no Body is set", async () => {
      const send = await endpoint.prepare();
      set("Status", 500);
      const response = await send();
      expect(response.headers.get("content-type")).toContain(
        "application/json",
      );
      expect(await response.json()).toHaveProperty("error");
    });

    it("takes a queued fault's own body", async () => {
      const send = await endpoint.prepare();
      set("Faults", [{ status: 502, body: "upstream down" }]);
      const first = await send();
      expect(await first.text()).toBe("upstream down");
      expect((await send()).status).toBe(endpoint.normal);
    });

    it("sends no Retry-After unless the knob is set", async () => {
      const send = await endpoint.prepare();
      set("Status", 429);
      expect((await send()).headers.get("retry-after")).toBeNull();
    });

    it("answers normally, but only after the delay, in slow mode", async () => {
      const send = await endpoint.prepare();
      set("DelayMs", 150);
      const started = performance.now();
      const response = await send();
      expect(performance.now() - started).toBeGreaterThanOrEqual(140);
      expect(response.status).toBe(endpoint.normal);
    });

    it("does not answer within TimeoutMs, so a client with a shorter timeout gives up", async () => {
      const send = await endpoint.prepare();
      set("TimeoutMs", 5_000);
      await expect(send(AbortSignal.timeout(100))).rejects.toMatchObject({
        name: "TimeoutError",
      });
    });

    it("drops the connection without an answer once TimeoutMs has passed", async () => {
      const send = await endpoint.prepare();
      set("TimeoutMs", 150);
      const started = performance.now();
      await expect(send()).rejects.toBeInstanceOf(TypeError);
      expect(performance.now() - started).toBeGreaterThanOrEqual(140);
    });

    it("stops holding a request once the client has left, so close() does not wait for it", async () => {
      const send = await endpoint.prepare();
      set("TimeoutMs", 60_000);
      await expect(send(AbortSignal.timeout(50))).rejects.toBeDefined();
      const started = performance.now();
      await services.close();
      expect(performance.now() - started).toBeLessThan(2_000);
      services = await startLocalServices();
    });

    it("applies each queued fault to one request, oldest first, then falls back to the knobs", async () => {
      const send = await endpoint.prepare();
      set("Status", 500);
      set("Faults", [{ status: 429, retryAfter: 2 }, {}, { status: 503 }]);
      const first = await send();
      expect(first.status).toBe(429);
      expect(first.headers.get("retry-after")).toBe("2");
      expect((await send()).status).toBe(endpoint.normal);
      expect((await send()).status).toBe(503);
      expect((await send()).status).toBe(500);
      expect(services.knobs[knob("Faults")]).toEqual([]);
    });

    it("serves once normally after a one-shot fault", async () => {
      const send = await endpoint.prepare();
      set("Faults", [{ status: 503 }]);
      expect((await send()).status).toBe(503);
      expect((await send()).status).toBe(endpoint.normal);
      expect((await send()).status).toBe(endpoint.normal);
    });
  },
);

describe("timed-out requests the service still served", () => {
  it("does not issue a credential when the acquire never reaches the broker logic", async () => {
    const { tokens } = await login();
    services.knobs.brokerTimeoutMs = 5_000;
    await expect(
      acquire(tokens.access_token, { signal: AbortSignal.timeout(100) }),
    ).rejects.toBeDefined();
    expect(services.state.credentialCount).toBe(0);
  });

  it("issues the credential but withholds the answer when brokerTimeoutServes is set", async () => {
    const { tokens } = await login();
    Object.assign(services.knobs, {
      brokerTimeoutMs: 5_000,
      brokerTimeoutServes: true,
    });
    await expect(
      acquire(tokens.access_token, { signal: AbortSignal.timeout(100) }),
    ).rejects.toBeDefined();
    expect(services.state.credentialCount).toBe(1);
  });

  it("replays that credential to a retry with the same key", async () => {
    services.knobs.brokerIdempotency = true;
    const { tokens } = await login();
    Object.assign(services.knobs, {
      brokerTimeoutMs: 5_000,
      brokerTimeoutServes: true,
    });
    await expect(
      acquire(tokens.access_token, {
        key: "key-1",
        signal: AbortSignal.timeout(100),
      }),
    ).rejects.toBeDefined();
    Object.assign(services.knobs, {
      brokerTimeoutMs: 0,
      brokerTimeoutServes: false,
    });
    const retry = await acquire(tokens.access_token, { key: "key-1" });
    expect(retry.headers.get("idempotent-replayed")).toBe("true");
    expect((await retry.json()).credential).toBe(
      [...services.state.credentials.keys()][0],
    );
    expect(services.state.credentialCount).toBe(1);
    expect(services.state.idempotencyKeys).toEqual(["key-1", "key-1"]);
  });

  it("does not issue anything when the client leaves during the delay of slow mode", async () => {
    const { tokens } = await login();
    services.knobs.brokerDelayMs = 400;
    await expect(
      acquire(tokens.access_token, { signal: AbortSignal.timeout(100) }),
    ).rejects.toBeDefined();
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(services.state.credentialCount).toBe(0);
  });

  it("revokes the credential but withholds the answer when revokeTimeoutServes is set", async () => {
    const { tokens } = await login();
    const issued = await (await acquire(tokens.access_token)).json();
    Object.assign(services.knobs, {
      revokeTimeoutMs: 5_000,
      revokeTimeoutServes: true,
    });
    await expect(
      revoke(issued.credential, AbortSignal.timeout(100)),
    ).rejects.toBeDefined();
    expect(services.state.revokedCredentials).toEqual([issued.credential_id]);
  });

  it("does not revoke when revokeTimeoutMs alone holds the request", async () => {
    const { tokens } = await login();
    const issued = await (await acquire(tokens.access_token)).json();
    services.knobs.revokeTimeoutMs = 5_000;
    await expect(
      revoke(issued.credential, AbortSignal.timeout(100)),
    ).rejects.toBeDefined();
    expect(services.state.revokedCredentials).toEqual([]);
  });

  it("issues tokens but withholds the answer when tokenTimeoutServes is set", async () => {
    const pending = await authorize();
    Object.assign(services.knobs, {
      tokenTimeoutMs: 5_000,
      tokenTimeoutServes: true,
    });
    await expect(
      fetch(`${services.issuer}/token`, {
        ...form({
          grant_type: "authorization_code",
          code: pending.code,
          code_verifier: pending.verifier,
          redirect_uri: REDIRECT,
        }),
        signal: AbortSignal.timeout(100),
      }),
    ).rejects.toBeDefined();
    expect(services.state.refreshTokens.size).toBe(1);
  });
});

describe("token endpoint faults", () => {
  it("fails the code exchange with a 5xx once and leaves the code usable for a retry", async () => {
    const pending = await authorize();
    services.knobs.tokenFaults.push({ status: 503 });
    expect((await exchange(pending)).status).toBe(503);
    const retry = await exchange(pending);
    expect(retry.status).toBe(200);
    expect(claimsOf((await retry.json()).id_token).sub).toBe("demo-user-1");
  });

  it("fails every refresh with a 5xx while tokenStatus is set, then recovers", async () => {
    const { tokens } = await login();
    services.knobs.tokenStatus = 500;
    expect((await refresh(tokens.refresh_token)).status).toBe(500);
    expect((await refresh(tokens.refresh_token)).status).toBe(500);
    services.knobs.tokenStatus = undefined;
    expect((await refresh(tokens.refresh_token)).status).toBe(200);
  });

  it("does not consume the refresh token on a failed refresh", async () => {
    const { tokens } = await login();
    services.knobs.tokenFaults.push({ status: 502 });
    expect((await refresh(tokens.refresh_token)).status).toBe(502);
    expect(services.state.refreshTokens.has(tokens.refresh_token)).toBe(true);
  });

  it("leaves discovery and the signing keys alone", async () => {
    services.knobs.tokenStatus = 500;
    const discovery = await fetch(
      `${services.issuer}/.well-known/openid-configuration`,
    );
    const keys = await fetch(`${services.issuer}/jwks`);
    expect([discovery.status, keys.status]).toEqual([200, 200]);
  });

  it("does not affect the broker", async () => {
    const { tokens } = await login();
    services.knobs.tokenStatus = 500;
    expect((await acquire(tokens.access_token)).status).toBe(200);
  });
});

describe("fixture state and defaults", () => {
  it("has every new knob off by default", () => {
    expect(services.knobs).toMatchObject({
      subject: "demo-user-1",
      email: undefined,
      displayName: undefined,
      refreshSubject: undefined,
      brokerIdempotency: false,
      brokerIdempotencyHeader: "Idempotency-Key",
      brokerStatus: undefined,
      brokerRetryAfter: undefined,
      brokerBody: undefined,
      brokerDelayMs: 0,
      brokerTimeoutMs: 0,
      brokerTimeoutServes: false,
      brokerFaults: [],
      revokeStatus: undefined,
      revokeRetryAfter: undefined,
      revokeBody: undefined,
      revokeDelayMs: 0,
      revokeTimeoutMs: 0,
      revokeTimeoutServes: false,
      revokeFaults: [],
      tokenStatus: undefined,
      tokenRetryAfter: undefined,
      tokenBody: undefined,
      tokenDelayMs: 0,
      tokenTimeoutMs: 0,
      tokenTimeoutServes: false,
      tokenFaults: [],
    });
  });

  it("starts with the knobs a test passes in options", async () => {
    await services.close();
    services = await startLocalServices({
      knobs: { subject: "carol", tokenFaults: [{ status: 503 }] },
    });
    expect((await tokenEndpoint({ grant_type: "x" })).status).toBe(503);
    expect((await login()).claims.sub).toBe("carol");
  });

  it("exposes issued and revoked credentials for inspection", async () => {
    const { tokens } = await login();
    const issued = await (await acquire(tokens.access_token)).json();
    expect(services.state.credentialCount).toBe(1);
    expect(services.state.revokedCredentials).toEqual([]);
    await revoke(issued.credential);
    expect(services.state.revokedCredentials).toEqual([issued.credential_id]);
  });

  it("does not let one service's faults leak into another", async () => {
    const other = await startLocalServices();
    try {
      services.knobs.brokerFaults.push({ status: 503 });
      expect(other.knobs.brokerFaults).toEqual([]);
    } finally {
      await other.close();
    }
  });
});
