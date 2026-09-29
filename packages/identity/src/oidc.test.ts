import { generateKeyPairSync, sign } from "node:crypto";
import { inspect } from "node:util";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type ManagedFetch,
  PiShipError,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  OidcPkceIdentityProvider,
  identityMetadata,
  identitySecret,
  restoreIdentitySession,
} from "./index.js";

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let services: Services;
beforeEach(async () => {
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
});

function provider(overrides: Record<string, unknown> = {}) {
  return new OidcPkceIdentityProvider({
    issuer: services.issuer,
    clientId: services.clientId,
    scopes: ["openid", "profile", "email"],
    redirectUri: "http://127.0.0.1/callback",
    fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
    ...overrides,
  });
}
const approve = (url: string) => {
  void services.approve(url);
};

describe("OIDC Authorization Code + PKCE (deterministic fixture, not live evidence)", () => {
  it("signs in with S256, state, and nonce, and keeps tokens secret", async () => {
    const identity = provider();
    const session = await identity.login({ openUrl: approve });
    expect(session).toMatchObject({
      subject: "demo-user-1",
      issuer: services.issuer,
      displayName: "Demo Developer",
      email: "developer@demo.example",
    });
    expect(session.accessToken).toBeInstanceOf(SecretValue);
    expect(JSON.stringify(session)).not.toContain(
      session.accessToken?.reveal() ?? "missing",
    );
    const authorization = services.state.authorizations[0];
    expect(authorization).toMatchObject({
      response_type: "code",
      code_challenge_method: "S256",
      client_id: services.clientId,
    });
    expect(authorization.state).toMatch(/^[\w-]{20,}$/);
    expect(authorization.nonce).toMatch(/^[\w-]{20,}$/);
    expect(authorization.code_challenge).toMatch(/^[\w-]{43}$/);
    expect(Object.keys(authorization)).not.toContain("client_secret");
    const tokenRequest = services.state.requests.find(
      (item: { path: string }) => item.path === "/idp/token",
    );
    expect(tokenRequest.body).toContain("code_verifier=");
    expect(tokenRequest.body).not.toContain("client_secret");
    const metadata = identityMetadata(session, "piship:acme:identity#1");
    expect(JSON.stringify(metadata)).not.toContain(
      session.accessToken?.reveal(),
    );
    expect(JSON.stringify(metadata)).not.toContain(
      session.refreshToken?.reveal(),
    );
    const restored = restoreIdentitySession(metadata, identitySecret(session));
    expect(restored.refreshToken?.reveal()).toBe(
      session.refreshToken?.reveal(),
    );
  });

  it("refreshes the same subject and revokes tokens on logout", async () => {
    const identity = provider();
    const session = await identity.login({ openUrl: approve });
    const refreshed = await identity.refresh(session);
    expect(refreshed.subject).toBe(session.subject);
    expect(refreshed.accessToken?.reveal()).not.toBe(
      session.accessToken?.reveal(),
    );
    await expect(identity.refresh(session)).rejects.toMatchObject({
      code: "IDENTITY_EXPIRED",
    });
    await identity.logout(refreshed);
    expect(services.state.revokedTokens).toHaveLength(2);
    await expect(identity.refresh(refreshed)).rejects.toMatchObject({
      code: "IDENTITY_EXPIRED",
    });
  });

  it("rejects a refresh whose ID token names another subject or issuer", async () => {
    const identity = provider();
    const session = await identity.login({ openUrl: approve });
    services.knobs.refreshSubject = "someone-else";
    await expect(identity.refresh(session)).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("does not match the signed-in subject"),
    });
    services.knobs.refreshSubject = undefined;
    // The same subject under another issuer is another principal.
    const other = await identity.login({ openUrl: approve });
    await expect(
      identity.refresh({ ...other, issuer: "https://other.example/idp" }),
    ).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("does not match the signed-in subject"),
    });
  });

  it.each([
    ["idTokenIssuer", "https://evil.example/idp", "IDENTITY_INVALID", /iss/],
    ["idTokenAudience", "another-client", "IDENTITY_INVALID", /aud/],
    ["idTokenNonce", "replayed-nonce", "IDENTITY_INVALID", /nonce/],
    [
      "signWithRogueKey",
      true,
      "IDENTITY_INVALID",
      /signature verification failed/,
    ],
    ["idTokenExpired", true, "IDENTITY_EXPIRED", /exp/],
    ["idTokenNotBefore", true, "IDENTITY_EXPIRED", /nbf/],
    ["stateOverride", "attacker-state", "IDENTITY_INVALID", /state/],
  ])("rejects a response with %s", async (knob, value, code, message) => {
    services.knobs[knob] = value;
    const error = await provider()
      .login({ openUrl: approve })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code });
    expect((error as Error).message).toMatch(message);
  });

  it("reports an identity provider that does not answer in time as retryable", async () => {
    const timedOut = provider({
      fetch: (async () => {
        throw new DOMException("The operation timed out", "TimeoutError");
      }) as ManagedFetch,
    });
    await expect(timedOut.configuration()).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
      component: "identity",
      message:
        "OIDC discovery failed: the identity provider did not respond in time",
    });
  });
  describe("token endpoint failures", () => {
    const PAGE_SENTINEL = "proxy-page-sentinel-0123456789";
    /** No token in the message, action, detail, cause, or any rendering. */
    function expectNoSecret(error: unknown, secrets: readonly string[]): void {
      const rendered = [
        String(error),
        JSON.stringify(error),
        inspect(error, { depth: 10, showHidden: true }),
        String((error as { cause?: unknown }).cause ?? ""),
      ].join("\n");
      for (const secret of [...secrets, PAGE_SENTINEL])
        expect(rendered).not.toContain(secret);
    }
    const inThirtySeconds = () => new Date(Date.now() + 30_000);

    // Regression: a transient 5xx or 429 used to map to the non-retryable
    // IDENTITY_INVALID ("contact your administrator").
    it.each([
      [{ status: 503, retryAfter: 7 }, "GATEWAY_UNREACHABLE", 7_000],
      [{ status: 500 }, "GATEWAY_UNREACHABLE", undefined],
      [
        {
          status: 502,
          body: `<html><body>${PAGE_SENTINEL} Bad gateway</body></html>`,
          retryAfter: 3,
        },
        "GATEWAY_UNREACHABLE",
        3_000,
      ],
      [{ status: 429, retryAfter: 4 }, "GATEWAY_RATE_LIMITED", 4_000],
      [{ status: 429, retryAfter: "date" }, "GATEWAY_RATE_LIMITED", "date"],
      [
        { status: 400, body: { error: "temporarily_unavailable" } },
        "GATEWAY_UNREACHABLE",
        undefined,
      ],
    ] as const)(
      "refresh: maps %j to retryable %s",
      async (fault, code, wait) => {
        const identity = provider();
        const session = await identity.login({ openUrl: approve });
        services.knobs.tokenFaults.push({
          ...fault,
          ...(fault.retryAfter === "date"
            ? { retryAfter: inThirtySeconds() }
            : {}),
        });
        const error = (await identity
          .refresh(session)
          .catch((caught: unknown) => caught)) as PiShipError;
        expect(error).toBeInstanceOf(PiShipError);
        expect(error).toMatchObject({
          code,
          retryable: true,
          component: "identity",
          message: expect.stringContaining(`HTTP ${fault.status}`),
        });
        if (wait === "date") {
          expect(error.retryAfterMs).toBeGreaterThan(20_000);
          expect(error.retryAfterMs).toBeLessThanOrEqual(30_000);
        } else expect(error.retryAfterMs).toBe(wait);
        expectNoSecret(error, [
          session.accessToken?.reveal() ?? "missing",
          session.refreshToken?.reveal() ?? "missing",
        ]);
        // The refresh token was not spent, so the next refresh succeeds.
        await expect(identity.refresh(session)).resolves.toMatchObject({
          subject: session.subject,
        });
      },
    );

    it.each([
      [{ status: 400, body: { error: "invalid_grant" } }, "IDENTITY_EXPIRED"],
      [{ status: 401, body: { error: "invalid_client" } }, "IDENTITY_INVALID"],
      [
        { status: 404, body: `<html>${PAGE_SENTINEL}</html>` },
        "IDENTITY_INVALID",
      ],
    ] as const)(
      "refresh: keeps %j non-retryable as %s",
      async (fault, code) => {
        const identity = provider();
        const session = await identity.login({ openUrl: approve });
        services.knobs.tokenFaults.push(fault);
        const error = await identity
          .refresh(session)
          .catch((caught: unknown) => caught);
        expect(error).toMatchObject({ code, retryable: false });
        expectNoSecret(error, [
          session.accessToken?.reveal() ?? "missing",
          session.refreshToken?.reveal() ?? "missing",
        ]);
      },
    );

    it("sign-in: a token endpoint outage is retryable", async () => {
      services.knobs.tokenFaults.push({ status: 503, retryAfter: 2 });
      const error = await provider()
        .login({ openUrl: approve })
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        code: "GATEWAY_UNREACHABLE",
        retryable: true,
        retryAfterMs: 2_000,
        message: expect.stringMatching(/^Sign-in failed:/),
      });
      expectNoSecret(error, []);
    });

    it("refresh: a token endpoint that never answers times out retryably", async () => {
      const identity = provider({ timeoutSeconds: 1 });
      const session = await identity.login({ openUrl: approve });
      services.knobs.tokenFaults.push({ timeoutMs: 5_000 });
      const started = Date.now();
      const error = await identity
        .refresh(session)
        .catch((caught: unknown) => caught);
      expect(Date.now() - started).toBeLessThan(4_000);
      expect(error).toMatchObject({
        code: "GATEWAY_UNREACHABLE",
        retryable: true,
      });
      expectNoSecret(error, [
        session.accessToken?.reveal() ?? "missing",
        session.refreshToken?.reveal() ?? "missing",
      ]);
    });
  });

  it("reports a denied sign-in, cancellation, and timeout visibly", async () => {
    services.knobs.denyLogin = true;
    await expect(provider().login({ openUrl: approve })).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("denied"),
    });
    const controller = new AbortController();
    await expect(
      provider().login({
        openUrl: () => controller.abort(),
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: expect.stringContaining("cancelled"),
    });
    await expect(
      provider().login({ openUrl: () => {}, timeoutMs: 50 }),
    ).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: expect.stringContaining("timed out"),
    });
  });

  it("refuses discovery from a non-loopback plain-HTTP issuer and undeclared private-only hosts", async () => {
    await expect(
      provider({ issuer: "http://idp.example" }).login({ openUrl: approve }),
    ).rejects.toThrow(/HTTPS/);
    const privateOnly = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      privateOnly: true,
      allowHosts: ["idp.internal.example"],
    });
    await expect(
      provider({ fetch: privateOnly }).login({ openUrl: approve }),
    ).rejects.toMatchObject({
      code: "NETWORK_DENIED",
    });
  });
});

describe("ID token authorized party (deterministic fixture, not live evidence)", () => {
  // The fixture signs ID tokens with a single audience. To exercise the
  // authorized-party rules, this test re-signs the fixture's ID token with its
  // own key and serves that key as the provider's JWKS, through the managed
  // fetch the provider already uses for every OIDC request.
  function resigning(patch: (claims: Record<string, unknown>) => void) {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const kid = "azp-test";
    const jwk = {
      ...publicKey.export({ format: "jwk" }),
      kid,
      alg: "RS256",
      use: "sig",
    };
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    const fetch: ManagedFetch = async (url, init) => {
      const response = await base(url, init);
      const path = new URL(String(url)).pathname;
      if (path === "/idp/jwks") return Response.json({ keys: [jwk] });
      if (path !== "/idp/token" || !response.ok) return response;
      const body = (await response.json()) as { id_token: string };
      const claims = JSON.parse(
        Buffer.from(body.id_token.split(".")[1] ?? "", "base64url").toString(
          "utf8",
        ),
      ) as Record<string, unknown>;
      patch(claims);
      const header = Buffer.from(
        JSON.stringify({ alg: "RS256", kid, typ: "JWT" }),
      ).toString("base64url");
      const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
      const signature = sign(
        "sha256",
        Buffer.from(`${header}.${payload}`),
        privateKey,
      ).toString("base64url");
      return Response.json({
        ...body,
        id_token: `${header}.${payload}.${signature}`,
      });
    };
    return provider({ fetch });
  }

  it("rejects multiple audiences with a wrong authorized party", async () => {
    const error = await resigning((claims) => {
      claims.aud = [services.clientId, "api://other-service"];
      claims.azp = "another-client";
    })
      .login({ openUrl: approve })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect((error as Error).message).toMatch(/azp/);
  });

  it("rejects multiple audiences without an authorized party", async () => {
    const error = await resigning((claims) => {
      claims.aud = [services.clientId, "api://other-service"];
    })
      .login({ openUrl: approve })
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect((error as Error).message).toMatch(/aud/);
  });

  it("accepts multiple audiences when this client is the authorized party", async () => {
    const session = await resigning((claims) => {
      claims.aud = [services.clientId, "api://other-service"];
      claims.azp = services.clientId;
    }).login({ openUrl: approve });
    expect(session.subject).toBe("demo-user-1");
    expect(session.claims?.azp).toBe(services.clientId);
  });
});
