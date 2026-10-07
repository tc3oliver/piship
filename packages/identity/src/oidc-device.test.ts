// identity.oidc.flow: device_code (RFC 8628) against the deterministic fixture
// IdP. Not live evidence: no real identity provider is involved.
import { generateKeyPairSync, sign } from "node:crypto";
import { inspect } from "node:util";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type DeviceCodePrompt,
  type LoginContext,
  type ManagedFetch,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { OidcPkceIdentityProvider } from "./index.js";

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let services: Services;
beforeEach(async () => {
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
});

const noWait = async () => {};

function provider(overrides: Record<string, unknown> = {}) {
  return new OidcPkceIdentityProvider({
    issuer: services.issuer,
    clientId: services.clientId,
    scopes: ["openid", "profile", "email"],
    flow: "device_code",
    fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
    sleep: noWait,
    ...overrides,
  });
}

/** A login context that records what the person would be shown. */
function context(extra: Partial<LoginContext> = {}) {
  const shown: DeviceCodePrompt[] = [];
  const ctx: LoginContext = {
    openUrl: () => {
      throw new Error("the device flow never opens an authorization URL");
    },
    presentDeviceCode: (prompt) => {
      shown.push(prompt);
    },
    ...extra,
  };
  return { ctx, shown };
}

const requestsTo = (path: string) =>
  services.state.requests.filter(
    (item: { path: string }) => item.path === path,
  );

describe("OIDC device authorization grant (deterministic fixture, not live evidence)", () => {
  it("shows the code, polls through pending and slow_down, and signs in", async () => {
    services.knobs.devicePolls = [
      "authorization_pending",
      "authorization_pending",
      "slow_down",
    ];
    services.knobs.deviceComplete = true;
    const waits: number[] = [];
    const { ctx, shown } = context();
    const session = await provider({
      sleep: async (ms: number) => {
        waits.push(ms);
      },
    }).login(ctx);

    expect(shown).toEqual([
      {
        verificationUri: `${services.issuer}/device`,
        userCode: "DEMO-CODE",
        verificationUriComplete: `${services.issuer}/device?user_code=DEMO-CODE`,
        expiresInSeconds: 300,
      },
    ]);
    // The provider's interval, the same after each pending, then +5 s.
    expect(waits).toEqual([1000, 1000, 1000, 6000]);
    expect(services.state.devicePolls).toHaveLength(4);
    expect(session).toMatchObject({
      subject: "demo-user-1",
      issuer: services.issuer,
      displayName: "Demo Developer",
      email: "developer@demo.example",
    });
    expect(session.accessToken).toBeInstanceOf(SecretValue);
    expect(session.refreshToken).toBeInstanceOf(SecretValue);
    expect(JSON.stringify(session)).not.toContain(
      session.accessToken?.reveal() ?? "missing",
    );
    // A public client with no PKCE, state, nonce, redirect, or secret.
    const [authorization] = services.state.deviceAuthorizations;
    expect(authorization).toEqual({
      client_id: services.clientId,
      scope: "openid profile email",
    });
    expect(services.state.authorizations).toEqual([]);
    for (const request of requestsTo("/idp/token"))
      expect(request.body).not.toMatch(
        /client_secret|code_verifier|redirect_uri/,
      );
  });

  it("leaves no timer behind after a sign-in, so the process can exit", async () => {
    const timers = () =>
      process.getActiveResourcesInfo().filter((name) => name === "Timeout")
        .length;
    const before = timers();
    await provider().login(context().ctx);
    expect(timers()).toBeLessThanOrEqual(before);
  });

  it("sends the audience, and never polls faster than once a second", async () => {
    services.knobs.deviceInterval = 0.1;
    const waits: number[] = [];
    await provider({
      audience: "api://acme",
      sleep: async (ms: number) => {
        waits.push(ms);
      },
    }).login(context().ctx);
    expect(services.state.deviceAuthorizations[0]).toMatchObject({
      audience: "api://acme",
    });
    expect(waits).toEqual([1000]);
  });

  it("keeps the principal, refreshes, and revokes on logout like the code flow", async () => {
    const identity = provider();
    const session = await identity.login(context().ctx);
    const refreshed = await identity.refresh(session);
    expect(refreshed.subject).toBe(session.subject);
    expect(refreshed.issuer).toBe(session.issuer);
    services.knobs.refreshSubject = "someone-else";
    await expect(identity.refresh(refreshed)).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
    });
    services.knobs.refreshSubject = undefined;
    await identity.logout(refreshed);
    expect(services.state.revokedTokens).toHaveLength(2);
  });

  it("goes through the managed fetch for every request, the device endpoint included", async () => {
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    const seen: string[] = [];
    await provider({
      fetch: ((url, init) => {
        seen.push(new URL(String(url)).pathname);
        return base(url, init);
      }) as ManagedFetch,
    }).login(context().ctx);
    expect(seen).toEqual(
      expect.arrayContaining(["/idp/devicecode", "/idp/token", "/idp/jwks"]),
    );
  });

  it("does not need the S256 check, which belongs to the code flow", async () => {
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    const session = await provider({
      fetch: (async (url, init) => {
        const response = await base(url, init);
        if (!String(url).endsWith("/.well-known/openid-configuration"))
          return response;
        return Response.json({
          ...((await response.json()) as object),
          code_challenge_methods_supported: ["plain"],
        });
      }) as ManagedFetch,
    }).login(context().ctx);
    expect(session.subject).toBe("demo-user-1");
  });

  describe("refusals before any request", () => {
    it("names the missing device endpoint as CONFIG_INVALID", async () => {
      services.knobs.deviceEndpoint = false;
      const { ctx, shown } = context();
      await expect(provider().login(ctx)).rejects.toMatchObject({
        code: "CONFIG_INVALID",
        message: expect.stringContaining("device_authorization_endpoint"),
      });
      expect(shown).toEqual([]);
      expect(requestsTo("/idp/devicecode")).toEqual([]);
    });

    it("refuses a context that cannot show the code, instead of waiting", async () => {
      await expect(
        provider().login({ openUrl: () => {} }),
      ).rejects.toMatchObject({ code: "CONFIG_UNAVAILABLE" });
      expect(requestsTo("/idp/devicecode")).toEqual([]);
    });

    it("needs a redirect URI only for the code flow", () => {
      expect(
        () =>
          new OidcPkceIdentityProvider({
            issuer: services.issuer,
            clientId: services.clientId,
            scopes: ["openid"],
            fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
          }),
      ).toThrow(/redirect URI/);
    });

    it("sends nothing when the sign-in was cancelled already", async () => {
      const controller = new AbortController();
      controller.abort();
      await expect(
        provider().login(context({ signal: controller.signal }).ctx),
      ).rejects.toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: "Sign-in was cancelled",
      });
      // A request that was sent anyway would arrive about now.
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(requestsTo("/idp/devicecode")).toEqual([]);
    });
  });

  describe("how a sign-in ends without a session", () => {
    const deviceCodes = () => [...services.state.devices.keys()] as string[];

    it("reports a declined request as IDENTITY_INVALID, without the device code", async () => {
      services.knobs.devicePolls = ["authorization_pending", "access_denied"];
      const error = await provider()
        .login(context().ctx)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        code: "IDENTITY_INVALID",
        message: expect.stringContaining("declined"),
      });
      expect(services.state.devicePolls).toHaveLength(2);
      for (const code of deviceCodes())
        expect(inspect(error, { depth: 10, showHidden: true })).not.toContain(
          code,
        );
    });

    it("reports an expired code as a timed-out sign-in", async () => {
      services.knobs.devicePolls = ["expired_token"];
      await expect(provider().login(context().ctx)).rejects.toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: expect.stringContaining("device code expired"),
      });
    });

    it("stops when the provider's expiry passes, and polls no more", async () => {
      services.knobs.deviceExpiresIn = 0.2;
      services.knobs.devicePolls = Array(50).fill("authorization_pending");
      await expect(
        provider({ sleep: undefined }).login(context().ctx),
      ).rejects.toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: expect.stringContaining("device code expired"),
      });
      expect(services.state.devicePolls).toEqual([]);
    });

    it("stops at the login deadline, and polls no more", async () => {
      services.knobs.devicePolls = Array(50).fill("authorization_pending");
      const started = Date.now();
      await expect(
        provider({ sleep: undefined }).login(context({ timeoutMs: 200 }).ctx),
      ).rejects.toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: expect.stringMatching(/^Sign-in timed out$/),
      });
      expect(Date.now() - started).toBeLessThan(900);
      expect(services.state.devicePolls).toEqual([]);
    });

    it("cancels at once on Ctrl-C and leaves no timer behind", async () => {
      services.knobs.deviceInterval = 30;
      const timers = () =>
        process.getActiveResourcesInfo().filter((name) => name === "Timeout")
          .length;
      const before = timers();
      const controller = new AbortController();
      const { ctx } = context({ signal: controller.signal });
      const login = provider({ sleep: undefined }).login(ctx);
      const outcome = login.catch((caught: unknown) => caught);
      await new Promise((resolve) => setTimeout(resolve, 100));
      const started = Date.now();
      controller.abort();
      expect(await outcome).toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: "Sign-in was cancelled",
      });
      expect(Date.now() - started).toBeLessThan(500);
      expect(timers()).toBeLessThanOrEqual(before);
      expect(services.state.devicePolls).toEqual([]);
    });

    it("cancels at once while a token request is in flight", async () => {
      services.knobs.tokenDelayMs = 3_000;
      const controller = new AbortController();
      const outcome = provider()
        .login(context({ signal: controller.signal }).ctx)
        .catch((caught: unknown) => caught);
      while (!services.state.devicePolls.length)
        await new Promise((resolve) => setTimeout(resolve, 10));
      const started = Date.now();
      controller.abort();
      expect(await outcome).toMatchObject({
        code: "IDENTITY_REQUIRED",
        message: "Sign-in was cancelled",
      });
      expect(Date.now() - started).toBeLessThan(500);
    });

    it("keeps a provider outage retryable and free of the device code", async () => {
      const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
      const error = await provider({
        fetch: ((url, init) =>
          String(url).endsWith("/devicecode")
            ? Promise.resolve(
                new Response("<html>bad gateway</html>", { status: 502 }),
              )
            : base(url, init)) as ManagedFetch,
      })
        .login(context().ctx)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        code: "GATEWAY_UNREACHABLE",
        retryable: true,
      });
    });
  });

  describe("ID token checks match the code flow", () => {
    it.each([
      ["idTokenIssuer", "https://evil.example/idp", "IDENTITY_INVALID", /iss/],
      ["idTokenAudience", "another-client", "IDENTITY_INVALID", /aud/],
      [
        "signWithRogueKey",
        true,
        "IDENTITY_INVALID",
        /signature verification failed/,
      ],
      ["idTokenExpired", true, "IDENTITY_EXPIRED", /exp/],
      ["idTokenNotBefore", true, "IDENTITY_EXPIRED", /nbf/],
    ])("rejects a response with %s", async (knob, value, code, message) => {
      services.knobs[knob] = value;
      const error = await provider()
        .login(context().ctx)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code });
      expect((error as Error).message).toMatch(message);
      // The tokens the provider did issue appear nowhere in the error.
      const rendered = inspect(error, { depth: 10, showHidden: true });
      for (const token of [
        ...services.state.idTokens,
        ...services.state.accessTokens.keys(),
        ...services.state.refreshTokens.keys(),
      ])
        expect(rendered).not.toContain(token);
    });

    it("rejects a response without an ID token", async () => {
      const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
      const error = await provider({
        fetch: (async (url, init) => {
          const response = await base(url, init);
          if (!String(url).endsWith("/token") || !response.ok) return response;
          const { id_token: _dropped, ...rest } =
            (await response.json()) as Record<string, unknown>;
          return Response.json(rest);
        }) as ManagedFetch,
      })
        .login(context().ctx)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    });

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
        const payload = Buffer.from(JSON.stringify(claims)).toString(
          "base64url",
        );
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
        .login(context().ctx)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
      expect((error as Error).message).toMatch(/azp/);
    });

    it("accepts multiple audiences when this client is the authorized party", async () => {
      const session = await resigning((claims) => {
        claims.aud = [services.clientId, "api://other-service"];
        claims.azp = services.clientId;
      }).login(context().ctx);
      expect(session.claims?.azp).toBe(services.clientId);
    });
  });

  it("denies a device endpoint on a host the network policy does not allow", async () => {
    const base = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      privateOnly: true,
      allowHosts: ["127.0.0.1"],
    });
    const { ctx, shown } = context();
    await expect(
      provider({
        fetch: (async (url, init) => {
          const response = await base(url, init);
          if (!String(url).endsWith("/.well-known/openid-configuration"))
            return response;
          return Response.json({
            ...((await response.json()) as object),
            device_authorization_endpoint: "https://other.example/devicecode",
          });
        }) as ManagedFetch,
      }).login(ctx),
    ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
    expect(shown).toEqual([]);
  });

  describe("plain HTTP to the device endpoint (httpTransport: http-allowed)", () => {
    const rewriting = (endpoint: string): ManagedFetch => {
      const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
      return async (url, init) => {
        const response = await base(url, init);
        if (!String(url).endsWith("/.well-known/openid-configuration"))
          return response;
        return Response.json({
          ...((await response.json()) as object),
          device_authorization_endpoint: endpoint,
        });
      };
    };

    it("refuses a public plain-HTTP device endpoint, without contacting it", async () => {
      await expect(
        provider({
          fetch: rewriting("http://login.acme.example/devicecode"),
          plainHttp: true,
        }).login(context().ctx),
      ).rejects.toMatchObject({
        code: "CONFIG_INVALID",
        message: expect.stringContaining(
          "device_authorization_endpoint is plain HTTP to login.acme.example",
        ),
      });
    });

    it("reports a private device endpoint so the fetch can admit exactly it", async () => {
      const reported: string[] = [];
      await provider({
        fetch: rewriting("http://10.0.0.8/devicecode"),
        plainHttp: true,
        onDiscoveredEndpoints: (urls: string[]) => reported.push(...urls),
      }).configuration();
      expect(reported).toContain("http://10.0.0.8/devicecode");
    });
  });
});
