// identity.oidc.flow: device_code against the deterministic fixture IdP, for
// what the provider's response can do to the client: text it sends, numbers it
// sends, requests that outlive a cancel, and outages while polling. Not live
// evidence: no real identity provider is involved.
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type DeviceCodePrompt,
  type LoginContext,
  type ManagedFetch,
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
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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

/** The managed fetch, with the answer to the request for `path` replaced. */
function answering(
  path: string,
  answer: (response: Response) => Promise<Response> | Response,
): ManagedFetch {
  const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
  return async (url, init) => {
    const response = await base(url, init);
    return new URL(String(url)).pathname === path ? answer(response) : response;
  };
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: the point.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

describe("text the provider sends is checked before it is shown or opened", () => {
  const refused = async (extra: Record<string, unknown> = {}) => {
    const { ctx, shown } = context();
    const error = await provider(extra)
      .login(ctx)
      .catch((caught: unknown) => caught);
    expect(shown).toEqual([]);
    expect(requestsTo("/idp/token")).toEqual([]);
    return error as Error;
  };

  it.each([
    ["file:", "file:///etc/passwd"],
    ["javascript:", "javascript:alert(1)"],
    ["ftp:", "ftp://login.example/device"],
    ["credentials", "https://user:secret@login.example/device"],
    ["an escape sequence", "https://login.example/\u001b[31mdevice"],
    ["a carriage return", "https://login.example/\rdevice"],
    ["a line separator", "https://login.example/ device"],
    ["a space", "https://login.example/de vice"],
    ["a length over 2048", `https://login.example/${"a".repeat(2100)}`],
    ["no URL", "login.example/device"],
    ["public plain HTTP", "http://login.acme.example/device"],
  ])("refuses a verification_uri with %s", async (_name, uri) => {
    services.knobs.deviceVerificationUri = uri;
    const error = await refused();
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    // The message never carries what the provider sent.
    expect(error.message).not.toMatch(
      /login\.example|etc\/passwd|secret|alert/,
    );
  });

  it("refuses a verification_uri_complete that fails the same checks", async () => {
    services.knobs.deviceVerificationUriComplete =
      "https://user:secret@login.example/device?user_code=X";
    expect(await refused()).toMatchObject({ code: "IDENTITY_INVALID" });
  });

  it.each([
    ["an escape sequence", "\u001b[2JABCD"],
    ["a carriage return", "AB\rCD"],
    ["a length over 32", "A".repeat(33)],
    ["nothing", ""],
    ["punctuation", "AB;CD"],
  ])("refuses a user_code with %s", async (_name, code) => {
    services.knobs.deviceUserCode = code;
    const error = await refused();
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect(error.message).not.toContain("ABCD");
  });

  it.each(["WDJB-MJHT", "WDJB MJHT", "bcd_fgh", "123456"])(
    "shows the user_code %s",
    async (code) => {
      services.knobs.deviceUserCode = code;
      const { ctx, shown } = context();
      await provider().login(ctx);
      expect(shown[0]?.userCode).toBe(code);
    },
  );

  it("shows the URL as the URL parser writes it, not as the provider wrote it", async () => {
    services.knobs.deviceVerificationUri = `${services.issuer}/dev/../device`;
    const { ctx, shown } = context();
    await provider().login(ctx);
    expect(shown[0]?.verificationUri).toBe(`${services.issuer}/device`);
  });

  describe("plain HTTP follows the manifest's httpTransport rule", () => {
    const at = (host: string): ManagedFetch =>
      answering("/idp/devicecode", async (response) =>
        Response.json({
          ...((await response.json()) as object),
          verification_uri: `http://${host}/device`,
        }),
      );

    it("admits a private host only with http-allowed", async () => {
      const allowed = context();
      await provider({ fetch: at("10.0.0.8"), plainHttp: true }).login(
        allowed.ctx,
      );
      expect(allowed.shown[0]?.verificationUri).toBe("http://10.0.0.8/device");
      services.state.requests.length = 0;
      const refusedOnDefault = context();
      await expect(
        provider({ fetch: at("10.0.0.8") }).login(refusedOnDefault.ctx),
      ).rejects.toMatchObject({ code: "IDENTITY_INVALID" });
      expect(refusedOnDefault.shown).toEqual([]);
    });

    it("refuses a public host even with http-allowed", async () => {
      const { ctx, shown } = context();
      await expect(
        provider({ fetch: at("login.acme.example"), plainHttp: true }).login(
          ctx,
        ),
      ).rejects.toMatchObject({ code: "IDENTITY_INVALID" });
      expect(shown).toEqual([]);
    });
  });

  it("keeps control characters from the provider's error out of the message", async () => {
    const error = await provider({
      fetch: answering("/idp/token", () =>
        Response.json(
          { error: `\u001b]0;pwned\u0007\r\nforged${"x".repeat(500)}` },
          { status: 400 },
        ),
      ),
    })
      .login(context().ctx)
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect((error as Error).message).not.toMatch(CONTROL);
    expect((error as Error).message.length).toBeLessThan(200);
  });
});

describe("numbers the provider and the caller send are bounded", () => {
  it("polls at most a minute apart and at least a second apart, however large or small the interval", async () => {
    services.knobs.deviceInterval = 1e9;
    const waits: number[] = [];
    await provider({
      sleep: async (ms: number) => {
        waits.push(ms);
      },
    }).login(context().ctx);
    expect(waits).toEqual([60_000]);
  });

  it("caps the interval after repeated slow_down too", async () => {
    services.knobs.devicePolls = Array(20).fill("slow_down");
    const waits: number[] = [];
    await provider({
      sleep: async (ms: number) => {
        waits.push(ms);
      },
    }).login(context().ctx);
    expect(Math.max(...waits)).toBe(60_000);
    expect(waits).toHaveLength(21);
  });

  it("does not expire at once when expires_in is huge", async () => {
    services.knobs.deviceExpiresIn = 1e10;
    const { ctx, shown } = context();
    const session = await provider({
      sleep: () => pause(30),
    }).login(ctx);
    expect(session.subject).toBe("demo-user-1");
    expect(shown[0]?.expiresInSeconds).toBe(300);
  });

  it("does not time out at once when the login deadline is huge", async () => {
    const { ctx, shown } = context({ timeoutMs: 1e12 });
    const session = await provider({ sleep: () => pause(30) }).login(ctx);
    expect(session.subject).toBe("demo-user-1");
    expect(shown[0]?.expiresInSeconds).toBe(900);
  });

  it("still ends at the login deadline while slow_down keeps asking for more", async () => {
    services.knobs.devicePolls = Array(500).fill("slow_down");
    await expect(
      provider({ sleep: () => pause(30) }).login(
        context({ timeoutMs: 300 }).ctx,
      ),
    ).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: "Sign-in timed out",
    });
    expect(services.state.devicePolls.length).toBeLessThan(40);
  });
});

describe("cancel and deadline abort the requests, not only the wait", () => {
  it("aborts the device authorization request on Ctrl-C", async () => {
    let seen: AbortSignal | undefined;
    const controller = new AbortController();
    const outcome = provider({
      fetch: ((url, init) => {
        if (!String(url).endsWith("/devicecode"))
          return createManagedFetch(DEFAULT_NETWORK_POLICY)(url, init);
        seen = init?.signal ?? undefined;
        return new Promise(() => {});
      }) as ManagedFetch,
    })
      .login(context({ signal: controller.signal }).ctx)
      .catch((caught: unknown) => caught);
    while (!seen) await pause(10);
    expect(seen.aborted).toBe(false);
    controller.abort();
    expect(await outcome).toMatchObject({ message: "Sign-in was cancelled" });
    expect(seen.aborted).toBe(true);
  });

  it("closes the connection of a token request that is in flight on Ctrl-C", async () => {
    // The fixture serves a held request only if the client is still there.
    services.knobs.tokenDelayMs = 400;
    const controller = new AbortController();
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    let started = false;
    const login = provider({
      fetch: ((url, init) => {
        if (String(url).endsWith("/idp/token")) started = true;
        return base(url, init);
      }) as ManagedFetch,
    })
      .login(context({ signal: controller.signal }).ctx)
      .catch((caught: unknown) => caught);
    while (!started) await pause(10);
    controller.abort();
    expect(await login).toMatchObject({ message: "Sign-in was cancelled" });
    await pause(700);
    expect(services.state.devicePolls).toEqual([]);
  });

  it("closes the connection of a token request that is in flight at the login deadline", async () => {
    services.knobs.tokenDelayMs = 600;
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    let tokenRequest: AbortSignal | undefined;
    await expect(
      provider({
        fetch: ((url, init) => {
          if (String(url).endsWith("/idp/token"))
            tokenRequest = init?.signal ?? undefined;
          return base(url, init);
        }) as ManagedFetch,
      }).login(context({ timeoutMs: 300 }).ctx),
    ).rejects.toMatchObject({ message: "Sign-in timed out" });
    expect(tokenRequest?.aborted).toBe(true);
    await pause(700);
    expect(services.state.devicePolls).toEqual([]);
  });
});

describe("a poll that fails for a reason that says nothing about the sign-in is asked again", () => {
  const outage = (status: number, retryAfter?: number) => ({
    status,
    ...(retryAfter === undefined ? {} : { retryAfter }),
  });
  const tokenRequests = () => requestsTo("/idp/token").length;

  it.each([502, 503, 500])(
    "asks again after an HTTP %i, and signs in",
    async (status) => {
      services.knobs.tokenFaults = [outage(status), outage(status)];
      const session = await provider().login(context().ctx);
      expect(session.subject).toBe("demo-user-1");
      expect(tokenRequests()).toBe(3);
    },
  );

  it("waits for the Retry-After of a 429, within the cap", async () => {
    services.knobs.tokenFaults = [outage(429, 7), outage(429, 100_000)];
    const waits: number[] = [];
    await provider({
      sleep: async (ms: number) => {
        waits.push(ms);
      },
    }).login(context().ctx);
    expect(waits).toEqual([1000, 7000, 60_000]);
  });

  it("asks again after a network failure", async () => {
    const base = createManagedFetch(DEFAULT_NETWORK_POLICY);
    let failures = 2;
    const session = await provider({
      fetch: ((url, init) => {
        if (String(url).endsWith("/idp/token") && failures-- > 0)
          return Promise.reject(
            new TypeError("fetch failed", {
              cause: Object.assign(new Error("reset"), { code: "ECONNRESET" }),
            }),
          );
        return base(url, init);
      }) as ManagedFetch,
    }).login(context().ctx);
    expect(session.subject).toBe("demo-user-1");
  });

  it("gives up after five failures in a row, with the provider's error", async () => {
    services.knobs.tokenStatus = 503;
    await expect(provider().login(context().ctx)).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
    });
    expect(tokenRequests()).toBe(5);
  });

  it("gives up on a rate limit with GATEWAY_RATE_LIMITED", async () => {
    services.knobs.tokenStatus = 429;
    await expect(provider().login(context().ctx)).rejects.toMatchObject({
      code: "GATEWAY_RATE_LIMITED",
    });
    expect(tokenRequests()).toBe(5);
  });

  it("counts failures in a row: a pending answer starts the count over", async () => {
    services.knobs.tokenFaults = [
      ...Array(4).fill(outage(503)),
      {},
      ...Array(4).fill(outage(503)),
    ];
    services.knobs.devicePolls = ["authorization_pending"];
    const session = await provider().login(context().ctx);
    expect(session.subject).toBe("demo-user-1");
  });

  it("still ends at the deadline while the provider is down", async () => {
    services.knobs.tokenStatus = 503;
    await expect(
      provider({ sleep: () => pause(60) }).login(
        context({ timeoutMs: 150 }).ctx,
      ),
    ).rejects.toMatchObject({ message: "Sign-in timed out" });
    expect(tokenRequests()).toBeLessThan(5);
  });

  it.each([
    ["invalid_request", 400],
    ["invalid_client", 401],
    ["unauthorized_client", 400],
    ["access_denied", 400],
  ])("does not ask again after %s", async (error, status) => {
    services.knobs.tokenFaults = [{ status, body: { error } }];
    await expect(provider().login(context().ctx)).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
    });
    expect(tokenRequests()).toBe(1);
  });

  it("does not ask again after an ID token that fails its checks", async () => {
    services.knobs.idTokenAudience = "another-client";
    await expect(provider().login(context().ctx)).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
    });
    expect(tokenRequests()).toBe(1);
  });
});
