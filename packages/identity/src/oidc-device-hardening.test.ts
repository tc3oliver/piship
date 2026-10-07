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
