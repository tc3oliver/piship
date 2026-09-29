import { generateKeyPairSync, type KeyObject, sign, verify } from "node:crypto";
import {
  type AdapterContext,
  defineIdentityAdapter,
  type IdentityProvider,
  type IdentitySession,
  isPiShipError,
  type LoginContext,
  PiShipError,
  parseRetryAfter,
  SecretValue,
  withTimeout,
} from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
import {
  type ConformanceReport,
  IDENTITY_ALLOWED_CLAIMS,
  IDENTITY_BEHAVIORS,
  IDENTITY_CONTRACT,
  type IdentityBehavior,
  type IdentityKitOptions,
  type IdentityServiceAnswer,
  type IdentityTokenHarness,
  type IdentityTokenKind,
  testIdentityAdapter,
} from "./index.js";

// The adapter under test ends a request after this long; the kit waits a
// few times longer before it reports a hang, so a busy machine has room.
const TIMEOUT_MS = 150;
const SERVICE = "https://sign-in.conformance.invalid";
const AUDIENCE = "conformance-client";
/** A fake platform token a workload presents; never a real one. */
const PLATFORM_TOKEN = "conformance-platform-token";

/** One seeded defect; the reference adapter has none. */
type Fault =
  | "never presents the URL"
  | "opens a browser in a workload adapter"
  | "swaps the subject on refresh"
  | "ignores expiry"
  | "throws on logout of a revoked session"
  | "returns the refresh token in claims"
  | "treats invalid_grant as a generic error"
  | "leaks a token in an error"
  | "returns the access token as a plain string"
  | "treats an outage as IDENTITY_INVALID"
  | "ignores the issuer"
  | "ignores the audience"
  | "accepts a bad signature"
  | "ignores the validity window"
  | "skips introspection";

/** How the reference adapter checks the ID token, as a company's would. */
interface Verification {
  readonly issuer: string;
  readonly publicKey: KeyObject;
}

interface ReferenceOptions {
  readonly fault?: Fault;
  /** A workload identity (`interactive: false`) that exchanges a platform token. */
  readonly workload?: boolean;
  /** `oauth`: the service speaks snake_case OAuth fields instead of the kit's default. */
  readonly wire?: "kit" | "oauth";
  readonly verify?: Verification;
  readonly refresh?: boolean;
  readonly logout?: boolean;
}

type Answer = Record<string, unknown>;

function decode(part: string | undefined): Answer | undefined {
  try {
    return JSON.parse(Buffer.from(part ?? "", "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
}

/**
 * A small identity adapter that follows the contract, written the way a
 * company would: SDK and `node:` only, one request per step, no retries.
 * Each `fault` breaks exactly one behavior.
 */
function referenceAdapter(options: ReferenceOptions = {}) {
  const { fault } = options;
  const snake = options.wire === "oauth";
  return defineIdentityAdapter((context: AdapterContext) => {
    const refused = (
      code: "IDENTITY_INVALID" | "IDENTITY_EXPIRED",
      message: string,
    ) =>
      new PiShipError(code, message, {
        component: "identity",
        userAction: "Run login again",
      });
    const malformed = () =>
      refused("IDENTITY_INVALID", "The sign-in service answer is malformed");

    async function call(
      path: string,
      body: unknown,
      signal?: AbortSignal,
      token?: SecretValue,
      parse = true,
    ): Promise<Answer> {
      let response: Response;
      try {
        response = await context.fetch(new URL(path, SERVICE), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: withTimeout(TIMEOUT_MS, signal),
        });
      } catch (error) {
        // Network and TLS policy refusals keep their own code. Never build a
        // message from a transport error: it can quote a header value.
        if (error instanceof PiShipError) throw error;
        throw new PiShipError(
          "GATEWAY_UNREACHABLE",
          signal?.aborted
            ? "Sign-in was cancelled"
            : "The sign-in service is unreachable",
          { retryable: !signal?.aborted, component: "identity" },
        );
      }
      const status = response.status;
      if (status === 429 || status >= 500) {
        response.body?.cancel().catch(() => {});
        if (fault === "treats an outage as IDENTITY_INVALID" && status >= 500)
          throw refused("IDENTITY_INVALID", `HTTP ${status}`);
        const retryAfterMs = parseRetryAfter(
          response.headers.get("retry-after"),
        );
        throw new PiShipError(
          status === 429 ? "GATEWAY_RATE_LIMITED" : "GATEWAY_UNREACHABLE",
          `The sign-in service answered HTTP ${status}`,
          {
            retryable: true,
            component: "identity",
            ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
          },
        );
      }
      if (!response.ok) {
        const answer = (await response.json().catch(() => undefined)) as
          | Answer
          | undefined;
        const error = typeof answer?.error === "string" ? answer.error : "";
        if (
          error === "invalid_grant" &&
          fault === "treats invalid_grant as a generic error"
        )
          throw new Error("The sign-in service refused the request");
        const failure = refused(
          status === 401 || error === "invalid_grant"
            ? "IDENTITY_EXPIRED"
            : "IDENTITY_INVALID",
          `The sign-in service refused the request (HTTP ${status})`,
        );
        // PiShipError redacts its own message; a cause is not redacted.
        if (fault === "leaks a token in an error" && token)
          Object.defineProperty(failure, "cause", {
            value: new Error(`refused ${token.reveal()}`),
          });
        throw failure;
      }
      if (!parse) {
        response.body?.cancel().catch(() => {});
        return {};
      }
      try {
        const answer: unknown = await response.json();
        if (!answer || typeof answer !== "object") throw malformed();
        return answer as Answer;
      } catch {
        throw malformed();
      }
    }

    /** The principal the ID token proves, checked as a company adapter would. */
    async function verified(
      idToken: unknown,
    ): Promise<{ issuer: string; subject: string }> {
      const check = options.verify;
      if (!check || typeof idToken !== "string") throw malformed();
      const [head, body, signature] = idToken.split(".");
      const payload = decode(body);
      if (!head || !payload || !signature) throw malformed();
      const signed = verify(
        null,
        Buffer.from(`${head}.${body}`),
        check.publicKey,
        Buffer.from(signature, "base64url"),
      );
      if (!signed && fault !== "accepts a bad signature")
        throw refused("IDENTITY_INVALID", "The ID token signature is invalid");
      if (payload.iss !== check.issuer && fault !== "ignores the issuer")
        throw refused(
          "IDENTITY_INVALID",
          "The ID token is from another issuer",
        );
      if (payload.aud !== AUDIENCE && fault !== "ignores the audience")
        throw refused("IDENTITY_INVALID", "The ID token is for another client");
      const now = Date.now() / 1000;
      if (
        fault !== "ignores the validity window" &&
        (Number(payload.exp) <= now - 30 || Number(payload.nbf) > now + 30)
      )
        throw refused(
          "IDENTITY_EXPIRED",
          "The ID token is outside its validity",
        );
      if (fault !== "skips introspection") {
        const status = await call("/introspect", { token: idToken });
        if (status.active !== true)
          throw refused("IDENTITY_EXPIRED", "The ID token was revoked");
      }
      return { issuer: String(payload.iss), subject: String(payload.sub) };
    }

    const read = (answer: Answer, camel: string, snakeName: string) =>
      snake ? answer[snakeName] : answer[camel];

    async function session(
      answer: Answer,
      operation: "login" | "refresh",
    ): Promise<IdentitySession> {
      const accessToken = read(answer, "accessToken", "access_token");
      const idToken = read(answer, "idToken", "id_token");
      const refreshToken = read(answer, "refreshToken", "refresh_token");
      const expiresIn = read(answer, "expiresIn", "expires_in");
      const principal = options.verify
        ? await verified(idToken)
        : {
            issuer: read(answer, "issuer", "iss"),
            subject: read(answer, "subject", "sub"),
          };
      if (
        typeof principal.issuer !== "string" ||
        typeof principal.subject !== "string" ||
        typeof accessToken !== "string" ||
        typeof expiresIn !== "number"
      )
        throw malformed();
      const email = typeof answer.email === "string" ? answer.email : undefined;
      const raw = (answer.claims ?? {}) as Answer;
      const claims: Answer = Object.fromEntries(
        Object.entries(raw).filter(([name]) =>
          IDENTITY_ALLOWED_CLAIMS.includes(name),
        ),
      );
      if (fault === "returns the refresh token in claims")
        claims.refresh_token = refreshToken;
      return {
        issuer: principal.issuer,
        subject:
          fault === "swaps the subject on refresh" &&
          operation === "refresh" &&
          email
            ? email
            : principal.subject,
        ...(typeof answer.name === "string"
          ? { displayName: answer.name }
          : {}),
        ...(email ? { email } : {}),
        accessToken:
          fault === "returns the access token as a plain string"
            ? (accessToken as unknown as SecretValue)
            : new SecretValue(accessToken),
        ...(typeof idToken === "string"
          ? { idToken: new SecretValue(idToken) }
          : {}),
        ...(typeof refreshToken === "string"
          ? { refreshToken: new SecretValue(refreshToken) }
          : {}),
        expiresAt: new Date(
          Date.now() +
            (fault === "ignores expiry" ? 3_600_000 : expiresIn * 1000),
        ),
        claims,
      };
    }

    if (options.workload)
      return {
        kind: "reference-workload",
        interactive: false,
        async login(ctx: LoginContext) {
          if (fault === "opens a browser in a workload adapter")
            await ctx.openUrl(`${SERVICE}/device`);
          return session(
            await call(
              "/token-exchange",
              { subjectToken: PLATFORM_TOKEN },
              ctx.signal,
            ),
            "login",
          );
        },
      } as IdentityProvider;

    const provider: IdentityProvider = {
      kind: "reference-device",
      async login(ctx) {
        const started = await call("/device", {}, ctx.signal);
        const url = read(started, "verificationUrl", "verification_uri");
        const code = read(started, "deviceCode", "device_code");
        if (typeof url !== "string" || typeof code !== "string")
          throw malformed();
        if (fault !== "never presents the URL") await ctx.openUrl(url);
        return session(
          await call("/token", { deviceCode: code }, ctx.signal),
          "login",
        );
      },
    };
    return {
      ...provider,
      ...(options.refresh === false
        ? {}
        : {
            async refresh(current: IdentitySession) {
              if (!current.refreshToken)
                throw refused("IDENTITY_EXPIRED", "The session has ended");
              return session(
                await call(
                  "/refresh",
                  { refreshToken: current.refreshToken.reveal() },
                  undefined,
                  current.refreshToken,
                ),
                "refresh",
              );
            },
          }),
      ...(options.logout === false
        ? {}
        : {
            async logout(current: IdentitySession) {
              const token = current.refreshToken ?? current.accessToken;
              if (!token) return;
              try {
                await call(
                  "/revoke",
                  { token: token.reveal() },
                  undefined,
                  token,
                  false,
                );
              } catch (error) {
                // Already revoked or unknown: there is nothing left to revoke.
                if (
                  fault !== "throws on logout of a revoked session" &&
                  isPiShipError(error) &&
                  error.code === "IDENTITY_EXPIRED"
                )
                  return;
                throw error;
              }
            },
          }),
    };
  });
}

// ------------------------------------------------------ token-minting harness

const seconds = (ms: number) => Math.floor(ms / 1000);

function jwt(payload: Answer, key: KeyObject): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const head = encode({ alg: "EdDSA", typ: "JWT" });
  const body = encode(payload);
  const signature = sign(null, Buffer.from(`${head}.${body}`), key);
  return `${head}.${body}.${signature.toString("base64url")}`;
}

/**
 * A company's harness: it signs ID tokens with the key its adapter trusts
 * (or, for `bad-signature`, another key) and answers introspection for the
 * tokens it revoked.
 */
function tokenHarness(cannot: readonly IdentityTokenKind[] = []) {
  const trusted = generateKeyPairSync("ed25519");
  const rogue = generateKeyPairSync("ed25519");
  const revoked = new Set<string>();
  const harness: IdentityTokenHarness = {
    mint({ kind, issuer, subject, expiresAt }) {
      if (cannot.includes(kind)) return undefined;
      const now = seconds(Date.now());
      const token = jwt(
        {
          iss:
            kind === "wrong-issuer"
              ? "https://rogue.conformance.invalid"
              : issuer,
          sub: subject,
          aud: kind === "wrong-audience" ? "another-client" : AUDIENCE,
          iat: now,
          nbf: kind === "not-yet-valid" ? now + 3_600 : now - 60,
          exp: kind === "expired" ? now - 3_600 : seconds(expiresAt.getTime()),
        },
        kind === "bad-signature" ? rogue.privateKey : trusted.privateKey,
      );
      if (kind === "revoked") revoked.add(token);
      return { idToken: token };
    },
    respond(request) {
      if (!request.url.endsWith("/introspect")) return undefined;
      const { token } = JSON.parse(request.body) as { token: string };
      return Response.json({ active: !revoked.has(token) });
    },
  };
  return { harness, publicKey: trusted.publicKey };
}

const ISSUER = "https://issuer.conformance.invalid";

/** A verifying adapter and the harness whose tokens it trusts. */
function verifyingSetup(
  options: ReferenceOptions = {},
  cannot: readonly IdentityTokenKind[] = [],
) {
  const { harness, publicKey } = tokenHarness(cannot);
  return {
    adapter: referenceAdapter({
      ...options,
      verify: { issuer: ISSUER, publicKey },
    }),
    harness,
  };
}

// ---------------------------------------------------------------- helpers

const run = (adapter = referenceAdapter(), options: IdentityKitOptions = {}) =>
  testIdentityAdapter(adapter, { requestTimeoutMs: TIMEOUT_MS, ...options });

const statuses = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results.map((result) => [result.behavior, result.status]),
  );

const TOKEN_BEHAVIORS: readonly IdentityBehavior[] = [
  "invalid issuer",
  "invalid audience",
  "invalid signature",
  "token validity window",
  "revoked token",
];

const expected = (
  overrides: Partial<Record<IdentityBehavior, string>> = {},
  harness = false,
) =>
  Object.fromEntries(
    IDENTITY_BEHAVIORS.map((behavior) => [
      behavior,
      overrides[behavior] ??
        (!harness && TOKEN_BEHAVIORS.includes(behavior) ? "skipped" : "passed"),
    ]),
  );

const WORKLOAD_SKIPS = { refresh: "skipped", logout: "skipped" } as const;

/** No reason may quote a token or a service answer body. */
function expectCleanReasons(report: ConformanceReport): void {
  for (const result of report.results)
    expect(result.reason ?? "").not.toMatch(
      /conformance-(access-token|id-token|refresh-token|device-code|service-body|platform-token)|eyJ/,
    );
}

const reasonOf = (report: ConformanceReport, behavior: IdentityBehavior) =>
  report.results.find((result) => result.behavior === behavior)?.reason;

// ------------------------------------------------------------------ tests

describe("identity conformance kit", () => {
  it("names each behavior of §16.1 once, each with a contract statement", () => {
    expect(IDENTITY_BEHAVIORS).toEqual([
      "login",
      "refresh",
      "expiry",
      "logout",
      "claim normalization",
      "revoked session",
      "secret redaction",
      "service outage",
      "invalid issuer",
      "invalid audience",
      "invalid signature",
      "token validity window",
      "revoked token",
    ]);
    for (const entry of IDENTITY_CONTRACT)
      expect(entry.statement.length).toBeGreaterThan(40);
  });

  it("passes an interactive device-style adapter, and skips the token checks without a harness", async () => {
    const report = await run();
    expect(report.kind).toBe("identity");
    expect(report.results.map((result) => result.behavior)).toEqual(
      IDENTITY_BEHAVIORS,
    );
    expect(statuses(report)).toEqual(expected());
    for (const behavior of TOKEN_BEHAVIORS)
      expect(reasonOf(report, behavior)).toMatch(/^needs harness: /);
  });

  it("passes a workload adapter, which is never refreshed or logged out", async () => {
    const report = await run(referenceAdapter({ workload: true }));
    expect(statuses(report)).toEqual(expected(WORKLOAD_SKIPS));
    expect(reasonOf(report, "refresh")).toMatch(/calls login\(\) again/);
    expect(reasonOf(report, "logout")).toMatch(/memory only/);
  });

  it("passes every behavior, the token checks included, for a verifying adapter with a good harness", async () => {
    const { adapter, harness } = verifyingSetup();
    const report = await run(adapter, { harness });
    expect(statuses(report)).toEqual(expected({}, true));
  });

  it("passes a verifying workload adapter with a good harness", async () => {
    const { adapter, harness } = verifyingSetup({ workload: true });
    const report = await run(adapter, { harness });
    expect(statuses(report)).toEqual(expected(WORKLOAD_SKIPS, true));
  });

  it("skips a token check the harness cannot mint, and never counts it as passed", async () => {
    const { adapter, harness } = verifyingSetup({}, [
      "revoked",
      "not-yet-valid",
    ]);
    const report = await run(adapter, { harness });
    expect(statuses(report)).toEqual(
      expected({ "revoked token": "skipped" }, true),
    );
    expect(reasonOf(report, "revoked token")).toMatch(
      /harness cannot mint a token that the issuer revoked/,
    );
  });

  it("fails the token checks when the harness cannot mint a valid token", async () => {
    const { adapter, harness } = verifyingSetup({}, ["valid"]);
    const report = await run(adapter, { harness });
    for (const behavior of TOKEN_BEHAVIORS)
      expect(reasonOf(report, behavior)).toMatch(/cannot mint a valid token/);
  });

  it("fails the token checks for an adapter that refuses every token, instead of passing them", async () => {
    // Without the harness's keys, the adapter refuses even a valid token.
    const { harness } = tokenHarness();
    const { adapter } = verifyingSetup();
    const report = await run(adapter, { harness });
    for (const behavior of TOKEN_BEHAVIORS) {
      expect(statuses(report)[behavior]).toBe("failed");
      expect(reasonOf(report, behavior)).toMatch(
        /valid minted token was refused \(IDENTITY_INVALID\)/,
      );
    }
  });

  it("skips refresh, logout, and the revoked session for an adapter without them", async () => {
    const report = await run(
      referenceAdapter({ refresh: false, logout: false }),
    );
    expect(statuses(report)).toEqual(
      expected({
        refresh: "skipped",
        logout: "skipped",
        "revoked session": "skipped",
      }),
    );
  });

  it("passes an adapter for another protocol through the respond hook", async () => {
    const respond = (_request: unknown, answer: IdentityServiceAnswer) => {
      switch (answer.kind) {
        case "session": {
          const identity = answer.identity;
          return Response.json({
            device_code: identity.deviceCode,
            verification_uri: identity.verificationUrl,
            iss: identity.issuer,
            sub: identity.subject,
            name: identity.name,
            email: identity.email,
            access_token: identity.accessToken,
            id_token: identity.idToken,
            refresh_token: identity.refreshToken,
            token_type: "Bearer",
            expires_in: identity.expiresIn,
            claims: identity.claims,
          });
        }
        case "logged-out":
        case "already-revoked":
          // RFC 7009: a revocation of an unknown token also answers 200.
          return new Response(null, { status: 200 });
        case "invalid-grant":
          return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
    };
    const adapter = referenceAdapter({ wire: "oauth" });
    expect(statuses(await run(adapter, { respond }))).toEqual(expected());
    // The kit's default answer is not that protocol.
    expect(statuses(await run(adapter)).login).toBe("failed");
  });

  it("checks the issuer the adapter reports against options.issuer", async () => {
    const report = await run(referenceAdapter(), {
      issuer: "https://another-issuer.conformance.invalid",
    });
    expect(statuses(report)).toEqual(expected());
    const fixed = await run(
      defineIdentityAdapter(async (context) => {
        const provider = await referenceAdapter()(context);
        return {
          ...provider,
          login: async (ctx) => ({
            ...(await provider.login(ctx)),
            issuer: "https://fixed.conformance.invalid",
          }),
        };
      }),
    );
    expect(reasonOf(fixed, "login")).toMatch(
      /issuer is not the one the service asserted/,
    );
  });

  it("fails every behavior it can exercise, with a reason, when the factory builds no provider", async () => {
    const report = await run(
      defineIdentityAdapter(() => undefined as unknown as IdentityProvider),
    );
    for (const result of report.results)
      if (TOKEN_BEHAVIORS.includes(result.behavior as IdentityBehavior))
        expect(result.status).toBe("skipped");
      else
        expect(result).toMatchObject({
          status: "failed",
          reason: "the adapter factory returned no identity provider",
        });
  });

  it("reports a factory that throws by code, never by its message", async () => {
    const report = await run(
      defineIdentityAdapter(() => {
        throw new TypeError("conformance-access-token-in-a-message");
      }),
    );
    for (const result of report.results)
      if (!TOKEN_BEHAVIORS.includes(result.behavior as IdentityBehavior))
        expect(result).toMatchObject({
          status: "failed",
          reason:
            "the check ended unexpectedly with a TypeError that is not a PiShipError",
        });
    expectCleanReasons(report);
  });

  it("refuses a request timeout that is not a positive number", async () => {
    for (const requestTimeoutMs of [
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ])
      await expect(
        testIdentityAdapter(referenceAdapter(), { requestTimeoutMs }),
      ).rejects.toThrow(RangeError);
  });

  // Each seeded defect breaks exactly one behavior: the kit fails that one,
  // with a reason, and still passes every other.
  type Seed = [Fault, IdentityBehavior, RegExp, ReferenceOptions?];
  const seeds: Seed[] = [
    [
      "never presents the URL",
      "login",
      /interactive login did not present a URL with openUrl/,
    ],
    [
      "opens a browser in a workload adapter",
      "login",
      /workload adapter \(interactive: false\) called openUrl/,
      { workload: true },
    ],
    [
      "swaps the subject on refresh",
      "refresh",
      /refreshed session names another subject/,
    ],
    ["ignores expiry", "expiry", /expiresAt is not the service's expiry/],
    [
      "throws on logout of a revoked session",
      "logout",
      /already revoked threw IDENTITY_EXPIRED; it must resolve/,
    ],
    [
      "returns the refresh token in claims",
      "claim normalization",
      /claims hold "refresh_token", which is not an allowlisted claim/,
    ],
    [
      "treats invalid_grant as a generic error",
      "revoked session",
      /refused as invalid_grant: the failure is not a PiShipError/,
    ],
    [
      "leaks a token in an error",
      "secret redaction",
      /refresh after a 400 .*: the error shows a token/,
    ],
    [
      "returns the access token as a plain string",
      "secret redaction",
      /accessToken is a plain string; wrap it in a SecretValue/,
      { workload: true },
    ],
    [
      "treats an outage as IDENTITY_INVALID",
      "service outage",
      /login after a 503 with Retry-After: expected GATEWAY_UNREACHABLE, got IDENTITY_INVALID/,
    ],
    [
      "treats an outage as IDENTITY_INVALID",
      "service outage",
      /expected GATEWAY_UNREACHABLE, got IDENTITY_INVALID/,
      { workload: true },
    ],
    [
      "ignores the issuer",
      "invalid issuer",
      /login whose token is wrong-issuer: the call succeeded/,
      { verify: {} as Verification },
    ],
    [
      "ignores the audience",
      "invalid audience",
      /login whose token is wrong-audience: the call succeeded/,
      { verify: {} as Verification },
    ],
    [
      "accepts a bad signature",
      "invalid signature",
      /login whose token is bad-signature: the call succeeded/,
      { verify: {} as Verification },
    ],
    [
      "ignores the validity window",
      "token validity window",
      /login whose token is expired: the call succeeded/,
      { verify: {} as Verification },
    ],
    [
      "skips introspection",
      "revoked token",
      /login whose token is revoked: the call succeeded/,
      { verify: {} as Verification },
    ],
  ];
  it.each(seeds)(
    "fails only %j, under %s",
    async (fault, behavior, reason, options = {}) => {
      const withHarness = !!options.verify;
      const { verify: _placeholder, ...rest } = options;
      const setup = withHarness
        ? verifyingSetup({ ...rest, fault })
        : { adapter: referenceAdapter({ ...rest, fault }), harness: undefined };
      const report = await run(
        setup.adapter,
        setup.harness ? { harness: setup.harness } : {},
      );
      expect(reasonOf(report, behavior)).toMatch(reason);
      expect(statuses(report)).toEqual(
        expected(
          {
            ...(options.workload ? WORKLOAD_SKIPS : {}),
            [behavior]: "failed",
          },
          withHarness,
        ),
      );
      expectCleanReasons(report);
    },
    30_000,
  );

  it("covers every behavior with at least one seeded defect", () => {
    expect(new Set(seeds.map(([, behavior]) => behavior))).toEqual(
      new Set(IDENTITY_BEHAVIORS),
    );
  });
});
