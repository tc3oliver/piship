// The identity conformance kit. It runs an identity adapter against a fake
// identity service the kit owns, answering through the adapter's managed
// fetch, so a run needs no network, no identity provider, and no PiShip
// internals. PiShip does no JWT cryptography (decision 15), so the checks on
// token validation (issuer, audience, signature, validity window, revocation)
// run only when the adapter author supplies a harness that mints such tokens;
// without one they are skipped, never passed.
import { randomBytes } from "node:crypto";
import {
  type AdapterContext,
  type AdapterFactory,
  type IdentityProvider,
  type IdentitySession,
  type LoginContext,
  type ManagedFetch,
  PiShipError,
  type PiShipErrorCode,
  RETAINED_CLAIMS,
  type ResolvedEndpoints,
} from "@piship/adapter-sdk";
import type { ConformanceReport, ConformanceResult } from "./index.js";
import {
  answer,
  check,
  codeOf,
  type Expected,
  expectError,
  expiryOf,
  Finding,
  type Outcome,
  RETRY_AFTER_SECONDS,
  rejection,
  requestText,
  revealed,
  secretsIn,
  settle,
} from "./shared.js";

/**
 * What the identity kit checks, in report order, each with the contract
 * statement it holds the adapter to. The last five need a harness.
 */
export const IDENTITY_CONTRACT = [
  {
    behavior: "login",
    statement:
      "login() reaches the service through the context's managed fetch and returns a session whose subject and issuer are the principal the service asserted; an interactive adapter presents a URL with openUrl, and a workload adapter (interactive: false) never calls openUrl",
  },
  {
    behavior: "refresh",
    statement:
      "refresh() asks the service again and returns a session for the same principal (iss, sub) with the access and refresh tokens the service issued, never the current ones; PiShip refuses a refresh that changes the principal",
  },
  {
    behavior: "expiry",
    statement:
      "expiresAt is the service's expiry, on login and on refresh; a session the service issued already expired is returned with that past expiry or refused with IDENTITY_EXPIRED, never given a later one",
  },
  {
    behavior: "logout",
    statement:
      "logout() sends a request that names the session's refresh or access token, and resolves, without throwing, for a session the service had already revoked",
  },
  {
    behavior: "claim normalization",
    statement:
      "claims hold only the allowlisted non-secret claims, with scalar or string-array values, and no token appears in claims, subject, issuer, displayName, or email",
  },
  {
    behavior: "revoked session",
    statement:
      "a refresh (for a workload adapter, a login) the service refuses as invalid_grant or with HTTP 401, or a refresh of a session without a refresh token, fails with IDENTITY_EXPIRED, not IDENTITY_INVALID or an uncoded error",
  },
  {
    behavior: "secret redaction",
    statement:
      "access, ID, and refresh tokens are SecretValues that never render, and no token or service answer body appears in any error's message, stack, detail, action, cause, or rendering",
  },
  {
    behavior: "service outage",
    statement:
      "a login or refresh that meets a 5xx, a connection failure, or a service that never answers fails with a retryable GATEWAY_UNREACHABLE, a 429 with a retryable GATEWAY_RATE_LIMITED, each with any Retry-After as retryAfterMs, never IDENTITY_INVALID; a network or TLS policy refusal keeps its code",
  },
  {
    behavior: "invalid issuer",
    statement:
      "with a harness: a session whose token names another issuer is refused with IDENTITY_INVALID, on login and on refresh",
  },
  {
    behavior: "invalid audience",
    statement:
      "with a harness: a session whose token is for another audience is refused with IDENTITY_INVALID, on login and on refresh",
  },
  {
    behavior: "invalid signature",
    statement:
      "with a harness: a session whose token has a signature the issuer's keys do not verify is refused with IDENTITY_INVALID, on login and on refresh",
  },
  {
    behavior: "token validity window",
    statement:
      "with a harness: a session whose token has expired or is not yet valid is refused with IDENTITY_EXPIRED or IDENTITY_INVALID, on login and on refresh",
  },
  {
    behavior: "revoked token",
    statement:
      "with a harness: a session whose token the issuer has revoked is refused with IDENTITY_EXPIRED or IDENTITY_INVALID, on login and on refresh",
  },
] as const;

export type IdentityBehavior = (typeof IDENTITY_CONTRACT)[number]["behavior"];

/** The behaviors the identity kit reports, in report order. */
export const IDENTITY_BEHAVIORS: readonly IdentityBehavior[] =
  IDENTITY_CONTRACT.map((entry) => entry.behavior);

/**
 * The claims an adapter may return, the allowlist of docs/identity.md:
 * PiShip's own `RETAINED_CLAIMS`, as the SDK re-exports it.
 */
export const IDENTITY_ALLOWED_CLAIMS: readonly string[] = RETAINED_CLAIMS;

/** Which provider method the kit is calling. */
export type IdentityOperation = "login" | "refresh" | "logout";

/**
 * A sign-in the fake service issued. Fake values only, never a real token.
 * `claims` holds allowlisted claims and some that are not, which an adapter
 * must drop.
 */
export interface IssuedIdentity {
  readonly subject: string;
  readonly issuer: string;
  readonly name: string;
  readonly email: string;
  readonly accessToken: string;
  readonly idToken: string;
  readonly refreshToken: string;
  /** When the session ends; `expiresIn` is the same in seconds from issue. */
  readonly expiresAt: Date;
  readonly expiresIn: number;
  readonly claims: Readonly<Record<string, unknown>>;
  /** For a device-style login: the URL to present, and the code to redeem. */
  readonly verificationUrl: string;
  readonly deviceCode: string;
}

/** One request the adapter sent through the context's fetch. */
export interface IdentityServiceRequest {
  readonly operation: IdentityOperation;
  /** The request's position within the current call, from 0. */
  readonly step: number;
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string;
}

/**
 * What the kit wants the service to say to a request. `respond` encodes it
 * the way the adapter's service does.
 *
 * - `session`: a successful login or refresh, or an intermediate step of
 *   one (a device authorization, a poll), with the identity it issues.
 * - `logged-out`: the service accepted a logout.
 * - `already-revoked`: a logout of a session the service had already
 *   revoked or no longer knows.
 * - `invalid-grant`: the service refuses the grant (the refresh token or the
 *   workload's token) because it expired or was revoked.
 */
export type IdentityServiceAnswer =
  | { readonly kind: "session"; readonly identity: IssuedIdentity }
  | { readonly kind: "logged-out" }
  | { readonly kind: "already-revoked" }
  | { readonly kind: "invalid-grant" };

/** The token a harness is asked to mint. */
export type IdentityTokenKind =
  | "valid"
  | "wrong-issuer"
  | "wrong-audience"
  | "bad-signature"
  | "expired"
  | "not-yet-valid"
  | "revoked";

export interface IdentityMintRequest {
  readonly kind: IdentityTokenKind;
  /** The principal the session names, and when it expires. */
  readonly issuer: string;
  readonly subject: string;
  readonly expiresAt: Date;
  readonly operation: IdentityOperation;
  /** The request being answered, for a harness that needs its nonce. */
  readonly request: IdentityServiceRequest;
}

/** Tokens that replace the kit's fake ones in the issued session. */
export interface IdentityMintedTokens {
  readonly idToken?: string;
  readonly accessToken?: string;
}

/**
 * Token-minting hooks from the adapter author. With a
 * harness, every session the service issues carries tokens `mint` made, so
 * an adapter that validates tokens accepts the kit's sessions, and the kit
 * checks it refuses invalid ones.
 */
export interface IdentityTokenHarness {
  /**
   * Mint tokens of `kind` for the principal. Return `undefined` for a kind
   * the harness cannot mint; that behavior is then skipped.
   */
  mint(
    request: IdentityMintRequest,
  ):
    | IdentityMintedTokens
    | undefined
    | Promise<IdentityMintedTokens | undefined>;
  /**
   * Answer a request the harness serves itself, such as discovery, the
   * issuer's keys (JWKS), or token introspection; `undefined` passes the
   * request on to the kit's service.
   */
  respond?(
    request: IdentityServiceRequest,
  ): Response | undefined | Promise<Response | undefined>;
}

export interface IdentityKitOptions {
  /**
   * The request timeout the adapter applies, in milliseconds. The kit waits
   * several times this long for a stalled request to end before it reports a
   * hang, so build the adapter under test with a short timeout (such as
   * 200 ms) to keep a run fast. Default 30 000.
   */
  readonly requestTimeoutMs?: number;
  /**
   * The issuer the service asserts and the adapter must report. Default: the
   * context's `endpoints.issuer`, `https://issuer.conformance.invalid`.
   */
  readonly issuer?: string;
  /**
   * The service's answer to one request, in the adapter's protocol. The
   * default answers every login and refresh request with one JSON body
   * (`deviceCode`, `verificationUrl`, `subject`, `issuer`, `name`, `email`,
   * `accessToken`, `idToken`, `refreshToken`, `expiresIn`, `expiresAt`,
   * `claims`), a logout with 204, an already revoked session's logout with
   * 401 `{"error":"invalid_token"}`, and an invalid grant with 400
   * `{"error":"invalid_grant"}`.
   */
  readonly respond?: (
    request: IdentityServiceRequest,
    answer: IdentityServiceAnswer,
  ) => Response | Promise<Response>;
  /** Token-minting hooks; without them the token validation behaviors are skipped. */
  readonly harness?: IdentityTokenHarness;
  /** Merged over the kit's placeholder endpoints in the adapter's context. */
  readonly endpoints?: Partial<ResolvedEndpoints>;
  readonly distributionId?: string;
}

// ------------------------------------------------------------ fake service

type Handler = (
  request: IdentityServiceRequest,
  signal: AbortSignal | undefined,
) => Response | Promise<Response>;

/** What the service does for the current call. */
type Plan =
  | {
      readonly kind: "session";
      readonly expiresIn?: number;
      readonly mint?: IdentityTokenKind;
    }
  | { readonly kind: "logged-out" | "already-revoked" | "invalid-grant" }
  | { readonly kind: "raw"; readonly handler: Handler };

const LOGIN_EXPIRES_IN = 900;
const REFRESH_EXPIRES_IN = 1_800;
const EXPIRED_BY = -120;
/** How far an adapter's expiresAt may be from the service's. */
const EXPIRY_TOLERANCE_MS = 5_000;

class FakeIdentityService {
  readonly requests: IdentityServiceRequest[] = [];
  readonly issued: IssuedIdentity[] = [];
  /** Every token value the service or the harness handed out. */
  readonly tokens = new Set<string>();
  readonly #pending = new Set<(error: unknown) => void>();
  operation: IdentityOperation = "login";
  plan: Plan = { kind: "session" };
  /** The identity issued in the current call, reused by its later steps. */
  current: IssuedIdentity | undefined;
  /** Whether the harness could mint the requested kind in this call. */
  unminted: IdentityTokenKind | undefined;
  #step = 0;

  constructor(
    readonly run: string,
    readonly issuer: string,
    readonly subject: string,
    readonly options: IdentityKitOptions,
  ) {}

  /** Start a call of `operation`: a fresh step count and identity. */
  begin(operation: IdentityOperation, plan: Plan): void {
    this.operation = operation;
    this.plan = plan;
    this.current = undefined;
    this.unminted = undefined;
    this.#step = 0;
  }

  readonly fetch: ManagedFetch = async (input, init = {}) => {
    const signal = init.signal ?? undefined;
    // Like a real fetch, a signal that is already aborted sends nothing.
    if (signal?.aborted) throw signal.reason;
    const request: IdentityServiceRequest = {
      operation: this.operation,
      step: this.#step++,
      url: String(input),
      method: (init.method ?? "GET").toUpperCase(),
      headers: new Headers(init.headers),
      body:
        typeof init.body === "string"
          ? init.body
          : init.body
            ? await new Response(init.body).text()
            : "",
    };
    this.requests.push(request);
    const plan = this.plan;
    if (plan.kind === "raw") return plan.handler(request, signal);
    const served = await this.options.harness?.respond?.(request);
    if (served) return served;
    if (plan.kind !== "session") return this.respond(request, plan);
    this.current ??= await this.issue(request, plan);
    return this.respond(request, {
      kind: "session",
      identity: this.current,
    });
  };

  respond(
    request: IdentityServiceRequest,
    answer: IdentityServiceAnswer,
  ): Response | Promise<Response> {
    return (this.options.respond ?? referenceAnswer)(request, answer);
  }

  async issue(
    request: IdentityServiceRequest,
    plan: Extract<Plan, { kind: "session" }>,
  ): Promise<IssuedIdentity> {
    const n = this.issued.length + 1;
    const expiresIn =
      plan.expiresIn ??
      (this.operation === "refresh" ? REFRESH_EXPIRES_IN : LOGIN_EXPIRES_IN);
    const expiresAt = new Date(
      Math.floor(Date.now() / 1000) * 1000 + expiresIn * 1000,
    );
    let accessToken = `conformance-access-token-${n}-${this.run}`;
    let idToken = `conformance-id-token-${n}-${this.run}`;
    const refreshToken = `conformance-refresh-token-${n}-${this.run}`;
    const harness = this.options.harness;
    if (harness) {
      const kind = plan.mint ?? "valid";
      const minted = await harness.mint({
        kind,
        issuer: this.issuer,
        subject: this.subject,
        expiresAt,
        operation: this.operation,
        request,
      });
      if (!minted) this.unminted = kind;
      if (minted?.accessToken) accessToken = minted.accessToken;
      if (minted?.idToken) idToken = minted.idToken;
    }
    const name = "Conformance User";
    const email = "conformance-user@conformance.invalid";
    const identity: IssuedIdentity = {
      subject: this.subject,
      issuer: this.issuer,
      name,
      email,
      accessToken,
      idToken,
      refreshToken,
      expiresAt,
      expiresIn,
      claims: {
        sub: this.subject,
        iss: this.issuer,
        name,
        preferred_username: "conformance-user",
        email,
        email_verified: true,
        groups: ["conformance-group"],
        // Not allowlisted: an adapter must drop these.
        employee_id: "conformance-employee-7",
        realm_access: { roles: ["conformance-role"] },
        session_state: `conformance-session-state-${n}`,
      },
      verificationUrl: `https://issuer.conformance.invalid/device?user_code=CONF-${n}`,
      deviceCode: `conformance-device-code-${n}-${this.run}`,
    };
    for (const token of [
      accessToken,
      idToken,
      refreshToken,
      identity.deviceCode,
    ])
      this.tokens.add(token);
    this.issued.push(identity);
    return identity;
  }

  /** No answer at all: it ends only when the request's signal aborts. */
  stall(signal: AbortSignal | undefined): Promise<Response> {
    return new Promise((_resolve, reject) => {
      const end = (reason: unknown) => {
        this.#pending.delete(end);
        reject(reason);
      };
      if (signal?.aborted) return end(signal.reason);
      this.#pending.add(end);
      signal?.addEventListener("abort", () => end(signal.reason), {
        once: true,
      });
    });
  }

  /** End every stalled request, so a hung adapter call settles. */
  release(): void {
    for (const end of [...this.#pending])
      end(new TypeError("fetch failed: the conformance service closed"));
    this.#pending.clear();
  }
}

/** The kit's default wire format; see `IdentityKitOptions.respond`. */
function referenceAnswer(
  _request: IdentityServiceRequest,
  answer: IdentityServiceAnswer,
): Response {
  switch (answer.kind) {
    case "session": {
      const identity = answer.identity;
      return Response.json({
        deviceCode: identity.deviceCode,
        verificationUrl: identity.verificationUrl,
        subject: identity.subject,
        issuer: identity.issuer,
        name: identity.name,
        email: identity.email,
        accessToken: identity.accessToken,
        idToken: identity.idToken,
        refreshToken: identity.refreshToken,
        expiresIn: identity.expiresIn,
        expiresAt: identity.expiresAt.toISOString(),
        claims: identity.claims,
      });
    }
    case "logged-out":
      return new Response(null, { status: 204 });
    case "already-revoked":
      return Response.json({ error: "invalid_token" }, { status: 401 });
    case "invalid-grant":
      return Response.json({ error: "invalid_grant" }, { status: 400 });
  }
}

// ------------------------------------------------------------ the harness

/** A behavior the kit cannot exercise: reported as skipped. */
class Skip extends Error {}

/** A provider with its declarations read once. */
interface Adapter {
  readonly provider: IdentityProvider;
  /** `interactive: false`: a workload identity. */
  readonly workload: boolean;
  /** The URLs `login()` passed to `openUrl`. */
  readonly opened: unknown[];
}

class Harness {
  readonly run = randomBytes(8).toString("hex");
  readonly bodySentinel = `conformance-service-body-${this.run}`;
  readonly subject = `conformance-user-${this.run.slice(0, 8)}`;
  readonly issuer: string;
  readonly timeoutMs: number;
  /** How long the kit waits for a stalled call to end before calling it hung. */
  readonly boundMs: number;
  service: FakeIdentityService;

  constructor(
    readonly factory: AdapterFactory<IdentityProvider>,
    readonly options: IdentityKitOptions,
  ) {
    this.timeoutMs = options.requestTimeoutMs ?? 30_000;
    this.boundMs = this.timeoutMs * 3 + 2_000;
    this.issuer =
      options.issuer ??
      options.endpoints?.issuer ??
      "https://issuer.conformance.invalid";
    this.service = this.#newService();
  }

  #newService(): FakeIdentityService {
    return new FakeIdentityService(
      this.run,
      this.issuer,
      this.subject,
      this.options,
    );
  }

  /** A fresh service and a fresh provider built against it. */
  async adapter(): Promise<Adapter> {
    this.service.release();
    this.service = this.#newService();
    const context: AdapterContext = {
      distributionId: this.options.distributionId ?? "conformance",
      fetch: this.service.fetch,
      endpoints: {
        issuer: this.issuer,
        brokerEndpoint: "https://broker.conformance.invalid/v1/credential",
        baseUrl: "https://gateway.conformance.invalid/v1",
        additionalCA: [],
        ...this.options.endpoints,
      },
    };
    // Bounded like every call into the adapter: a hung factory fails the
    // check instead of hanging the kit.
    const made = await settle(() => this.factory(context), this.boundMs);
    check(
      made.kind !== "hung",
      "the adapter factory did not end within the kit's bound",
    );
    if (made.kind === "rejected") throw made.error;
    const provider = made.value;
    check(
      provider && typeof provider.login === "function",
      "the adapter factory returned no identity provider",
    );
    const interactive = (provider as { interactive?: unknown }).interactive;
    return {
      provider,
      workload: interactive === false,
      opened: [],
    };
  }

  /** A login context whose openUrl records the URL and returns. */
  loginContext(adapter: Adapter): LoginContext {
    return {
      openUrl: (url) => {
        adapter.opened.push(url);
      },
    };
  }

  /** Settle a call, or report it hung after the bound and release it. */
  settle<T>(call: () => Promise<T>): Promise<Outcome<T>> {
    return settle(call, this.boundMs, () => this.service.release());
  }

  login(adapter: Adapter, plan: Plan = { kind: "session" }) {
    this.service.begin("login", plan);
    return this.settle(() =>
      adapter.provider.login(this.loginContext(adapter)),
    );
  }

  refresh(
    adapter: Adapter,
    session: IdentitySession,
    plan: Plan = { kind: "session" },
  ) {
    this.service.begin("refresh", plan);
    return this.settle(async () => {
      const refresh = adapter.provider.refresh;
      check(refresh, "the adapter has no refresh()");
      return refresh.call(adapter.provider, session);
    });
  }

  logout(adapter: Adapter, session: IdentitySession, plan: Plan) {
    this.service.begin("logout", plan);
    return this.settle(async () => {
      const logout = adapter.provider.logout;
      check(logout, "the adapter has no logout()");
      return logout.call(adapter.provider, session);
    });
  }

  /** A session from a successful login, needed to set up a check. */
  async signedIn(adapter: Adapter): Promise<IdentitySession> {
    const outcome = await this.login(adapter);
    check(
      outcome.kind === "resolved" && outcome.value,
      `a successful login, needed to set up this check, failed (${outcome.kind === "rejected" ? codeOf(outcome.error) : outcome.kind})`,
    );
    return outcome.value;
  }

  /** Every token the service handed out, and the answer-body sentinel. */
  secrets(): string[] {
    return [...this.service.tokens, this.bodySentinel];
  }
}

// ---------------------------------------------------------------- helpers

/** A claim name safe to quote in a reason. */
function claimName(name: string, secrets: readonly string[]): string {
  return /^[A-Za-z0-9_.:-]{1,64}$/.test(name) &&
    !secrets.some((secret) => name.includes(secret))
    ? `"${name}"`
    : "a claim";
}

function claimValue(value: unknown): boolean {
  if (["string", "number", "boolean"].includes(typeof value)) return true;
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

const TOKEN_FIELDS = ["accessToken", "idToken", "refreshToken"] as const;

const EXPIRED: readonly PiShipErrorCode[] = ["IDENTITY_EXPIRED"];
const INVALID: readonly PiShipErrorCode[] = ["IDENTITY_INVALID"];
const REFUSED: readonly PiShipErrorCode[] = [
  "IDENTITY_EXPIRED",
  "IDENTITY_INVALID",
];

/** Whether the adapter refreshes; a workload identity never does. */
function refreshes(adapter: Adapter): boolean {
  return !adapter.workload && typeof adapter.provider.refresh === "function";
}

// ---------------------------------------------------------------- checks

type Check = (h: Harness) => Promise<void>;

/**
 * The login and, for an adapter that refreshes, the refresh that the
 * failure-path checks drive: each runs the operation with `plan` and
 * returns its outcome.
 */
async function operations(
  h: Harness,
  adapter: Adapter,
): Promise<[string, (plan: Plan) => Promise<Outcome<IdentitySession>>][]> {
  const list: [string, (plan: Plan) => Promise<Outcome<IdentitySession>>][] = [
    ["login", (plan) => h.login(adapter, plan)],
  ];
  if (refreshes(adapter)) {
    const session = await h.signedIn(adapter);
    list.push(["refresh", (plan) => h.refresh(adapter, session, plan)]);
  }
  return list;
}

/** A token validation check: the harness mints `kinds`; the adapter must refuse each. */
function tokenCheck(
  kinds: readonly IdentityTokenKind[],
  codes: readonly PiShipErrorCode[],
  what: string,
): Check {
  return async (h) => {
    if (!h.options.harness)
      throw new Skip(
        `needs harness: PiShip does no JWT cryptography, so the kit cannot mint a token ${what}; pass options.harness`,
      );
    const adapter = await h.adapter();
    // A setup that refuses every token would pass the refusals below.
    const valid = await h.login(adapter);
    check(
      h.service.unminted !== "valid",
      "the harness cannot mint a valid token",
    );
    check(
      valid.kind === "resolved",
      `a session with a valid minted token was refused (${valid.kind === "rejected" ? codeOf(valid.error) : valid.kind}), so a refusal would prove nothing`,
    );
    let exercised = 0;
    for (const kind of kinds) {
      for (const [operation, run] of await operations(h, adapter)) {
        const outcome = await run({ kind: "session", mint: kind });
        if (h.service.unminted === kind) continue;
        exercised++;
        const label = `a ${operation} whose token is ${kind}`;
        expectError(rejection(outcome, label), label, { codes });
      }
    }
    if (exercised === 0)
      throw new Skip(`the harness cannot mint a token ${what}`);
  };
}

const checks: Record<IdentityBehavior, Check> = {
  async login(h) {
    const adapter = await h.adapter();
    const { provider } = adapter;
    check(
      typeof provider.kind === "string" && provider.kind.length > 0,
      "the provider has no kind",
    );
    const interactive = (provider as { interactive?: unknown }).interactive;
    check(
      interactive === undefined || typeof interactive === "boolean",
      "interactive is neither true nor false; PiShip refuses the adapter with CONFIG_INVALID",
    );
    const outcome = await h.login(adapter);
    check(outcome.kind !== "hung", "login did not end within the kit's bound");
    check(
      outcome.kind === "resolved",
      `login failed against a service that signed the user in (${outcome.kind === "rejected" ? codeOf(outcome.error) : ""})`,
    );
    check(
      h.service.requests.length > 0,
      "login sent no request through the context's managed fetch",
    );
    const session = outcome.value;
    check(session, "login returned no session");
    check(
      typeof session.subject === "string" && session.subject.length > 0,
      "the session has no subject",
    );
    check(
      typeof session.issuer === "string" && session.issuer.length > 0,
      "the session has no issuer",
    );
    check(
      session.subject === h.subject,
      "the session's subject is not the one the service asserted",
    );
    check(
      session.issuer === h.issuer,
      "the session's issuer is not the one the service asserted (set options.issuer to the issuer the adapter reports)",
    );
    if (adapter.workload)
      check(
        adapter.opened.length === 0,
        "a workload adapter (interactive: false) called openUrl; PiShip fails that run with IDENTITY_INVALID",
      );
    else {
      check(
        adapter.opened.length > 0,
        "an interactive login did not present a URL with openUrl",
      );
      check(
        adapter.opened.every(
          (url) => typeof url === "string" && URL.canParse(url),
        ),
        "openUrl received something that is not a URL",
      );
    }
  },

  async refresh(h) {
    const adapter = await h.adapter();
    if (adapter.workload)
      throw new Skip(
        "a workload identity (interactive: false) is not refreshed: PiShip calls login() again",
      );
    if (!adapter.provider.refresh)
      throw new Skip(
        "the adapter has no refresh(); PiShip asks the user to sign in again when the session expires",
      );
    const session = await h.signedIn(adapter);
    const before = h.service.requests.length;
    const outcome = await h.refresh(adapter, session);
    check(
      outcome.kind !== "hung",
      "refresh did not end within the kit's bound",
    );
    check(
      outcome.kind === "resolved" && outcome.value,
      `refresh failed against a service that refreshed the session (${outcome.kind === "rejected" ? codeOf(outcome.error) : ""})`,
    );
    check(
      h.service.requests.length > before,
      "refresh sent no request to the service",
    );
    const refreshed = outcome.value;
    check(
      refreshed.issuer === session.issuer,
      "the refreshed session names another issuer; PiShip refuses a refresh that changes the principal (iss, sub)",
    );
    check(
      refreshed.subject === session.subject,
      "the refreshed session names another subject; PiShip refuses a refresh that changes the principal (iss, sub)",
    );
    const issued = h.service.current;
    check(issued, "the service issued no refreshed session");
    check(
      revealed(refreshed.accessToken) !== revealed(session.accessToken),
      "refresh returned the current access token instead of the new one",
    );
    check(
      revealed(refreshed.accessToken) === issued.accessToken,
      "the refreshed access token is not the one the service issued",
    );
    check(
      revealed(refreshed.refreshToken) === issued.refreshToken,
      "the refreshed session does not carry the refresh token the service rotated to",
    );
  },

  async expiry(h) {
    const adapter = await h.adapter();
    const near = (session: IdentitySession, expected: Date) => {
      const at = expiryOf(session);
      return (
        at !== undefined &&
        Math.abs(at - expected.getTime()) <= EXPIRY_TOLERANCE_MS
      );
    };
    const session = await h.signedIn(adapter);
    const issued = h.service.current;
    check(issued, "the service issued no session");
    check(
      expiryOf(session) !== undefined,
      "the session has no expiresAt although the service gave an expiry",
    );
    check(
      near(session, issued.expiresAt),
      "the session's expiresAt is not the service's expiry",
    );
    if (refreshes(adapter)) {
      const renewed = await h.refresh(adapter, session);
      const next = h.service.current;
      check(
        renewed.kind === "resolved" && renewed.value && next,
        "refresh failed, so the refreshed expiry could not be checked",
      );
      check(
        near(renewed.value, next.expiresAt),
        "the refreshed session's expiresAt is not the service's new expiry",
      );
    }
    const expired = await h.login(adapter, {
      kind: "session",
      expiresIn: EXPIRED_BY,
    });
    const past = h.service.current;
    check(
      expired.kind !== "hung",
      "a login the service answered with an expired session did not end within the kit's bound",
    );
    if (expired.kind === "rejected")
      expectError(
        expired.error,
        "a session the service issued already expired",
        {
          codes: EXPIRED,
        },
      );
    else
      check(
        past && expired.value && near(expired.value, past.expiresAt),
        "a session the service issued already expired was returned with another expiry",
      );
  },

  async logout(h) {
    const adapter = await h.adapter();
    if (adapter.workload)
      throw new Skip(
        "a workload identity (interactive: false) is not logged out: PiShip holds its session in memory only",
      );
    if (!adapter.provider.logout)
      throw new Skip(
        "the adapter has no logout(); PiShip deletes the stored session without revoking it",
      );
    const session = await h.signedIn(adapter);
    const before = h.service.requests.length;
    const outcome = await h.logout(adapter, session, { kind: "logged-out" });
    check(outcome.kind !== "hung", "logout did not end within the kit's bound");
    check(
      outcome.kind === "resolved",
      `logout failed although the service accepted it (${outcome.kind === "rejected" ? codeOf(outcome.error) : ""})`,
    );
    const sent = h.service.requests.slice(before);
    check(sent.length > 0, "logout sent no request to the service");
    const names = [session.refreshToken, session.accessToken]
      .map(revealed)
      .filter((token): token is string => !!token);
    check(
      sent.some((request) => {
        const text = requestText(request);
        return names.some((token) => text.includes(token));
      }),
      "the logout request names neither the refresh token nor the access token",
    );
    const revoked = await h.signedIn(adapter);
    const again = await h.logout(adapter, revoked, {
      kind: "already-revoked",
    });
    check(
      again.kind !== "hung",
      "logout of an already revoked session did not end within the kit's bound",
    );
    check(
      again.kind === "resolved",
      `logout of a session the service had already revoked threw ${again.kind === "rejected" ? codeOf(again.error) : ""}; it must resolve`,
    );
  },

  async "claim normalization"(h) {
    const adapter = await h.adapter();
    const session = await h.signedIn(adapter);
    const sessions: [string, IdentitySession][] = [["the session", session]];
    if (refreshes(adapter)) {
      const refreshed = await h.refresh(adapter, session);
      check(
        refreshed.kind === "resolved" && refreshed.value,
        "refresh failed, so the refreshed claims could not be checked",
      );
      sessions.push(["the refreshed session", refreshed.value]);
    }
    const secrets = h.secrets();
    for (const [what, session] of sessions) {
      const claims: unknown = session.claims;
      if (claims !== undefined) {
        check(
          claims !== null &&
            typeof claims === "object" &&
            !Array.isArray(claims),
          `${what}'s claims are not an object`,
        );
        for (const [name, value] of Object.entries(claims)) {
          check(
            IDENTITY_ALLOWED_CLAIMS.includes(name),
            `${what}'s claims hold ${claimName(name, secrets)}, which is not an allowlisted claim`,
          );
          check(
            claimValue(value),
            `${what}'s claim ${claimName(name, secrets)} is neither a scalar nor a list of strings`,
          );
        }
      }
      const shown = {
        subject: session.subject,
        issuer: session.issuer,
        displayName: session.displayName,
        email: session.email,
        claims,
      };
      check(
        !secretsIn(shown, secrets),
        `${what} shows a token in its claims, subject, issuer, displayName, or email`,
      );
    }
  },

  async "revoked session"(h) {
    const adapter = await h.adapter();
    if (!adapter.workload && !adapter.provider.refresh)
      throw new Skip(
        "the adapter has no refresh(), so a revoked refresh token is never presented",
      );
    const cases: [string, Plan][] = [
      ["refused as invalid_grant", { kind: "invalid-grant" }],
      [
        "refused with HTTP 401",
        {
          kind: "raw",
          handler: () =>
            answer(
              401,
              { "content-type": "application/json" },
              '{"error":"invalid_token"}',
            ),
        },
      ],
    ];
    if (adapter.workload) {
      for (const [how, plan] of cases) {
        const what = `a workload login the service ${how}`;
        expectError(rejection(await h.login(adapter, plan), what), what, {
          codes: EXPIRED,
        });
      }
      return;
    }
    const session = await h.signedIn(adapter);
    for (const [how, plan] of cases) {
      const what = `a refresh the service ${how}`;
      expectError(
        rejection(await h.refresh(adapter, session, plan), what),
        what,
        {
          codes: EXPIRED,
        },
      );
    }
    if (session.refreshToken) {
      const { refreshToken: _dropped, ...withoutRefresh } = session;
      const what = "a refresh of a session without a refresh token";
      expectError(
        rejection(await h.refresh(adapter, withoutRefresh), what),
        what,
        { codes: EXPIRED },
      );
    }
  },

  async "secret redaction"(h) {
    const adapter = await h.adapter();
    const session = await h.signedIn(adapter);
    for (const field of TOKEN_FIELDS) {
      const token: unknown = session[field];
      if (token === undefined) continue;
      check(
        typeof token !== "string",
        `the session's ${field} is a plain string; wrap it in a SecretValue`,
      );
      const value = revealed(token);
      check(value !== undefined, `the session's ${field} is not a SecretValue`);
      check(
        !secretsIn(token, [value]),
        `the session's ${field} renders its token; wrap it in a SecretValue`,
      );
    }
    const refreshToken = revealed(session.refreshToken) ?? "";
    const accessToken = revealed(session.accessToken) ?? "";
    const body = JSON.stringify({
      error: "invalid_request",
      error_description: `${h.bodySentinel} ${refreshToken}`,
    });
    const answers: [string, Handler][] = [
      [
        "a 400 whose body holds a sentinel and the refresh token",
        () => answer(400, { "content-type": "application/json" }, body),
      ],
      [
        "a 401 whose body holds a sentinel",
        () => answer(401, { "content-type": "application/json" }, body),
      ],
      [
        "a 502 whose HTML body holds a sentinel",
        () =>
          answer(
            502,
            { "content-type": "text/html" },
            `<html><body>${h.bodySentinel}</body></html>`,
          ),
      ],
      [
        "a 200 whose body is not the expected answer",
        () =>
          answer(
            200,
            { "content-type": "application/json" },
            `<html>${h.bodySentinel}</html>`,
          ),
      ],
      [
        "a transport error that quotes the access token",
        () => {
          throw new TypeError(
            `Invalid value "Bearer ${accessToken}" for header "authorization"`,
          );
        },
      ],
    ];
    for (const [operation, run] of await operations(h, adapter))
      for (const [what, handler] of answers) {
        const outcome = await run({ kind: "raw", handler });
        const label = `${operation} after ${what}`;
        check(
          outcome.kind !== "hung",
          `${label}: the call did not end within the kit's bound`,
        );
        if (outcome.kind === "rejected")
          check(
            !secretsIn(outcome.error, h.secrets()),
            `${label}: the error shows a token or the service's answer body`,
          );
      }
    if (!adapter.workload && adapter.provider.logout)
      for (const [what, handler] of answers.slice(2)) {
        const outcome = await h.logout(adapter, session, {
          kind: "raw",
          handler,
        });
        check(
          outcome.kind !== "hung",
          `logout after ${what}: the call did not end within the kit's bound`,
        );
        if (outcome.kind === "rejected")
          check(
            !secretsIn(outcome.error, h.secrets()),
            `logout after ${what}: the error shows a token or the service's answer body`,
          );
      }
    if (h.options.harness) {
      const outcome = await h.login(adapter, {
        kind: "session",
        mint: "bad-signature",
      });
      if (outcome.kind === "rejected")
        check(
          !secretsIn(outcome.error, h.secrets()),
          "the refusal of a token with a bad signature shows the token",
        );
    }
  },

  async "service outage"(h) {
    const adapter = await h.adapter();
    const unavailable: [string, Handler, Expected][] = [
      [
        "a 503 with Retry-After",
        () => answer(503, { "retry-after": "5" }),
        {
          codes: ["GATEWAY_UNREACHABLE"],
          retryable: true,
          retryAfterMs: 5_000,
        },
      ],
      [
        "a 502 HTML error page",
        () =>
          answer(
            502,
            { "content-type": "text/html" },
            "<html>bad gateway</html>",
          ),
        { codes: ["GATEWAY_UNREACHABLE"], retryable: true },
      ],
      [
        "a 429 with Retry-After",
        () => answer(429, { "retry-after": String(RETRY_AFTER_SECONDS) }),
        {
          codes: ["GATEWAY_RATE_LIMITED"],
          retryable: true,
          retryAfterMs: RETRY_AFTER_SECONDS * 1000,
        },
      ],
      [
        "a refused connection",
        () => {
          throw new TypeError("fetch failed", {
            cause: { code: "ECONNREFUSED" },
          });
        },
        { codes: ["GATEWAY_UNREACHABLE"], retryable: true },
      ],
      [
        "a service that never answers",
        (_request, signal) => h.service.stall(signal),
        { codes: ["GATEWAY_UNREACHABLE"], retryable: true },
      ],
      [
        "a NETWORK_DENIED refusal from the managed fetch",
        () => {
          throw new PiShipError(
            "NETWORK_DENIED",
            "refused by the network policy",
            {
              component: "network",
            },
          );
        },
        { codes: ["NETWORK_DENIED"], retryable: false },
      ],
    ];
    for (const [operation, run] of await operations(h, adapter))
      for (const [what, handler, expected] of unavailable) {
        const label = `${operation} after ${what}`;
        expectError(
          rejection(await run({ kind: "raw", handler }), label),
          label,
          expected,
        );
      }
  },

  "invalid issuer": tokenCheck(
    ["wrong-issuer"],
    INVALID,
    "with a wrong issuer",
  ),
  "invalid audience": tokenCheck(
    ["wrong-audience"],
    INVALID,
    "for a wrong audience",
  ),
  "invalid signature": tokenCheck(
    ["bad-signature"],
    INVALID,
    "with a bad signature",
  ),
  "token validity window": tokenCheck(
    ["expired", "not-yet-valid"],
    REFUSED,
    "outside its validity window",
  ),
  "revoked token": tokenCheck(["revoked"], REFUSED, "that the issuer revoked"),
};

/**
 * Run an identity adapter against the kit's fake identity service and report
 * each behavior of `IDENTITY_CONTRACT` as passed, failed, or skipped, with a
 * reason for anything but passed. `adapter` is the adapter module's default
 * export, as `defineIdentityAdapter` returns it; the kit calls it with a
 * context whose `fetch` reaches only the fake service. Without
 * `options.harness`, the token-validation behaviors are skipped.
 */
export async function testIdentityAdapter(
  adapter: AdapterFactory<IdentityProvider>,
  options: IdentityKitOptions = {},
): Promise<ConformanceReport> {
  const timeout = options.requestTimeoutMs;
  if (timeout !== undefined && !(Number.isFinite(timeout) && timeout > 0))
    throw new RangeError("requestTimeoutMs must be a positive number");
  const harness = new Harness(adapter, options);
  const results: ConformanceResult[] = [];
  for (const behavior of IDENTITY_BEHAVIORS) {
    try {
      await checks[behavior](harness);
      results.push({ behavior, status: "passed" });
    } catch (error) {
      results.push(
        error instanceof Skip
          ? { behavior, status: "skipped", reason: error.message }
          : {
              behavior,
              status: "failed",
              reason:
                error instanceof Finding
                  ? error.message
                  : `the check ended unexpectedly with ${codeOf(error)}`,
            },
      );
    } finally {
      harness.service.release();
    }
  }
  return { kind: "identity", results };
}
