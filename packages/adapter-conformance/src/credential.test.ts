import {
  type CredentialContext,
  type CredentialProvider,
  defineCredentialAdapter,
  type IdentitySession,
  PiShipError,
  parseRetryAfter,
  type RuntimeCredential,
  SecretValue,
  withTimeout,
} from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_BEHAVIORS,
  CREDENTIAL_CONTRACT,
  type ConformanceReport,
  type CredentialBehavior,
  type IssuedCredential,
  testCredentialAdapter,
} from "./index.js";

// The adapter under test ends a request after this long; the kit waits a
// few times longer before it reports a hang, so a busy machine has room.
const TIMEOUT_MS = 150;

/** One seeded defect; the reference adapter has none. */
type Fault =
  | "acquire returns an unknown kind"
  | "refresh keeps the current credential ID"
  | "ignores the broker's expiry"
  | "revoke does not name the credential"
  | "reads 401 as a retryable failure"
  | "treats 403 as retryable"
  | "reads the 403 body before deciding"
  | "drops Retry-After on 429"
  | "treats 5xx as final"
  | "lets the caller signal replace the timeout"
  | "treats a timeout as final"
  | "ignores the abort signal"
  | "keeps the transport error as cause"
  | "echoes the broker answer in errors"
  | "shares the credential ID between calls"
  | "retries a retryable failure once"
  | "makes a policy refusal retryable"
  | "does not send the idempotency key"
  | "does not report the idempotency key";

interface ReferenceOptions {
  readonly fault?: Fault;
  /** `custom`: the service answers `{key, id, expiresAt}` instead of the http-broker shape. */
  readonly wire?: "http-broker" | "custom";
  readonly revoke?: boolean;
}

type Operation = "acquire" | "revoke";

/**
 * A small credential adapter that follows the contract, written the way a
 * company would: SDK only, one request per operation, no retries. Each
 * `fault` breaks exactly one behavior.
 */
function referenceAdapter(options: ReferenceOptions = {}) {
  const fault = options.fault;
  return defineCredentialAdapter((context) => {
    let sharedId: string | undefined;
    const failure = (
      operation: Operation,
      reason: string,
      message: string,
      extra: {
        readonly retryable?: boolean;
        readonly retryAfterMs?: number | undefined;
        readonly key?: string | undefined;
      } = {},
    ) =>
      new PiShipError(
        operation === "revoke"
          ? "CREDENTIAL_REVOKED"
          : "CREDENTIAL_ACQUIRE_FAILED",
        message,
        {
          component: "credential",
          retryable: extra.retryable ?? false,
          ...(extra.retryAfterMs === undefined
            ? {}
            : { retryAfterMs: extra.retryAfterMs }),
          sanitizedDetail: {
            operation,
            reason,
            ...(extra.key && fault !== "does not report the idempotency key"
              ? { idempotencyKey: extra.key }
              : {}),
          },
        },
      );

    /** One request; returns the answer for a success, throws the contract error otherwise. */
    async function send(
      operation: Operation,
      url: string,
      token: SecretValue | undefined,
      body: unknown,
      ctx: CredentialContext,
      attempt = 0,
    ): Promise<string> {
      const key = operation === "acquire" ? ctx.idempotencyKey : undefined;
      const again = (error: PiShipError) => {
        if (
          fault === "retries a retryable failure once" &&
          error.retryable &&
          attempt === 0
        )
          return send(operation, url, token, body, ctx, attempt + 1);
        throw error;
      };
      if (ctx.signal?.aborted)
        throw failure(operation, "cancelled", "The request was cancelled", {
          key,
        });
      const signal =
        fault === "lets the caller signal replace the timeout"
          ? (ctx.signal ?? AbortSignal.timeout(TIMEOUT_MS))
          : fault === "ignores the abort signal"
            ? AbortSignal.timeout(TIMEOUT_MS)
            : withTimeout(TIMEOUT_MS, ctx.signal);
      // The failure of a request without an answer, or of its body.
      const lost = (error: unknown): PiShipError => {
        if (ctx.signal?.aborted)
          return failure(operation, "cancelled", "The request was cancelled", {
            key,
          });
        if (
          (error as Error)?.name === "TimeoutError" ||
          (error as Error)?.name === "AbortError"
        )
          return failure(
            operation,
            "timeout",
            "The credential service did not respond in time",
            { retryable: fault !== "treats a timeout as final", key },
          );
        const unreachable = failure(
          operation,
          "unreachable",
          "The credential service is unreachable",
          { retryable: true, key },
        );
        if (fault === "keeps the transport error as cause")
          Object.defineProperty(unreachable, "cause", { value: error });
        return unreachable;
      };
      let response: Response;
      try {
        response = await context.fetch(url, {
          method: "POST",
          headers: {
            ...(token ? { authorization: `Bearer ${token.reveal()}` } : {}),
            "content-type": "application/json",
            ...(key && fault !== "does not send the idempotency key"
              ? { "idempotency-key": key }
              : {}),
          },
          body: JSON.stringify(body),
          signal,
        });
      } catch (error) {
        // Network and TLS policy refusals keep their own code.
        if (error instanceof PiShipError) {
          if (fault === "makes a policy refusal retryable")
            throw failure(operation, "unreachable", "Refused", {
              retryable: true,
              key,
            });
          throw error;
        }
        return again(lost(error));
      }
      const status = response.status;
      if (status >= 300) {
        // The status decides; the body is read only by the seeded defects.
        const reads =
          (fault === "reads the 403 body before deciding" && status === 403) ||
          (fault === "echoes the broker answer in errors" && status !== 403);
        if (!reads) response.body?.cancel().catch(() => {});
        const text = reads
          ? await response.text().catch((error: unknown) => {
              throw lost(error);
            })
          : "";
        if (status === 401 && operation === "revoke") return "";
        if (status === 401)
          throw fault === "reads 401 as a retryable failure"
            ? failure(operation, "authentication", "Rejected", {
                retryable: true,
                key,
              })
            : new PiShipError(
                "IDENTITY_EXPIRED",
                "The credential service rejected the sign-in",
                { component: "credential", userAction: "Run login again" },
              );
        if (status === 403 && fault !== "treats 403 as retryable")
          throw new PiShipError(
            "CREDENTIAL_DENIED",
            "The credential service denied this user",
            { component: "credential" },
          );
        const retryable =
          status === 429 ||
          status === 403 ||
          (status >= 500 && fault !== "treats 5xx as final");
        const retryAfterMs =
          retryable && !(status === 429 && fault === "drops Retry-After on 429")
            ? parseRetryAfter(response.headers.get("retry-after"))
            : undefined;
        return again(
          failure(
            operation,
            status === 429
              ? "rate-limited"
              : status >= 500
                ? "unavailable"
                : status === 403
                  ? "denied"
                  : "rejected",
            fault === "echoes the broker answer in errors"
              ? `The credential service answered HTTP ${status}: ${text}`
              : `The credential service answered HTTP ${status}`,
            { retryable, retryAfterMs, key },
          ),
        );
      }
      try {
        return await response.text();
      } catch (error) {
        throw lost(error);
      }
    }

    function parse(text: string, key: string | undefined): RuntimeCredential {
      const malformed = () =>
        failure(
          "acquire",
          "contract",
          fault === "echoes the broker answer in errors"
            ? `The credential service answered ${text}`
            : "The credential service answer is malformed",
          { key },
        );
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(text) as Record<string, unknown>;
      } catch {
        throw malformed();
      }
      const custom = options.wire === "custom";
      const secret = custom ? body.key : body.credential;
      const id = custom ? body.id : body.credential_id;
      const expires = custom ? body.expiresAt : body.expires_at;
      if (
        typeof secret !== "string" ||
        typeof id !== "string" ||
        typeof expires !== "string"
      )
        throw malformed();
      const expiresAt = new Date(expires);
      if (fault !== "ignores the broker's expiry" && expiresAt <= new Date())
        throw new PiShipError(
          "CREDENTIAL_EXPIRED",
          "The credential service issued an expired credential",
          { component: "credential" },
        );
      return {
        kind: "api_key",
        secret: new SecretValue(secret),
        credentialId: id,
        ...(fault === "ignores the broker's expiry" ? {} : { expiresAt }),
      };
    }

    async function acquire(
      identity: IdentitySession | null,
      ctx: CredentialContext,
    ): Promise<RuntimeCredential> {
      const text = await send(
        "acquire",
        context.endpoints.brokerEndpoint ?? "",
        identity?.accessToken,
        { distribution: ctx.distributionId },
        ctx,
      );
      const credential = parse(text, ctx.idempotencyKey);
      if (fault !== "shares the credential ID between calls") return credential;
      // A value kept on the adapter instead of the call.
      sharedId = credential.credentialId;
      await new Promise((resolve) => setImmediate(resolve));
      return { ...credential, ...(sharedId ? { credentialId: sharedId } : {}) };
    }

    const provider: CredentialProvider = {
      mode: "adapter",
      requiresIdentity: true,
      async acquire(identity, ctx) {
        const credential = await acquire(identity, ctx);
        return fault === "acquire returns an unknown kind"
          ? ({ ...credential, kind: "key" } as unknown as RuntimeCredential)
          : credential;
      },
      async refresh(identity, current, ctx) {
        const credential = await acquire(identity, ctx);
        return fault === "refresh keeps the current credential ID" &&
          current.credentialId
          ? { ...credential, credentialId: current.credentialId }
          : credential;
      },
    };
    if (options.revoke === false) return provider;
    return {
      ...provider,
      async revoke(credential, ctx) {
        const unnamed = fault === "revoke does not name the credential";
        await send(
          "revoke",
          context.endpoints.brokerRevokeEndpoint ?? "",
          unnamed ? undefined : credential.secret,
          unnamed ? {} : { credential_id: credential.credentialId ?? null },
          ctx,
        );
      },
    };
  });
}

const run = (adapter = referenceAdapter(), options = {}) =>
  testCredentialAdapter(adapter, { requestTimeoutMs: TIMEOUT_MS, ...options });

const statuses = (report: ConformanceReport) =>
  Object.fromEntries(
    report.results.map((result) => [result.behavior, result.status]),
  );

const allPassed = Object.fromEntries(
  CREDENTIAL_BEHAVIORS.map((behavior) => [behavior, "passed"]),
);

/** No reason may quote a token, a credential, or a broker body. */
function expectCleanReasons(report: ConformanceReport): void {
  for (const result of report.results)
    expect(result.reason ?? "").not.toMatch(
      /conformance-(credential|identity-token|broker-body)-/,
    );
}

describe("credential conformance kit", () => {
  it("names each behavior of §16.2 once, each with a contract statement", () => {
    expect(CREDENTIAL_BEHAVIORS).toEqual([
      "acquire",
      "refresh",
      "expiry",
      "revoke",
      "401",
      "403",
      "429",
      "5xx",
      "timeout",
      "abort",
      "redaction",
      "concurrent refresh",
      "retry behavior",
      "idempotency",
    ]);
    for (const entry of CREDENTIAL_CONTRACT)
      expect(entry.statement.length).toBeGreaterThan(40);
  });

  // Each kit run is independent (its own adapter and broker) and mostly
  // waits out request timeouts, so the runs below are one concurrent group.
  it.concurrent("passes every behavior for a conforming adapter", async () => {
    const report = await run();
    expect(report.kind).toBe("credential");
    expect(report.results.map((result) => result.behavior)).toEqual(
      CREDENTIAL_BEHAVIORS,
    );
    expect(
      report.results.filter((result) => result.status !== "passed"),
    ).toEqual([]);
  });

  it.concurrent("passes an adapter for another wire format through the issue hook", async () => {
    const report = await run(referenceAdapter({ wire: "custom" }), {
      issue: (credential: IssuedCredential) =>
        Response.json({
          key: credential.secret,
          id: credential.credentialId,
          expiresAt: credential.expiresAt.toISOString(),
        }),
    });
    expect(statuses(report)).toEqual(allPassed);
    // The default http-broker answer is not that wire format.
    const mismatched = await run(referenceAdapter({ wire: "custom" }));
    expect(statuses(mismatched).acquire).toBe("failed");
  });

  it.concurrent("skips revoke for an adapter without revoke() and never counts it as passed", async () => {
    const report = await run(referenceAdapter({ revoke: false }));
    const revoke = report.results.find(
      (result) => result.behavior === "revoke",
    );
    expect(revoke).toEqual({
      behavior: "revoke",
      status: "skipped",
      reason: expect.stringContaining("no revoke()"),
    });
    expect(statuses(report)).toEqual({ ...allPassed, revoke: "skipped" });
  });

  it.concurrent("skips idempotency when the adapter declares its service ignores keys", async () => {
    const report = await run(referenceAdapter(), { idempotency: false });
    expect(statuses(report)).toEqual({ ...allPassed, idempotency: "skipped" });
    expect(
      report.results.find((result) => result.behavior === "idempotency")
        ?.reason,
    ).toMatch(/does not honor idempotency keys/);
  });

  it.concurrent("fails every behavior, with a reason, when the factory builds no provider", async () => {
    const report = await run(
      defineCredentialAdapter(() => undefined as unknown as CredentialProvider),
    );
    for (const result of report.results) {
      expect(result.status).toBe("failed");
      expect(result.reason).toMatch(/returned no credential provider/);
    }
  });

  it.concurrent("reports a factory that throws by code, never by its message", async () => {
    const report = await run(
      defineCredentialAdapter(() => {
        throw new TypeError("conformance-identity-token-in-a-message");
      }),
    );
    for (const result of report.results)
      expect(result).toMatchObject({
        status: "failed",
        reason:
          "the check ended unexpectedly with a TypeError that is not a PiShipError",
      });
    expectCleanReasons(report);
  });

  it.concurrent("refuses a request timeout that is not a positive number", async () => {
    for (const requestTimeoutMs of [
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ])
      await expect(
        testCredentialAdapter(referenceAdapter(), { requestTimeoutMs }),
      ).rejects.toThrow(RangeError);
  });

  // Each seeded defect breaks exactly one behavior: the kit fails that one,
  // with a reason, and still passes every other.
  const seeds: [Fault, CredentialBehavior, RegExp][] = [
    ["acquire returns an unknown kind", "acquire", /kind is not api_key/],
    [
      "refresh keeps the current credential ID",
      "refresh",
      /credential ID does not belong/,
    ],
    [
      "ignores the broker's expiry",
      "expiry",
      /expiresAt is not the broker's expiry/,
    ],
    ["revoke does not name the credential", "revoke", /names neither/],
    [
      "reads 401 as a retryable failure",
      "401",
      /expected IDENTITY_EXPIRED, got CREDENTIAL_ACQUIRE_FAILED/,
    ],
    [
      "treats 403 as retryable",
      "403",
      /expected CREDENTIAL_DENIED, got CREDENTIAL_ACQUIRE_FAILED/,
    ],
    [
      "reads the 403 body before deciding",
      "403",
      /body that never arrives: expected CREDENTIAL_DENIED/,
    ],
    ["drops Retry-After on 429", "429", /expected retryAfterMs 7000, got none/],
    [
      "treats 5xx as final",
      "5xx",
      /answered 500: expected retryable true, got false/,
    ],
    [
      "lets the caller signal replace the timeout",
      "timeout",
      /with a caller signal .*did not end within the kit's bound/,
    ],
    [
      "treats a timeout as final",
      "timeout",
      /never answers: expected retryable true, got false/,
    ],
    ["ignores the abort signal", "abort", /not ended by the caller's signal/],
    [
      "keeps the transport error as cause",
      "redaction",
      /quotes the identity token: the error shows/,
    ],
    [
      "echoes the broker answer in errors",
      "redaction",
      /the error shows a token, credential, or answer body/,
    ],
    [
      "shares the credential ID between calls",
      "concurrent refresh",
      /carries the ID or expiry of the credential issued to the other call/,
    ],
    [
      "retries a retryable failure once",
      "retry behavior",
      /after a timeout: the adapter sent 2 requests where one acquire sends 1/,
    ],
    [
      "makes a policy refusal retryable",
      "retry behavior",
      /NETWORK_DENIED refusal .*expected NETWORK_DENIED, got CREDENTIAL_ACQUIRE_FAILED/,
    ],
    [
      "does not send the idempotency key",
      "idempotency",
      /did not carry CredentialContext.idempotencyKey/,
    ],
    [
      "does not report the idempotency key",
      "idempotency",
      /does not report its key as detail.idempotencyKey/,
    ],
  ];
  it.concurrent.each(seeds)(
    "fails only %j, under %s",
    async (fault, behavior, reason) => {
      const report = await run(referenceAdapter({ fault }));
      const result = report.results.find((item) => item.behavior === behavior);
      expect(result?.status).toBe("failed");
      expect(result?.reason).toMatch(reason);
      expect(statuses(report)).toEqual({ ...allPassed, [behavior]: "failed" });
      expectCleanReasons(report);
    },
    30_000,
  );

  it("covers every behavior with at least one seeded defect", () => {
    expect(new Set(seeds.map(([, behavior]) => behavior))).toEqual(
      new Set(CREDENTIAL_BEHAVIORS),
    );
  });
});
