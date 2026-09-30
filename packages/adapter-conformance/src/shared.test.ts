import { inspect } from "node:util";
import { PiShipError, SecretValue } from "@piship/adapter-sdk";
import { describe, expect, it } from "vitest";
import * as barrel from "./index.js";
import {
  answer,
  check,
  codeOf,
  expectError,
  expiryOf,
  Finding,
  rejection,
  renderings,
  requestText,
  revealed,
  secretsIn,
  settle,
} from "./shared.js";

const SENTINEL = "shared-helper-sentinel-value";

describe("the kits' shared helpers", () => {
  it("are internal: the barrel exports none of them", () => {
    for (const name of [
      "Finding",
      "check",
      "settle",
      "rejection",
      "expectError",
      "renderings",
      "secretsIn",
      "revealed",
      "expiryOf",
      "codeOf",
      "answer",
      "requestText",
      "RETRY_AFTER_SECONDS",
    ])
      expect(barrel, name).not.toHaveProperty(name);
  });

  it("fail a check with a Finding that carries the reason", () => {
    expect(() => check(true, "never")).not.toThrow();
    expect(() => check(0, "the reason")).toThrow(Finding);
    expect(() => check(undefined, "the reason")).toThrow("the reason");
  });

  it("settle a call as resolved, rejected, or hung", async () => {
    expect(await settle(() => 7, 1_000)).toEqual({
      kind: "resolved",
      value: 7,
    });
    const error = new Error("no");
    expect(await settle(() => Promise.reject(error), 1_000)).toEqual({
      kind: "rejected",
      error,
    });
    // A synchronous throw is a rejection, not an escape.
    expect(
      await settle(() => {
        throw error;
      }, 1_000),
    ).toEqual({ kind: "rejected", error });
    const started = Date.now();
    expect(await settle(() => new Promise(() => undefined), 50)).toEqual({
      kind: "hung",
    });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("call the call at once, and release a hung call and wait for it to end", async () => {
    let called = false;
    const pending = settle(() => {
      called = true;
    }, 1_000);
    expect(called).toBe(true);
    await pending;
    let end: (() => void) | undefined;
    const ended: string[] = [];
    const outcome = await settle(
      () =>
        new Promise<void>((resolve) => {
          end = () => {
            ended.push("released");
            resolve();
          };
        }),
      50,
      () => end?.(),
    );
    expect(outcome).toEqual({ kind: "hung" });
    expect(ended).toEqual(["released"]);
  });

  it("demand a rejection and name what else happened", () => {
    const error = new Error("x");
    expect(rejection({ kind: "rejected", error }, "a call")).toBe(error);
    expect(() => rejection({ kind: "hung" }, "a call")).toThrow(
      "a call: the call did not end within the kit's bound",
    );
    expect(() => rejection({ kind: "resolved", value: 1 }, "a call")).toThrow(
      "a call: the call succeeded instead of failing",
    );
  });

  it("hold a failure to the error contract", () => {
    const error = new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "failed", {
      retryable: true,
      retryAfterMs: 7_000,
    });
    expect(
      expectError(error, "it", {
        codes: ["CREDENTIAL_ACQUIRE_FAILED"],
        retryable: true,
        retryAfterMs: 7_000,
      }),
    ).toBe(error);
    expectError(error, "it", {
      codes: ["CREDENTIAL_ACQUIRE_FAILED"],
      retryAfterMs: [7_000, 7_000],
    });
    expect(() =>
      expectError(new Error("plain"), "it", { codes: ["IDENTITY_EXPIRED"] }),
    ).toThrow("it: the failure is not a PiShipError from @piship/adapter-sdk");
    expect(() =>
      expectError(error, "it", {
        codes: ["IDENTITY_EXPIRED", "IDENTITY_INVALID"],
      }),
    ).toThrow(
      "it: expected IDENTITY_EXPIRED or IDENTITY_INVALID, got CREDENTIAL_ACQUIRE_FAILED",
    );
    expect(() =>
      expectError(error, "it", {
        codes: ["CREDENTIAL_ACQUIRE_FAILED"],
        retryable: false,
      }),
    ).toThrow("it: expected retryable false, got true");
    expect(() =>
      expectError(error, "it", {
        codes: ["CREDENTIAL_ACQUIRE_FAILED"],
        retryAfterMs: 5_000,
      }),
    ).toThrow("it: expected retryAfterMs 5000, got 7000");
    for (const range of [
      [7_001, 9_000],
      [1_000, 6_999],
    ] as const)
      expect(() =>
        expectError(error, "it", {
          codes: ["CREDENTIAL_ACQUIRE_FAILED"],
          retryAfterMs: range,
        }),
      ).toThrow(
        `it: expected retryAfterMs between ${range[0]} and ${range[1]}, got 7000`,
      );
    expect(() =>
      expectError(new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "x"), "it", {
        codes: ["CREDENTIAL_ACQUIRE_FAILED"],
        retryAfterMs: [1, 2],
      }),
    ).toThrow("got none");
  });

  it("find a secret wherever a value can show it", () => {
    const cases: [string, unknown][] = [
      ["a message", new Error(`failed: ${SENTINEL}`)],
      ["a cause", new Error("outer", { cause: new Error(SENTINEL) })],
      [
        "a cause several levels down",
        new Error("1", {
          cause: new Error("2", {
            cause: new Error("3", { cause: { note: SENTINEL } }),
          }),
        }),
      ],
      ["a stack", Object.assign(new Error("x"), { stack: SENTINEL })],
      [
        "a hidden property",
        Object.defineProperty(new Error("x"), "hidden", { value: SENTINEL }),
      ],
      [
        "a userAction",
        new PiShipError("IDENTITY_EXPIRED", "x", {
          userAction: `Run ${SENTINEL}`,
        }),
      ],
      [
        "a detail",
        new PiShipError("IDENTITY_EXPIRED", "x", {
          sanitizedDetail: { status: SENTINEL },
        }),
      ],
      ["a plain object", { nested: { deep: [SENTINEL] } }],
      ["a string", SENTINEL],
    ];
    for (const [what, value] of cases)
      expect(secretsIn(value, ["other", SENTINEL]), what).toBe(true);
    expect(secretsIn(new Error("clean"), [SENTINEL])).toBe(false);
    expect(secretsIn(new SecretValue(SENTINEL), [SENTINEL])).toBe(false);
    // A rendering that throws is skipped, never fatal.
    const hostile = {
      toString() {
        throw new Error("no");
      },
      toJSON() {
        throw new Error("no");
      },
      [inspect.custom]() {
        throw new Error("no");
      },
    };
    expect(() => renderings(hostile)).not.toThrow();
  });

  it("search each rendering, also when every other one hides the secret", () => {
    // Each value shows the secret through one path only.
    const hidden = {
      toString: () => "hidden",
      toJSON: () => ({}),
      [inspect.custom]: () => "hidden",
    };
    // Only the cause chain holds it.
    const viaCause = { ...hidden, cause: { note: SENTINEL } };
    // Only the raw message holds it: formatError redacts a bearer token.
    const bearer = `Bearer ${SENTINEL}`;
    const viaMessage = Object.assign(new Error(bearer), hidden, {
      stack: "hidden",
    });
    // Only sanitizedDetail holds it.
    class Quiet extends PiShipError {
      override toJSON() {
        return {};
      }
      override toString() {
        return "hidden";
      }
      [inspect.custom]() {
        return "hidden";
      }
    }
    // A value another test wrapped in a SecretValue is redacted from a
    // PiShipError's detail, so this one is new.
    const detail = "shared-helper-detail-value";
    const viaDetail = Object.assign(
      new Quiet("IDENTITY_EXPIRED", "x", {
        sanitizedDetail: { status: detail },
      }),
      { stack: "hidden" },
    );
    for (const [what, value, secret] of [
      ["the cause chain", viaCause, SENTINEL],
      ["the raw message", viaMessage, SENTINEL],
      ["sanitizedDetail", viaDetail, detail],
    ] as const)
      expect(secretsIn(value, [secret]), what).toBe(true);
  });

  it("read a SecretValue, an expiry, and a failure's code", () => {
    expect(revealed(new SecretValue("v"))).toBe("v");
    expect(revealed("v")).toBeUndefined();
    expect(revealed(null)).toBeUndefined();
    expect(
      revealed({
        reveal: () => {
          throw new Error("no");
        },
      }),
    ).toBeUndefined();
    expect(revealed({ reveal: () => 1 })).toBeUndefined();
    const at = new Date(Date.UTC(2026, 0, 1));
    expect(expiryOf({ expiresAt: at })).toBe(at.getTime());
    expect(expiryOf({ expiresAt: at.toISOString() })).toBe(at.getTime());
    expect(expiryOf({})).toBeUndefined();
    expect(expiryOf({ expiresAt: 5 })).toBeUndefined();
    expect(codeOf(new PiShipError("IDENTITY_EXPIRED", SENTINEL))).toBe(
      "IDENTITY_EXPIRED",
    );
    expect(codeOf(new TypeError(SENTINEL))).toBe(
      "a TypeError that is not a PiShipError",
    );
    expect(codeOf(SENTINEL)).toBe("a value that is not an error");
  });

  it("build an answer and read a request as one text", async () => {
    const response = answer(429, { "retry-after": "7" }, "body");
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("7");
    expect(await response.text()).toBe("body");
    const text = requestText({
      url: "https://x.invalid/revoke/id%3A1",
      headers: new Headers({ authorization: "Bearer t" }),
      body: '{"id":"b"}',
    });
    expect(text).toContain("/revoke/id:1");
    expect(text).toContain("authorization: Bearer t");
    expect(text).toContain('{"id":"b"}');
  });
});
