import { SecretValue } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import {
  installCrashRedaction,
  redactErrorInPlace,
  uninstallCrashRedaction,
} from "./crash-redaction.js";

const SECRET = "piship-fake-crash-secret-0123456789";
new SecretValue(SECRET);

afterEach(() => uninstallCrashRedaction());

describe("redactErrorInPlace", () => {
  it("rewrites message, stack, cause, and nested strings on the same object", () => {
    const error = new Error(`failed with ${SECRET}`) as Error & {
      cause?: unknown;
      response?: unknown;
    };
    error.cause = new AggregateError([new Error(`inner ${SECRET}`)], SECRET);
    error.response = { headers: { authorization: `Bearer ${SECRET}` } };
    const same = error;
    redactErrorInPlace(error);
    expect(error).toBe(same);
    expect(error.message).toBe("failed with [REDACTED]");
    expect(error.stack).toContain("failed with [REDACTED]");
    expect(JSON.stringify(error.response)).not.toContain(SECRET);
    const cause = error.cause as AggregateError;
    expect(cause.message).toBe("[REDACTED]");
    expect((cause.errors[0] as Error).message).toBe("inner [REDACTED]");
    expect((cause.errors[0] as Error).stack).not.toContain(SECRET);
  });

  it("handles a thrown plain object, a cycle, and a read-only property", () => {
    const thrown: Record<string, unknown> = { detail: `x ${SECRET}` };
    thrown.self = thrown;
    Object.defineProperty(thrown, "fixed", { value: SECRET, writable: false });
    expect(() => redactErrorInPlace(thrown)).not.toThrow();
    expect(thrown.detail).toBe("x [REDACTED]");
    expect(() => redactErrorInPlace(SECRET)).not.toThrow();
  });
});

describe("installCrashRedaction", () => {
  it("puts itself in front of the listeners installed before it, once", () => {
    const earlier = () => {};
    process.prependListener("uncaughtException", earlier);
    try {
      installCrashRedaction();
      installCrashRedaction();
      const listeners = process.listeners("uncaughtException");
      expect(listeners[1]).toBe(earlier);
      expect(listeners.filter((item) => item !== earlier).length).toBe(
        listeners.length - 1,
      );
      const error = new Error(`boom ${SECRET}`);
      listeners[0]?.(error, "uncaughtException");
      expect(error.message).toBe("boom [REDACTED]");
      const count = listeners.length;
      uninstallCrashRedaction();
      expect(process.listeners("uncaughtException").length).toBe(count - 1);
    } finally {
      process.off("uncaughtException", earlier);
    }
  });
});
