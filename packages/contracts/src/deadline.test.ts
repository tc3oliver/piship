import { describe, expect, it } from "vitest";
import { callWithDeadline } from "./index.js";

const never = () => new Promise<never>(() => undefined);
const failures = {
  timedOut: () => new Error("timed out"),
  cancelled: () => new Error("cancelled"),
};

describe("callWithDeadline", () => {
  it("ends a call that never settles at the deadline and aborts its signal", async () => {
    let seen: AbortSignal | undefined;
    await expect(
      callWithDeadline(
        (signal) => {
          seen = signal;
          return never();
        },
        { timeoutMs: 20, ...failures },
      ),
    ).rejects.toThrow("timed out");
    expect(seen?.aborted).toBe(true);
    expect((seen?.reason as Error | undefined)?.name).toBe("TimeoutError");
  });

  it("returns what the call settles with before the deadline", async () => {
    await expect(
      callWithDeadline(async () => "value", { timeoutMs: 1_000, ...failures }),
    ).resolves.toBe("value");
    await expect(
      callWithDeadline(
        () => {
          throw new Error("own failure");
        },
        { timeoutMs: 1_000, ...failures },
      ),
    ).rejects.toThrow("own failure");
  });

  it("ends a call that ignores the caller's cancellation, and never calls with an aborted signal", async () => {
    const controller = new AbortController();
    const running = callWithDeadline(never, {
      timeoutMs: 60_000,
      signal: controller.signal,
      ...failures,
    });
    controller.abort();
    await expect(running).rejects.toThrow("cancelled");
    let called = false;
    await expect(
      callWithDeadline(
        () => {
          called = true;
          return "value";
        },
        { timeoutMs: 1_000, signal: controller.signal, ...failures },
      ),
    ).rejects.toThrow("cancelled");
    expect(called).toBe(false);
  });

  it("hands a value that arrives after the deadline to onLate", async () => {
    let finish: (value: string) => void = () => {};
    const late: string[] = [];
    await expect(
      callWithDeadline(
        () =>
          new Promise<string>((resolve) => {
            finish = resolve;
          }),
        { timeoutMs: 10, ...failures, onLate: (value) => late.push(value) },
      ),
    ).rejects.toThrow("timed out");
    finish("issued too late");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(late).toEqual(["issued too late"]);
  });
});
