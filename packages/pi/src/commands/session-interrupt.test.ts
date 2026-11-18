import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LaunchContext, PreparedAccess } from "../launch/context.js";
import { openInterruptible } from "./session.js";

const ctx = {} as LaunchContext;
const prepared = {} as PreparedAccess;

/** Whether `promise` settled once pending callbacks ran. */
async function settled(promise: Promise<unknown>): Promise<boolean> {
  let done = false;
  promise.then(
    () => {
      done = true;
    },
    () => {
      done = true;
    },
  );
  await vi.advanceTimersByTimeAsync(0);
  return done;
}

/** The governance open, faked: it settles only when the launch is interrupted. */
function fakeOpen(onAbort: "resolve" | "reject", close = vi.fn()) {
  let signal: AbortSignal | undefined;
  const open = ((...args: unknown[]) => {
    signal = args[4] as AbortSignal;
    return new Promise((resolve, reject) =>
      signal?.addEventListener("abort", () =>
        onAbort === "resolve"
          ? resolve({ close })
          : reject(new Error("aborted")),
      ),
    );
  }) as never;
  return { open, close, signal: () => signal };
}

// Windows has no SIGINT handler here (STARTUP_SIGNALS is SIGTERM only).
describe.skipIf(process.platform === "win32")("openInterruptible", () => {
  beforeEach(() => {
    // The handler's 10 s fallback exit must never fire in the test process.
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it("aborts a pending open on SIGINT, closes a session that opened anyway, and exits 130", async () => {
    const exit = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    const fake = fakeOpen("resolve");
    const { gov, release } = openInterruptible(ctx, prepared, false, fake.open);
    expect(fake.signal()?.aborted).toBe(false);
    process.emit("SIGINT", "SIGINT");
    expect(fake.signal()?.aborted).toBe(true);
    // The launch does not go on with a session the handler is closing.
    expect(await settled(gov)).toBe(false);
    expect(exit).toHaveBeenCalledWith(130);
    expect(fake.close).toHaveBeenCalledOnce();
    expect(process.exitCode).toBe(130);
    release();
  });

  it("exits 130 without an error when the interrupted open fails", async () => {
    const exit = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    const fake = fakeOpen("reject");
    const { gov, release } = openInterruptible(ctx, prepared, false, fake.open);
    process.emit("SIGINT", "SIGINT");
    // No error reaches the launch: it never settles while the handler exits.
    expect(await settled(gov)).toBe(false);
    expect(exit).toHaveBeenCalledWith(130);
    release();
  });

  it("hands the signals back on release", () => {
    const before = process.listenerCount("SIGTERM");
    const { release } = openInterruptible(
      ctx,
      prepared,
      false,
      fakeOpen("resolve").open,
    );
    expect(process.listenerCount("SIGTERM")).toBe(before + 1);
    release();
    expect(process.listenerCount("SIGTERM")).toBe(before);
  });
});
