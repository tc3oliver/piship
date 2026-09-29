import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { withFileLock } from "./index.js";

let temp: string;
/** Added to the wall clock; monotonic time (performance.now) runs on. */
let offset = 0;
const realNow = Date.now.bind(Date);
const HOUR = 60 * 60_000;

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-file-lock-"));
  offset = 0;
  vi.spyOn(Date, "now").mockImplementation(() => realNow() + offset);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(temp, { recursive: true, force: true });
});

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Hold the lock from another call chain (as another process would) until
 * `release` is called; `acquired` settles once it holds it.
 */
function holder(path: string, heartbeatMs = 20) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let acquired!: () => void;
  const holding = new Promise<void>((resolve) => {
    acquired = resolve;
  });
  const events: string[] = [];
  const done = withFileLock(
    path,
    async () => {
      events.push("holder:start");
      acquired();
      await released;
      events.push("holder:end");
    },
    { heartbeatMs, staleMs: 60_000, waitMs: 60_000 },
  );
  return { holding, release, done, events };
}

/** Settle within `ms` of real time, or fail the test instead of hanging. */
function within<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    sleep(ms).then(() => {
      throw new Error(`did not settle within ${ms} ms`);
    }),
  ]);
}

describe("file lock ownership over a changing wall clock", () => {
  it("never lets a waiter steal a live holder's lock when the wall clock jumps forward", async () => {
    const path = join(temp, "inference.json");
    const live = holder(path);
    await live.holding;
    offset = 10 * 60_000;
    const started = performance.now();
    const waiter = withFileLock(
      path,
      async () => {
        live.events.push("waiter");
      },
      { staleMs: 200, waitMs: 5_000 },
    );
    await sleep(800);
    // Four stale intervals passed on the monotonic clock, and the mtime
    // looks ten minutes old against the jumped wall clock: still the
    // holder's, because its heartbeat kept changing it.
    expect(live.events).toEqual(["holder:start"]);
    live.release();
    await within(Promise.all([live.done, waiter]), 3_000);
    expect(live.events).toEqual(["holder:start", "holder:end", "waiter"]);
    expect(performance.now() - started).toBeGreaterThanOrEqual(750);
  });

  it("keeps the caller's wait on the monotonic clock: a forward jump does not collapse it", async () => {
    const path = join(temp, "inference.json");
    const live = holder(path);
    await live.holding;
    const started = performance.now();
    const waiter = withFileLock(path, async () => "ran", {
      staleMs: 200,
      waitMs: 600,
    }).catch((error: unknown) => error);
    await sleep(50);
    offset = 10 * 60_000;
    const error = await within(waiter, 3_000);
    const elapsed = performance.now() - started;
    live.release();
    await live.done;
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    expect(elapsed).toBeGreaterThanOrEqual(550);
    expect(live.events).toEqual(["holder:start", "holder:end"]);
  });

  it("times out near the configured wait when the wall clock jumps backward by hours", async () => {
    const path = join(temp, "inference.json");
    const live = holder(path);
    await live.holding;
    const started = performance.now();
    const waiter = withFileLock(path, async () => "ran", {
      staleMs: 200,
      waitMs: 400,
    }).catch((error: unknown) => error);
    await sleep(50);
    offset = -5 * HOUR;
    const error = await within(waiter, 3_000);
    const elapsed = performance.now() - started;
    live.release();
    await live.done;
    expect(error).toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
    expect(elapsed).toBeGreaterThanOrEqual(350);
    expect(elapsed).toBeLessThan(2_000);
    expect(live.events).toEqual(["holder:start", "holder:end"]);
  });

  it.each([
    ["an hour ahead (the holder's clock was fast)", HOUR],
    ["ten minutes behind", -10 * 60_000],
    ["current", 0],
  ])(
    "recovers a crashed holder's lock whose mtime is %s after the stale interval",
    async (_label, skew) => {
      const path = join(temp, "inference.json");
      const lock = `${path}.lock`;
      writeFileSync(lock, "4242-crashed-holder");
      const mtime = new Date(realNow() + skew);
      utimesSync(lock, mtime, mtime);
      // The wall clock also moves while the waiter watches.
      offset = -2 * HOUR;
      const started = performance.now();
      const result = await within(
        withFileLock(path, async () => "recovered", {
          staleMs: 300,
          waitMs: 5_000,
        }),
        4_000,
      );
      expect(result).toBe("recovered");
      // Taken over only after watching no progress for the stale interval.
      expect(performance.now() - started).toBeGreaterThanOrEqual(280);
      expect(existsSync(lock)).toBe(false);
      expect(readdirSync(temp)).toEqual([]);
    },
  );

  it("is unaffected by NTP-sized wall clock adjustments", async () => {
    const path = join(temp, "inference.json");
    const live = holder(path);
    await live.holding;
    const adjust = setInterval(() => {
      offset = offset > 0 ? -400 : 400;
    }, 30);
    try {
      const waiter = withFileLock(
        path,
        async () => {
          live.events.push("waiter");
        },
        { staleMs: 200, waitMs: 5_000 },
      );
      await sleep(600);
      expect(live.events).toEqual(["holder:start"]);
      live.release();
      await within(Promise.all([live.done, waiter]), 3_000);
    } finally {
      clearInterval(adjust);
    }
    expect(live.events).toEqual(["holder:start", "holder:end", "waiter"]);
  });
});
