import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { withFileLock } from "./index.js";

/**
 * Attempts to create a lock file. A waiter that loops without pausing blocks
 * the event loop, so no timer (a test timeout included) could stop it; this
 * counter is the hard limit: past it the create fails the test at once.
 */
const attempts = vi.hoisted(() => ({ count: 0, limit: 2_000 }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const openSync = ((path: string, ...rest: unknown[]) => {
    if (String(path).endsWith(".lock") && ++attempts.count > attempts.limit)
      throw new Error(`the lock loop spun: ${attempts.count} attempts`);
    return (actual.openSync as (...args: unknown[]) => number)(path, ...rest);
  }) as typeof actual.openSync;
  return { ...actual, openSync, default: { ...actual, openSync } };
});

let temp: string;
/** Added to the wall clock; monotonic time (performance.now) runs on. */
let offset = 0;
const realNow = Date.now.bind(Date);
const HOUR = 60 * 60_000;

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-file-lock-"));
  offset = 0;
  attempts.count = 0;
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

// Permissions and what a directory at a file's path does differ on Windows,
// and a root user reads a mode 000 file, so these run on POSIX as a normal user.
const posixUser = process.platform !== "win32" && process.getuid?.() !== 0;

describe.runIf(posixUser)("a lock path whose content cannot be read", () => {
  /** A generous bound on attempts in `waitMs`: the loop pauses 50 ms per pass. */
  const paused = (waitMs: number) => Math.ceil(waitMs / 50) * 4;

  it("times out on a directory at the lock path instead of spinning, and leaves it alone", async () => {
    const path = join(temp, "inference.json");
    const lock = `${path}.lock`;
    mkdirSync(lock);
    const started = performance.now();
    const error = await withFileLock(path, async () => "ran", {
      staleMs: 150,
      waitMs: 500,
    }).catch((caught: unknown) => caught);
    const elapsed = performance.now() - started;
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    expect(elapsed).toBeGreaterThanOrEqual(450);
    expect(elapsed).toBeLessThan(2_000);
    expect(attempts.count).toBeLessThan(paused(500));
    // Not a lock, so never moved aside or deleted.
    expect(lstatSync(lock).isDirectory()).toBe(true);
    expect(readdirSync(temp)).toEqual(["inference.json.lock"]);
  });

  it("times out on a dangling symlink at the lock path instead of spinning", async () => {
    const path = join(temp, "inference.json");
    const lock = `${path}.lock`;
    symlinkSync(join(temp, "nowhere"), lock);
    const started = performance.now();
    const error = await withFileLock(path, async () => "ran", {
      staleMs: 150,
      waitMs: 500,
    }).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
    expect(performance.now() - started).toBeGreaterThanOrEqual(450);
    expect(attempts.count).toBeLessThan(paused(500));
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
  });

  it("takes over an unreadable lock its holder no longer refreshes, after the stale interval", async () => {
    const path = join(temp, "inference.json");
    const lock = `${path}.lock`;
    // What a crashed `sudo <brand> login` leaves: a file this user cannot read.
    writeFileSync(lock, "4242-crashed-holder");
    chmodSync(lock, 0o000);
    const started = performance.now();
    const result = await within(
      withFileLock(path, async () => "recovered", {
        staleMs: 300,
        waitMs: 5_000,
      }),
      4_000,
    );
    expect(result).toBe("recovered");
    expect(performance.now() - started).toBeGreaterThanOrEqual(280);
    expect(attempts.count).toBeLessThan(paused(1_000));
    expect(readdirSync(temp)).toEqual([]);
  });

  it("does not take over an unreadable lock whose modification time keeps changing", async () => {
    const path = join(temp, "inference.json");
    const lock = `${path}.lock`;
    writeFileSync(lock, "4242-live-holder");
    chmodSync(lock, 0o000);
    let beat = realNow();
    const heartbeat = setInterval(() => {
      beat += 1_000;
      utimesSync(lock, new Date(beat), new Date(beat));
    }, 40);
    try {
      const error = await withFileLock(path, async () => "ran", {
        staleMs: 200,
        waitMs: 800,
      }).catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
      expect(existsSync(lock)).toBe(true);
    } finally {
      clearInterval(heartbeat);
    }
  });
});

/** The PID of a process that existed on this host and was killed with SIGKILL. */
async function killedPid(): Promise<number> {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  const pid = child.pid;
  if (pid === undefined) throw new Error("the child did not start");
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await exited;
  return pid;
}

describe("file lock holder identity", () => {
  it("breaks at once a lock whose holder on this host was killed", async () => {
    const path = join(temp, "inference.json");
    const lock = `${path}.lock`;
    const pid = await killedPid();
    writeFileSync(lock, `${pid}-0123456789abcdef@${hostname()}`);
    const notices: string[] = [];
    const started = performance.now();
    // The default stale interval (75 s): only the dead holder lets it through.
    const result = await within(
      withFileLock(path, async () => "recovered", {
        waitMs: 5_000,
        notify: (message) => notices.push(message),
      }),
      2_000,
    );
    expect(result).toBe("recovered");
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(notices).toEqual([]);
    expect(readdirSync(temp)).toEqual([]);
  });

  it("tells a waiter which lock it waits for and who holds it, once", async () => {
    const path = join(temp, "inference.json");
    const live = holder(path);
    await live.holding;
    const notices: string[] = [];
    const error = await within(
      withFileLock(path, async () => "ran", {
        noticeMs: 100,
        waitMs: 600,
        notify: (message) => notices.push(message),
      }).catch((caught: unknown) => caught),
      3_000,
    );
    live.release();
    await live.done;
    const named = `process ${process.pid} on ${hostname()}`;
    expect(notices).toEqual([
      `Waiting for ${path}.lock, held by ${named} (up to 1 s)`,
    ]);
    expect(error).toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
    expect((error as Error).message).toContain(`held by ${named}`);
    expect(live.events).toEqual(["holder:start", "holder:end"]);
  });

  it.each([
    ["another host", (pid: number) => `${pid}-0123456789abcdef@other-host`],
    ["a token without a host", (pid: number) => `${pid}-0123456789abcdef`],
  ])(
    "keeps the stale interval for a dead PID from %s",
    async (_label, token) => {
      const path = join(temp, "inference.json");
      writeFileSync(`${path}.lock`, token(await killedPid()));
      const started = performance.now();
      const result = await within(
        withFileLock(path, async () => "recovered", {
          staleMs: 300,
          waitMs: 5_000,
          notify: () => {},
        }),
        4_000,
      );
      expect(result).toBe("recovered");
      expect(performance.now() - started).toBeGreaterThanOrEqual(280);
    },
  );

  it.runIf(posixUser)(
    "treats a holder this user may not signal as alive",
    async () => {
      const path = join(temp, "inference.json");
      const lock = `${path}.lock`;
      // PID 1 always exists and belongs to root: kill(1, 0) fails with EPERM.
      writeFileSync(lock, `1-0123456789abcdef@${hostname()}`);
      const error = await withFileLock(path, async () => "ran", {
        waitMs: 300,
        notify: () => {},
      }).catch((caught: unknown) => caught);
      expect(error).toMatchObject({ code: "CREDENTIAL_ACQUIRE_FAILED" });
      expect(existsSync(lock)).toBe(true);
    },
  );
});
