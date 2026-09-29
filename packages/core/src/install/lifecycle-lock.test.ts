// The lifecycle lock as a lease: a stale lock is recovered even when its
// process ID now belongs to another live process, and a live holder that
// keeps refreshing its lease is never displaced.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  LIFECYCLE_LOCK_SCHEMA,
  LIFECYCLE_LOCK_STALE_MS,
  acquireLifecycleLock,
} from "./lifecycle-lock.js";

let dir: string;
let lock: string;
const children: ChildProcess[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "piship-lifecycle-lock-"));
  lock = join(dir, ".lifecycle.lock");
});
afterEach(() => {
  vi.useRealTimers();
  for (const child of children.splice(0)) child.kill();
  rmSync(dir, { recursive: true, force: true });
});

class Busy extends Error {
  constructor(readonly pid: number | null) {
    super(`busy ${pid}`);
  }
}
const acquire = () =>
  acquireLifecycleLock(
    lock,
    (pid) => new Busy(pid),
    () => new Error("unavailable"),
  );

/** A live process that is not this one: the reused process ID. */
function livePid(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}
function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid as number;
}
function record(pid: number, instance: string): string {
  return JSON.stringify({
    schema: LIFECYCLE_LOCK_SCHEMA,
    pid,
    instance,
    acquiredAt: new Date().toISOString(),
  });
}
function age(ms: number): void {
  const then = new Date(Date.now() - ms);
  utimesSync(lock, then, then);
}
function busy(): Busy {
  try {
    acquire();
  } catch (error) {
    if (error instanceof Busy) return error;
    throw error;
  }
  throw new Error("expected the lock to be busy");
}

describe("lifecycle lock", () => {
  it("records its holder's process and instance, and releases only its own lock", () => {
    const release = acquire();
    const held = JSON.parse(readFileSync(lock, "utf8"));
    expect(held).toMatchObject({
      schema: LIFECYCLE_LOCK_SCHEMA,
      pid: process.pid,
      instance: expect.stringMatching(/^[0-9a-f]{16}$/),
    });
    expect(busy().pid).toBe(process.pid);
    // Another holder took the lock over (after this one went stale).
    writeFileSync(lock, record(process.pid, "someone-else"));
    release();
    expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
      "someone-else",
    );
  });

  it("recovers a lock whose holder is gone while another process has its ID", () => {
    // Instance A crashed and left the lock; process B now has A's ID.
    writeFileSync(lock, record(livePid(), "instance-a"));
    age(LIFECYCLE_LOCK_STALE_MS + 1_000);
    const release = acquire();
    expect(JSON.parse(readFileSync(lock, "utf8")).pid).toBe(process.pid);
    release();
    expect(existsSync(lock)).toBe(false);
  });

  it("recovers a lock written before instance IDs whose process ID was reused", () => {
    writeFileSync(lock, String(livePid()));
    age(LIFECYCLE_LOCK_STALE_MS + 1_000);
    acquire()();
    expect(existsSync(lock)).toBe(false);
  });

  it("recovers at once a lock whose process is gone, and an unreadable lock", () => {
    writeFileSync(lock, record(deadPid(), "instance-a"));
    acquire()();
    writeFileSync(lock, "garbage");
    acquire()();
    expect(existsSync(lock)).toBe(false);
  });

  it("waits for a live holder within its lease", () => {
    const holder = livePid();
    writeFileSync(lock, record(holder, "instance-b"));
    age(LIFECYCLE_LOCK_STALE_MS - 60_000);
    expect(busy().pid).toBe(holder);
    writeFileSync(lock, String(holder));
    expect(busy().pid).toBe(holder);
    // A lock being created right now has no record yet.
    writeFileSync(lock, "");
    expect(busy().pid).toBeNull();
    expect(readFileSync(lock, "utf8")).toBe("");
  });

  it("keeps a held lock's lease fresh while its holder runs", () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const release = acquire();
    age(LIFECYCLE_LOCK_STALE_MS + 1_000);
    vi.advanceTimersByTime(15_000);
    expect(Date.now() - statSync(lock).mtimeMs).toBeLessThan(60_000);
    expect(busy().pid).toBe(process.pid);
    release();
    expect(existsSync(lock)).toBe(false);
  });
});
