// The lifecycle lock as a lease: a stale lock is recovered even when its
// process ID now belongs to another live process, a live holder is never
// displaced by a wall clock that moved, and a holder that lost its lock
// anyway can tell.
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  age,
  deadPid,
  livePid,
  useLifecycleHomes,
} from "../../../../tests/helpers/lifecycle-faults.js";
import {
  LIFECYCLE_LOCK_REUSE_MS,
  LIFECYCLE_LOCK_SCHEMA,
  acquireLifecycleLock,
} from "./lifecycle-lock.js";

// Stops the live processes `livePid` starts.
useLifecycleHomes();

let dir: string;
let lock: string;
const realNow = Date.now.bind(Date);
/** Added to the wall clock, as a correction or a resumed VM would. */
let jump = 0;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "piship-lifecycle-lock-"));
  lock = join(dir, ".lifecycle.lock");
  jump = 0;
  vi.spyOn(Date, "now").mockImplementation(() => realNow() + jump);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
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

function record(pid: number, instance: string): string {
  return JSON.stringify({
    schema: LIFECYCLE_LOCK_SCHEMA,
    pid,
    instance,
    acquiredAt: new Date().toISOString(),
  });
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
    const hold = acquire();
    const held = JSON.parse(readFileSync(lock, "utf8"));
    expect(held).toMatchObject({
      schema: LIFECYCLE_LOCK_SCHEMA,
      pid: process.pid,
      instance: expect.stringMatching(/^[0-9a-f]{16}$/),
    });
    expect(busy().pid).toBe(process.pid);
    // Another holder took the lock over (after this one went stale).
    writeFileSync(lock, record(process.pid, "someone-else"));
    hold.release();
    expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
      "someone-else",
    );
  });

  it("recovers a lock whose holder is gone while another process has its ID", () => {
    // Instance A crashed and left the lock; process B now has A's ID.
    writeFileSync(lock, record(livePid(), "instance-a"));
    age(lock, LIFECYCLE_LOCK_REUSE_MS + 1_000);
    const hold = acquire();
    expect(JSON.parse(readFileSync(lock, "utf8")).pid).toBe(process.pid);
    hold.release();
    expect(existsSync(lock)).toBe(false);
  });

  it("recovers a lock written before instance IDs whose process ID was reused", () => {
    writeFileSync(lock, String(livePid()));
    age(lock, LIFECYCLE_LOCK_REUSE_MS + 1_000);
    acquire().release();
    expect(existsSync(lock)).toBe(false);
  });

  it("recovers at once a lock whose process is gone, and a lock that names no process", () => {
    writeFileSync(lock, record(deadPid(), "instance-a"));
    acquire().release();
    writeFileSync(lock, "garbage");
    acquire().release();
    expect(existsSync(lock)).toBe(false);
  });

  it("waits for a live holder within its lease", () => {
    const holder = livePid();
    writeFileSync(lock, record(holder, "instance-b"));
    age(lock, LIFECYCLE_LOCK_REUSE_MS - 60_000);
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
    const hold = acquire();
    age(lock, LIFECYCLE_LOCK_REUSE_MS + 1_000);
    vi.advanceTimersByTime(15_000);
    expect(Date.now() - statSync(lock).mtimeMs).toBeLessThan(60_000);
    expect(busy().pid).toBe(process.pid);
    hold.release();
    expect(existsSync(lock)).toBe(false);
  });
});

describe("lifecycle lock over a changing wall clock", () => {
  it.each([
    ["eleven minutes", 11 * 60_000],
    ["an hour", 60 * 60_000],
    ["twenty hours", 20 * 60 * 60_000],
  ])(
    "never lets a second process take a live holder's lock after the clock jumps forward %s",
    (_label, ahead) => {
      // A launch check holds the holder in a synchronous step, so its
      // heartbeat is not running when the clock moves.
      const holder = livePid();
      writeFileSync(lock, record(holder, "checking-payload"));
      jump = ahead;
      expect(busy().pid).toBe(holder);
      expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe(
        "checking-payload",
      );
    },
  );

  it("never lets a second operation of the same process take a held lock after a forward jump", () => {
    const hold = acquire();
    jump = 60 * 60_000;
    expect(busy().pid).toBe(process.pid);
    expect(hold.stillHeld()).toBe(true);
    hold.release();
  });

  it("recovers a reused process ID once the lease has run out, whichever clock ran it out", () => {
    writeFileSync(lock, record(livePid(), "instance-a"));
    age(lock, LIFECYCLE_LOCK_REUSE_MS - 60_000);
    expect(busy().pid).not.toBeNull();
    jump = 2 * 60_000;
    acquire().release();
    expect(existsSync(lock)).toBe(false);
  });
});

describe("a holder that lost its lock", () => {
  it("knows while it holds the lock", () => {
    const hold = acquire();
    expect(hold.stillHeld()).toBe(true);
    hold.release();
    expect(hold.stillHeld()).toBe(false);
  });

  it("knows when another process took the lock over, and does not release the new holder's lock", () => {
    const hold = acquire();
    writeFileSync(lock, record(livePid(), "usurper"));
    expect(hold.stillHeld()).toBe(false);
    hold.release();
    expect(JSON.parse(readFileSync(lock, "utf8")).instance).toBe("usurper");
  });

  it("knows when the lock was removed", () => {
    const hold = acquire();
    rmSync(lock);
    expect(hold.stillHeld()).toBe(false);
    hold.release();
  });
});

// Permissions and what a directory at a file's path does differ on Windows,
// and a root user reads a mode 000 file.
describe.runIf(process.platform !== "win32" && process.getuid?.() !== 0)(
  "a lock whose content cannot be read",
  () => {
    it("is busy while it is fresh, and recovered once its lease ran out", () => {
      // A root-owned lock: it may be a live `sudo` holder's, which refreshes it.
      writeFileSync(lock, record(livePid(), "root-holder"));
      chmodSync(lock, 0o000);
      expect(busy().pid).toBeNull();
      age(lock, LIFECYCLE_LOCK_REUSE_MS - 60_000);
      expect(busy().pid).toBeNull();
      age(lock, LIFECYCLE_LOCK_REUSE_MS + 1_000);
      acquire().release();
      expect(existsSync(lock)).toBe(false);
    });

    it("is never removed when it is a directory, however old", () => {
      mkdirSync(lock);
      const old = new Date(realNow() - 2 * LIFECYCLE_LOCK_REUSE_MS);
      utimesSync(lock, old, old);
      expect(busy().pid).toBeNull();
      expect(lstatSync(lock).isDirectory()).toBe(true);
    });

    it("is never removed when it is a symlink, and a dangling one fails as unavailable", () => {
      const target = join(dir, "target");
      const gone = deadPid();
      writeFileSync(target, record(gone, "instance-a"));
      symlinkSync(target, lock);
      // Not a lock this module made, so not taken over even though its
      // process is gone.
      expect(busy().pid).toBe(gone);
      rmSync(target);
      expect(acquire).toThrow("unavailable");
      expect(lstatSync(lock).isSymbolicLink()).toBe(true);
    });
  },
);
