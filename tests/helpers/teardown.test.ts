import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { acquireLease, runAll, storeScenarioTeardown } from "./teardown.js";

// The E2E teardown and platform-store lease, with fake store hooks: no
// platform store is touched.

describe("scenario teardown", () => {
  it("runs every step after a failure and rethrows it", async () => {
    const ran: string[] = [];
    const failure = new Error("update host did not close");
    await expect(
      runAll([
        () => {
          ran.push("host");
          throw failure;
        },
        async () => {
          ran.push("services");
        },
        () => ran.push("temp"),
      ]),
    ).rejects.toBe(failure);
    expect(ran).toEqual(["host", "services", "temp"]);
  });

  it("reports several failures together", async () => {
    await expect(
      runAll([
        () => {
          throw new Error("a");
        },
        () => {
          throw new Error("b");
        },
      ]),
    ).rejects.toBeInstanceOf(AggregateError);
  });

  it("clears the store before closing the services and always releases the lease", async () => {
    const ran: string[] = [];
    const teardown = storeScenarioTeardown({
      clearStore: () => ran.push("clear"),
      closeServices: async () => {
        ran.push("close");
        throw new Error("fixture services did not close");
      },
      release: () => ran.push("release"),
    });
    await expect(teardown()).rejects.toThrow("fixture services did not close");
    expect(ran).toEqual(["clear", "close", "release"]);
  });

  it("still closes the services and releases the lease when clearing fails", async () => {
    const ran: string[] = [];
    const teardown = storeScenarioTeardown({
      clearStore: () => {
        throw new Error("Platform store entries remain");
      },
      closeServices: () => ran.push("close"),
      release: () => ran.push("release"),
    });
    await expect(teardown()).rejects.toThrow("Platform store entries remain");
    expect(ran).toEqual(["close", "release"]);
  });
});

describe("platform-store lease", () => {
  let temp: string;
  let lease: string;
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-lease-"));
    lease = join(temp, "platform-store.lease");
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });

  it("is held by one holder at a time", async () => {
    const release = await acquireLease(lease, { pollMs: 10 });
    let second = false;
    const waiting = acquireLease(lease, { pollMs: 10 }).then((next) => {
      second = true;
      return next;
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(second).toBe(false);
    release();
    (await waiting)();
    expect(second).toBe(true);
    expect(existsSync(lease)).toBe(false);
  });

  it("fails at its deadline, naming the holder, instead of waiting forever", async () => {
    await acquireLease(lease);
    await expect(
      acquireLease(lease, { deadlineMs: 150, pollMs: 10 }),
    ).rejects.toThrow(`held by process ${process.pid}`);
  });

  it("breaks the lease of a process that no longer runs", async () => {
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    mkdirSync(lease);
    writeFileSync(join(lease, "owner"), String(dead));
    const release = await acquireLease(lease, {
      deadlineMs: 1000,
      pollMs: 10,
    });
    release();
    expect(existsSync(lease)).toBe(false);
  });

  it("never breaks a lease another waiter took after breaking the same stale one", async () => {
    // Fake PIDs: 1001 crashed holding the lease, 1002 is the other waiter.
    const dead = 1001;
    const other = 1002;
    mkdirSync(lease);
    writeFileSync(join(lease, "owner"), String(dead));
    // This waiter read the dead owner; before it breaks the lease, the
    // other waiter breaks it and takes a lease of its own.
    let interleaved = false;
    const waiting = acquireLease(lease, {
      deadlineMs: 200,
      pollMs: 10,
      alive: (pid) => pid !== dead,
      beforeBreak: () => {
        if (interleaved) return;
        interleaved = true;
        rmSync(lease, { recursive: true, force: true });
        mkdirSync(lease);
        writeFileSync(join(lease, "owner"), String(other));
      },
    });
    await expect(waiting).rejects.toThrow(`held by process ${other}`);
    expect(interleaved).toBe(true);
    expect(readFileSync(join(lease, "owner"), "utf8")).toBe(String(other));
  });

  it("breaks a lease left without an owner after the grace period only", async () => {
    // Its creator died between creating the lease and writing its PID.
    mkdirSync(lease);
    await expect(
      acquireLease(lease, { deadlineMs: 100, pollMs: 10 }),
    ).rejects.toThrow("held by process unknown");
    const old = new Date(Date.now() - 60_000);
    utimesSync(lease, old, old);
    const release = await acquireLease(lease, {
      deadlineMs: 1000,
      pollMs: 10,
      ownerlessGraceMs: 10_000,
    });
    expect(readFileSync(join(lease, "owner"), "utf8")).toBe(
      String(process.pid),
    );
    release();
  });

  it("releases only a lease this process holds", async () => {
    const release = await acquireLease(lease);
    // Another process broke this lease and holds it now.
    writeFileSync(join(lease, "owner"), String(process.pid + 1));
    release();
    expect(existsSync(lease)).toBe(true);
  });
});
