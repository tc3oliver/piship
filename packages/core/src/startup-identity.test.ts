// What a launch asks the system about processes. Reading a process's start
// identity starts a process (PowerShell on Windows, `ps` on macOS), so the
// leases, locks and owner records a launch writes name their process by pid,
// host, start time and a random instance without asking, and only a process
// that has to judge someone else's record asks.
import * as childProcess from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { processHostToken } from "@piship/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  livePid,
  stopLiveProcesses,
} from "../../../tests/helpers/processes.js";
import { acquireLifecycleLock } from "./install/lifecycle-lock.js";
import { holdRuntimeLease, runtimeLeases } from "./install/runtime-lease.js";
import {
  processIdentity,
  recordedIdentity,
  recordedProcessGone,
  recordedStart,
  START_TOLERANCE_MS,
} from "./process-identity.js";

vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, execFileSync: vi.fn(actual.execFileSync) };
});

const spawned = () => vi.mocked(childProcess.execFileSync);
const roots: string[] = [];
const savedHome = process.env.PISHIP_INSTALL_HOME;
afterEach(() => {
  stopLiveProcesses();
  spawned().mockClear();
  if (savedHome === undefined) delete process.env.PISHIP_INSTALL_HOME;
  else process.env.PISHIP_INSTALL_HOME = savedHome;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function home(): string {
  const root = mkdtempSync(join(tmpdir(), "piship-startup-identity-"));
  roots.push(root);
  process.env.PISHIP_INSTALL_HOME = root;
  return root;
}

function leaseFile(root: string, fields: Record<string, unknown>): string {
  const directory = join(root, "apps", "acme", ".runtime-leases", "1.0.0");
  mkdirSync(directory, { recursive: true });
  const instance = "11111111-1111-4111-8111-111111111111";
  const path = join(directory, `${instance}.json`);
  writeFileSync(
    path,
    JSON.stringify({
      schema: "piship-runtime-lease/v1",
      identity: null,
      host: processHostToken(),
      instance,
      version: "1.0.0",
      ...fields,
    }),
  );
  const now = new Date();
  utimesSync(path, now, now);
  return path;
}

describe("an uncontended start", () => {
  it("holds a runtime lease and a lifecycle lock without a process start", () => {
    const root = home();
    const release = holdRuntimeLease("acme", "1.0.0");
    const hold = acquireLifecycleLock(
      join(root, "test.lock"),
      () => new Error("busy"),
      () => new Error("unavailable"),
    );
    try {
      expect(spawned()).not.toHaveBeenCalled();
      const [lease] = readdirSync(
        join(root, "apps", "acme", ".runtime-leases", "1.0.0"),
      );
      const record = JSON.parse(
        readFileSync(
          join(
            root,
            "apps",
            "acme",
            ".runtime-leases",
            "1.0.0",
            lease as string,
          ),
          "utf8",
        ),
      );
      // Named by pid, host, start time and a random instance.
      expect(record).toMatchObject({
        pid: process.pid,
        host: processHostToken(),
        started: recordedStart(),
        identity: recordedIdentity(),
      });
      expect(record.instance).toMatch(/^[0-9a-f-]{36}$/);
      if (process.platform !== "linux") expect(record.identity).toBeNull();
      const lock = JSON.parse(readFileSync(join(root, "test.lock"), "utf8"));
      expect(lock).toMatchObject({
        pid: process.pid,
        started: recordedStart(),
      });
      // The holder still knows itself.
      expect(runtimeLeases("acme")).toMatchObject([
        { live: true, self: true, version: "1.0.0" },
      ]);
      expect(spawned()).not.toHaveBeenCalled();
    } finally {
      hold.release();
      release();
    }
  });

  it("does not run the lookup again for a failed own identity", () => {
    // PowerShell blocked by policy would otherwise cost every caller its
    // five-second timeout.
    processIdentity(process.pid);
    const calls = spawned().mock.calls.length;
    processIdentity(process.pid);
    processIdentity(process.pid);
    expect(spawned().mock.calls.length).toBe(calls);
  });
});

// Linux counts ticks from boot, which a start time cannot be compared with.
describe.runIf(process.platform !== "linux")(
  "a contended record that names only a start time",
  () => {
    it("is a gone owner when a process with the ID started at another time", () => {
      const root = home();
      leaseFile(root, {
        pid: livePid(),
        started: Date.now() - 60 * 60_000,
      });
      expect(runtimeLeases("acme", true)[0]?.live).toBe(false);
      // Asked now, because judging someone else's record needs it.
      expect(spawned()).toHaveBeenCalled();
    });

    it("is a live owner when the process with the ID started when the record says", () => {
      const root = home();
      leaseFile(root, { pid: livePid(), started: Date.now() });
      expect(runtimeLeases("acme", true)[0]?.live).toBe(true);
    });

    it("tolerates the gap between a process's creation and Node's time origin", () => {
      // A cold first launch on Windows can spend seconds loading and scanning
      // node.exe before Node takes its time origin, so a live owner's recorded
      // start (its timeOrigin) lies AFTER the creation time the system reports
      // for the same process. The record is therefore dated later than ~now.
      const root = home();
      leaseFile(root, { pid: livePid(), started: Date.now() + 10_000 });
      expect(runtimeLeases("acme", true)[0]?.live).toBe(true);
      expect(START_TOLERANCE_MS).toBeGreaterThan(10_000);
    });

    it("tells this process's own record from a dead process's that had its ID, without asking the system", () => {
      const own = {
        pid: process.pid,
        identity: null,
        host: processHostToken(),
      };
      spawned().mockClear();
      expect(recordedProcessGone({ ...own, started: recordedStart() })).toBe(
        false,
      );
      // Within the start tolerance of this process, but not its start.
      expect(
        recordedProcessGone({ ...own, started: recordedStart() - 1_000 }),
      ).toBe(true);
      expect(spawned()).not.toHaveBeenCalled();
    });

    it("judges the same way a record read by any other launcher is judged", () => {
      const pid = livePid();
      const record = (started: number) => ({
        pid,
        identity: null,
        host: processHostToken(),
        started,
      });
      expect(recordedProcessGone(record(Date.now()))).toBe(false);
      expect(recordedProcessGone(record(Date.now() - 3_600_000))).toBe(true);
    });

    it("is not this process's own lease when the start time differs", () => {
      const root = home();
      leaseFile(root, { pid: process.pid, started: recordedStart() - 60_000 });
      expect(runtimeLeases("acme")[0]?.self).toBe(false);
    });
  },
);
