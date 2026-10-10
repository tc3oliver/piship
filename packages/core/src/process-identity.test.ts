import { spawn, spawnSync } from "node:child_process";
import { processHostToken } from "@piship/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  processIdentity,
  processIdentityMatches,
  recordedProcessGone,
  START_SKEW_MS,
  START_TOLERANCE_MS,
} from "./process-identity.js";

const saved = { TZ: process.env.TZ, LC_ALL: process.env.LC_ALL };
const children: ReturnType<typeof spawn>[] = [];
afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const child of children.splice(0)) child.kill("SIGKILL");
});

function sleeper(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}

it("reads one process's identity the same in every time zone and locale", () => {
  const pid = sleeper();
  const seen = new Set<string | undefined>();
  for (const [tz, locale] of [
    ["UTC", "C"],
    ["Asia/Tokyo", "C"],
    ["America/Los_Angeles", "fr_FR.UTF-8"],
    ["Asia/Kolkata", "de_DE.UTF-8"],
  ] as const) {
    process.env.TZ = tz;
    process.env.LC_ALL = locale;
    seen.add(processIdentity(pid));
  }
  expect(seen.size).toBe(1);
  expect([...seen][0]).toMatch(/\S/);
});

it("tells a matching, a different and an unknown start identity apart", () => {
  const pid = sleeper();
  const identity = processIdentity(pid) as string;
  expect(processIdentityMatches(identity, pid)).toBe(true);
  expect(processIdentityMatches("1", pid)).toBe(false);
  expect(processIdentityMatches(null, pid)).toBeUndefined();
});

it.runIf(process.platform === "darwin")(
  "reads macOS start time as UTC seconds and leaves the earlier text unknown",
  () => {
    const pid = sleeper();
    const identity = processIdentity(pid) as string;
    expect(identity).toMatch(/^\d+$/);
    expect(Math.abs(Number(identity) - Date.now() / 1000)).toBeLessThan(120);
    expect(
      processIdentityMatches("Thu Jan  1 00:00:00 1970", pid),
    ).toBeUndefined();
  },
);

it("writes nothing to the caller's terminal for a process that has exited", () => {
  const gone = spawnSync(process.execPath, ["-e", "0"], { encoding: "utf8" });
  const pid = gone.pid as number;
  const dist = new URL("../dist/process-identity.js", import.meta.url).href;
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const { processIdentity } = await import(${JSON.stringify(dist)}); console.log(String(processIdentity(${pid})));`,
    ],
    { encoding: "utf8" },
  );
  expect(result.stdout.trim()).toBe("undefined");
  expect(result.stderr).toBe("");
});

// Linux counts ticks from boot, which no start time is compared against: a
// record whose ID a process has is unknown there, and a Linux writer records
// the identity itself.
describe.runIf(process.platform !== "linux")(
  "judging a record by its start time is directional",
  () => {
    const record = (over: Partial<Parameters<typeof recordedProcessGone>[0]>) =>
      recordedProcessGone({
        pid: sleeper(),
        identity: null,
        host: processHostToken(),
        started: Date.now(),
        ...over,
      });

    it("keeps a live process whose record was written after the system's creation time", () => {
      // The Windows cold-start gap: Node takes its time origin seconds after
      // the process was created, so the record is the later of the two.
      expect(record({ started: Date.now() + 10_000 })).toBe(false);
      expect(START_TOLERANCE_MS).toBeGreaterThan(10_000);
    });

    it("keeps a live process whose record is slightly the earlier of the two", () => {
      // Timestamp rounding, and a clock stepped backwards, are within skew.
      expect(record({ started: Date.now() - 2_000 })).toBe(false);
    });

    it("judges a process the system dates clearly after the record as a reused ID", () => {
      const pid = sleeper();
      expect(
        recordedProcessGone({
          pid,
          identity: null,
          host: processHostToken(),
          started: Date.now() - (START_SKEW_MS + 3_000),
        }),
      ).toBe(true);
    });

    it("cannot judge a record when the system's clock has moved backwards", () => {
      const pid = sleeper();
      const identity = processIdentity(pid) as string;
      // A creation stamp in the future (the clock stepped back since the
      // process was created) makes every start-time comparison untrustworthy:
      // a live holder must not be judged gone, or its lock is taken down
      // mid-transaction.
      vi.spyOn(Date, "now").mockReturnValue(Number(identity) * 1000 - 60_000);
      try {
        expect(
          recordedProcessGone({
            pid,
            identity: null,
            host: processHostToken(),
            started: Date.now(),
          }),
        ).toBeUndefined();
      } finally {
        vi.restoreAllMocks();
      }
    });

    it("judges a record whose process is gone, or whose ID another process took", () => {
      const gone = spawnSync(process.execPath, ["-e", "0"]).pid as number;
      expect(record({ pid: gone })).toBe(true);
      // A different start identity for the same ID is the reuse itself.
      expect(record({ identity: "1" })).toBe(true);
    });

    it("cannot tell a record from another host, or one with nothing to compare", () => {
      const pid = sleeper();
      expect(record({ pid, host: "000000000000" })).toBeUndefined();
      // A legacy pid-only record whose ID a live process has: unknown, not dead.
      expect(
        record({ pid, host: null, identity: null, started: null }),
      ).toBeUndefined();
    });
  },
);
