import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createStageTimer,
  debugTiming,
  stopwatch,
  TIMING_SCHEMA,
} from "./timing.js";

const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

function capture(enabled: boolean): { lines: () => string[]; end: () => void } {
  const saved = process.env.PISHIP_DEBUG_TIMING;
  if (enabled) process.env.PISHIP_DEBUG_TIMING = "1";
  else delete process.env.PISHIP_DEBUG_TIMING;
  const written: string[] = [];
  const spy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: string | Uint8Array) => {
      written.push(String(chunk));
      return true;
    });
  return {
    lines: () => written.join("").split("\n").filter(Boolean),
    end: () => {
      spy.mockRestore();
      if (saved === undefined) delete process.env.PISHIP_DEBUG_TIMING;
      else process.env.PISHIP_DEBUG_TIMING = saved;
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("stage timing", () => {
  it("prints a stage as `label: N ms` only when timing is on", () => {
    for (const enabled of [false, true]) {
      const output = capture(enabled);
      try {
        debugTiming("inventory hashing", process.hrtime.bigint());
      } finally {
        output.end();
      }
      expect(output.lines().length).toBe(enabled ? 1 : 0);
      if (enabled)
        expect(output.lines()[0]).toMatch(/^inventory hashing: \d+\.\d ms$/);
    }
  });

  it("reports nothing when timing is off", async () => {
    const output = capture(false);
    try {
      const timer = createStageTimer();
      await timer.run("work", () => 1);
      timer.report("release");
    } finally {
      output.end();
    }
    expect(output.lines()).toEqual([]);
  });

  it("lists stages longest first with their start offsets, then one JSON line", async () => {
    const output = capture(true);
    try {
      const timer = createStageTimer();
      const first = timer.run("short", () => sleep(5));
      const second = timer.run("long", () => sleep(60));
      const end = timer.start("middle");
      await sleep(30);
      end();
      await Promise.all([first, second]);
      timer.report("release");
    } finally {
      output.end();
    }
    const lines = output.lines();
    expect(lines.slice(0, 3).map((line) => line.split(":")[0])).toEqual([
      "release long",
      "release middle",
      "release short",
    ]);
    for (const line of lines.slice(0, 3))
      expect(line).toMatch(/^release .+: \d+\.\d ms$/);
    const summary = JSON.parse(lines[3] as string);
    expect(lines).toHaveLength(4);
    expect(summary).toMatchObject({
      schema: TIMING_SCHEMA,
      command: "release",
    });
    expect(summary.stages.map((stage: { name: string }) => stage.name)).toEqual(
      ["long", "middle", "short"],
    );
    // The stages overlap, so each is counted in full and the sum exceeds the
    // total; every stage starts near zero.
    const sum = summary.stages.reduce(
      (total: number, stage: { ms: number }) => total + stage.ms,
      0,
    );
    expect(sum).toBeGreaterThan(summary.totalMs);
    expect(summary.stages[0].startMs).toBeLessThan(summary.stages[0].ms);
  });

  it("ends a stage whose work throws or rejects, and marks one never ended", async () => {
    const output = capture(true);
    try {
      const timer = createStageTimer();
      await expect(
        timer.run("rejects", async () => {
          throw new Error("no");
        }),
      ).rejects.toThrow("no");
      await expect(
        timer.run("throws", () => {
          throw new Error("sync");
        }),
      ).rejects.toThrow("sync");
      timer.start("abandoned");
      timer.report("release");
    } finally {
      output.end();
    }
    const summary = JSON.parse(output.lines().at(-1) as string);
    const byName = Object.fromEntries(
      summary.stages.map((stage: { name: string }) => [stage.name, stage]),
    );
    expect(byName.rejects.unfinished).toBeUndefined();
    expect(byName.throws.unfinished).toBeUndefined();
    expect(byName.abandoned.unfinished).toBe(true);
  });
});

function startup(env: Record<string, string>, body: string) {
  return spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `const c = await import("@piship/contracts");\n${body}`,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, PISHIP_DEBUG_TIMING: "", ...env },
    },
  );
}

const summaryOf = (stderr: string) =>
  JSON.parse(
    stderr.split("\n").find((line) => line.startsWith('{"schema"')) as string,
  );

describe("startup timing", () => {
  it("reports its marks in the piship-timing/v1 format: readable lines, then one JSON line", () => {
    const result = startup(
      { PISHIP_DEBUG_TIMING: "1" },
      `c.startupNote("installed_launcher", "abc123abc123");
c.startupMark("launcher_start");
c.startupCount("identity_spawns");
c.startupCount("identity_spawns");
c.startupMark("ui_ready");`,
    );
    expect(result.status, result.stderr).toBe(0);
    const report = summaryOf(result.stderr);
    expect(report).toMatchObject({
      schema: TIMING_SCHEMA,
      command: "launch",
      counters: { identity_spawns: 2 },
      notes: {
        installed_launcher: "abc123abc123",
        platform: expect.any(String),
      },
    });
    const names = report.marks.map((mark: { name: string }) => mark.name);
    expect(names).toEqual(["launcher_start", "ui_ready", "process_exit"]);
    // Milliseconds since the process started, never going back; each stage is
    // the phase that ended at its mark, so they add up to the total.
    const times = report.marks.map((mark: { ms: number }) => mark.ms);
    expect(times[0]).toBeGreaterThan(0);
    expect([...times].sort((a: number, b: number) => a - b)).toEqual(times);
    expect(report.stages.map((stage: { name: string }) => stage.name)).toEqual(
      names,
    );
    const sum = report.stages.reduce(
      (total: number, stage: { ms: number }) => total + stage.ms,
      0,
    );
    expect(Math.abs(sum - report.totalMs)).toBeLessThan(1);
    const lines = result.stderr.split("\n").filter(Boolean);
    expect(lines.slice(0, 3)).toEqual([
      expect.stringMatching(/^launch launcher_start: \d+\.\d ms$/),
      expect.stringMatching(/^launch ui_ready: \d+\.\d ms$/),
      expect.stringMatching(/^launch process_exit: \d+\.\d ms$/),
    ]);
  });

  it("adds the marks a launcher wrote before any payload module loaded", () => {
    const result = startup(
      { PISHIP_DEBUG_TIMING: "1" },
      `globalThis[Symbol.for("piship.startup-timing")] = { marks: [{ name: "launcher_start", ms: 12.5 }], counters: {}, notes: {} };
c.startupMark("node_entry");`,
    );
    expect(
      summaryOf(result.stderr).marks.map((mark: { name: string }) => mark.name),
    ).toEqual(["launcher_start", "node_entry", "process_exit"]);
  });

  it("does nothing without the variable: no store, no output, no exit handler", () => {
    const result = startup(
      {},
      `c.startupMark("launcher_start");
c.startupCount("identity_spawns");
c.startupNote("pi", "1");
process.stdout.write(String(globalThis[Symbol.for("piship.startup-timing")]) + " " + process.listenerCount("exit"));`,
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("undefined 0");
    expect(result.stderr).toBe("");
  });

  it("times a stopwatch's laps like a stage", () => {
    const output = capture(true);
    try {
      const lap = stopwatch();
      lap("first");
      lap("second");
    } finally {
      output.end();
    }
    expect(output.lines()).toEqual([
      expect.stringMatching(/^first: \d+\.\d ms$/),
      expect.stringMatching(/^second: \d+\.\d ms$/),
    ]);
  });
});
