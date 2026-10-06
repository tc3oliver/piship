import { afterEach, describe, expect, it, vi } from "vitest";
import { createStageTimer, debugTiming, TIMING_SCHEMA } from "./timing.js";

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
