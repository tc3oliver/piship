// Startup phase timing: a report only with PISHIP_DEBUG_TIMING=1, one shared
// store across module copies, and nothing allocated or printed otherwise.
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

function run(env: Record<string, string>, body: string) {
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

describe("startup timing", () => {
  it("reports marks, counters and notes as one JSON line and a readable summary", () => {
    const result = run(
      { PISHIP_DEBUG_TIMING: "1" },
      `c.startupNote("installed_launcher", "abc123abc123");
c.startupMark("launcher_start");
c.startupCount("identity_spawns");
c.startupCount("identity_spawns");
c.startupMark("ui_ready");`,
    );
    expect(result.status, result.stderr).toBe(0);
    const json = result.stderr
      .split("\n")
      .find((line) => line.startsWith("PISHIP_TIMING_JSON "));
    const report = JSON.parse(
      (json as string).slice("PISHIP_TIMING_JSON ".length),
    );
    expect(report.schema).toBe("piship-startup-timing/v1");
    expect(report.notes).toEqual({ installed_launcher: "abc123abc123" });
    expect(report.counters).toEqual({ identity_spawns: 2 });
    expect(report.marks.map((mark: { name: string }) => mark.name)).toEqual([
      "launcher_start",
      "ui_ready",
      "process_exit",
    ]);
    // Milliseconds since the process started, never going back.
    const times = report.marks.map((mark: { ms: number }) => mark.ms);
    expect(times[0]).toBeGreaterThan(0);
    expect([...times].sort((a: number, b: number) => a - b)).toEqual(times);
    expect(result.stderr).toMatch(/PISHIP_TIMING launcher_start +[\d.]+ ms/);
    expect(result.stderr).toContain("PISHIP_TIMING identity_spawns = 2");
    expect(result.stderr).toContain(
      "PISHIP_TIMING installed_launcher = abc123abc123",
    );
  });

  it("adds the marks a launcher wrote before any payload module loaded", () => {
    const result = run(
      { PISHIP_DEBUG_TIMING: "1" },
      `globalThis[Symbol.for("piship.startup-timing")] = { marks: [{ name: "launcher_start", ms: 12.5 }], counters: {}, notes: {} };
c.startupMark("node_entry");`,
    );
    const report = JSON.parse(
      (
        result.stderr
          .split("\n")
          .find((line) => line.startsWith("PISHIP_TIMING_JSON ")) as string
      ).slice(19),
    );
    expect(report.marks.map((mark: { name: string }) => mark.name)).toEqual([
      "launcher_start",
      "node_entry",
      "process_exit",
    ]);
  });

  it("does nothing without the variable: no store, no output, no exit handler", () => {
    const result = run(
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
});
