import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const script = fileURLToPath(
  new URL("../scripts/unit-durations.mjs", import.meta.url),
);

function runLogs(logs: readonly string[]) {
  const root = mkdtempSync(join(tmpdir(), "piship-unit-durations-"));
  try {
    const paths = logs.map((text, index) => {
      const path = join(root, `${index}.log`);
      writeFileSync(path, text);
      return path;
    });
    const output = join(root, "durations.json");
    const result = spawnSync(
      process.execPath,
      [script, "--out", output, ...paths],
      { encoding: "utf8" },
    );
    return {
      ...result,
      durations: existsSync(output)
        ? (JSON.parse(readFileSync(output, "utf8")) as Record<string, number[]>)
        : undefined,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const sample = (
  target: string,
  color: (value: string) => string,
  ms: number,
) =>
  `check (${target}-latest, unit 1/1)\tRun npm test\t2026-10-29T00:00:00Z  ${color("✓")} packages/core/src/sample.test.ts (2 tests) ${color(String(ms))}ms\n`;

const rawAnsi = (value: string) => `\u001b[32m${value}\u001b[39m`;
const caretAnsi = (value: string) => `^[[32m${value}^[[39m`;

describe("unit duration log refresh", () => {
  it("parses raw ANSI and caret-escaped GitHub job logs for all targets", () => {
    const result = runLogs([
      sample("ubuntu", rawAnsi, 100),
      sample("macos", caretAnsi, 200),
      sample("windows", rawAnsi, 300),
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.durations).toEqual({
      "packages/core/src/sample.test.ts": [0.1, 0.2, 0.3],
    });
  });

  it("refuses a missing platform rather than writing partial durations", () => {
    const result = runLogs([sample("ubuntu", rawAnsi, 100)]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("No unit durations for macos");
    expect(result.durations).toBeUndefined();
  });

  it("refuses a log with no parseable test durations", () => {
    const result = runLogs([
      "check (ubuntu-latest, unit 1/1)\tno tests\n",
      sample("macos", rawAnsi, 200),
      sample("windows", rawAnsi, 300),
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("has no parsed Vitest file durations");
    expect(result.durations).toBeUndefined();
  });
});
