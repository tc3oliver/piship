import { describe, expect, it } from "vitest";
import { progressReporter } from "./progress.js";

describe("progressReporter", () => {
  const lines: string[] = [];
  const write = (line: string) => lines.push(line);

  it("writes a line per step for a terminal", () => {
    lines.length = 0;
    progressReporter(write, { isTTY: true }, {})?.("Downloading 1.1.0");
    expect(lines).toEqual(["Downloading 1.1.0..."]);
  });

  it("stays silent when stderr is not a terminal, unless asked", () => {
    expect(progressReporter(write, { isTTY: false }, {})).toBeUndefined();
    expect(progressReporter(write, {}, { PISHIP_PROGRESS: "1" })).toBeDefined();
    expect(
      progressReporter(write, { isTTY: true }, { PISHIP_PROGRESS: "0" }),
    ).toBeUndefined();
  });
});
