import { describe, expect, it, vi } from "vitest";
import { announceWait, progressReporter } from "./progress.js";

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

describe("announceWait", () => {
  it("uses progress when someone watches, else one plain stderr line unless PISHIP_PROGRESS=0", () => {
    const steps: string[] = [];
    const written = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    try {
      announceWait("Installing", (step) => steps.push(step), {});
      expect(steps).toEqual(["Installing"]);
      expect(written).not.toHaveBeenCalled();
      announceWait("Installing", undefined, {});
      expect(written).toHaveBeenCalledWith("Installing...\n");
      written.mockClear();
      announceWait("Installing", undefined, { PISHIP_PROGRESS: "0" });
      expect(written).not.toHaveBeenCalled();
    } finally {
      written.mockRestore();
    }
  });
});
