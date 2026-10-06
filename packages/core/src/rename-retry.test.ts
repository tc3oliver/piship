import { describe, expect, it } from "vitest";
import { RENAME_DELAYS_MS, renameWithRetry } from "./rename-retry.js";

const blocked = (code: string): NodeJS.ErrnoException =>
  Object.assign(new Error(`${code}: rename`), { code });

/** A rename that fails with `code` for its first `failures` calls. */
function flaky(code: string, failures: number) {
  const state = { calls: 0, waits: [] as number[] };
  return {
    state,
    options: {
      platform: "win32" as const,
      rename: () => {
        if (++state.calls <= failures) throw blocked(code);
      },
      sleep: (ms: number) => state.waits.push(ms),
    },
  };
}

describe("renameWithRetry", () => {
  it("waits about four and a half seconds in all by default, over ten attempts", () => {
    expect(RENAME_DELAYS_MS).toHaveLength(9);
    expect(RENAME_DELAYS_MS.reduce((sum, ms) => sum + ms, 0)).toBe(4500);
  });

  it.each(["EPERM", "EBUSY", "EACCES"])(
    "retries %s on Windows with a growing pause, then succeeds",
    (code) => {
      const { state, options } = flaky(code, 2);
      renameWithRetry("a", "b", options);
      expect(state.calls).toBe(3);
      expect(state.waits).toEqual([100, 200]);
    },
  );

  it("gives up with the error of the last attempt, or the one the caller builds", () => {
    const first = flaky("EBUSY", 99);
    expect(() => renameWithRetry("a", "b", first.options)).toThrow(/EBUSY/);
    expect(first.state.calls).toBe(10);
    expect(first.state.waits).toEqual([...RENAME_DELAYS_MS]);
    const second = flaky("EPERM", 99);
    expect(() =>
      renameWithRetry("from-dir", "to-dir", {
        ...second.options,
        delays: [1, 2],
        giveUp: ({ from, to, code }) =>
          new Error(`stuck ${from} ${to} ${code}`),
      }),
    ).toThrow("stuck from-dir to-dir EPERM");
    expect(second.state.calls).toBe(3);
    expect(second.state.waits).toEqual([1, 2]);
  });

  it("does not retry other errors, EXDEV included, or the same codes off Windows", () => {
    for (const [platform, code] of [
      ["win32", "ENOENT"],
      ["win32", "EXDEV"],
      ["linux", "EPERM"],
      ["darwin", "EBUSY"],
    ] as const) {
      const attempt = flaky(code, 99);
      expect(() =>
        renameWithRetry("a", "b", { ...attempt.options, platform }),
      ).toThrow(code);
      expect(attempt.state.calls).toBe(1);
      expect(attempt.state.waits).toEqual([]);
    }
  });
});
