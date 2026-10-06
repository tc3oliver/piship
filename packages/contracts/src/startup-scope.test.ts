import { describe, expect, it } from "vitest";
import { duringStartup, inStartup, startupMemo } from "./startup-scope.js";

describe("the startup memo", () => {
  it("computes each time outside startup", () => {
    let calls = 0;
    const compute = () => ++calls;
    expect(startupMemo("k", "a", compute)).toBe(1);
    expect(startupMemo("k", "a", compute)).toBe(2);
    expect(inStartup()).toBe(false);
  });

  it("computes once per kind and key while startup runs, across awaits, then forgets", async () => {
    let calls = 0;
    const compute = () => ++calls;
    await duringStartup(async () => {
      expect(inStartup()).toBe(true);
      expect(startupMemo("k", "a", compute)).toBe(1);
      await new Promise((done) => setTimeout(done, 5));
      expect(startupMemo("k", "a", compute)).toBe(1);
      // Another key, and another kind of the same key, are other questions.
      expect(startupMemo("k", "b", compute)).toBe(2);
      expect(startupMemo("other", "a", compute)).toBe(3);
    });
    expect(inStartup()).toBe(false);
    expect(startupMemo("k", "a", compute)).toBe(4);
  });

  it("remembers an undefined answer, and does not remember a failure", async () => {
    let calls = 0;
    await duringStartup(async () => {
      const missing = () => {
        calls += 1;
        return undefined;
      };
      startupMemo("k", "missing", missing);
      startupMemo("k", "missing", missing);
      expect(calls).toBe(1);
      const failing = () => {
        calls += 1;
        throw new Error("no");
      };
      expect(() => startupMemo("k", "fails", failing)).toThrow("no");
      expect(() => startupMemo("k", "fails", failing)).toThrow("no");
      expect(calls).toBe(3);
    });
  });

  it("lets a nested startup join the outer one, and ends when the outer one does", async () => {
    let calls = 0;
    const compute = () => ++calls;
    await duringStartup(async () => {
      startupMemo("k", "a", compute);
      await duringStartup(async () => {
        expect(startupMemo("k", "a", compute)).toBe(1);
      });
      expect(inStartup()).toBe(true);
    });
    expect(inStartup()).toBe(false);
  });

  it("ends when the work fails", async () => {
    await expect(
      duringStartup(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(inStartup()).toBe(false);
  });
});
