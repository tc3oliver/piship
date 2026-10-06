import { afterEach, describe, expect, it, vi } from "vitest";
import { installDistribution } from "./install/index.js";
import * as threadpool from "./threadpool.js";
import { updateDistribution } from "./update/index.js";

afterEach(() => vi.restoreAllMocks());

describe("raiseThreadpool", () => {
  it("sets 16 on Windows", () => {
    const env: NodeJS.ProcessEnv = {};
    expect(threadpool.raiseThreadpool(env, "win32")).toBe(true);
    expect(env.UV_THREADPOOL_SIZE).toBe("16");
  });

  it("never overrides a size the user set, on Windows or anywhere", () => {
    for (const value of ["4", "64", ""]) {
      const env: NodeJS.ProcessEnv = { UV_THREADPOOL_SIZE: value };
      expect(threadpool.raiseThreadpool(env, "win32")).toBe(false);
      expect(env.UV_THREADPOOL_SIZE).toBe(value);
    }
  });

  it.each(["darwin", "linux"] as const)("leaves %s alone", (platform) => {
    const env: NodeJS.ProcessEnv = {};
    expect(threadpool.raiseThreadpool(env, platform)).toBe(false);
    expect(env.UV_THREADPOOL_SIZE).toBeUndefined();
  });
});

describe("install and update ask for it first", () => {
  it("installDistribution raises the pool before it reads anything", async () => {
    const raise = vi.spyOn(threadpool, "raiseThreadpool");
    await expect(installDistribution("/no/such/release")).rejects.toThrow();
    expect(raise).toHaveBeenCalledTimes(1);
  });

  it("updateDistribution raises the pool before it reads anything", async () => {
    const raise = vi.spyOn(threadpool, "raiseThreadpool");
    await expect(updateDistribution("not-installed")).rejects.toThrow();
    expect(raise).toHaveBeenCalledTimes(1);
  });
});
