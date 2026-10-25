import * as childProcess from "node:child_process";
import { afterEach, expect, it, vi } from "vitest";
import { trackLeader, untrackLeader } from "./process.js";

// Each snapshot answers at once with an empty table.
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return {
    ...actual,
    execFile: vi.fn(
      (
        _file: string,
        _args: string[],
        _options: object,
        done: (error: null, stdout: string) => void,
      ) => {
        void Promise.resolve().then(() => done(null, ""));
        return { kill: () => true };
      },
    ),
  };
});

afterEach(() => vi.useRealTimers());

it("keeps polling while short commands keep starting beside a long one", async () => {
  vi.useFakeTimers();
  const snapshots = vi.mocked(childProcess.execFile);
  snapshots.mockClear();
  trackLeader(900); // a long-lived MCP server
  for (let leader = 1000; leader < 1020; leader += 1) {
    trackLeader(leader);
    await vi.advanceTimersByTimeAsync(50);
    untrackLeader(leader);
    await vi.advanceTimersByTimeAsync(50);
  }
  untrackLeader(900);
  // 2 s at 250 ms is 8 ticks; a poller postponed by every start makes none.
  expect(snapshots.mock.calls.length).toBeGreaterThanOrEqual(6);
  await vi.advanceTimersByTimeAsync(5000);
  const stopped = snapshots.mock.calls.length;
  await vi.advanceTimersByTimeAsync(5000);
  expect(snapshots.mock.calls.length).toBe(stopped);
});
