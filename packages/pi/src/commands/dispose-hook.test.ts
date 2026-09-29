import { describe, expect, it } from "vitest";
import { endInsideDispose } from "./dispose-hook.js";

function fakeProcess() {
  const exits: (number | undefined)[] = [];
  const proc = {
    exit: ((code?: number) => {
      exits.push(code);
      return undefined as never;
    }) as (code?: number) => never,
  };
  return { proc, exits };
}

describe("ending the governance session inside Pi's dispose", () => {
  it("runs the teardown once, however many times dispose and the caller ask", async () => {
    const { proc } = fakeProcess();
    let runs = 0;
    const runtime = { dispose: async () => {} };
    const end = endInsideDispose(
      runtime,
      async () => {
        runs += 1;
      },
      () => {},
      proc,
    );
    await runtime.dispose();
    await runtime.dispose();
    await end(false);
    await end(true);
    expect(runs).toBe(1);
  });

  it("leaves the exit code alone when the teardown succeeds", async () => {
    const { proc, exits } = fakeProcess();
    const original = proc.exit;
    const runtime = { dispose: async () => {} };
    endInsideDispose(
      runtime,
      async () => {},
      () => {},
      proc,
    );
    await runtime.dispose();
    expect(proc.exit).toBe(original);
    proc.exit(0);
    expect(exits).toEqual([0]);
  });

  it("reports a teardown failure and turns Pi's exit(0) into 1, keeping other codes", async () => {
    const { proc, exits } = fakeProcess();
    const reported: unknown[] = [];
    const runtime = { dispose: async () => {} };
    endInsideDispose(
      runtime,
      async () => {
        throw new Error("audit lost");
      },
      (error) => reported.push(error),
      proc,
    );
    // The failure is reported, never thrown at Pi: dispose still resolves.
    await expect(runtime.dispose()).resolves.toBeUndefined();
    expect(reported).toHaveLength(1);
    proc.exit(0);
    proc.exit(undefined);
    proc.exit(143);
    expect(exits).toEqual([1, 1, 143]);
  });

  it("does not run the teardown again after a failed one", async () => {
    const { proc } = fakeProcess();
    let runs = 0;
    const runtime = { dispose: async () => {} };
    const end = endInsideDispose(
      runtime,
      async () => {
        runs += 1;
        throw new Error("audit lost");
      },
      () => {},
      proc,
    );
    await runtime.dispose();
    await expect(end(false)).rejects.toThrow("audit lost");
    expect(runs).toBe(1);
  });
});
