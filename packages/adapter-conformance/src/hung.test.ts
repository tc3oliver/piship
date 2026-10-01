// Adapters that never settle. PiShip stops waiting for such an adapter at
// its deadline; each kit must likewise report it as failing, within its own
// bound, instead of hanging the adapter's test run.
import type { SandboxBackend } from "@piship/adapter-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type ConformanceReport,
  testCredentialAdapter,
  testIdentityAdapter,
  testSandboxAdapter,
} from "./index.js";

const never = () => new Promise<never>(() => undefined);

/**
 * Every check the kit could run failed, none passed, and the hang is named:
 * by every check (`every`), or by at least one where a check fails earlier
 * for want of a result the hung call never gave.
 */
function allFailed(
  report: ConformanceReport,
  hang: RegExp,
  every = true,
): void {
  const ran = report.results.filter((result) => result.status !== "skipped");
  expect(ran.length).toBeGreaterThan(0);
  for (const result of ran) expect(result.status).toBe("failed");
  const named = ran.filter((result) => hang.test(result.reason ?? ""));
  if (every) expect(named).toHaveLength(ran.length);
  else expect(named.length).toBeGreaterThan(0);
}

/**
 * Run a kit on fake timers, advancing them until it reports: an identity or
 * credential kit waits at least 2 s per hung call, real time a test cannot
 * afford for every check.
 */
async function onFakeTimers(
  kit: () => Promise<ConformanceReport>,
): Promise<ConformanceReport> {
  vi.useFakeTimers();
  let report: ConformanceReport | undefined;
  let failure: unknown;
  const running = kit().then(
    (value) => {
      report = value;
    },
    (error: unknown) => {
      failure = error ?? new Error("the kit failed");
    },
  );
  for (let step = 0; step < 10_000 && !report && !failure; step++)
    await vi.advanceTimersByTimeAsync(500);
  await running;
  if (failure) throw failure;
  if (!report) throw new Error("the kit never reported");
  return report;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("an adapter that never settles", () => {
  it("fails every identity check whose factory or login never settles", async () => {
    allFailed(
      await onFakeTimers(() =>
        testIdentityAdapter(() => never(), { requestTimeoutMs: 20 }),
      ),
      /factory did not end within the kit's bound/,
    );
    allFailed(
      await onFakeTimers(() =>
        testIdentityAdapter(
          () => ({ kind: "hung", login: never, refresh: never, logout: never }),
          { requestTimeoutMs: 20 },
        ),
      ),
      /did not end within the kit's bound/,
      false,
    );
  });

  it("fails every credential check whose factory or acquire never settles", async () => {
    allFailed(
      await onFakeTimers(() =>
        testCredentialAdapter(() => never(), { requestTimeoutMs: 20 }),
      ),
      /factory did not end within the kit's bound/,
    );
    allFailed(
      await onFakeTimers(() =>
        testCredentialAdapter(
          () => ({
            mode: "adapter" as const,
            requiresIdentity: true,
            acquire: never,
            refresh: never,
            revoke: never,
          }),
          { requestTimeoutMs: 20 },
        ),
      ),
      /did not end within the kit's bound/,
      false,
    );
  });

  it("fails every sandbox check whose factory, available(), or prepare() never settles", {
    timeout: 30_000,
  }, async () => {
    const timings = { callTimeoutMs: 100, settleMs: 100 };
    allFailed(
      await testSandboxAdapter(() => never(), timings),
      /factory did not end within the kit's bound/,
    );
    // A backend object, not one defineSandboxAdapter wrapped: nothing but
    // the kit's own bound ends its calls.
    const hung: SandboxBackend = {
      id: "hung",
      provider: "custom",
      available: never,
      capabilities: () => ({
        isolation: "remote",
        planes: [
          "host-filesystem-isolation",
          "network-deny",
          "environment-filter",
        ],
        network: ["deny"],
        localProcesses: false,
      }),
      prepare: never,
    };
    const report = await testSandboxAdapter(hung, timings);
    expect(
      report.results.find((result) => result.behavior === "availability"),
    ).toMatchObject({
      status: "failed",
      reason: expect.stringContaining("did not end within the kit's bound"),
    });
    for (const result of report.results)
      if (result.behavior !== "capabilities")
        expect(result.status).not.toBe("passed");
  });
});
