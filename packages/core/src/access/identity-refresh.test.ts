import { PiShipError } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { refreshWithRetry } from "./identity-refresh.js";

const transient = () =>
  new PiShipError("GATEWAY_UNREACHABLE", "Identity provider unavailable", {
    retryable: true,
  });

describe("identity refresh retry bounds", () => {
  it("recovers after a transient provider outage without reusing the old token", async () => {
    let calls = 0;
    const delays: number[] = [];
    const renewed = await refreshWithRetry(
      async () => {
        if (++calls < 3) throw transient();
        return "renewed";
      },
      { sleep: async (ms) => void delays.push(ms), random: () => 0 },
    );
    expect(renewed).toBe("renewed");
    expect(calls).toBe(3);
    expect(delays).toEqual([100, 200]);
  });

  it("stops after three retryable failures", async () => {
    let calls = 0;
    await expect(
      refreshWithRetry<string>(
        async () => {
          calls++;
          throw transient();
        },
        { sleep: async () => {}, random: () => 0 },
      ),
    ).rejects.toMatchObject({ code: "GATEWAY_UNREACHABLE" });
    expect(calls).toBe(3);
  });

  it("does not retry revoked or invalid identities", async () => {
    for (const code of ["IDENTITY_EXPIRED", "IDENTITY_INVALID"] as const) {
      let calls = 0;
      await expect(
        refreshWithRetry<string>(async () => {
          calls++;
          throw new PiShipError(code, "Sign in again");
        }),
      ).rejects.toMatchObject({ code });
      expect(calls).toBe(1);
    }
  });

  it("honors a short rate limit and refuses a long retry-after", async () => {
    const delays: number[] = [];
    let calls = 0;
    await refreshWithRetry(
      async () => {
        if (++calls === 1)
          throw new PiShipError("GATEWAY_RATE_LIMITED", "Rate limited", {
            retryable: true,
            retryAfterMs: 350,
          });
        return true;
      },
      { sleep: async (ms) => void delays.push(ms), random: () => 0 },
    );
    expect(delays).toEqual([350]);
    calls = 0;
    await expect(
      refreshWithRetry<string>(async () => {
        calls++;
        throw new PiShipError("GATEWAY_RATE_LIMITED", "Try later", {
          retryable: true,
          retryAfterMs: 30_000,
        });
      }),
    ).rejects.toMatchObject({ retryAfterMs: 30_000 });
    expect(calls).toBe(1);
  });

  it("does not retry an unclassified error", async () => {
    let calls = 0;
    await expect(
      refreshWithRetry<string>(async () => {
        calls++;
        throw new Error("unexpected failure");
      }),
    ).rejects.toThrow("unexpected failure");
    expect(calls).toBe(1);
  });

  it("rejects invalid retry-after values without another request", async () => {
    for (const delay of [NaN, -1, Infinity]) {
      let calls = 0;
      await expect(
        refreshWithRetry<string>(
          async () => {
            calls++;
            throw new PiShipError("GATEWAY_RATE_LIMITED", "Try later", {
              retryable: true,
              retryAfterMs: delay,
            });
          },
          {
            sleep: async () => {
              throw new Error("unexpected sleep");
            },
          },
        ),
      ).rejects.toBeInstanceOf(PiShipError);
      expect(calls).toBe(1);
    }
  });
});
