// Who may start a session with `--yolo`: it needs a policy to relax, and a
// managed distribution must allow auto-approval (`policy.userAuto`).
import { PiShipError } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { yoloRefusal } from "./branded/auto.js";
import type { DistributionLock } from "./index.js";
import { describeYolo } from "./user-auto.js";

const lock = (
  mode: "personal" | "managed",
  policy?: { userAuto?: "allowed" | "off" },
) =>
  ({
    app: { command: "acmecode" },
    deployment: { mode },
    ...(policy ? { governance: { manifest: { policy } } } : {}),
  }) as unknown as DistributionLock;

describe("yoloRefusal", () => {
  it("lets a personal distribution with a policy start with --yolo", () => {
    expect(yoloRefusal(lock("personal", {}))).toBeUndefined();
  });

  it("lets a managed distribution start with --yolo only when it allows auto-approval", () => {
    expect(
      yoloRefusal(lock("managed", { userAuto: "allowed" })),
    ).toBeUndefined();
    for (const policy of [{}, { userAuto: "off" as const }]) {
      const refusal = yoloRefusal(lock("managed", policy));
      expect(refusal).toBeInstanceOf(PiShipError);
      expect(refusal).toMatchObject({
        code: "POLICY_DENIED",
        message:
          "--yolo is not allowed: this distribution does not allow auto-approval (policy.userAuto is off)",
      });
      expect(refusal?.userAction).toContain("acmecode");
    }
  });

  it("refuses a distribution that declares no policy, in either mode", () => {
    for (const mode of ["personal", "managed"] as const)
      expect(yoloRefusal(lock(mode))).toMatchObject({
        code: "CONFIG_INVALID",
        message: expect.stringContaining("declares no policy"),
      });
  });
});

describe("describeYolo", () => {
  it("says what stays in force in each mode, and that nothing is stored", () => {
    expect(describeYolo("personal")).toContain("every ask is approved");
    expect(describeYolo("personal")).toContain("deny still applies");
    expect(describeYolo("managed")).toContain(
      "deny and enforced rules still apply",
    );
    for (const mode of ["personal", "managed"] as const)
      expect(describeYolo(mode)).toContain("nothing is stored");
  });
});
