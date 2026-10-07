import { describe, expect, it, vi } from "vitest";
import type { LaunchContext } from "../launch/context.js";

const core = vi.hoisted(() => ({
  reclaimObsoleteVersions: vi.fn(),
  describeReclaimed: vi.fn(),
  verifyPayload: vi.fn(),
}));

vi.mock("@piship/core", async (original) => ({
  ...(await original<typeof import("@piship/core")>()),
  verifyPayload: core.verifyPayload,
  sweepStateTemporaries: vi.fn(),
  reclaimLaunchTemporaries: vi.fn(() => undefined),
  refreshInstalledLauncher: vi.fn(),
  // The shared store of the test run may be in use by other test files.
  maintainRuntimeStore: vi.fn(() => undefined),
  reclaimObsoleteVersions: core.reclaimObsoleteVersions,
  describeReclaimed: core.describeReclaimed,
}));
vi.mock("../doctor/data.js", () => ({
  collectDoctorData: vi.fn(async () => {
    throw new Error("stop after maintenance");
  }),
}));

import { runDoctor } from "./doctor.js";

function context() {
  const err: string[] = [];
  const ctx = {
    metadata: { app: { id: "acmepi", command: "acmepi", name: "AcmePi" } },
    distributionDir: "/dist",
    stateDir: "/state",
    out: vi.fn(),
    err: (message: string) => err.push(message),
  } as unknown as LaunchContext;
  return { ctx, err };
}

describe("doctor reclaims obsolete release directories", () => {
  it("runs the reclaim for this distribution and prints what it did", async () => {
    const result = { removed: ["0.9.0"] };
    core.reclaimObsoleteVersions.mockReturnValue(result);
    core.describeReclaimed.mockReturnValue(
      "Removed 1 obsolete release directory.",
    );
    const { ctx, err } = context();
    await expect(runDoctor(ctx)).rejects.toThrow("stop after maintenance");
    expect(core.reclaimObsoleteVersions).toHaveBeenCalledWith("acmepi");
    expect(core.describeReclaimed).toHaveBeenCalledWith(result);
    expect(err).toEqual(["Removed 1 obsolete release directory."]);
  });

  it("continues to the report, and changes nothing, when the payload fails verification", async () => {
    core.reclaimObsoleteVersions.mockClear();
    core.verifyPayload.mockImplementationOnce(() => {
      throw new Error("Payload files changed");
    });
    const { ctx } = context();
    await expect(runDoctor(ctx)).rejects.toThrow("stop after maintenance");
    expect(core.reclaimObsoleteVersions).not.toHaveBeenCalled();
  });

  it("says nothing when there was nothing to say, and never on --help", async () => {
    core.reclaimObsoleteVersions.mockClear();
    core.describeReclaimed.mockReturnValue(undefined);
    const quiet = context();
    await expect(runDoctor(quiet.ctx)).rejects.toThrow(
      "stop after maintenance",
    );
    expect(quiet.err).toEqual([]);
    core.reclaimObsoleteVersions.mockClear();
    await runDoctor(context().ctx, ["--help"]);
    expect(core.reclaimObsoleteVersions).not.toHaveBeenCalled();
  });
});
