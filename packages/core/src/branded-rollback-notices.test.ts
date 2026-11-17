// A committed rollback's notices reach the person even when its audit fails.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BrandedContext } from "./branded/context.js";

vi.mock("./index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./index.js")>()),
  readInstallReceipt: () => ({ payload: payloadDir }),
  rollbackDistribution: async () => ({
    id: "acmepi",
    from: "1.1.0",
    to: "1.0.0",
    notices: ["run acmepi login to sign in again"],
  }),
}));
vi.mock("./branded/context.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./branded/context.js")>()),
  governedLock: () => ({}),
  recordAudit: async () => {
    throw new PiShipError("AUDIT_UNAVAILABLE", "Required audit sink down");
  },
}));

const { runRollback } = await import("./branded/lifecycle.js");

let payloadDir = "";
afterEach(() => rmSync(payloadDir, { recursive: true, force: true }));

describe("branded rollback with an unreachable required audit sink", () => {
  it("prints the rollback's notices before the audit fails", async () => {
    payloadDir = mkdtempSync(join(tmpdir(), "piship-rollback-notice-"));
    const errors: string[] = [];
    const ctx = {
      metadata: { app: { id: "acmepi", name: "AcmePi", command: "acmepi" } },
      distributionDir: payloadDir,
      stateDir: join(payloadDir, "state"),
      mode: "personal",
      out: () => {},
      err: (line: string) => errors.push(line),
    } as unknown as BrandedContext;
    await expect(runRollback(ctx)).rejects.toMatchObject({
      code: "AUDIT_UNAVAILABLE",
    });
    expect(errors).toContain("Notice: run acmepi login to sign in again");
  });
});
