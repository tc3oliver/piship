import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DistributionLock } from "../index.js";
import type { InstallReceipt } from "../install/index.js";
import { installationTrust, resolveSource } from "./update.js";

function noSource(mode: "personal" | "managed"): PiShipError {
  const lock = {
    app: { name: "MyAgent", command: "myagent" },
    deployment: { mode },
    updates: { channel: "stable", channels: ["stable"] },
  } as unknown as DistributionLock;
  try {
    resolveSource(lock, undefined, {});
  } catch (error) {
    return error as PiShipError;
  }
  throw new Error("resolveSource did not throw");
}

describe("an update with no update source", () => {
  it("tells a personal owner to rebuild or set updates.source", () => {
    const error = noSource("personal");
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toBe("MyAgent has no update source configured");
    expect(error.userAction).toMatch(
      /^Rebuild and reinstall it.*updates\.source/,
    );
    expect(error.userAction).not.toMatch(/distribution owner/);
  });

  it("keeps the managed wording", () => {
    const error = noSource("managed");
    expect(error.message).toBe(
      "MyAgent declares no update source; pass --from <directory|url>",
    );
    expect(error.userAction).toMatch(/your distribution owner publishes$/);
  });
});

describe("an update with no release keys", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "piship-notrust-"));
    vi.stubEnv("PISHIP_INSTALL_HOME", home);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    rmSync(home, { recursive: true, force: true });
  });

  function noTrust(mode: "personal" | "managed"): PiShipError {
    const lock = {
      app: { name: "MyAgent", command: "myagent" },
      deployment: { mode },
      updates: { channel: "stable", channels: ["stable"] },
    } as unknown as DistributionLock;
    try {
      installationTrust("myagent", {} as InstallReceipt, lock, new Date());
    } catch (error) {
      return error as PiShipError;
    }
    throw new Error("installationTrust did not throw");
  }

  it("tells a personal owner that updates are rebuilds", () => {
    const error = noTrust("personal");
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.userAction).toMatch(/^MyAgent has no update keys/);
    expect(error.userAction).toMatch(/updates\.trust\.bootstrap/);
    expect(error.userAction).not.toMatch(/distribution owner/);
  });

  it("keeps the managed wording", () => {
    expect(noTrust("managed").userAction).toMatch(
      /^Ask the distribution owner/,
    );
  });
});
