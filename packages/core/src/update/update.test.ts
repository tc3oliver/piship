import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PiShipError } from "@piship/contracts";
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

describe("an update source resolved from a variable", () => {
  function badSource(value: string): PiShipError {
    const lock = {
      app: { name: "AcmeCode", command: "acmecode" },
      deployment: { mode: "managed" },
      updates: {
        channel: "stable",
        channels: ["stable"],
        source: "${ACMECODE_UPDATE_SOURCE}",
      },
      access: { variables: ["ACMECODE_UPDATE_SOURCE"] },
    } as unknown as DistributionLock;
    try {
      resolveSource(lock, undefined, { ACMECODE_UPDATE_SOURCE: value });
    } catch (error) {
      return error as PiShipError;
    }
    throw new Error("resolveSource did not throw");
  }

  it("names the variable and gives a valid example for a relative path", () => {
    const error = badSource("chan");
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toBe(
      "ACMECODE_UPDATE_SOURCE (updates.source) resolved to chan, which is neither a URL nor an absolute local directory",
    );
    expect(error.userAction).toMatch(
      /^Set ACMECODE_UPDATE_SOURCE to an https URL such as https:\/\/updates\.example\.com\/channel, or an absolute local directory\. Plain http is accepted only to loopback, a private IP address/,
    );
  });

  it("names the variable for a URL with a query string", () => {
    const error = badSource("https://updates.example.com/c?token=x");
    expect(error.message).toBe(
      "ACMECODE_UPDATE_SOURCE (updates.source) may not contain a query string or fragment",
    );
    expect(error.userAction).toMatch(
      /^Set ACMECODE_UPDATE_SOURCE to an https URL/,
    );
    expect(error.userAction).toMatch(/without \?query or #fragment/);
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
