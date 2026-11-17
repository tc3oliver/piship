import { PiShipError } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import type { DistributionLock } from "../index.js";
import { resolveSource } from "./update.js";

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
