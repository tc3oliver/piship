import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const bin = new URL("../../packages/cli/dist/bin.js", import.meta.url);

describe("CLI", () => {
  it("prints help", () => {
    const result = spawnSync(process.execPath, [fileURLToPath(bin), "--help"], {
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Usage: piship <command>");
    expect(result.stdout).toContain("Planned commands (not yet available)");
  });

  it("prints its version", () => {
    const result = spawnSync(
      process.execPath,
      [fileURLToPath(bin), "--version"],
      {
        encoding: "utf8",
      },
    );
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("0.0.0");
  });

  it("rejects unavailable commands", () => {
    const result = spawnSync(process.execPath, [fileURLToPath(bin), "build"], {
      encoding: "utf8",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("not available yet");
  });
});
