import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PINNED_PI_VERSION } from "@piship/pi";

const repoRoot = new URL("../../", import.meta.url);
function jsonAt(path: string): unknown {
  return JSON.parse(
    readFileSync(fileURLToPath(new URL(path, repoRoot)), "utf8"),
  );
}

describe("pinned Pi compatibility", () => {
  it("aligns the dependency and compatibility metadata", () => {
    const manifest = jsonAt("packages/pi/package.json") as {
      dependencies: Record<string, string>;
    };
    const matrix = jsonAt("compatibility/pi.json") as {
      versions: Record<string, { status: string }>;
    };
    expect(manifest.dependencies["@earendil-works/pi-coding-agent"]).toBe(
      PINNED_PI_VERSION,
    );
    expect(matrix.versions[PINNED_PI_VERSION]?.status).toBe("supported");
  });
});
