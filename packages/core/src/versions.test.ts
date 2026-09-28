// PiShip and Pi versions are written as constants in core (they travel inside
// built payloads, which never read a package.json at run time). These tests
// keep each constant equal to the workspace metadata it mirrors, so a version
// bump that misses one place fails here instead of in a release.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  PI_COMPATIBILITY,
  PI_PACKAGE,
  PI_VERSION,
  PISHIP_VERSION,
} from "./index.js";

const repoRoot = new URL("../../../", import.meta.url);
function jsonAt(path: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(fileURLToPath(new URL(path, repoRoot)), "utf8"),
  ) as Record<string, unknown>;
}
const packageNames = readdirSync(
  fileURLToPath(new URL("packages/", repoRoot)),
  {
    withFileTypes: true,
  },
)
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name);
type Manifest = {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
};

describe("PiShip version", () => {
  it("matches the workspace and every package version", () => {
    expect(jsonAt("package.json").version).toBe(PISHIP_VERSION);
    for (const name of packageNames)
      expect(
        (jsonAt(`packages/${name}/package.json`) as Manifest).version,
        name,
      ).toBe(PISHIP_VERSION);
  });

  it("pins every workspace dependency to the same version", () => {
    for (const name of packageNames) {
      const manifest = jsonAt(`packages/${name}/package.json`) as Manifest;
      for (const [dependency, version] of Object.entries(
        manifest.dependencies ?? {},
      ))
        if (dependency.startsWith("@piship/"))
          expect(version, `${name} -> ${dependency}`).toBe(PISHIP_VERSION);
    }
  });
});

describe("pinned Pi version", () => {
  it("matches the pi package dependency and the committed npm lock", () => {
    const pi = jsonAt("packages/pi/package.json") as Manifest;
    expect(pi.dependencies?.[PI_PACKAGE]).toBe(PI_VERSION);
    const lock = jsonAt("package-lock.json") as {
      packages: Record<string, { version?: string }>;
    };
    expect(lock.packages[`node_modules/${PI_PACKAGE}`]?.version).toBe(
      PI_VERSION,
    );
  });

  it("is a known version in the compatibility matrix", () => {
    const matrix = jsonAt("compatibility/pi.json") as {
      versions: Record<string, { status: string }>;
    };
    expect(["candidate", "supported"]).toContain(
      matrix.versions[PI_VERSION]?.status,
    );
    expect(PI_COMPATIBILITY[PI_VERSION]).toBeDefined();
  });
});
