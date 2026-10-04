import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PI_COMPATIBILITY, PI_VERSION } from "@piship/core";
import { PI_SIBLING_PINS, PINNED_PI_VERSION } from "@piship/pi";

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
    expect(["candidate", "supported"]).toContain(
      matrix.versions[PINNED_PI_VERSION]?.status,
    );
  });

  it("uses one pinned Pi version in core and the Pi seam", () => {
    expect(PI_VERSION).toBe(PINNED_PI_VERSION);
  });

  // The Pi latest canary removes the overrides and installs newer siblings
  // with the newest Pi, so this drift check applies only to the pin.
  it.skipIf(process.env.PISHIP_PI_CANARY === "1")(
    "pins Pi's sibling packages in the overrides, the npm lock, and the install",
    () => {
      const root = jsonAt("package.json") as {
        overrides?: Record<string, string>;
      };
      const lock = jsonAt("package-lock.json") as {
        packages: Record<string, { version?: string }>;
      };
      expect(root.overrides).toEqual(PI_SIBLING_PINS);
      // Pi releases its packages in lockstep.
      for (const version of Object.values(PI_SIBLING_PINS))
        expect(version).toBe(PINNED_PI_VERSION);
      // Every @earendil-works package that Pi or a sibling depends on is
      // pinned, so a new sibling cannot arrive unpinned.
      const reached = new Set<string>();
      const pending = ["@earendil-works/pi-coding-agent"];
      for (let name = pending.pop(); name; name = pending.pop()) {
        const manifest = jsonAt(`node_modules/${name}/package.json`) as {
          dependencies?: Record<string, string>;
        };
        for (const dependency of Object.keys(manifest.dependencies ?? {}))
          if (
            dependency.startsWith("@earendil-works/") &&
            !reached.has(dependency)
          ) {
            reached.add(dependency);
            pending.push(dependency);
          }
      }
      expect([...reached].sort()).toEqual(Object.keys(PI_SIBLING_PINS).sort());
      for (const [name, version] of Object.entries(PI_SIBLING_PINS)) {
        expect(lock.packages[`node_modules/${name}`]?.version, name).toBe(
          version,
        );
        expect(
          (jsonAt(`node_modules/${name}/package.json`) as { version: string })
            .version,
          name,
        ).toBe(version);
      }
      // No second copy of a sibling nested under another package.
      const nested = Object.keys(lock.packages).filter((path) =>
        Object.keys(PI_SIBLING_PINS).some((name) =>
          path.endsWith(`/node_modules/${name}`),
        ),
      );
      expect(nested).toEqual([]);
    },
  );

  it("records the same surfaces in releases as in the compatibility matrix", () => {
    const matrix = jsonAt("compatibility/pi.json") as {
      versions: Record<string, { surfaces: Record<string, string> }>;
    };
    expect(PI_COMPATIBILITY).toEqual(
      Object.fromEntries(
        Object.entries(matrix.versions).map(([version, entry]) => [
          version,
          entry.surfaces,
        ]),
      ),
    );
  });
});
