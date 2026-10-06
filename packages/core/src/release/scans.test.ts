import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { workspacePackages } from "../runtime-dependencies.js";
import { withWorkspaceManifests } from "./scans.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** A payload that carries the build input, as a release payload does. */
function payload(): string {
  const root = mkdtempSync(join(tmpdir(), "piship-scans-"));
  roots.push(root);
  const input = join(
    root,
    "node_modules",
    "@piship",
    "core",
    "dist",
    "build-input",
    "packages",
  );
  for (const name of workspacePackages) {
    mkdirSync(join(input, name), { recursive: true });
    writeFileSync(
      join(input, name, "package.json"),
      JSON.stringify({ name: `@piship/${name}` }),
    );
  }
  return root;
}

describe("the registry signature check's view of the payload", () => {
  it("has the workspace manifests while npm runs, because npm reaches the runtime packages only through them, and none afterwards", async () => {
    const root = payload();
    const seen = await withWorkspaceManifests(root, async () =>
      readdirSync(join(root, "packages")).sort(),
    );
    expect(seen).toEqual([...workspacePackages].sort());
    expect(existsSync(join(root, "packages"))).toBe(false);
  });

  it("copies each manifest as it is and removes them when npm fails", async () => {
    const root = payload();
    await expect(
      withWorkspaceManifests(root, async () => {
        const name = workspacePackages[0] as string;
        expect(
          JSON.parse(
            readFileSync(join(root, "packages", name, "package.json"), "utf8"),
          ),
        ).toEqual({ name: `@piship/${name}` });
        throw new Error("npm failed");
      }),
    ).rejects.toThrow("npm failed");
    expect(existsSync(join(root, "packages"))).toBe(false);
  });

  it("leaves a payload without a build input, and a packages directory it already has, alone", async () => {
    const bare = mkdtempSync(join(tmpdir(), "piship-scans-bare-"));
    roots.push(bare);
    await withWorkspaceManifests(bare, async () => {
      expect(existsSync(join(bare, "packages"))).toBe(false);
    });
    const root = payload();
    mkdirSync(join(root, "packages", "mine"), { recursive: true });
    await withWorkspaceManifests(root, async () => {
      expect(readdirSync(join(root, "packages"))).toEqual(["mine"]);
    });
    expect(readdirSync(join(root, "packages"))).toEqual(["mine"]);
  });
});
