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
import { excerpt, withWorkspaceManifests } from "./scans.js";

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

describe("the excerpt of npm's output in a gate message", () => {
  it("cuts long output in the middle, keeping the whole log path npm ends with", () => {
    const log = `/private/tmp/${"x".repeat(120)}/_logs/2026-11-16T00_00_00_000Z-debug-0.log`;
    const text = `npm warn audit request to https://registry.npmjs.org/-/npm/v1/security/advisories/bulk failed, reason: connect ETIMEDOUT\n${"npm verbose noise\n".repeat(40)}npm error A complete log of this run can be found in: ${log}\n`;
    const line = excerpt(text);
    expect(line).toMatch(/^npm warn audit request/);
    expect(line.endsWith(log)).toBe(true);
    expect(line).toContain(" ... ");
    expect(line.length).toBeLessThan(420);
    expect(excerpt("short\n output")).toBe("short output");
    expect(excerpt(" \n")).toBe("no output");
  });
});
