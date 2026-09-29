import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { removeForeignPlatformPackages } from "./payload.js";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-payload-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const nested = "node_modules/pi/node_modules";
const packages: Record<string, object> = {
  "": { name: "stage" },
  "node_modules/pi": { version: "1.0.0" },
  [`${nested}/esbuild`]: { version: "0.28.2" },
  [`${nested}/@esbuild/linux-x64`]: {
    optional: true,
    os: ["linux"],
    cpu: ["x64"],
  },
  [`${nested}/@esbuild/darwin-arm64`]: {
    optional: true,
    os: ["darwin"],
    cpu: ["arm64"],
  },
  [`${nested}/@esbuild/win32-x64`]: {
    optional: true,
    os: ["win32"],
    cpu: ["x64"],
  },
  "node_modules/not-windows": { optional: true, os: ["!win32"] },
  "node_modules/any-platform": { optional: true },
  "node_modules/required-linux": { os: ["linux"], cpu: ["x64"] },
};

function stage(): void {
  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages }),
  );
  for (const path of Object.keys(packages).filter(Boolean)) {
    mkdirSync(join(root, path), { recursive: true });
    writeFileSync(join(root, path, "package.json"), "{}");
  }
}

describe("removeForeignPlatformPackages", () => {
  it("removes optional packages the lock marks for another os or cpu", () => {
    stage();
    expect(removeForeignPlatformPackages(root, "darwin", "arm64")).toEqual([
      `${nested}/@esbuild/linux-x64`,
      `${nested}/@esbuild/win32-x64`,
    ]);
    expect(existsSync(join(root, nested, "@esbuild", "darwin-arm64"))).toBe(
      true,
    );
    expect(existsSync(join(root, nested, "esbuild"))).toBe(true);
    for (const kept of ["not-windows", "any-platform", "required-linux"])
      expect(existsSync(join(root, "node_modules", kept))).toBe(true);
  });

  it("applies negated os entries", () => {
    stage();
    expect(removeForeignPlatformPackages(root, "win32", "x64")).toEqual([
      `${nested}/@esbuild/linux-x64`,
      `${nested}/@esbuild/darwin-arm64`,
      "node_modules/not-windows",
    ]);
    expect(existsSync(join(root, nested, "@esbuild", "win32-x64"))).toBe(true);
  });
});
