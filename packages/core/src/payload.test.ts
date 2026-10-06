import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  removeForeignPlatformPackages,
  stripRuntimeIrrelevant,
} from "./payload.js";

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

  it("keeps Codemode's QuickJS sandbox and worker on every target", () => {
    // Pi resolves quickjs-wasi/quickjs.wasm and the pi-codemode worker at
    // run time; pruning either would fail every Codemode call.
    copyFileSync(
      fileURLToPath(new URL("../../../package-lock.json", import.meta.url)),
      join(root, "package-lock.json"),
    );
    const pi = "node_modules/@earendil-works/pi-coding-agent/node_modules";
    const runtime = [`${pi}/quickjs-wasi`, `${pi}/@earendil-works/pi-codemode`];
    for (const [platform, arch] of [
      ["linux", "x64"],
      ["linux", "arm64"],
      ["darwin", "arm64"],
      ["darwin", "x64"],
      ["win32", "x64"],
    ] as const) {
      const removed = removeForeignPlatformPackages(root, platform, arch);
      for (const path of runtime) expect(removed).not.toContain(path);
    }
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

describe("stripRuntimeIrrelevant", () => {
  const files: Record<string, string> = {
    "piship.yaml": "app: {}\n",
    "package.json": "{}",
    "bin/app": "#!/usr/bin/env node",
    "node_modules/pi/index.js": "module.exports=1",
    "node_modules/pi/index.d.ts": "export=1",
    "node_modules/pi/index.js.map": "{}",
    "node_modules/pi/types/index.d.mts": "export=1",
    "node_modules/pi/types/index.d.cts": "export=1",
    "node_modules/pi/types/index.d.mts.map": "{}",
    "node_modules/pi/prompts/system.md": "you are pi",
    "node_modules/quickjs/quickjs.wasm": "wasm",
    "node_modules/native/hook.node": "bin",
    "node_modules/pkg/README.md": "docs",
  };
  function stageFiles(): void {
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(join(root, dirname(path)), { recursive: true });
      writeFileSync(join(root, path), body);
    }
  }
  it("removes source maps and declaration files, keeps everything runnable", () => {
    stageFiles();
    const removed = stripRuntimeIrrelevant(root).sort();
    expect(removed).toEqual(
      [
        "node_modules/pi/index.d.ts",
        "node_modules/pi/index.js.map",
        "node_modules/pi/types/index.d.cts",
        "node_modules/pi/types/index.d.mts",
        "node_modules/pi/types/index.d.mts.map",
      ].sort(),
    );
    for (const kept of [
      "piship.yaml",
      "package.json",
      "bin/app",
      "node_modules/pi/index.js",
      "node_modules/pi/prompts/system.md",
      "node_modules/quickjs/quickjs.wasm",
      "node_modules/native/hook.node",
      "node_modules/pkg/README.md",
    ])
      expect(existsSync(join(root, kept))).toBe(true);
  });
});
