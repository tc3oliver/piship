import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readManifest } from "@piship/schema";
import { digest, hash } from "./digest.js";
import type { DistributionLock } from "./lock-schema.js";
import {
  inventory,
  payloadInventory,
  removeForeignPlatformPackages,
  stripRuntimeIrrelevant,
  verifyLaunchPayload,
  verifyPayloadContents,
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

  it("removes a directory that only held declarations, and the ones above it that this empties", () => {
    mkdirSync(join(root, "node_modules/pkg/types/deep"), { recursive: true });
    writeFileSync(join(root, "node_modules/pkg/types/deep/a.d.ts"), "");
    writeFileSync(join(root, "node_modules/pkg/types/b.d.mts"), "");
    mkdirSync(join(root, "node_modules/pkg/lib"), { recursive: true });
    writeFileSync(join(root, "node_modules/pkg/lib/c.js"), "");
    writeFileSync(join(root, "node_modules/pkg/lib/c.js.map"), "");
    mkdirSync(join(root, "node_modules/pkg/untouched"), { recursive: true });
    stripRuntimeIrrelevant(root);
    expect(existsSync(join(root, "node_modules/pkg/types"))).toBe(false);
    expect(existsSync(join(root, "node_modules/pkg/lib/c.js"))).toBe(true);
    // Only directories stripping emptied go; the root and others stay.
    expect(existsSync(join(root, "node_modules/pkg/untouched"))).toBe(true);
    expect(existsSync(root)).toBe(true);
  });
});

describe("inventory", () => {
  const write = (path: string, body: string): void => {
    mkdirSync(join(root, dirname(path)), { recursive: true });
    writeFileSync(join(root, path), body);
  };

  it("hashes every file but its own listing, depth first in name order", () => {
    write("b/z.txt", "z");
    write("b/a/deep.txt", "deep");
    write("a.txt", "a");
    write("metadata/inventory.json", "{}");
    write("metadata/target.json", "{}");
    const found = inventory(root);
    expect(Object.keys(found)).toEqual([
      "a.txt",
      "b/a/deep.txt",
      "b/z.txt",
      "metadata/target.json",
    ]);
    expect(found["b/a/deep.txt"]).toBe(hash("deep"));
    expect(payloadInventory(root)).toEqual(found);
  });

  it("takes digests it is given instead of reading those files, and hashes the rest", () => {
    write("kept.js", "kept");
    write("other.js", "other");
    const given = "1".repeat(64);
    const found = inventory(root, {
      "kept.js": given,
      "missing.js": "2".repeat(64),
      constructor: "3".repeat(64),
    });
    // A digest is only ever used for a file that is there.
    expect(found).toEqual({ "kept.js": given, "other.js": hash("other") });
  });

  it("does not mistake a file named like an object property for a known digest", () => {
    write("constructor", "body");
    write("toString", "body");
    expect(inventory(root)).toEqual({
      constructor: hash("body"),
      toString: hash("body"),
    });
  });

  it("refuses a link, which a payload may never contain", () => {
    if (process.platform === "win32") return;
    write("real.txt", "real");
    symlinkSync("real.txt", join(root, "link.txt"));
    expect(() => inventory(root)).toThrow(/symlink is not allowed: link\.txt/);
  });
});

describe("launch integrity verification", () => {
  const dirOf = new Set<string>();
  const write = (dir: string, path: string, body: string): void => {
    mkdirSync(join(dir, dirname(path)), { recursive: true });
    writeFileSync(join(dir, path), body);
  };
  /** A minimal, internally consistent piship/v1alpha6 payload. */
  function buildPayload(verifyAtLaunch?: boolean): string {
    const dir = mkdtempSync(join(tmpdir(), "piship-launch-"));
    dirOf.add(dir);
    const manifest = {
      schema: "piship/v1alpha6",
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: {
        pi: "1.0.0",
        ...(verifyAtLaunch === undefined ? {} : { verifyAtLaunch }),
      },
      deployment: { mode: "personal" },
      updates: { channel: "stable", channels: ["stable"] },
    };
    write(dir, "piship.yaml", JSON.stringify(manifest));
    write(dir, "package-lock.json", "{}\n");
    const lock = {
      manifest: {
        schema: "piship/v1alpha6",
        sha256: digest(readManifest(join(dir, "piship.yaml"))),
      },
      app: readManifest(join(dir, "piship.yaml")).app,
      runtime: { npmLockSha256: hash("{}\n") },
    } as unknown as DistributionLock;
    write(dir, "piship.lock", JSON.stringify(lock));
    write(
      dir,
      "metadata/target.json",
      JSON.stringify({ platform: process.platform, arch: process.arch }),
    );
    write(dir, "bin/mypi", "#!/usr/bin/env node\n");
    write(
      dir,
      "metadata/inventory.json",
      JSON.stringify(payloadInventory(dir)),
    );
    return dir;
  }
  afterEach(() => {
    for (const dir of dirOf) rmSync(dir, { recursive: true, force: true });
    dirOf.clear();
  });

  it("full verification fails when a payload file is tampered with", () => {
    const dir = buildPayload();
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    expect(() =>
      verifyPayloadContents(dir, { requireTarget: true, verifyContents: true }),
    ).toThrow();
  });
  it("verifyContents:false skips the content hash but keeps the bindings", () => {
    const dir = buildPayload();
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    expect(() =>
      verifyPayloadContents(dir, {
        requireTarget: true,
        verifyContents: false,
      }),
    ).not.toThrow();
  });
  it("verifyContents:false still rejects a broken manifest/lock binding", () => {
    const dir = buildPayload();
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    const lock = JSON.parse(readFileSync(join(dir, "piship.lock"), "utf8"));
    lock.app = { ...lock.app, version: "9.9.9" };
    writeFileSync(join(dir, "piship.lock"), JSON.stringify(lock));
    expect(() =>
      verifyPayloadContents(dir, {
        requireTarget: true,
        verifyContents: false,
      }),
    ).toThrow(/manifest and lock mismatch/);
  });
  it("verifyContents:false still rejects the wrong target", () => {
    const dir = buildPayload();
    write(
      dir,
      "metadata/target.json",
      JSON.stringify({ platform: "plan9", arch: "mips" }),
    );
    expect(() =>
      verifyPayloadContents(dir, {
        requireTarget: true,
        verifyContents: false,
      }),
    ).toThrow(/does not match this machine/);
  });
  it("verifyLaunchPayload skips the hash when verifyAtLaunch is false", () => {
    const dir = buildPayload(false);
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    expect(() => verifyLaunchPayload(dir)).not.toThrow();
  });
  it("verifyLaunchPayload never hashes contents even when verifyAtLaunch is true", () => {
    const dir = buildPayload(true);
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    expect(() => verifyLaunchPayload(dir)).not.toThrow();
  });
  it("verifyLaunchPayload never hashes contents when the legacy flag is absent", () => {
    const dir = buildPayload();
    writeFileSync(join(dir, "bin", "mypi"), "tampered\n");
    expect(() => verifyLaunchPayload(dir)).not.toThrow();
  });
  it("boots without inventory, manifest or npm lock, leaving full verification to diagnostics", () => {
    const dir = buildPayload();
    for (const name of [
      "metadata/inventory.json",
      "piship.yaml",
      "package-lock.json",
    ])
      rmSync(join(dir, name));
    expect(verifyLaunchPayload(dir).app.command).toBe("mypi");
    expect(() => verifyPayloadContents(dir)).toThrow();
  });
  it("still refuses a payload for another OS before loading its native runtime", () => {
    const dir = buildPayload();
    write(
      dir,
      "metadata/target.json",
      JSON.stringify({ platform: "plan9", arch: "mips" }),
    );
    expect(() => verifyLaunchPayload(dir)).toThrow(
      /does not match this machine/,
    );
  });
});
