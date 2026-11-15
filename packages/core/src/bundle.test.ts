import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runtimeBundleScript } from "./bundle.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function write(path: string, text: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  return path;
}

/** A tiny payload under `<root>/outer`, with the files the runtime bundle reads. */
function payloadWith(mainSource: string) {
  const root = realpathSync.native(
    mkdtempSync(join(tmpdir(), "piship-bundle-")),
  );
  roots.push(root);
  const payload = join(root, "outer", "payload");
  const stub = (name: string, exports: string) =>
    write(
      join(payload, "node_modules", "@piship", name, "dist", "index.js"),
      exports,
    );
  stub("contracts", "export const formatError = () => '';");
  stub("core", "export const verifyLaunchPayload = () => ({});");
  write(
    join(payload, "node_modules", "@piship", "pi", "dist", "environment.js"),
    "export const preparePiEnvironment = () => ({});",
  );
  const entries = {
    "piship-a": write(join(payload, "a.js"), mainSource),
    "codemode-worker": write(join(payload, "worker.js"), "export {};"),
    "image-resize-worker": write(join(payload, "image.js"), "export {};"),
  };
  const runtime = join(payload, "runtime");
  mkdirSync(runtime, { recursive: true });
  const esbuild = createRequire(import.meta.url).resolve("esbuild");
  return { root, payload, entries, runtime, esbuild };
}

function bundle(fixture: ReturnType<typeof payloadWith>) {
  return spawnSync(process.execPath, ["--input-type=module", "-"], {
    input: runtimeBundleScript(
      fixture.esbuild,
      fixture.payload,
      fixture.entries,
      fixture.runtime,
    ),
    encoding: "utf8",
    cwd: fixture.root,
  });
}

describe("the runtime bundle stays inside the payload", () => {
  it("bundles a payload whose imports it holds itself", () => {
    const fixture = payloadWith("export const a = 1;");
    const result = bundle(fixture);
    expect(result.status, result.stderr).toBe(0);
  });

  it("refuses a module that only a node_modules above the payload provides", () => {
    const fixture = payloadWith(
      'import { leak } from "leaky"; export const a = leak;',
    );
    // On the build machine, above the payload: not in the lock.
    write(
      join(fixture.root, "outer", "node_modules", "leaky", "index.js"),
      "export const leak = 1;",
    );
    write(
      join(fixture.root, "outer", "node_modules", "leaky", "package.json"),
      '{"name":"leaky","version":"1.0.0","type":"module","main":"index.js"}',
    );
    const result = bundle(fixture);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("outside the payload");
    expect(result.stderr).toContain("leaky");
  });
});
