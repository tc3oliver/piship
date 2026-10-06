import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const prepareScript = fileURLToPath(
  new URL("../scripts/prepare-build-input.mjs", import.meta.url),
);
const roots: string[] = [];
function fixture() {
  const workspace = mkdtempSync(join(tmpdir(), "piship-input-"));
  roots.push(workspace);
  for (const name of ["package.json", "package-lock.json"])
    writeFileSync(join(workspace, name), "{}\n");
  for (const name of [
    "schema",
    "contracts",
    "policy",
    "audit",
    "sandbox",
    "mcp",
    "identity",
    "credentials",
    "inference",
    "core",
    "pi",
    "cli",
    "adapter-sdk",
  ]) {
    const directory = join(workspace, "packages", name);
    mkdirSync(join(directory, "dist"), { recursive: true });
    writeFileSync(
      join(directory, "package.json"),
      `${JSON.stringify({ name: `@piship/${name}` })}\n`,
    );
    writeFileSync(
      join(directory, "dist", "index.js"),
      `export const name=${JSON.stringify(name)};\n`,
    );
  }
  return {
    workspace,
    input: join(workspace, "packages", "core", "dist", "build-input"),
  };
}
function prepare(workspace: string) {
  const script = `import {prepareBuildInput} from ${JSON.stringify(pathToFileURL(prepareScript).href)}; console.log(JSON.stringify(prepareBuildInput(${JSON.stringify(workspace)})));`;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    files: number;
    hashed: number;
    copied: number;
    removed: number;
    sha256: string;
  };
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("incremental relocatable build input", () => {
  it("leaves an unchanged snapshot and generation marker untouched", () => {
    const { workspace, input } = fixture();
    const first = prepare(workspace);
    expect(first.files).toBe(28);
    expect(first.copied).toBe(first.files);
    const marker = join(input, ".piship-build-input.json");
    const before = statSync(marker).mtimeMs;
    const warm = prepare(workspace);
    expect(warm).toEqual({ ...first, hashed: 0, copied: 0 });
    expect(statSync(marker).mtimeMs).toBe(before);
    expect(
      readFileSync(join(input, "packages", "pi", "dist", "index.js"), "utf8"),
    ).toContain('"pi"');
    expect(first.files).toBe(prepare(workspace).files);
  });
  it("copies only changed bytes and updates the content fingerprint", () => {
    const { workspace, input } = fixture();
    const first = prepare(workspace);
    writeFileSync(
      join(workspace, "packages", "pi", "dist", "index.js"),
      "export const changed=true;\n",
    );
    const next = prepare(workspace);
    expect(next.hashed).toBe(1);
    expect(next.copied).toBe(1);
    expect(next.sha256).not.toBe(first.sha256);
    expect(
      readFileSync(join(input, "packages", "pi", "dist", "index.js"), "utf8"),
    ).toContain("changed");
  });
  it("does not copy a source whose timestamp changed but content did not", () => {
    const { workspace } = fixture();
    const first = prepare(workspace);
    const source = join(workspace, "packages", "pi", "dist", "index.js");
    const future = new Date(Date.now() + 10_000);
    utimesSync(source, future, future);
    const next = prepare(workspace);
    expect(next.hashed).toBe(1);
    expect(next.copied).toBe(0);
    expect(next.sha256).toBe(first.sha256);
  });
  it("repairs missing destination files and removes stale or unexpected files", () => {
    const { workspace, input } = fixture();
    prepare(workspace);
    rmSync(join(input, "packages", "pi", "dist", "index.js"));
    writeFileSync(join(input, "unexpected.js"), "unwanted");
    rmSync(join(workspace, "packages", "audit", "dist", "index.js"));
    const next = prepare(workspace);
    expect(next.hashed).toBe(0);
    expect(next.copied).toBe(1);
    expect(next.removed).toBe(2);
    expect(next.files).toBe(27);
  });
  it("does not recursively include its own snapshot", () => {
    const { workspace, input } = fixture();
    mkdirSync(input, { recursive: true });
    writeFileSync(join(input, "old-input.js"), "unwanted");
    const first = prepare(workspace);
    expect(first.files).toBe(28);
    expect(first.removed).toBe(1);
    expect(prepare(workspace).copied).toBe(0);
  });
});
