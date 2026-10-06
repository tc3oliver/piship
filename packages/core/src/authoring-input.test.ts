import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUTHORING_SNAPSHOT,
  forgetAuthoringInputs,
  authoringBuildInput,
  writeAuthoringSnapshot,
} from "./authoring-input.js";
import { buildInputDigest } from "./build-cache.js";
import { workspacePackages } from "./runtime-dependencies.js";

const roots: string[] = [];
const temporary = () => {
  const root = mkdtempSync(join(tmpdir(), "piship-authoring-test-"));
  roots.push(root);
  return root;
};
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function source() {
  const root = temporary();
  writeFileSync(join(root, "package.json"), '{"type":"module"}');
  writeFileSync(join(root, "package-lock.json"), '{"lockfileVersion":3}');
  for (const name of workspacePackages) {
    const directory = join(root, "packages", name, "dist");
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      join(root, "packages", name, "package.json"),
      JSON.stringify({ name }),
    );
    writeFileSync(
      join(directory, "index.js"),
      `export const name = "${name}";`,
    );
  }
  writeFileSync(
    join(root, "packages", "core", "dist", "binary.dat"),
    Buffer.from([0, 255, 128, 1]),
  );
  return root;
}

describe("portable authoring inputs", () => {
  it("restores the exact inputs in a private copy, without changing the payload", () => {
    const original = source();
    const payload = temporary();
    const archive = join(payload, AUTHORING_SNAPSHOT);
    writeAuthoringSnapshot(original, archive);
    const bytes = readFileSync(archive);
    const env = { PISHIP_CACHE_HOME: temporary() };
    const restored = authoringBuildInput(payload, env);
    expect(buildInputDigest(restored)).toBe(buildInputDigest(original));
    expect(authoringBuildInput(payload, env)).toBe(restored);
    expect(readFileSync(archive)).toEqual(bytes);
    // Header byte 9 is the zlib OS id; it is fixed so every platform writes the same bytes.
    expect(bytes[9]).toBe(0xff);
    forgetAuthoringInputs();
    // A corrupted warm cache must never become the next distribution's source.
    writeFileSync(
      join(restored, "packages", "core", "dist", "index.js"),
      "corrupt",
    );
    forgetAuthoringInputs();
    expect(buildInputDigest(authoringBuildInput(payload, env))).toBe(
      buildInputDigest(original),
    );
    const { mtimeMs } = statSync(
      join(restored, "packages", "core", "dist", "index.js"),
    );
    forgetAuthoringInputs();
    expect(authoringBuildInput(payload, env)).toBe(restored);
    expect(
      statSync(join(restored, "packages", "core", "dist", "index.js")).mtimeMs,
    ).toBe(mtimeMs);
    // Rebuilding a distribution retains the same snapshot bytes and its ability to author.
    const rebuilt = temporary();
    writeAuthoringSnapshot(restored, join(rebuilt, AUTHORING_SNAPSHOT));
    expect(readFileSync(join(rebuilt, AUTHORING_SNAPSHOT))).toEqual(bytes);
    expect(buildInputDigest(authoringBuildInput(rebuilt, env))).toBe(
      buildInputDigest(original),
    );
  });

  it("uses an existing source snapshot without expansion", () => {
    const original = source();
    expect(authoringBuildInput(original)).toBe(original);
  });

  it.each(["../escape.js", "/escape.js", "D:\\escape.js"])(
    "refuses snapshot path %s before writing outside its private directory",
    (path) => {
      const payload = temporary();
      writeFileSync(
        join(payload, AUTHORING_SNAPSHOT),
        gzipSync(
          JSON.stringify({
            schema: "piship-authoring-input/v1",
            files: [[path, 0o600, ""]],
          }),
        ),
      );
      expect(() => authoringBuildInput(payload)).toThrow(
        "Unsafe archive entry path",
      );
    },
  );
});
