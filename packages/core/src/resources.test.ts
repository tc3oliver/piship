import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ManifestError, readManifest } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import { resolveResources } from "./resources.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** Resolve a personal v1 manifest whose `resources` block is `block`. */
function resolveWith(block: string, files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "piship-resources-"));
  roots.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  const manifest = join(dir, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1",
      "app: { id: demo, name: Demo, command: demo, version: 1.0.0 }",
      "deployment: { mode: personal }",
      "updates: { channel: stable, channels: [stable] }",
      "resources:",
      block,
      "",
    ].join("\n"),
  );
  try {
    resolveResources(readManifest(manifest), manifest);
    return undefined;
  } catch (error) {
    expect(error).toBeInstanceOf(ManifestError);
    return error as ManifestError;
  }
}

describe("declared resource roots", () => {
  it("names the entry of a missing resource, with its line", () => {
    const error = resolveWith(
      "  instructions:\n    user:\n      - ./AGENTS.md\n      - ./missing.md",
      { "AGENTS.md": "Hi" },
    );
    expect(error?.field).toBe("resources.instructions.user[1]");
    expect(error?.message).toContain("./missing.md does not exist");
    expect(error?.message).toContain("line 9");
  });
  it("rejects an extension directory Pi cannot load", () => {
    const error = resolveWith("  extensions:\n    user: [./ext]", {
      "ext/main.ts": "export default () => {};",
    });
    expect(error?.field).toBe("resources.extensions.user[0]");
    expect(error?.message).toContain("without index.ts or index.js");
  });
  it("rejects a nested folder that is not extensions/", () => {
    const error = resolveWith("  extensions:\n    user: [./ext]", {
      "ext/lib/tool.ts": "export default () => {};",
    });
    expect(error?.message).toContain("without index.ts or index.js");
  });
  it.each([
    "ext/index.ts",
    "ext/index.js",
    "ext/package.json",
    "ext/extensions/tool.ts",
  ])("accepts an extension directory with %s", (entry) => {
    expect(
      resolveWith("  extensions:\n    user: [./ext]", {
        "ext/main.ts": "export default () => {};",
        [entry]: entry.endsWith(".json")
          ? '{"pi":{"extensions":["./main.ts"]}}'
          : "export default () => {};",
      }),
    ).toBeUndefined();
  });
});
