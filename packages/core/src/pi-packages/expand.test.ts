import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { expandPackageResources, globToRegExp } from "./expand.js";
import type { PackageFilters } from "./types.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function packageRoot(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "piship-expand-"));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

const paths = (root: string, filters: PackageFilters = {}) =>
  expandPackageResources("fixture", root, filters).map(
    (item) => `${item.kind}:${item.path}`,
  );

const CONVENTIONAL = {
  "package.json": JSON.stringify({ name: "conventional", version: "1.0.0" }),
  "extensions/alpha.ts": "export default () => {};\n",
  "extensions/beta/index.ts": "export default () => {};\n",
  "extensions/beta/helper.ts": "export {};\n",
  "extensions/.hidden.ts": "export default () => {};\n",
  "skills/review/SKILL.md": "---\nname: review\n---\n",
  "skills/review/notes.md": "not a skill\n",
  "skills/top.md": "---\nname: top\n---\n",
  "prompts/fix.md": "fix\n",
  "prompts/nested/plan.md": "plan\n",
  "themes/dark.json": "{}\n",
  "node_modules/dep/extensions/x.ts": "export default () => {};\n",
};

describe("Pi package expansion", () => {
  it("follows Pi's conventional directories without a pi manifest", () => {
    expect(paths(packageRoot(CONVENTIONAL))).toEqual([
      "extensions:extensions/alpha.ts",
      "extensions:extensions/beta/index.ts",
      "skills:skills/review/SKILL.md",
      "skills:skills/top.md",
      "prompts:prompts/fix.md",
      "prompts:prompts/nested/plan.md",
      "themes:themes/dark.json",
    ]);
  });

  it("records each file's sha256", () => {
    const [first] = expandPackageResources(
      "fixture",
      packageRoot(CONVENTIONAL),
      {
        extensions: ["extensions/alpha.ts"],
        skills: [],
        prompts: [],
        themes: [],
      },
    );
    expect(first).toEqual({
      kind: "extensions",
      path: "extensions/alpha.ts",
      sha256: createHash("sha256")
        .update("export default () => {};\n")
        .digest("hex"),
    });
  });

  it("uses only the pi manifest when one exists, with its globs and exclusions", () => {
    const root = packageRoot({
      ...CONVENTIONAL,
      "package.json": JSON.stringify({
        name: "manifest",
        pi: {
          extensions: ["./src/*.ts", "!src/legacy.ts"],
          skills: ["./resources/skills"],
        },
      }),
      "src/main.ts": "export default () => {};\n",
      "src/legacy.ts": "export default () => {};\n",
      "resources/skills/deploy/SKILL.md": "---\nname: deploy\n---\n",
    });
    expect(paths(root)).toEqual([
      "extensions:src/main.ts",
      "skills:resources/skills/deploy/SKILL.md",
    ]);
  });

  it("applies the declaration's filters: [] none, globs, !, +, -", () => {
    const root = packageRoot(CONVENTIONAL);
    expect(
      paths(root, {
        extensions: ["extensions/*.ts", "-extensions/alpha.ts"],
        skills: ["!review"],
        prompts: [],
        themes: ["+themes/dark.json"],
      }),
    ).toEqual(["skills:skills/top.md", "themes:themes/dark.json"]);
    expect(
      paths(root, {
        extensions: ["!**/*.ts", "+extensions/beta/index.ts"],
        skills: [],
        prompts: ["**/plan.md"],
        themes: [],
      }),
    ).toEqual([
      "extensions:extensions/beta/index.ts",
      "prompts:prompts/nested/plan.md",
    ]);
  });

  it("filters never expose what the package does not declare", () => {
    const root = packageRoot({
      "package.json": JSON.stringify({
        name: "narrow",
        pi: { extensions: ["extensions/alpha.ts"] },
      }),
      "extensions/alpha.ts": "export default () => {};\n",
      "extensions/beta.ts": "export default () => {};\n",
    });
    expect(paths(root, { extensions: ["+extensions/beta.ts"] })).toEqual([
      "extensions:extensions/alpha.ts",
    ]);
  });

  it("refuses a manifest entry outside the package root", () => {
    const root = packageRoot({
      "package/package.json": JSON.stringify({
        name: "escape",
        pi: { extensions: ["../outside.ts"] },
      }),
      "outside.ts": "export default () => {};\n",
    });
    expect(() => paths(join(root, "package"))).toThrow(
      /outside the package root/,
    );
  });

  it("refuses a resource reached through a symlink", () => {
    const root = packageRoot({
      "package.json": JSON.stringify({ name: "link" }),
      "real/alpha.ts": "export default () => {};\n",
    });
    // A junction needs no privilege on Windows and is a symlink elsewhere.
    symlinkSync(join(root, "real"), join(root, "extensions"), "junction");
    expect(() => paths(root)).toThrow(/through a symlink/);
  });

  it("refuses ignore files inside a resource directory", () => {
    const root = packageRoot({
      ...CONVENTIONAL,
      "prompts/.gitignore": "fix.md\n",
    });
    expect(() => paths(root)).toThrow(/narrows Pi resource discovery/);
  });
});

describe("package globs", () => {
  it.each([
    ["src/*.ts", "src/a.ts", true],
    ["src/*.ts", "src/a/b.ts", false],
    ["src/*.ts", "src/.a.ts", false],
    ["**/*.md", "a.md", true],
    ["**/*.md", "a/b/c.md", true],
    ["a/**", "a/b/c", true],
    ["*.{ts,js}", "x.js", true],
    ["*.{ts,js}", "x.mjs", false],
    ["file?.md", "file1.md", true],
    ["[ab].md", "c.md", false],
  ])("%s matches %s: %s", (pattern, path, expected) => {
    expect(globToRegExp(pattern).test(path)).toBe(expected);
  });
});

describe("the enterprise reference package fixture", () => {
  it("expands to its extension, skill, and prompt", () => {
    const fixture = fileURLToPath(
      new URL(
        "../../../../examples/enterprise-reference/packages/pi-platform",
        import.meta.url,
      ),
    );
    expect(paths(fixture)).toEqual([
      "extensions:extensions/platform.ts",
      "skills:skills/platform-release/SKILL.md",
      "prompts:prompts/release-notes.md",
    ]);
  });
});
