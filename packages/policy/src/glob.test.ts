import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, parse, sep } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  expandPathTokens,
  isWithin,
  matchAction,
  matchGlob,
  normalizePathResource,
  toPosixPath,
} from "./glob.js";

describe("matchGlob", () => {
  it.each([
    ["*", "docs", true],
    ["*", "docs:search", false],
    ["*", "a/b", false],
    ["docs:*", "docs:search", true],
    ["docs:*", "docs:a/b", false],
    ["docs:delete_*", "docs:delete_document", true],
    ["**", "", true],
    ["**", "a/b:c", true],
    ["a/**", "a", true],
    ["a/**", "a/b/c", true],
    ["a/**", "ab", false],
    ["a/**/b", "a/b", true],
    ["a/**/b", "a/x/y/b", true],
    ["/home/u/.ssh/**", "/home/u/.ssh", true],
    ["/home/u/.ssh/**", "/home/u/.sshx", false],
    ["Docs", "docs", false],
    ["docs", "docs2", false],
    ["docs", "xdocs", false],
    ["a.b", "axb", false],
    ["(x)+[y]", "(x)+[y]", true],
    ["git *", "git status --short", true],
    ["git *", "git status\nrm -rf x", false],
    ["git **", "git status\nrm -rf /", true],
    ["git.example.com/**", "git.example.com/team/repo", true],
    ["git.example.com/*", "git.example.com/team/repo", false],
  ])("%s ~ %j = %s", (pattern, value, expected) => {
    expect(matchGlob(pattern, value)).toBe(expected);
  });
});

describe("matchAction", () => {
  it("matches exact, prefix, and wildcard actions", () => {
    expect(matchAction("mcp.tool.call", "mcp.tool.call")).toBe(true);
    expect(matchAction("mcp.*", "mcp.tool.call")).toBe(true);
    expect(matchAction("mcp.tool.*", "mcp.tool.call")).toBe(true);
    expect(matchAction("mcp.*", "mcpx.call")).toBe(false);
    expect(matchAction("*", "model.select")).toBe(true);
    expect(matchAction("model.select", "model.selected")).toBe(false);
  });
});

describe("expandPathTokens", () => {
  const context = { workspaceRoot: "/w", homeDir: "/h", tmpDir: "/t" };
  it.each([
    ["workspace", "/w"],
    ["workspace/**", "/w/**"],
    ["tmp", "/t"],
    ["tmp/x", "/t/x"],
    ["~", "/h"],
    ["~/.ssh/**", "/h/.ssh/**"],
    ["workspaces/x", "workspaces/x"],
    ["~user/x", "~user/x"],
    ["/abs/**", "/abs/**"],
  ])("%s -> %s", (pattern, expected) => {
    expect(expandPathTokens(pattern, context)).toBe(expected);
  });
  it("handles a root base", () => {
    expect(expandPathTokens("~/x", { ...context, homeDir: "/" })).toBe("/x");
  });
});

describe("toPosixPath", () => {
  it("converts Windows separators and keeps the drive letter", () => {
    expect(toPosixPath("C:\\Users\\me\\repo", "\\")).toBe("C:/Users/me/repo");
    expect(toPosixPath("/a/b", "/")).toBe("/a/b");
  });
});

describe("isWithin", () => {
  it("checks path containment on segment boundaries", () => {
    expect(isWithin("/a/b", "/a/b")).toBe(true);
    expect(isWithin("/a/b", "/a/b/c")).toBe(true);
    expect(isWithin("/a/b", "/a/bc")).toBe(false);
    expect(isWithin("/", "/x")).toBe(true);
  });
});

function trySymlink(
  target: string,
  path: string,
  type?: "dir" | "file",
): boolean {
  try {
    symlinkSync(target, path, type);
    return true;
  } catch (error) {
    // Windows without developer mode or elevation cannot create symlinks.
    expect(process.platform).toBe("win32");
    expect((error as NodeJS.ErrnoException).code).toBe("EPERM");
    return false;
  }
}

describe("normalizePathResource", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-policy-glob-")));
  afterAll(() => rmSync(base, { recursive: true, force: true }));
  const posix = (path: string) => toPosixPath(path);
  const workspace = join(base, "work");
  const outside = join(base, "outside");
  mkdirSync(join(workspace, "src"), { recursive: true });
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(outside, "secret.txt"), "x");

  it("resolves relative paths against the workspace", () => {
    expect(
      normalizePathResource("src/a.ts", { workspaceRoot: workspace }),
    ).toBe(posix(join(workspace, "src", "a.ts")));
    expect(
      normalizePathResource("./src/../src/./b", { workspaceRoot: workspace }),
    ).toBe(posix(join(workspace, "src", "b")));
  });
  it("keeps missing segments below the nearest existing ancestor", () => {
    expect(
      normalizePathResource(join(workspace, "new", "deep", "file"), {
        workspaceRoot: workspace,
      }),
    ).toBe(posix(join(workspace, "new", "deep", "file")));
  });
  it("resolves symlinked directories and files", () => {
    const link = join(workspace, "link");
    if (!trySymlink(outside, link, "dir")) return;
    expect(
      normalizePathResource("link/secret.txt", { workspaceRoot: workspace }),
    ).toBe(posix(join(outside, "secret.txt")));
    expect(
      normalizePathResource("link/missing/x", { workspaceRoot: workspace }),
    ).toBe(posix(join(outside, "missing", "x")));
    // `..` after a symlink walks from the link target, as the kernel does.
    expect(
      normalizePathResource("link/../x", { workspaceRoot: workspace }),
    ).toBe(posix(join(base, "x")));
  });
  it("follows dangling symlinks to their would-be target", () => {
    const link = join(workspace, "dangling");
    if (!trySymlink(join(outside, "not-yet"), link, "file")) return;
    expect(
      normalizePathResource("dangling", { workspaceRoot: workspace }),
    ).toBe(posix(join(outside, "not-yet")));
  });
  it("uses the realpath of the temp directory itself", () => {
    const resolved = normalizePathResource(tmpdir(), {
      workspaceRoot: workspace,
    });
    expect(resolved).toBe(posix(realpathSync.native(tmpdir())));
  });
});

describe("normalizePathResource on a path that exists in full", () => {
  // The walk over every prefix this resolution had before it took one call
  // for such a path: kept here to show the two agree.
  function walk(path: string, depth = 0): string {
    if (depth > 40) return path;
    const { root } = parse(path);
    const segments = path.slice(root.length).split(/[\\/]+/);
    const real = (target: string) => {
      try {
        return realpathSync.native(target);
      } catch {
        return undefined;
      }
    };
    const isLink = (target: string) => {
      try {
        return lstatSync(target).isSymbolicLink();
      } catch {
        return false;
      }
    };
    let current = real(root) ?? root;
    let existing = true;
    for (let index = 0; index < segments.length; index += 1) {
      const segment = segments[index] ?? "";
      if (segment === "" || segment === ".") continue;
      if (segment === "..") {
        current = dirname(current);
        continue;
      }
      const next = join(current, segment);
      if (!existing) {
        current = next;
        continue;
      }
      const resolved = real(next);
      if (resolved !== undefined) {
        current = resolved;
        continue;
      }
      if (isLink(next)) {
        const target = readlinkSync(next);
        const absolute = isAbsolute(target) ? target : join(current, target);
        const rest = segments.slice(index + 1).join(sep);
        return walk(
          rest === "" ? absolute : `${absolute}${sep}${rest}`,
          depth + 1,
        );
      }
      existing = false;
      current = next;
    }
    return current;
  }

  const base = realpathSync(mkdtempSync(join(tmpdir(), "piship-policy-glob-")));
  afterAll(() => rmSync(base, { recursive: true, force: true }));
  const deep = join(base, "a", "b", "c", "d");
  mkdirSync(deep, { recursive: true });
  writeFileSync(join(deep, "file"), "x");
  const aliased = join(base, "alias");
  const aliasMade = trySymlink(join(base, "a", "b"), aliased, "dir");
  const chained = join(base, "chain");
  const chainMade = aliasMade && trySymlink(aliased, chained, "dir");
  const dangling = join(base, "dangling");
  const danglingMade = trySymlink(join(base, "not-yet", "x"), dangling, "file");

  it("asks the system once for an existing path, and agrees with the walk over each prefix", () => {
    const paths = [
      join(deep, "file"),
      deep,
      `${deep}${sep}`,
      `${base}${sep}a${sep}b${sep}..${sep}b${sep}c`,
      join(base, "a", "missing", "file"),
      join(base, "a", "missing", "deeper", "still", "file"),
      join(deep, "file", "below-a-file"),
      join(base, "nothing"),
      ...(aliasMade ? [join(aliased, "c", "missing", "deeper")] : []),
      ...(danglingMade ? [dangling, join(dangling, "below")] : []),
      base,
      parse(base).root,
      ...(aliasMade ? [join(aliased, "c", "d", "file")] : []),
      ...(chainMade
        ? [
            join(chained, "c", "d", "file"),
            `${chained}${sep}c${sep}..${sep}b${sep}c`,
          ]
        : []),
    ];
    for (const path of paths) {
      const spy = vi.spyOn(realpathSync, "native");
      const found = normalizePathResource(path, { workspaceRoot: base });
      const calls = spy.mock.calls.length;
      spy.mockRestore();
      expect(found, path).toBe(toPosixPath(walk(path)));
      const dotted = path.split(/[\\/]+/).some((s) => s === "." || s === "..");
      // One call for a path that exists and names no `.` or `..`.
      if (!dotted && path !== parse(base).root && existsSync(path))
        expect(calls, path).toBe(1);
    }
  });
});
