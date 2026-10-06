import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  expandPathToken,
  protectedAncestors,
  realpathNearest,
  resolveProfile,
  type SandboxPolicy,
  writableProtected,
} from "./profile.js";

const policy = (overrides: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  required: true,
  filesystem: {
    read: { deny: ["~/.ssh", "~/.netrc"] },
    write: { allow: ["workspace", "tmp"] },
  },
  network: { mode: "deny" },
  environment: { allow: ["PATH", "HOME", "PATH"] },
  ...overrides,
});

/**
 * Whether this platform lets a test create a symbolic link: Windows without
 * developer mode or elevation does not.
 */
const canSymlink = (() => {
  try {
    const probe = mkdtempSync(join(tmpdir(), "piship-symlink-probe-"));
    try {
      symlinkSync(probe, join(probe, "link"), "dir");
      return true;
    } finally {
      rmSync(probe, { recursive: true, force: true });
    }
  } catch {
    return false;
  }
})();

describe("path tokens", () => {
  const ctx = { workspace: "/w", homeDir: "/h", tmpDir: "/t" };
  it("expands workspace, tmp, ~ and nested forms", () => {
    expect(expandPathToken("workspace", ctx)).toBe("/w");
    expect(expandPathToken("workspace/build", ctx)).toBe(join("/w", "build"));
    expect(expandPathToken("tmp", ctx)).toBe("/t");
    expect(expandPathToken("tmp/cache", ctx)).toBe(join("/t", "cache"));
    expect(expandPathToken("~", ctx)).toBe("/h");
    expect(expandPathToken("~/.ssh", ctx)).toBe(join("/h", ".ssh"));
    expect(expandPathToken("/etc/shadow", ctx)).toBe("/etc/shadow");
  });
  it("rejects relative paths and look-alike tokens", () => {
    for (const value of ["build", "tmpfiles", "workspaces/x", "~user/x"])
      expect(() => expandPathToken(value, ctx)).toThrow(
        expect.objectContaining({ code: "CONFIG_INVALID" }),
      );
  });
});

describe("resolveProfile", () => {
  it("preserves resolved Git directory provenance without changing protection", () => {
    const ws = join(root, "ws");
    const git = join(ws, ".git", "hooks");
    const claude = join(ws, ".claude");
    const profile = resolveProfile(policy(), {
      workspace: ws,
      homeDir: root,
      tmpDir: join(root, "t"),
      protectedPaths: {
        files: [],
        directories: [git, claude],
        gitDirectories: [git],
      },
    });
    expect(profile.writeProtect.directories).toEqual([git, claude]);
    expect(profile.writeProtect.gitDirectories).toEqual([git]);
  });

  let root: string;
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "piship-profile-")));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("resolves to realpaths through the nearest existing ancestor and dedupes", () => {
    const real = join(root, "real-home");
    mkdirSync(join(real, ".ssh"), { recursive: true });
    symlinkSync(real, join(root, "home-link"));
    mkdirSync(join(root, "ws"));
    const profile = resolveProfile(
      policy({
        filesystem: {
          read: { deny: ["~/.ssh", "~/.ssh", "~/.aws/credentials"] },
          write: { allow: ["workspace", "tmp", "workspace"] },
        },
      }),
      {
        workspace: join(root, "ws"),
        homeDir: join(root, "home-link"),
        tmpDir: join(root, "session-tmp"),
        extraWritable: [join(root, "ws")],
        extraReadOnly: [join(root, "ws"), join(root, "ro")],
      },
    );
    expect(profile.homeDir).toBe(real);
    expect(profile.readDeny).toEqual([
      join(real, ".ssh"),
      join(real, ".aws", "credentials"),
    ]);
    expect(profile.writeAllow).toEqual([
      join(root, "ws"),
      join(root, "session-tmp"),
    ]);
    expect(profile.readOnly).toEqual([join(root, "ro")]);
    expect(profile.environmentAllow).toEqual(["PATH", "HOME"]);
    expect(profile.network).toBe("deny");
    expect(profile.warnings).toEqual([]);
  });

  it("maps the tmp token to the private session directory, not the host temp root", () => {
    const profile = resolveProfile(policy(), {
      workspace: root,
      homeDir: root,
      tmpDir: join(root, "session"),
    });
    expect(profile.writeAllow).toContain(join(root, "session"));
    expect(profile.writeAllow).not.toContain(realpathNearest(tmpdir()));
  });

  it("resolves protected paths and lists those inside a writable path with their parents", () => {
    const ws = join(root, "ws");
    mkdirSync(join(ws, ".git", "hooks"), { recursive: true });
    symlinkSync(ws, join(root, "ws-link"));
    const link = join(root, "ws-link", ".git");
    const profile = resolveProfile(policy(), {
      workspace: ws,
      homeDir: root,
      tmpDir: join(root, "t"),
      protectedPaths: {
        files: [join(link, "config"), join(root, "outside", "config")],
        directories: [join(link, "hooks"), join(link, "hooks", "nested")],
      },
    });
    expect(profile.writeProtect).toEqual({
      files: [join(ws, ".git", "config"), join(root, "outside", "config")],
      directories: [
        join(ws, ".git", "hooks"),
        join(ws, ".git", "hooks", "nested"),
      ],
    });
    const entries = writableProtected(profile);
    expect(entries).toEqual([
      { path: join(ws, ".git", "config"), directory: false },
      { path: join(ws, ".git", "hooks"), directory: true },
    ]);
    expect(protectedAncestors(profile, entries)).toEqual([join(ws, ".git")]);
  });

  it("pins the directories above a protected path that exists, and none above one that does not", () => {
    const ws = join(root, "ws");
    mkdirSync(join(ws, "config"), { recursive: true });
    writeFileSync(join(ws, "config", "local.cfg"), "");
    const profile = resolveProfile(policy(), {
      workspace: ws,
      homeDir: root,
      tmpDir: join(root, "t"),
      protectedPaths: {
        files: [
          join(ws, "config", "local.cfg"),
          join(ws, "absent", "dir", "local.cfg"),
        ],
        directories: [],
      },
    });
    const entries = writableProtected(profile);
    expect(entries.map((entry) => entry.path)).toEqual([
      join(ws, "config", "local.cfg"),
      join(ws, "absent", "dir", "local.cfg"),
    ]);
    // Moving `config` aside would move the file that exists; there is nothing
    // to move aside for the one that does not.
    expect(protectedAncestors(profile, entries)).toEqual([join(ws, "config")]);
    expect(
      protectedAncestors(profile, entries, undefined, () => false),
    ).toEqual([]);
  });

  it("pins existing ancestors of an absent protected directory against rename", () => {
    const ws = join(root, "workspace");
    mkdirSync(join(ws, "packages/app"), { recursive: true });
    const profile = resolveProfile(policy(), {
      workspace: ws,
      homeDir: root,
      tmpDir: join(root, "tmp"),
      protectedPaths: {
        files: [],
        directories: [join(ws, "packages/app/.claude")],
      },
    });
    expect(protectedAncestors(profile, writableProtected(profile))).toEqual([
      join(ws, "packages"),
      join(ws, "packages/app"),
    ]);
  });

  it("carries the reason a protected list is incomplete into the profile and its warnings", () => {
    const ctx = { workspace: join(root, "ws"), homeDir: root, tmpDir: root };
    const complete = resolveProfile(policy(), {
      ...ctx,
      protectedPaths: { files: [], directories: [] },
    });
    expect(complete.writeProtect).toEqual({ files: [], directories: [] });
    expect(complete.warnings).toEqual([]);
    const incomplete = resolveProfile(policy(), {
      ...ctx,
      protectedPaths: {
        files: [],
        directories: [],
        unverified: "the git config lists too much",
      },
    });
    expect(incomplete.writeProtect.unverified).toBe(
      "the git config lists too much",
    );
    expect(incomplete.warnings).toEqual([
      "git control is not verified: the git config lists too much",
    ]);
  });

  it("reports git control unverified for a link in a directory the sandbox may write, and only there", () => {
    const ws = join(root, "ws");
    mkdirSync(ws);
    const ctx = {
      workspace: ws,
      homeDir: join(root, "home"),
      tmpDir: join(root, "t"),
    };
    const resolve = (links: string[], unverified?: string) =>
      resolveProfile(policy(), {
        ...ctx,
        protectedPaths: {
          files: [],
          directories: [],
          links,
          ...(unverified ? { unverified } : {}),
        },
      });
    // Protection covers what a link points to, and nothing holds the link
    // itself in place: a link the sandbox can replace is a path it can retarget.
    const inside = resolve([join(ws, ".gitconfig-team")]);
    expect(inside.writeProtect.unverified).toContain("symbolic link");
    expect(inside.writeProtect.unverified).toContain(
      join(ws, ".gitconfig-team"),
    );
    expect(inside.warnings).toEqual([
      `git control is not verified: ${inside.writeProtect.unverified}`,
    ]);
    // A link the sandbox cannot write next to is not retargetable from inside.
    const outside = resolve([
      join(root, "home", ".gitconfig"),
      join(root, "elsewhere", "hooks"),
    ]);
    expect(outside.writeProtect).toEqual({ files: [], directories: [] });
    expect(outside.warnings).toEqual([]);
    // Every reason is kept, and a long list of links is counted.
    const both = resolve(
      Array.from({ length: 5 }, (_, index) => join(ws, `link-${index}`)),
      "the git config lists too much",
    );
    expect(both.writeProtect.unverified).toMatch(
      /^the git config lists too much; .*link-0.*link-2 and 2 more\)/,
    );
    expect(both.writeProtect.unverified).not.toContain("link-3");
  });

  // Skipped, and reported as skipped, where links cannot be made; the check
  // before it fails on Linux and macOS.
  it("can create symbolic links on this platform, which the test below needs", () => {
    if (process.platform !== "win32") expect(canSymlink).toBe(true);
  });

  it.skipIf(!canSymlink)(
    "takes the directory that holds a link as it resolves, however it is named",
    () => {
      const ws = join(root, "ws");
      mkdirSync(ws);
      symlinkSync(ws, join(root, "ws-link"));
      const profile = resolveProfile(policy(), {
        workspace: ws,
        homeDir: join(root, "home"),
        tmpDir: join(root, "t"),
        protectedPaths: {
          files: [],
          directories: [],
          links: [join(root, "ws-link", "x")],
        },
      });
      expect(profile.writeProtect.unverified).toContain("symbolic link");
    },
  );

  it("warns when a deny hides a writable path", () => {
    const profile = resolveProfile(
      policy({
        filesystem: { read: { deny: ["~"] }, write: { allow: ["workspace"] } },
      }),
      { workspace: join(root, "ws"), homeDir: root, tmpDir: join(root, "t") },
    );
    expect(profile.warnings[0]).toContain("deny wins");
  });
});
