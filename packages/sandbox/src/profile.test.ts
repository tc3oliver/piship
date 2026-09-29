import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
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
