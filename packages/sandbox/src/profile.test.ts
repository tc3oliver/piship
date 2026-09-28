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
  realpathNearest,
  resolveProfile,
  type SandboxPolicy,
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
    expect(expandPathToken("workspace/build", ctx)).toBe("/w/build");
    expect(expandPathToken("tmp", ctx)).toBe("/t");
    expect(expandPathToken("tmp/cache", ctx)).toBe("/t/cache");
    expect(expandPathToken("~", ctx)).toBe("/h");
    expect(expandPathToken("~/.ssh", ctx)).toBe("/h/.ssh");
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
