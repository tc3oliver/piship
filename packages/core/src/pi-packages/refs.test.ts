import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalSourceUrl,
  checkGitDeclaration,
  checkLocalDeclaration,
  checkLockfileClosure,
  checkNpmDeclaration,
  type NpmLockfileEntry,
  optionalDependenciesFor,
} from "./refs.js";
import type { Manifest } from "@piship/schema";
import { checkPackageTrust, effectivePackageTrust } from "./trust.js";
import type { PackageTrustConfig } from "./types.js";

const SHA = "92af01c3d4e5f60718293a4b5c6d7e8f90a1b2c3";
const INTEGRITY = `sha512-${Buffer.alloc(64, 1).toString("base64")}`;
const managed = effectivePackageTrust(undefined, "managed");
const personal = effectivePackageTrust(undefined, "personal");

const npm = (version: string, extra: Record<string, unknown> = {}) => ({
  id: "company-platform",
  source: "npm" as const,
  package: "@company/pi-platform",
  version,
  class: "company" as const,
  filters: {},
  ...extra,
});

describe("packageTrust validation", () => {
  const manifest = (mode: string, trust: PackageTrustConfig) =>
    ({
      deployment: { mode },
      governance: { packageTrust: trust },
    }) as unknown as Manifest;

  it("rejects a managed manifest that turns integrity or commit SHAs off", () => {
    expect(() =>
      checkPackageTrust(
        manifest("managed", { ...managed, npm: { requireIntegrity: false } }),
      ),
    ).toThrow(/requires npm integrity/);
    expect(() =>
      checkPackageTrust(
        manifest("managed", {
          ...managed,
          git: { requireCommitSha: false },
        }),
      ),
    ).toThrow(/requires a full commit SHA/);
    expect(() =>
      checkPackageTrust(
        manifest("personal", { ...personal, npm: { requireIntegrity: false } }),
      ),
    ).not.toThrow();
  });
});

describe("packageTrust defaults", () => {
  it("managed requires integrity and commit SHAs and allows no local paths", () => {
    expect(managed).toEqual({
      npm: { requireIntegrity: true },
      git: { requireCommitSha: true },
      local: { paths: [] },
    });
  });

  it("a managed manifest cannot turn a requirement off", () => {
    expect(() =>
      effectivePackageTrust(
        { ...managed, git: { requireCommitSha: false } },
        "managed",
      ),
    ).toThrow(/cannot turn off/);
    expect(() =>
      effectivePackageTrust(
        { ...managed, npm: { requireIntegrity: false } },
        "managed",
      ),
    ).toThrow(/cannot turn off/);
  });

  it("personal accepts branches and any local path unless narrowed", () => {
    expect(personal).toEqual({
      npm: { requireIntegrity: true },
      git: { requireCommitSha: false },
      local: {},
    });
  });
});

describe("npm declarations", () => {
  it("accepts an exact version in managed and a range in personal", () => {
    expect(() => checkNpmDeclaration(npm("1.4.2"), "managed")).not.toThrow();
    expect(() => checkNpmDeclaration(npm("^1.4.0"), "personal")).not.toThrow();
    expect(() =>
      checkNpmDeclaration(npm(">=1.2.0 <2 || 3.x"), "personal"),
    ).not.toThrow();
  });

  it("refuses a range in managed", () => {
    expect(() => checkNpmDeclaration(npm("^1.4.0"), "managed")).toThrow(
      /not exact/,
    );
  });

  it.each([
    "latest",
    "next",
    "npm:other@1.0.0",
    "file:../x",
    "link:../x",
    "workspace:*",
    "github:o/r",
  ])("refuses %s even in personal", (version) => {
    expect(() => checkNpmDeclaration(npm(version), "personal")).toThrow(
      /dist-tag|alias/,
    );
  });

  it("refuses a host-provided Pi package", () => {
    expect(() =>
      checkNpmDeclaration(
        { ...npm("1.0.0"), package: "@earendil-works/pi-ai" },
        "personal",
      ),
    ).toThrow(/provided by the Pi host/);
  });

  it("refuses a registry with credentials without echoing them", () => {
    let message = "";
    try {
      checkNpmDeclaration(
        npm("1.0.0", { registry: "https://ci:hunter2@registry.company.test" }),
        "personal",
      );
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/carries credentials/);
    expect(message).not.toContain("hunter2");
  });
});

describe("git declarations", () => {
  const git = (repository: string, ref = SHA) => ({
    id: "pi-security",
    source: "git" as const,
    repository,
    ref,
    class: "company" as const,
    filters: {},
  });

  it("accepts an https repository on an allowed host at a full SHA", () => {
    expect(
      checkGitDeclaration(
        git("https://github.company.com/platform/pi-security/"),
        {
          ...managed,
          git: { hosts: ["github.company.com"], requireCommitSha: true },
        },
      ),
    ).toBe("https://github.company.com/platform/pi-security");
  });

  it.each([
    "github:platform/pi-security",
    "gitlab:platform/pi-security",
    "git+ssh://git@github.company.com/platform/pi-security",
    "git+https://github.company.com/platform/pi-security",
    "ssh://git@github.company.com/platform/pi-security",
    "git@github.company.com:platform/pi-security.git",
    "git://github.company.com/platform/pi-security",
    "file:///srv/git/pi-security",
    "http://github.company.com/platform/pi-security",
  ])("refuses %s", (repository) => {
    expect(() => checkGitDeclaration(git(repository), personal)).toThrow(
      /https|only https/,
    );
  });

  it("refuses a URL with userinfo or a query", () => {
    expect(() =>
      checkGitDeclaration(
        git("https://token:x@github.company.com/platform/pi-security"),
        personal,
      ),
    ).toThrow(/credentials/);
    expect(() =>
      checkGitDeclaration(
        git("https://github.company.com/platform/pi-security?ref=main"),
        personal,
      ),
    ).toThrow(/query/);
  });

  it("refuses a host outside packageTrust.git.hosts", () => {
    expect(() =>
      checkGitDeclaration(git("https://github.com/someone/pi-security"), {
        ...personal,
        git: { hosts: ["github.company.com"], requireCommitSha: false },
      }),
    ).toThrow(/not in packageTrust.git.hosts/);
  });

  it("refuses an abbreviated SHA everywhere and a branch or tag in managed", () => {
    const url = "https://github.company.com/platform/pi-security";
    expect(() => checkGitDeclaration(git(url, "92af01c"), personal)).toThrow(
      /abbreviated/,
    );
    expect(() => checkGitDeclaration(git(url, "v1.2.0"), managed)).toThrow(
      /requireCommitSha/,
    );
    expect(() => checkGitDeclaration(git(url, "HEAD"), managed)).toThrow(
      /requireCommitSha/,
    );
    expect(checkGitDeclaration(git(url, "v1.2.0"), personal)).toBe(url);
  });
});

describe("local declarations", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0))
      rmSync(root, { recursive: true, force: true });
  });
  const distribution = () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-local-")));
    roots.push(root);
    mkdirSync(join(root, "dist", "packages", "company"), { recursive: true });
    mkdirSync(join(root, "outside"), { recursive: true });
    return join(root, "dist");
  };
  const local = (path: string) => ({
    id: "local-company",
    source: "local" as const,
    path,
    class: "company" as const,
    filters: {},
  });

  it("returns the package root inside the distribution and local.paths", () => {
    const dir = distribution();
    expect(
      checkLocalDeclaration(local("./packages/company"), dir, {
        ...personal,
        local: { paths: ["./packages"] },
      }),
    ).toBe(join(dir, "packages", "company"));
  });

  it("refuses .., absolute paths, and paths outside local.paths", () => {
    const dir = distribution();
    expect(() =>
      checkLocalDeclaration(local("../outside"), dir, personal),
    ).toThrow(/without \.\./);
    expect(() =>
      checkLocalDeclaration(local(join(dir, "packages")), dir, personal),
    ).toThrow(/relative path/);
    expect(() =>
      checkLocalDeclaration(local("packages/company"), dir, managed),
    ).toThrow(/outside packageTrust.local.paths \(none\)/);
  });

  it("refuses a symlink that leaves the distribution directory", () => {
    const dir = distribution();
    // A junction needs no privilege on Windows and is a symlink elsewhere.
    symlinkSync(
      join(dir, "..", "outside"),
      join(dir, "packages", "escape"),
      "junction",
    );
    expect(() =>
      checkLocalDeclaration(local("packages/escape"), dir, personal),
    ).toThrow(/through a symlink/);
  });
});

describe("the package lockfile closure", () => {
  const tarball = (name: string, version: string) =>
    `https://registry.company.test/${name}/-/${name.split("/").at(-1)}-${version}.tgz`;
  const entry = (
    name: string,
    version = "1.0.0",
    extra: Partial<NpmLockfileEntry> = {},
  ): NpmLockfileEntry => ({
    version,
    resolved: tarball(name, version),
    integrity: INTEGRITY,
    ...extra,
  });
  const lockfile = (packages: Record<string, NpmLockfileEntry>) => ({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { "@company/pi-platform": "1.4.2" } },
      "node_modules/@company/pi-platform": entry(
        "@company/pi-platform",
        "1.4.2",
        {
          dependencies: { "left-pad": "^1.0.0" },
        },
      ),
      ...packages,
    },
  });

  it("returns every installed dependency, skipping peers", () => {
    const closure = checkLockfileClosure(
      "company-platform",
      lockfile({
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          hasInstallScript: true,
        }),
        "node_modules/@earendil-works/pi-ai": entry(
          "@earendil-works/pi-ai",
          "1.0.3",
          {
            peer: true,
          },
        ),
      }),
      managed,
    );
    expect(closure.map((item) => `${item.path}@${item.version}`)).toEqual([
      "node_modules/@company/pi-platform@1.4.2",
      "node_modules/left-pad@1.3.0",
    ]);
    expect(closure[1]?.installScript).toBe(true);
  });

  it.each<[string, Record<string, NpmLockfileEntry>, RegExp]>([
    [
      "a range",
      { "node_modules/left-pad": entry("left-pad", "^1.3.0") },
      /not an exact version/,
    ],
    [
      "an npm: alias",
      { "node_modules/left-pad": entry("left-pad", "1.3.0", { name: "evil" }) },
      /alias/,
    ],
    [
      "a link",
      {
        "node_modules/left-pad": { link: true, resolved: "../left-pad" },
      },
      /link, workspace, or file/,
    ],
    [
      "a git dependency",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          resolved: `git+ssh://git@github.com/x/left-pad.git#${SHA}`,
        }),
      },
      /git or file dependency/,
    ],
    [
      "a URL with userinfo",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          resolved:
            "https://u:p@registry.company.test/left-pad/-/left-pad-1.3.0.tgz",
        }),
      },
      /credentials/,
    ],
    [
      "a URL with a query",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          resolved:
            "https://registry.company.test/left-pad/-/left-pad-1.3.0.tgz?t=1",
        }),
      },
      /query/,
    ],
    [
      "an unpinned tarball URL",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          resolved: "https://cdn.company.test/left-pad/latest",
        }),
      },
      /pinned registry tarball/,
    ],
    [
      "missing integrity",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", { integrity: "" }),
      },
      /no sha512 integrity/,
    ],
    [
      "a vendored host-provided package",
      { "node_modules/typebox": entry("typebox", "1.0.0") },
      /host-provided typebox/,
    ],
    [
      "a dependency listing a Pi package",
      {
        "node_modules/left-pad": entry("left-pad", "1.3.0", {
          dependencies: { "@earendil-works/pi-coding-agent": "^1.0.0" },
        }),
      },
      /lists host-provided @earendil-works\/pi-coding-agent/,
    ],
  ])("refuses %s anywhere in the closure", (_name, packages, message) => {
    expect(() =>
      checkLockfileClosure("company-platform", lockfile(packages), managed),
    ).toThrow(message);
  });

  it("accepts missing integrity only when packageTrust opts out", () => {
    const packages = {
      "node_modules/left-pad": entry("left-pad", "1.3.0", { integrity: "" }),
    };
    expect(() =>
      checkLockfileClosure("company-platform", lockfile(packages), {
        npm: { requireIntegrity: false },
      }),
    ).not.toThrow();
  });

  it("records the optional dependencies each target installs", () => {
    const value = lockfile({
      "node_modules/@x/darwin-arm64": entry("@x/darwin-arm64", "1.0.0", {
        optional: true,
        os: ["darwin"],
        cpu: ["arm64"],
      }),
      "node_modules/@x/linux-x64": entry("@x/linux-x64", "1.0.0", {
        optional: true,
        os: ["linux"],
        cpu: ["x64"],
      }),
      "node_modules/@x/not-windows": entry("@x/not-windows", "1.0.0", {
        optional: true,
        os: ["!win32"],
      }),
    });
    expect(optionalDependenciesFor(value, "darwin-arm64")).toEqual([
      "node_modules/@x/darwin-arm64@1.0.0",
      "node_modules/@x/not-windows@1.0.0",
    ]);
    expect(optionalDependenciesFor(value, "win32-x64")).toEqual([]);
  });
});

describe("source URLs", () => {
  it("strips a trailing slash and refuses fragments", () => {
    expect(canonicalSourceUrl("x", "registry", "https://r.test/npm/")).toBe(
      "https://r.test/npm",
    );
    expect(() =>
      canonicalSourceUrl("x", "registry", "https://r.test/#frag"),
    ).toThrow(/fragment/);
  });
});
