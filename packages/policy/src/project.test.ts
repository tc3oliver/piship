import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { ProjectTrustPolicy } from "@piship/schema";
import { afterAll, describe, expect, it } from "vitest";
import { makePolicy } from "./fixtures.test-helpers.js";
import { toPosixPath } from "./glob.js";
import {
  discoverProjectResources,
  identifyProject,
  normalizeRemote,
  parseInstructionImports,
  parseOriginUrl,
  projectDimensionEffect,
  readProjectRestrictions,
  type ProjectResourceCandidate,
} from "./project.js";
import { defaultProjectTrust } from "./trust.js";

const base = realpathSync(
  mkdtempSync(join(tmpdir(), "piship-policy-project-")),
);
afterAll(() => rmSync(base, { recursive: true, force: true }));
let counter = 0;
function dir(name: string): string {
  counter += 1;
  const path = join(base, `${counter}-${name}`);
  mkdirSync(path, { recursive: true });
  return path;
}
function write(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}
function gitRepo(root: string, url?: string): void {
  write(
    join(root, ".git", "config"),
    `[core]\n\tbare = false\n${url ? `[remote "upstream"]\n\turl = https://other.example/x.git\n[remote "origin"]\n\turl = ${url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n` : ""}`,
  );
}
function trySymlink(
  target: string,
  path: string,
  type: "dir" | "file",
): boolean {
  try {
    mkdirSync(dirname(path), { recursive: true });
    symlinkSync(target, path, type);
    return true;
  } catch (error) {
    // Windows without developer mode or elevation cannot create symlinks.
    expect(process.platform).toBe("win32");
    expect((error as NodeJS.ErrnoException).code).toBe("EPERM");
    return false;
  }
}
const posix = (path: string) => toPosixPath(path);

const trust: ProjectTrustPolicy = {
  ...defaultProjectTrust("managed"),
  company: {
    ...defaultProjectTrust("managed").company,
    match: [{ remote: "git.acme.example/**" }],
  },
  external: {
    ...defaultProjectTrust("managed").external,
    match: [{ path: `${posix(base)}/*vendor-*` }],
  },
};

describe("normalizeRemote", () => {
  it.each([
    ["https://git.acme.example/team/repo.git", "git.acme.example/team/repo"],
    [
      "https://user:s3cr3t-token@GIT.Acme.Example:8443/team/repo.git",
      "git.acme.example/team/repo",
    ],
    [
      "ssh://git@git.acme.example:2222/team/repo.git/",
      "git.acme.example/team/repo",
    ],
    ["git@git.acme.example:team/repo.git", "git.acme.example/team/repo"],
    ["git.acme.example:team/Repo", "git.acme.example/team/Repo"],
    ["git://git.acme.example/team/repo", "git.acme.example/team/repo"],
    ["https://[::1]:8080/a/b.git", "[::1]/a/b"],
    ["file:///srv/repo.git", undefined],
    ["/srv/repo.git", undefined],
    ["../relative/repo", undefined],
    ["C:\\repos\\x", undefined],
  ])("%s -> %s", (url, expected) => {
    expect(normalizeRemote(url)).toBe(expected);
  });
});

describe("parseOriginUrl", () => {
  it("reads only the origin remote", () => {
    const config = `[remote "upstream"]\n  url = https://a/x\n[remote "origin"] # c\n  fetch = x\n  URL = "git@b:c/d.git" ; comment\n[branch "main"]\n  url = nope\n`;
    expect(parseOriginUrl(config)).toBe("git@b:c/d.git");
    expect(parseOriginUrl("[core]\n")).toBeUndefined();
  });
});

describe("identifyProject", () => {
  it("classifies a company repository by remote from a nested cwd", () => {
    const root = dir("company");
    gitRepo(root, "git@git.acme.example:team/app.git");
    const nested = join(root, "src", "deep");
    mkdirSync(nested, { recursive: true });
    const identity = identifyProject(nested, trust);
    expect(identity).toEqual({
      root: posix(root),
      remote: "git.acme.example/team/app",
      origin: "company",
      matchedBy: { remote: "git.acme.example/**" },
    });
  });
  it("requires both the remote and the path when a matcher has both", () => {
    const both: ProjectTrustPolicy = {
      ...trust,
      company: {
        ...trust.company,
        match: [
          { remote: "git.acme.example/**", path: `${posix(base)}/*-managed` },
        ],
      },
    };
    const managed = dir("managed");
    gitRepo(managed, "https://git.acme.example/team/app.git");
    expect(identifyProject(managed, both).origin).toBe("company");
    // A spoofed origin remote outside the managed path is not company.
    const spoofed = dir("spoofed");
    gitRepo(spoofed, "https://git.acme.example/team/app.git");
    expect(identifyProject(spoofed, both).origin).toBe("unknown");
    // The right path with another remote is not company either.
    const other = dir("other-managed");
    gitRepo(other, "https://elsewhere.example/team/app.git");
    expect(identifyProject(other, both).origin).toBe("unknown");
  });
  it("strips credentials from the remote", () => {
    const root = dir("creds");
    gitRepo(
      root,
      "https://bot:ghp_secretvalue123@git.acme.example/team/app.git",
    );
    const identity = identifyProject(root, trust);
    expect(identity.remote).toBe("git.acme.example/team/app");
    expect(JSON.stringify(identity)).not.toContain("secretvalue");
  });
  it("follows a .git file to a worktree gitdir and its common config", () => {
    const main = dir("main");
    gitRepo(main, "https://git.acme.example/team/app");
    const worktreeGit = join(main, ".git", "worktrees", "wt");
    write(join(worktreeGit, "commondir"), "../..\n");
    const worktree = dir("worktree");
    write(join(worktree, ".git"), `gitdir: ${worktreeGit}\n`);
    expect(identifyProject(worktree, trust)).toMatchObject({
      root: posix(worktree),
      origin: "company",
    });
  });
  it("follows a relative .git file (submodule layout)", () => {
    const parent = dir("parent");
    gitRepo(parent);
    const moduleGit = join(parent, ".git", "modules", "lib");
    write(
      join(moduleGit, "config"),
      `[remote "origin"]\n\turl = https://elsewhere.example/lib.git\n`,
    );
    const sub = join(parent, "lib");
    write(join(sub, ".git"), "gitdir: ../.git/modules/lib\n");
    expect(identifyProject(sub, trust)).toMatchObject({
      root: posix(sub),
      remote: "elsewhere.example/lib",
      origin: "unknown",
    });
  });
  it("classifies by path and falls back to unknown without git", () => {
    const vendor = dir("vendor-sdk");
    expect(identifyProject(vendor, trust)).toMatchObject({
      root: posix(vendor),
      origin: "external",
    });
    const plain = dir("plain");
    const identity = identifyProject(plain, trust);
    expect(identity).toEqual({ root: posix(plain), origin: "unknown" });
  });
  it("realpaths a symlinked cwd", () => {
    const root = dir("real");
    gitRepo(root, "https://git.acme.example/x/y");
    const link = join(base, `link-${counter}`);
    if (!trySymlink(root, link, "dir")) return;
    expect(identifyProject(link, trust).root).toBe(posix(root));
  });
});

describe("projectDimensionEffect", () => {
  it("applies resourceTrust.project before project trust", () => {
    const policy = makePolicy();
    expect(
      projectDimensionEffect(policy, { origin: "company" }, "skills"),
    ).toBe("allow");
    const denied = makePolicy({
      resourceTrust: { ...policy.resourceTrust, project: "deny" },
    });
    expect(
      projectDimensionEffect(denied, { origin: "company" }, "passiveContext"),
    ).toBe("deny");
    const allowed = makePolicy({
      resourceTrust: { ...policy.resourceTrust, project: "allow" },
    });
    expect(
      projectDimensionEffect(allowed, { origin: "unknown" }, "skills"),
    ).toBe("allow");
    expect(
      projectDimensionEffect(allowed, { origin: "unknown" }, "hooks"),
    ).toBe("deny");
  });
});

function byKind(
  candidates: readonly ProjectResourceCandidate[],
  relative: string,
) {
  return candidates.find((item) => item.path.endsWith(relative));
}

describe("discoverProjectResources", () => {
  const home = dir("home");
  const managed = makePolicy({ projectTrust: trust });

  it("discovers every candidate and decides each dimension", () => {
    const root = dir("full");
    gitRepo(root, "https://git.acme.example/team/full");
    for (const file of [
      "AGENTS.md",
      "AGENTS.override.md",
      "CLAUDE.md",
      ".pi/SYSTEM.md",
      ".pi/APPEND_SYSTEM.md",
      ".pi/prompts/a.md",
      ".pi/skills/s/SKILL.md",
      ".agents/skills/t/SKILL.md",
      ".pi/extensions/e/index.ts",
      ".pi/settings.json",
      ".pi/themes/t.json",
      ".pi/agents/a.md",
      ".mcp.json",
      ".piship/providers/p/index.ts",
      ".piship/policy.json",
    ])
      write(join(root, file), file.endsWith(".json") ? "{}" : "text\n");
    const identity = identifyProject(root, trust);
    const found = discoverProjectResources(identity, managed, {
      homeDir: home,
    });
    const summary = Object.fromEntries(
      found.map((item) => [
        item.path.slice(posix(root).length + 1),
        [item.dimension, item.effect],
      ]),
    );
    expect(summary).toEqual({
      "AGENTS.md": ["instructions", "allow"],
      "AGENTS.override.md": ["instructions", "allow"],
      "CLAUDE.md": ["instructions", "allow"],
      ".pi/SYSTEM.md": ["instructions", "allow"],
      ".pi/APPEND_SYSTEM.md": ["instructions", "allow"],
      ".pi/prompts": ["instructions", "allow"],
      ".pi/skills": ["skills", "allow"],
      ".agents/skills": ["skills", "allow"],
      ".pi/extensions": ["extensions", "deny"],
      ".pi/settings.json": ["hooks", "deny"],
      ".pi/themes": ["passiveContext", "allow"],
      ".pi/agents": ["agents", "deny"],
      ".mcp.json": ["mcp", "company-approved"],
      ".piship/providers": ["providers", "deny"],
      ".piship/policy.json": ["restrictions", "allow"],
    });
    expect(byKind(found, ".pi/extensions")?.reason).toBe(
      "company-approved admits only distribution-approved items",
    );
    expect(byKind(found, ".mcp.json")?.allowlistOnly).toBe(true);
  });

  it("denies a symlinked skills directory that points outside the root", () => {
    const outside = dir("outside-skills");
    write(join(outside, "evil", "SKILL.md"), "x");
    const root = dir("symlinked");
    gitRepo(root, "https://git.acme.example/team/sym");
    if (!trySymlink(outside, join(root, ".pi", "skills"), "dir")) return;
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    const skills = byKind(found, ".pi/skills");
    expect(skills).toMatchObject({
      effect: "deny",
      origin: "unknown",
      resolvedPath: posix(outside),
    });
    expect(skills?.reason).toContain("outside the project root");
  });

  it("re-evaluates an outside instruction link as unknown and never reads it", () => {
    const outside = dir("outside-instructions");
    write(join(outside, "AGENTS.md"), "@inside.md\n");
    write(join(outside, "inside.md"), "x");
    const root = dir("instr-link");
    if (
      !trySymlink(join(outside, "AGENTS.md"), join(root, "AGENTS.md"), "file")
    )
      return;
    const personal = makePolicy({}, "personal");
    const found = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      {
        homeDir: home,
      },
    );
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ origin: "unknown", effect: "ask" });
  });

  it("denies instruction imports that escape the root", () => {
    const root = dir("imports");
    gitRepo(root, "https://git.acme.example/team/imports");
    write(
      join(root, "AGENTS.md"),
      "# Rules\n@docs/style.md\n@../../etc/passwd\n@~/.ssh/id_ed25519\n@/etc/hosts\n@missing.md\n```\n@not/an/import.md\n```\nmail me @ home\n",
    );
    write(join(root, "docs", "style.md"), "@nested.md\n@style.md\n");
    write(join(root, "docs", "nested.md"), "x\n");
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    const imports = found.filter((item) => item.kind === "instruction-import");
    expect(imports.map((item) => [item.path, item.effect])).toEqual([
      ["docs/style.md", "allow"],
      ["nested.md", "allow"],
      ["style.md", "allow"],
      ["../../etc/passwd", "deny"],
      ["~/.ssh/id_ed25519", "deny"],
      ["/etc/hosts", "deny"],
      ["missing.md", "deny"],
    ]);
    const passwd = imports.find((item) => item.path === "../../etc/passwd");
    expect(passwd?.reason).toContain("outside the project root");
    expect(passwd?.importedFrom).toBe(`${posix(root)}/AGENTS.md`);
  });

  it("denies .pi/extensions in an unknown repository", () => {
    for (const mode of ["managed", "personal"] as const) {
      const root = dir(`unknown-${mode}`);
      gitRepo(root, "https://random.example/x/y.git");
      write(
        join(root, ".pi", "extensions", "x.ts"),
        "export default () => {}\n",
      );
      write(join(root, ".pi", "settings.json"), "{}");
      const policy = makePolicy({}, mode);
      const identity = identifyProject(root, policy.projectTrust);
      expect(identity.origin).toBe("unknown");
      const found = discoverProjectResources(identity, policy, {
        homeDir: home,
      });
      expect(byKind(found, ".pi/extensions")?.effect).toBe(
        mode === "managed" ? "deny" : "ask",
      );
      expect(byKind(found, ".pi/settings.json")?.effect).toBe("deny");
    }
  });

  it("treats the project restriction file as narrowing only", () => {
    const root = dir("restrict");
    write(
      join(root, ".piship", "policy.json"),
      JSON.stringify({
        rules: [
          { id: "p.allow-all", action: "*", resource: "**", effect: "allow" },
          {
            id: "p.no-push",
            action: "shell.execute",
            resource: "git push*",
            effect: "deny",
          },
        ],
      }),
    );
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    const parsed = readProjectRestrictions(found);
    expect(parsed.rules.map((item) => item.id)).toEqual(["p.no-push"]);
    expect(parsed.ignored.map((item) => item.rule.id)).toEqual(["p.allow-all"]);
  });

  it("does not read a restriction file that escapes the root", () => {
    const outside = dir("outside-policy");
    write(join(outside, "policy.json"), "not json");
    const root = dir("restrict-link");
    if (
      !trySymlink(
        join(outside, "policy.json"),
        join(root, ".piship", "policy.json"),
        "file",
      )
    )
      return;
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    expect(byKind(found, ".piship/policy.json")?.effect).toBe("deny");
    expect(readProjectRestrictions(found).rules).toEqual([]);
  });

  it("rejects an invalid restriction file", () => {
    const root = dir("restrict-bad");
    write(join(root, ".piship", "policy.json"), "{");
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    expect(() => readProjectRestrictions(found)).toThrow(PiShipError);
  });

  it("never admits a company-approved project extension", () => {
    const root = dir("company-ext");
    gitRepo(root, "git@git.acme.example:team/ext.git");
    write(join(root, ".pi", "extensions", "approved-looking", "index.ts"), "x");
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    expect(byKind(found, ".pi/extensions")).toMatchObject({
      effect: "deny",
      origin: "company",
      reason: "company-approved admits only distribution-approved items",
    });
  });

  it("reports a dangling link without following it for content", () => {
    const root = dir("dangling");
    if (
      !trySymlink(
        join(base, "nowhere", "ext"),
        join(root, ".pi", "extensions"),
        "dir",
      )
    )
      return;
    const found = discoverProjectResources(
      identifyProject(root, trust),
      managed,
      { homeDir: home },
    );
    expect(byKind(found, ".pi/extensions")).toMatchObject({ effect: "deny" });
  });

  it("parses import lines outside code fences only", () => {
    expect(
      parseInstructionImports("@a.md\n  @b/c.md  \n```\n@d\n```\ntext @e\n"),
    ).toEqual(["a.md", "b/c.md"]);
  });
});
