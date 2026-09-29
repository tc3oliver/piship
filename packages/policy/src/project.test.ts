import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
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
  parseHooksPaths,
  parseInstructionImports,
  parseOriginUrl,
  projectDimensionEffect,
  projectGitControlDirectories,
  projectGitControlFiles,
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

describe("project git control paths", () => {
  it("lists the config files and the hooks and info trees of a repository", () => {
    const root = dir("control");
    gitRepo(root, "https://git.acme.example/team/app");
    const git = posix(join(root, ".git"));
    expect(projectGitControlFiles(root)).toEqual([
      git,
      `${git}/config`,
      `${git}/config.worktree`,
      `${git}/commondir`,
    ]);
    expect(projectGitControlDirectories(root)).toEqual([
      `${git}/hooks`,
      `${git}/info`,
      `${git}/modules`,
      `${git}/worktrees`,
    ]);
  });
  it("covers the worktree gitdir and the shared directory it names", () => {
    const main = dir("control-main");
    gitRepo(main, "https://git.acme.example/team/app");
    const worktreeGit = join(main, ".git", "worktrees", "wt");
    write(join(worktreeGit, "commondir"), "../..\n");
    const worktree = dir("control-worktree");
    write(join(worktree, ".git"), `gitdir: ${worktreeGit}\n`);
    const common = posix(join(main, ".git"));
    const own = posix(worktreeGit);
    expect(projectGitControlFiles(worktree)).toEqual(
      expect.arrayContaining([
        posix(join(worktree, ".git")),
        `${own}/config`,
        `${own}/config.worktree`,
        `${own}/commondir`,
        `${common}/config`,
      ]),
    );
    const trees = (base: string) =>
      ["hooks", "info", "modules", "worktrees"].map(
        (name) => `${base}/${name}`,
      );
    expect(projectGitControlDirectories(worktree)).toEqual([
      ...trees(posix(join(worktree, ".git"))),
      ...trees(own),
      ...trees(common),
    ]);
  });
  it("still names the .git trees of a directory that is not a repository yet", () => {
    const plain = dir("control-plain");
    const git = posix(join(plain, ".git"));
    expect(projectGitControlDirectories(plain)).toEqual([
      `${git}/hooks`,
      `${git}/info`,
      `${git}/modules`,
      `${git}/worktrees`,
    ]);
  });
  it("protects the submodule git directories and the linked-worktree metadata as whole trees", () => {
    const root = dir("control-trees");
    gitRepo(root);
    const git = posix(join(root, ".git"));
    const directories = projectGitControlDirectories(root);
    // A submodule's config, hooks, and info, and a worktree's commondir,
    // gitdir, and config.worktree, are all below one of these.
    expect(directories).toEqual(
      expect.arrayContaining([`${git}/modules`, `${git}/worktrees`]),
    );
  });
  it("covers the git directory a submodule checkout points to", () => {
    const parent = dir("control-parent");
    gitRepo(parent);
    const moduleGit = join(parent, ".git", "modules", "lib");
    write(join(moduleGit, "config"), "[core]\n");
    const sub = join(parent, "lib");
    write(join(sub, ".git"), "gitdir: ../.git/modules/lib\n");
    const module = posix(moduleGit);
    expect(projectGitControlFiles(sub)).toEqual(
      expect.arrayContaining([
        posix(join(sub, ".git")),
        `${module}/config`,
        `${module}/config.worktree`,
        `${module}/commondir`,
      ]),
    );
    expect(projectGitControlDirectories(sub)).toEqual(
      expect.arrayContaining([
        `${module}/hooks`,
        `${module}/info`,
        `${module}/modules`,
        `${module}/worktrees`,
      ]),
    );
  });
});

describe("parseHooksPaths", () => {
  it("reads core.hooksPath in any spelling and skips other sections", () => {
    const config = [
      "[core]",
      "\tbare = false",
      "\tHooksPath = .husky/_ # husky",
      "[alias]",
      "\thooksPath = not-this",
      '[core "sub"]',
      "\thooksPath = nor-this",
      '[core] hookspath = "quoted dir"',
      "[CORE]",
      "  ; a comment",
      "  hooksPath=/abs/hooks",
      "  hooksPath =",
      '[remote "origin"]',
      "\turl = https://example.test/x.git",
    ].join("\n");
    expect(parseHooksPaths(config)).toEqual([
      ".husky/_",
      "quoted dir",
      "/abs/hooks",
    ]);
    expect(parseHooksPaths("[core]\n\tbare = false\n")).toEqual([]);
    expect(parseHooksPaths("")).toEqual([]);
  });
});

describe("core.hooksPath", () => {
  function repoWithHooksPath(value: string, section = "config"): string {
    const root = dir("hooks-path");
    write(join(root, ".git", section), `[core]\n\thooksPath = ${value}\n`);
    if (section !== "config") gitRepo(root);
    return root;
  }
  const base = (root: string) => posix(join(root, ".git"));

  it("protects a hooks directory in the working tree, as husky sets it up", () => {
    const root = repoWithHooksPath(".husky/_");
    expect(projectGitControlDirectories(root)).toContain(
      posix(join(root, ".husky", "_")),
    );
    // The config that names it is protected too, so it cannot be repointed.
    expect(projectGitControlFiles(root)).toContain(`${base(root)}/config`);
  });

  it("protects an absolute directory, one outside the project, and one under the home directory", () => {
    const outside = dir("shared-hooks");
    const root = repoWithHooksPath(posix(outside));
    expect(projectGitControlDirectories(root)).toContain(posix(outside));
    const relative = repoWithHooksPath("../shared-hooks-rel");
    expect(projectGitControlDirectories(relative)).toContain(
      posix(join(relative, "..", "shared-hooks-rel")),
    );
    const unique = `piship-hooks-test-${process.pid}-${counter}`;
    const home = repoWithHooksPath(`~/${unique}/hooks`);
    expect(projectGitControlDirectories(home)).toContain(
      posix(join(realpathSync(homedir()), unique, "hooks")),
    );
  });

  it("reads it from config.worktree and from the shared config of a worktree", () => {
    const root = repoWithHooksPath("wt-hooks", "config.worktree");
    expect(projectGitControlDirectories(root)).toContain(
      posix(join(root, "wt-hooks")),
    );
    const shared = dir("hooks-shared");
    const main = dir("hooks-main");
    write(
      join(main, ".git", "config"),
      `[core]\n\thooksPath = ${posix(shared)}\n`,
    );
    const worktreeGit = join(main, ".git", "worktrees", "wt");
    write(join(worktreeGit, "commondir"), "../..\n");
    const worktree = dir("hooks-worktree");
    write(join(worktree, ".git"), `gitdir: ${worktreeGit}\n`);
    expect(projectGitControlDirectories(worktree)).toContain(posix(shared));
  });

  it("protects every value when a later line overrides an earlier one", () => {
    const root = dir("hooks-override");
    write(
      join(root, ".git", "config"),
      "[core]\n\thooksPath = first\n\thooksPath = second\n",
    );
    const directories = projectGitControlDirectories(root);
    expect(directories).toContain(posix(join(root, "first")));
    expect(directories).toContain(posix(join(root, "second")));
  });

  it("leaves out a path that holds the project root, which would make it all read-only", () => {
    for (const value of [".", "..", "./", "../.."]) {
      const root = repoWithHooksPath(value);
      const directories = projectGitControlDirectories(root);
      expect(directories).not.toContain(posix(root));
      expect(directories).not.toContain(posix(dirname(root)));
      // The four .git trees are still there.
      expect(directories).toHaveLength(4);
    }
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

  it("denies a skills directory with a nested link that points outside the root", () => {
    const outside = dir("outside-nested");
    write(join(outside, "SKILL.md"), "x");
    const root = dir("nested-link");
    const personal = makePolicy({}, "personal");
    write(join(root, ".pi", "skills", "good", "SKILL.md"), "x");
    const clean = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      { homeDir: home },
    );
    expect(byKind(clean, ".pi/skills")?.effect).not.toBe("deny");
    if (
      !trySymlink(
        outside,
        join(root, ".pi", "skills", "good", "deep", "evil"),
        "dir",
      )
    )
      return;
    const found = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      { homeDir: home },
    );
    const skills = byKind(found, ".pi/skills");
    expect(skills).toMatchObject({ effect: "deny", origin: "unknown" });
    expect(skills?.reason).toContain(
      "The directory contains a link that leaves the project root (.pi/skills/good/deep/evil)",
    );
  });

  it("evaluates a prompts directory with a nested outside link as unknown origin", () => {
    const outside = dir("outside-prompt");
    write(join(outside, "p.md"), "x");
    const root = dir("nested-prompt");
    gitRepo(root, "https://git.acme.example/team/prompts");
    write(join(root, ".pi", "prompts", "ok.md"), "x");
    if (
      !trySymlink(
        join(outside, "p.md"),
        join(root, ".pi", "prompts", "p.md"),
        "file",
      )
    )
      return;
    const personal = makePolicy({}, "personal");
    const found = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      { homeDir: home },
    );
    expect(byKind(found, ".pi/prompts")).toMatchObject({ origin: "unknown" });
  });

  it("follows nested links that stay inside the root and stops at cycles", () => {
    const root = dir("inner-links");
    const personal = makePolicy({}, "personal");
    write(join(root, "shared", "SKILL.md"), "x");
    write(join(root, ".pi", "skills", "a", "SKILL.md"), "x");
    if (
      !trySymlink(join(root, "shared"), join(root, ".pi", "skills", "s"), "dir")
    )
      return;
    trySymlink(
      join(root, ".pi", "skills"),
      join(root, "shared", "loop"),
      "dir",
    );
    const inside = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      { homeDir: home },
    );
    expect(byKind(inside, ".pi/skills")?.effect).not.toBe("deny");
    // A link that leaves the root behind an inside link is still found.
    trySymlink(dir("outside-behind"), join(root, "shared", "out"), "dir");
    const found = discoverProjectResources(
      identifyProject(root, personal.projectTrust),
      personal,
      { homeDir: home },
    );
    expect(byKind(found, ".pi/skills")).toMatchObject({ effect: "deny" });
  });

  it("does not trust a resource directory nested deeper than the walk limit", () => {
    const personal = makePolicy({}, "personal");
    const shallow = dir("walk-shallow");
    write(
      join(shallow, ".pi", "skills", ...Array(31).fill("d"), "SKILL.md"),
      "x",
    );
    expect(
      byKind(
        discoverProjectResources(
          identifyProject(shallow, personal.projectTrust),
          personal,
          { homeDir: home },
        ),
        ".pi/skills",
      )?.effect,
    ).not.toBe("deny");
    const deep = dir("walk-deep");
    write(join(deep, ".pi", "skills", ...Array(33).fill("d"), "SKILL.md"), "x");
    const skills = byKind(
      discoverProjectResources(
        identifyProject(deep, personal.projectTrust),
        personal,
        { homeDir: home },
      ),
      ".pi/skills",
    );
    expect(skills).toMatchObject({ effect: "deny", origin: "unknown" });
    expect(skills?.reason).toContain("nests deeper than 32 levels");
  });

  it("stops at a link cycle inside a resource directory", () => {
    const personal = makePolicy({}, "personal");
    const root = dir("walk-cycle");
    write(join(root, ".pi", "prompts", "a", "p.md"), "x");
    const discover = () =>
      byKind(
        discoverProjectResources(
          identifyProject(root, personal.projectTrust),
          personal,
          { homeDir: home },
        ),
        ".pi/prompts",
      );
    const clean = discover();
    if (
      !trySymlink(
        join(root, ".pi", "prompts"),
        join(root, ".pi", "prompts", "a", "up"),
        "dir",
      )
    )
      return;
    trySymlink(
      join(root, ".pi", "prompts", "a"),
      join(root, ".pi", "prompts", "a", "self"),
      "dir",
    );
    expect(discover()).toEqual(clean);
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
