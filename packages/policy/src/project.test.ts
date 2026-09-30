import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { ProjectTrustPolicy } from "@piship/schema";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { makePolicy } from "./fixtures.test-helpers.js";
import { toPosixPath } from "./glob.js";
import {
  discoverProjectResources,
  identifyProject,
  normalizeRemote,
  parseConfigIncludes,
  parseHooksPaths,
  parseInstructionImports,
  parseOriginUrl,
  projectDimensionEffect,
  projectGitControlDirectories,
  projectGitControlFiles,
  projectGitControlUnverified,
  readProjectRestrictions,
  type ProjectResourceCandidate,
} from "./project.js";
import { defaultProjectTrust } from "./trust.js";

const base = realpathSync(
  mkdtempSync(join(tmpdir(), "piship-policy-project-")),
);
// The git control paths read the user's global git config through the home
// directory: every test gets an empty home of its own, so what a developer's
// real config sets never reaches an expectation.
const fakeHome = join(base, "home-of-the-test");
// The variables git reads its config from, which the tests set and clear.
const CONFIG_VARIABLES = [
  "HOME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "GIT_CONFIG_NOSYSTEM",
  "GIT_CONFIG_COUNT",
  ...Array.from({ length: 8 }, (_, index) => `GIT_CONFIG_KEY_${index}`),
  ...Array.from({ length: 8 }, (_, index) => `GIT_CONFIG_VALUE_${index}`),
];
const savedEnv = Object.fromEntries(
  CONFIG_VARIABLES.map((name) => [name, process.env[name]]),
);
beforeEach(() => {
  rmSync(fakeHome, { recursive: true, force: true });
  mkdirSync(fakeHome, { recursive: true });
  for (const name of CONFIG_VARIABLES) delete process.env[name];
  process.env.HOME = fakeHome;
  process.env.USERPROFILE = fakeHome;
  // Not the machine's /etc/gitconfig.
  process.env.GIT_CONFIG_NOSYSTEM = "1";
});
afterAll(() => {
  for (const [name, value] of Object.entries(savedEnv))
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  rmSync(base, { recursive: true, force: true });
});
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

describe("parseConfigIncludes", () => {
  it("reads include.path and includeIf.*.path, whatever the condition", () => {
    const config = [
      "[include]",
      "\tpath = ../.gitconfig",
      '[includeIf "gitdir:~/work/"]',
      '  PATH = "~/work.gitconfig" # work',
      '[includeIf "onbranch:main"] path = branch.cfg',
      '[include "sub"]',
      "\tpath = not-this",
      "[includeIf]",
      "\tpath = nor-this",
      "[core]",
      "\tpath = nor-this-either",
      "[include]",
      "\tpath =",
      "\tother = x",
    ].join("\n");
    expect(parseConfigIncludes(config)).toEqual([
      "../.gitconfig",
      "~/work.gitconfig",
      "branch.cfg",
    ]);
    expect(parseConfigIncludes("")).toEqual([]);
  });
});

describe("the global git config and included files", () => {
  const cfg = (text: string) => `${text}\n`;
  const hooks = (value: string) => cfg(`[core]\n\thooksPath = ${value}`);
  const dirs = (root: string) => projectGitControlDirectories(root);
  const files = (root: string) => projectGitControlFiles(root);
  const at = (root: string, ...parts: string[]) => posix(join(root, ...parts));

  it("protects a relative core.hooksPath set in ~/.gitconfig, which lands in every working tree", () => {
    write(join(fakeHome, ".gitconfig"), hooks(".githooks"));
    const root = dir("global-hooks");
    gitRepo(root);
    expect(dirs(root)).toContain(at(root, ".githooks"));
    // A relative value is taken from each project's root.
    const other = dir("global-hooks-other");
    gitRepo(other);
    expect(dirs(other)).toContain(at(other, ".githooks"));
  });

  it("reads $XDG_CONFIG_HOME/git/config, or ~/.config/git/config without it", () => {
    write(join(fakeHome, ".config", "git", "config"), hooks(".default-hooks"));
    const root = dir("xdg-hooks");
    gitRepo(root);
    expect(dirs(root)).toContain(at(root, ".default-hooks"));
    const xdg = dir("xdg");
    write(join(xdg, "git", "config"), hooks(".xdg-hooks"));
    process.env.XDG_CONFIG_HOME = xdg;
    expect(dirs(root)).toContain(at(root, ".xdg-hooks"));
    // Git reads the XDG file instead of the default one when it is set.
    expect(dirs(root)).not.toContain(at(root, ".default-hooks"));
  });

  it("reads no other file than the known ones: not a decoy beside them, not a variable git does not read", () => {
    write(join(fakeHome, ".gitconfig-decoy"), hooks(".decoy"));
    write(join(fakeHome, ".config", "git", "other"), hooks(".other"));
    const elsewhere = dir("elsewhere");
    write(join(elsewhere, "config"), hooks(".from-env"));
    const root = dir("no-other-config");
    gitRepo(root);
    // GIT_CONFIG is the old variable only `git config` itself reads.
    process.env.GIT_CONFIG = join(elsewhere, "config");
    try {
      const directories = dirs(root);
      for (const name of [".decoy", ".other", ".from-env"])
        expect(directories).not.toContain(at(root, name));
      expect(directories).toHaveLength(4);
    } finally {
      delete process.env.GIT_CONFIG;
    }
  });

  it("follows include and includeIf, from the including file's directory, and protects the files", () => {
    const root = dir("includes");
    write(
      join(root, ".git", "config"),
      cfg(
        [
          "[include]",
          "\tpath = ../.gitconfig-team",
          '[includeIf "gitdir:~/x/"]',
          "\tpath = extra/cfg",
        ].join("\n"),
      ),
    );
    write(
      join(root, ".gitconfig-team"),
      cfg("[include]\n\tpath = nested\n[core]\n\thooksPath = team-hooks"),
    );
    write(
      join(root, "nested"),
      cfg(
        "[core]\n\thooksPath = nested-hooks\n[include]\n\tpath = ~/from-home",
      ),
    );
    write(join(fakeHome, "from-home"), hooks("home-hooks"));
    const controlled = files(root);
    // The include in the working tree, the one it includes (relative to it),
    // one relative to .git/config that does not exist yet, one under ~/.
    expect(controlled).toEqual(
      expect.arrayContaining([
        at(root, ".gitconfig-team"),
        at(root, "nested"),
        at(root, ".git", "extra", "cfg"),
        at(fakeHome, "from-home"),
      ]),
    );
    expect(dirs(root)).toEqual(
      expect.arrayContaining([
        at(root, "team-hooks"),
        at(root, "nested-hooks"),
        at(root, "home-hooks"),
      ]),
    );
  });

  it("ends at an include cycle, and at the depth git itself allows", () => {
    const cycle = dir("include-cycle");
    write(join(cycle, ".git", "config"), cfg("[include]\n\tpath = ../a"));
    write(join(cycle, "a"), cfg("[include]\n\tpath = b"));
    write(
      join(cycle, "b"),
      `${cfg("[include]\n\tpath = a")}${hooks("b-hooks")}`,
    );
    expect(dirs(cycle)).toContain(at(cycle, "b-hooks"));
    expect(files(cycle)).toEqual(
      expect.arrayContaining([at(cycle, "a"), at(cycle, "b")]),
    );

    const chain = dir("include-chain");
    write(join(chain, ".git", "config"), cfg("[include]\n\tpath = ../c0"));
    for (let index = 0; index < 14; index++)
      write(
        join(chain, `c${index}`),
        `${cfg(`[include]\n\tpath = c${index + 1}`)}${hooks(`h${index}`)}`,
      );
    const directories = dirs(chain);
    // The config is the first level, c0 the second, and c9 the tenth.
    expect(directories).toContain(at(chain, "h9"));
    expect(directories).not.toContain(at(chain, "h10"));
  });

  it("protects a global config file, and what it includes, only where it lies inside the project", () => {
    const outside = dir("global-outside");
    write(
      join(fakeHome, ".gitconfig"),
      cfg(`[include]\n\tpath = ${posix(join(outside, "extra"))}`),
    );
    write(join(outside, "extra"), hooks("outside-hooks"));
    const root = dir("global-project");
    gitRepo(root);
    // Read for its hooksPath, but a file outside the project is not one the
    // project's sandbox writes, so it is not listed.
    expect(dirs(root)).toContain(at(root, "outside-hooks"));
    const listed = files(root);
    expect(listed).not.toContain(at(fakeHome, ".gitconfig"));
    expect(listed).not.toContain(at(outside, "extra"));

    // A project that holds the home directory holds the global config too.
    const home = dir("home-project");
    gitRepo(home);
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    write(
      join(home, ".gitconfig"),
      cfg("[include]\n\tpath = .gitconfig.local"),
    );
    expect(files(home)).toEqual(
      expect.arrayContaining([
        at(home, ".gitconfig"),
        at(home, ".gitconfig.local"),
      ]),
    );
  });
});

describe("system, GIT_CONFIG_GLOBAL, and environment config", () => {
  const cfg = (text: string) => `${text}\n`;
  const hooks = (value: string) => cfg(`[core]\n\thooksPath = ${value}`);
  const dirs = (root: string) => projectGitControlDirectories(root);
  const files = (root: string) => projectGitControlFiles(root);
  const at = (root: string, ...parts: string[]) => posix(join(root, ...parts));
  const repo = (name: string) => {
    const root = dir(name);
    gitRepo(root);
    return root;
  };
  const setting = (index: number, key: string, value: string) => {
    process.env[`GIT_CONFIG_KEY_${index}`] = key;
    process.env[`GIT_CONFIG_VALUE_${index}`] = value;
  };

  it("reads GIT_CONFIG_GLOBAL in place of ~/.gitconfig and the XDG file", () => {
    write(join(fakeHome, ".gitconfig"), hooks(".home-hooks"));
    write(join(fakeHome, ".config", "git", "config"), hooks(".xdg-hooks"));
    const elsewhere = dir("global-env");
    write(join(elsewhere, "gitconfig"), hooks(".env-hooks"));
    const root = repo("global-env-repo");
    expect(dirs(root)).toContain(at(root, ".home-hooks"));
    process.env.GIT_CONFIG_GLOBAL = join(elsewhere, "gitconfig");
    const directories = dirs(root);
    expect(directories).toContain(at(root, ".env-hooks"));
    expect(directories).not.toContain(at(root, ".home-hooks"));
    expect(directories).not.toContain(at(root, ".xdg-hooks"));
    // Set and empty, git reads no global file at all.
    process.env.GIT_CONFIG_GLOBAL = "";
    expect(dirs(root)).toHaveLength(4);
  });

  it("reads the system config from GIT_CONFIG_SYSTEM unless GIT_CONFIG_NOSYSTEM is true", () => {
    const elsewhere = dir("system");
    write(join(elsewhere, "gitconfig"), hooks(".system-hooks"));
    process.env.GIT_CONFIG_SYSTEM = join(elsewhere, "gitconfig");
    const root = repo("system-repo");
    const system = at(root, ".system-hooks");
    // The tests start with GIT_CONFIG_NOSYSTEM=1.
    expect(dirs(root)).not.toContain(system);
    // Only a clear "true" turns it off; an odd value never hides the file.
    for (const value of ["0", "false", "no", "off", "", "nonsense"]) {
      process.env.GIT_CONFIG_NOSYSTEM = value;
      expect(dirs(root), `NOSYSTEM=${value}`).toContain(system);
    }
    for (const value of ["1", "true", "yes", "on", "2", "TRUE"]) {
      process.env.GIT_CONFIG_NOSYSTEM = value;
      expect(dirs(root), `NOSYSTEM=${value}`).not.toContain(system);
    }
    delete process.env.GIT_CONFIG_NOSYSTEM;
    expect(dirs(root)).toContain(system);
  });

  it("takes core.hooksPath and include.path from GIT_CONFIG_COUNT settings", () => {
    const outside = dir("env-include");
    write(join(outside, "extra"), hooks("extra-hooks"));
    write(join(fakeHome, "from-env-home"), hooks("home-env-hooks"));
    const root = repo("env-repo");
    setting(0, "core.hooksPath", ".env-set-hooks");
    setting(1, "include.path", posix(join(outside, "extra")));
    setting(2, "includeIf.gitdir:~/x/.path", "~/from-env-home");
    // Git refuses a relative include from the environment.
    setting(3, "include.path", "relative-is-refused");
    setting(4, "core.editor", "vi");
    setting(5, "include.path", posix(join(root, ".gitconfig.env")));
    // No key or value at index 6: skipped.
    process.env.GIT_CONFIG_COUNT = "7";
    const directories = dirs(root);
    expect(directories).toEqual(
      expect.arrayContaining([
        at(root, ".env-set-hooks"),
        at(root, "extra-hooks"),
        at(root, "home-env-hooks"),
      ]),
    );
    const listed = files(root);
    // A file the environment includes is listed only inside the project.
    expect(listed).toContain(at(root, ".gitconfig.env"));
    expect(listed).not.toContain(at(outside, "extra"));
    expect(listed).not.toContain(at(root, "relative-is-refused"));
    expect(listed).not.toContain(at(process.cwd(), "relative-is-refused"));
    // A count that is not a number reads nothing.
    process.env.GIT_CONFIG_COUNT = "many";
    expect(dirs(root)).toHaveLength(4);
  });

  it("lists the config outside the project for sandboxed processes only, not for the file tools", () => {
    const outside = dir("sandbox-scope");
    write(
      join(fakeHome, ".gitconfig"),
      cfg(`[include]\n\tpath = ${posix(join(outside, "extra"))}`),
    );
    write(join(outside, "extra"), hooks("outside-hooks"));
    write(join(outside, "system"), hooks("system-hooks"));
    process.env.GIT_CONFIG_SYSTEM = join(outside, "system");
    delete process.env.GIT_CONFIG_NOSYSTEM;
    setting(0, "include.path", posix(join(outside, "from-env")));
    process.env.GIT_CONFIG_COUNT = "1";
    const root = repo("sandbox-scope-repo");
    // What the file tools refuse to write leaves the user's own git
    // configuration editable.
    const tools = files(root);
    for (const path of [
      at(fakeHome, ".gitconfig"),
      at(fakeHome, ".config", "git", "config"),
      at(outside, "extra"),
      at(outside, "system"),
      at(outside, "from-env"),
    ])
      expect(tools).not.toContain(path);
    // A sandboxed command must not plant a hooks path there either, when the
    // sandbox may write the directory that holds one.
    const sandbox = projectGitControlFiles(root, { scope: "sandbox" });
    expect(sandbox).toEqual(
      expect.arrayContaining([
        at(fakeHome, ".gitconfig"),
        at(fakeHome, ".config", "git", "config"),
        at(outside, "extra"),
        at(outside, "system"),
        at(outside, "from-env"),
        ...tools,
      ]),
    );
    // The default scope is the project's.
    expect(projectGitControlFiles(root, { scope: "project" })).toEqual(tools);
  });

  it("protects a GIT_CONFIG_GLOBAL or GIT_CONFIG_SYSTEM file only where it lies inside the project", () => {
    const root = repo("known-inside");
    const elsewhere = dir("known-outside");
    write(join(root, ".gitconfig-global"), hooks("global-hooks"));
    write(join(elsewhere, "system"), hooks("system-hooks"));
    process.env.GIT_CONFIG_GLOBAL = join(root, ".gitconfig-global");
    process.env.GIT_CONFIG_SYSTEM = join(elsewhere, "system");
    delete process.env.GIT_CONFIG_NOSYSTEM;
    const listed = files(root);
    expect(listed).toContain(at(root, ".gitconfig-global"));
    expect(listed).not.toContain(at(elsewhere, "system"));
    // Both are read for their hooks path all the same.
    expect(dirs(root)).toEqual(
      expect.arrayContaining([
        at(root, "global-hooks"),
        at(root, "system-hooks"),
      ]),
    );
  });
});

describe("the limit on what the git config lists, and the scan cache", () => {
  const cfg = (text: string) => `${text}\n`;
  const hooks = (value: string) => cfg(`[core]\n\thooksPath = ${value}`);
  const dirs = (root: string) => projectGitControlDirectories(root);
  const files = (root: string) => projectGitControlFiles(root);
  const at = (root: string, ...parts: string[]) => posix(join(root, ...parts));
  const repo = (name: string) => {
    const root = dir(name);
    gitRepo(root);
    return root;
  };
  const lines = (count: number, make: (index: number) => string) =>
    Array.from({ length: count }, (_, index) => make(index)).join("\n");

  it("follows the first 64 includes of a config that lists thousands, and reports git control unverified", () => {
    const root = repo("many-includes");
    write(
      join(root, ".git", "config"),
      cfg(lines(5000, (index) => `[include]\n\tpath = extra-${index}`)),
    );
    const listed = files(root);
    // The base set and 64 includes, not 5000.
    expect(listed.length).toBeLessThan(80);
    expect(listed).toContain(at(root, ".git", "extra-0"));
    expect(listed).toContain(at(root, ".git", "extra-63"));
    expect(listed).not.toContain(at(root, ".git", "extra-64"));
    expect(projectGitControlUnverified(root)).toMatch(
      /more than 64 included files, hooks paths, or environment settings/,
    );
  });

  it("counts every include entry, however many of them name one file", () => {
    const root = repo("same-include");
    write(
      join(root, ".git", "config"),
      cfg(lines(5000, () => "[include]\n\tpath = same")),
    );
    expect(files(root).length).toBeLessThan(80);
    expect(projectGitControlUnverified(root)).toBeDefined();
  });

  it("follows the first 64 hooks paths, and 64 settings, and reports git control unverified", () => {
    const root = repo("many-hooks");
    write(
      join(root, ".git", "config"),
      cfg(`[core]\n${lines(5000, (index) => `\thooksPath = h${index}`)}`),
    );
    const directories = dirs(root);
    expect(directories.length).toBeLessThan(80);
    expect(directories).toContain(at(root, "h63"));
    expect(directories).not.toContain(at(root, "h64"));
    expect(projectGitControlUnverified(root)).toBeDefined();

    const settings = repo("many-settings");
    process.env.GIT_CONFIG_COUNT = "100000";
    expect(projectGitControlUnverified(settings)).toBeDefined();
  });

  it("reports a config file over 1 MiB, which is not read, as unverified", () => {
    const root = repo("huge-config");
    write(
      join(root, ".git", "config"),
      cfg(lines(60_000, (index) => `[include]\n\tpath = extra-${index}`)),
    );
    expect(statSync(join(root, ".git", "config")).size).toBeGreaterThan(
      1024 * 1024,
    );
    expect(files(root).length).toBeLessThan(80);
    expect(projectGitControlUnverified(root)).toMatch(/larger than 1 MiB/);
  });

  it("does not report an ordinary config, includes and all, as unverified", () => {
    const root = repo("ordinary");
    write(
      join(root, ".git", "config"),
      cfg("[include]\n\tpath = ../.gitconfig"),
    );
    write(join(root, ".gitconfig"), hooks(".githooks"));
    expect(projectGitControlUnverified(root)).toBeUndefined();
  });

  describe("cache", () => {
    // A whole second in the past, so the time reads back exactly and a
    // rewrite can put it back.
    const T = new Date(Math.floor(Date.now() / 1000) * 1000 - 60_000);
    const stamp = (path: string, time = T) => utimesSync(path, time, time);

    it("reuses a scan while nothing it read changed, and sees a change at the next access", () => {
      const root = repo("cache");
      const config = join(root, ".git", "config");
      write(config, hooks("aaaa"));
      stamp(config);
      expect(dirs(root)).toContain(at(root, "aaaa"));
      // Same size, time, and inode: the scan is not repeated, so this is not seen.
      writeFileSync(config, hooks("bbbb"));
      stamp(config);
      expect(dirs(root)).toContain(at(root, "aaaa"));
      expect(dirs(root)).not.toContain(at(root, "bbbb"));
      // A new modification time is a change.
      stamp(config, new Date(T.getTime() + 5000));
      expect(dirs(root)).toContain(at(root, "bbbb"));
      expect(dirs(root)).not.toContain(at(root, "aaaa"));
    });

    it("sees a replaced file and a size change, though the time is kept", () => {
      const root = repo("cache-replaced");
      const config = join(root, ".git", "config");
      write(config, hooks("aaaa"));
      stamp(config);
      expect(dirs(root)).toContain(at(root, "aaaa"));
      // A new file under the old name and time: another inode.
      write(`${config}.new`, hooks("cccc"));
      stamp(`${config}.new`);
      renameSync(`${config}.new`, config);
      expect(dirs(root)).toContain(at(root, "cccc"));
      // The same file, longer.
      writeFileSync(config, hooks("dddddd"));
      stamp(config);
      expect(dirs(root)).toContain(at(root, "dddddd"));
    });

    it("sees an include created after the scan that found it missing", () => {
      const root = repo("cache-include");
      write(join(root, ".git", "config"), cfg("[include]\n\tpath = later"));
      expect(dirs(root)).toHaveLength(4);
      write(join(root, ".git", "later"), hooks("created-hooks"));
      expect(dirs(root)).toContain(at(root, "created-hooks"));
    });

    it("scans again after ten seconds, even when no file looks changed", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
        const root = repo("cache-age");
        const config = join(root, ".git", "config");
        write(config, hooks("aaaa"));
        stamp(config);
        expect(dirs(root)).toContain(at(root, "aaaa"));
        writeFileSync(config, hooks("bbbb"));
        stamp(config);
        vi.setSystemTime(new Date("2026-01-01T00:00:09Z"));
        expect(dirs(root)).toContain(at(root, "aaaa"));
        vi.setSystemTime(new Date("2026-01-01T00:00:11Z"));
        expect(dirs(root)).toContain(at(root, "bbbb"));
      } finally {
        vi.useRealTimers();
      }
    });

    it("scans again when the environment changes", () => {
      const root = repo("cache-env");
      write(join(fakeHome, ".gitconfig"), hooks(".home-hooks"));
      expect(dirs(root)).toContain(at(root, ".home-hooks"));
      const elsewhere = dir("cache-env-global");
      write(join(elsewhere, "gitconfig"), hooks(".env-hooks"));
      process.env.GIT_CONFIG_GLOBAL = join(elsewhere, "gitconfig");
      expect(dirs(root)).toContain(at(root, ".env-hooks"));
      expect(dirs(root)).not.toContain(at(root, ".home-hooks"));
    });
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
