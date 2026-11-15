// `<command> sandbox pull --branch`: the patch lands on a new branch in a new worktree.
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { runSandbox } from "./branded/sandbox.js";
import { shellArg } from "./invocation.js";
import {
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "./remote-workspace.js";

// Git for Windows turns LF into CRLF in the work tree by default; these tests compare bytes.
process.env.GIT_CONFIG_COUNT = "1";
process.env.GIT_CONFIG_KEY_0 = "core.autocrlf";
process.env.GIT_CONFIG_VALUE_0 = "false";

const answer = vi.hoisted(() => ({ value: "y" }));
vi.mock("node:readline", () => ({
  createInterface: () => ({
    once: () => {},
    question: (_q: string, cb: (a: string) => void) => cb(answer.value),
    close: () => {},
  }),
}));

let temp: string;
let repo: string;
let state: string;
let out: string[];
let ctx: BrandedContext;

// Commands in the output quote a path the shell would not take bare (a Windows path).
const git = (cwd: string, ...args: string[]) =>
  execFileSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
    { cwd },
  );
const worktrees = () =>
  git(repo, "worktree", "list", "--porcelain")
    .toString()
    .split("\n")
    .filter((l) => l.startsWith("worktree "));

beforeEach(() => {
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-pull-branch-")));
  repo = join(temp, "repo");
  state = join(temp, "state");
  mkdirSync(repo);
  mkdirSync(state);
  git(repo, "init", "-q");
  // CI runners have no global identity; the commit under test needs one.
  git(repo, "config", "user.name", "t");
  git(repo, "config", "user.email", "t@invalid");
  for (const f of ["a.txt", "c.txt", "d.txt"])
    writeFileSync(join(repo, f), "one\ntwo\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "base");
  out = [];
  ctx = {
    stateDir: state,
    metadata: { app: { command: "demo" } },
    out: (m: string) => out.push(m),
    err: () => {},
  } as unknown as BrandedContext;
  vi.spyOn(process, "cwd").mockReturnValue(repo);
  answer.value = "y";
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  rmSync(temp, { recursive: true, force: true });
});

/** A checkpoint that edits a.txt and adds b.txt; `seedEdit` makes it relative to an edit the host never committed. */
function checkpoint(
  options: {
    baseHead?: string | null;
    confirm?: string;
    seedEdit?: boolean;
  } = {},
): void {
  const clone = join(temp, "clone");
  git(temp, "clone", "-q", repo, clone);
  if (options.seedEdit) {
    writeFileSync(join(clone, "a.txt"), "uncommitted\ntwo\n");
    git(clone, "commit", "-qam", "seed");
  }
  writeFileSync(join(clone, "a.txt"), "one\nthree\n");
  writeFileSync(join(clone, "b.txt"), "new\n");
  git(clone, "add", "-A");
  writeRemoteWorkspaceCheckpoint(
    state,
    repo,
    git(clone, "diff", "--cached", "--binary", "HEAD"),
    {
      session: "sess1234-abcd",
      baseHead:
        options.baseHead === undefined
          ? git(repo, "rev-parse", "HEAD").toString().trim()
          : options.baseHead,
      files: 2,
      ...(options.confirm
        ? { pull: { confirm: options.confirm } as never }
        : {}),
    },
  );
}
const stored = () => existsSync(remoteWorkspacePaths(state, repo).patch);
const wt = () => join(temp, "repo-sandbox-sess1234");

describe("sandbox pull --branch", () => {
  it("commits on a new branch in a new worktree and leaves the checkout byte-identical", async () => {
    checkpoint();
    // The host moves on and has local work of every kind.
    writeFileSync(join(repo, "m.txt"), "later\n");
    git(repo, "add", "m.txt");
    git(repo, "commit", "-q", "-m", "later");
    writeFileSync(join(repo, "c.txt"), "edited\n");
    writeFileSync(join(repo, "d.txt"), "staged\n");
    git(repo, "add", "d.txt");
    writeFileSync(join(repo, "u.txt"), "untracked\n");
    const index = readFileSync(join(repo, ".git", "index"));
    const head = git(repo, "rev-parse", "HEAD").toString();

    await runSandbox(ctx, ["pull", "--branch", "--yes"]);

    expect(readFileSync(join(repo, ".git", "index")).equals(index)).toBe(true);
    expect(git(repo, "rev-parse", "HEAD").toString()).toBe(head);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
    expect(readFileSync(join(repo, "c.txt"), "utf8")).toBe("edited\n");
    expect(readFileSync(join(repo, "u.txt"), "utf8")).toBe("untracked\n");
    expect(existsSync(join(repo, "b.txt"))).toBe(false);

    expect(readFileSync(join(wt(), "a.txt"), "utf8")).toBe("one\nthree\n");
    expect(readFileSync(join(wt(), "b.txt"), "utf8")).toBe("new\n");
    expect(existsSync(join(wt(), "m.txt"))).toBe(false); // started from baseHead
    expect(git(wt(), "branch", "--show-current").toString().trim()).toBe(
      "sandbox/sess1234",
    );
    expect(git(wt(), "log", "-1", "--format=%s").toString().trim()).toBe(
      "sandbox: changes from session sess1234",
    );
    expect(git(wt(), "status", "--porcelain").toString()).toBe("");
    expect(stored()).toBe(false);
    const text = out.join("\n");
    expect(text).toContain(`Created branch sandbox/sess1234 in ${wt()}`);
    expect(text).toMatch("the commit the session started from");
    expect(text).toContain(`git -C ${shellArg(wt())} log -1`);
    expect(text).toContain("git merge sandbox/sess1234");
    expect(text).toContain(`git worktree remove ${shellArg(wt())}`);
  });

  it("takes a given name and says when it started from the current HEAD", async () => {
    checkpoint({ baseHead: "1".repeat(40) });
    await runSandbox(ctx, ["pull", "--branch", "try-it", "--yes"]);
    expect(out.join("\n")).toMatch(
      /your current HEAD .* \(the session's starting commit 1111111 is not in this repository\)/,
    );
    expect(existsSync(join(temp, "repo-sandbox-try-it", "b.txt"))).toBe(true);
    expect(git(repo, "branch", "--list", "try-it").toString()).toMatch(
      "try-it",
    );
  });

  it("refuses a name that exists, one git rejects, and a directory in the way, leaving nothing", async () => {
    checkpoint();
    git(repo, "branch", "taken");
    const failed = (name: string) =>
      runSandbox(ctx, ["pull", "--branch", name, "--yes"]).then(
        () => undefined,
        (error: Error & { userAction?: string }) => error,
      );
    expect((await failed("taken"))?.message).toMatch(/already exists/);
    expect((await failed("bad..name"))?.message).toMatch(
      /not a valid branch name/,
    );
    mkdirSync(join(temp, "repo-sandbox-free"));
    expect((await failed("free"))?.message).toMatch(/already exists/);
    expect(worktrees()).toHaveLength(1);
    expect(stored()).toBe(true);
  });

  const refused = (name: string) =>
    runSandbox(ctx, ["pull", "--branch", name, "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string }) => error,
    );

  it("never deletes the previous branch when the name is @{-1}, @{u}, or another expansion", async () => {
    checkpoint();
    const main = git(repo, "branch", "--show-current").toString().trim();
    git(repo, "checkout", "-q", "-b", "precious");
    writeFileSync(join(repo, "p.txt"), "unmerged\n");
    git(repo, "add", "p.txt");
    git(repo, "commit", "-q", "-m", "unmerged work");
    git(repo, "checkout", "-q", main);
    const refs = () => git(repo, "for-each-ref").toString();
    const before = refs();
    for (const name of ["@{-1}", "@{u}", "a@{b", "@"]) {
      const error = await refused(name);
      expect(error?.message, name).toMatch(/not a valid branch name/);
    }
    const long = await refused("n".repeat(300));
    expect(long?.message).toMatch(/not a valid branch name/);
    expect(refs()).toBe(before);
    expect(git(repo, "rev-parse", "precious").toString()).toBeTruthy();
    expect(worktrees()).toHaveLength(1);
    expect(stored()).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a dangling symlink at the worktree path and leaves it in place",
    async () => {
      checkpoint();
      symlinkSync(join(temp, "nowhere"), join(temp, "repo-sandbox-dang"));
      const error = await refused("dang");
      expect(error?.message).toMatch(/already exists/);
      expect(lstatSync(join(temp, "repo-sandbox-dang")).isSymbolicLink()).toBe(
        true,
      );
      expect(git(repo, "branch", "--list", "dang").toString()).toBe("");
      expect(stored()).toBe(true);
    },
  );

  it("removes nothing when git itself cannot create the worktree", async () => {
    checkpoint();
    git(repo, "branch", "sandbox/keep");
    // A stale lock on the new ref makes `worktree add -b` fail after every check passed.
    writeFileSync(join(repo, ".git", "refs", "heads", "sandbox", "x.lock"), "");
    const before = git(repo, "for-each-ref").toString();
    const error = await refused("sandbox/x");
    expect(error?.message).toMatch(/git could not create the worktree/);
    expect(git(repo, "for-each-ref").toString()).toBe(before);
    expect(worktrees()).toHaveLength(1);
    expect(existsSync(join(temp, "repo-sandbox-x"))).toBe(false);
    expect(stored()).toBe(true);
  });

  it("commits every file of the patch even when ignore rules match it", async () => {
    checkpoint();
    writeFileSync(join(repo, ".git", "info", "exclude"), "b.txt\n");
    await runSandbox(ctx, ["pull", "--branch", "--yes"]);
    expect(git(wt(), "ls-files").toString()).toMatch(/^b\.txt$/m);
    expect(git(wt(), "show", "--name-only", "--format=").toString()).toBe(
      "a.txt\nb.txt\n",
    );
    expect(git(wt(), "status", "--porcelain").toString()).toBe("");
    expect(out.join("\n")).toMatch(/Committed as/);
  });

  it.skipIf(process.platform === "win32")(
    "runs no repository hook in any step, post-index-change included",
    async () => {
      checkpoint();
      const marker = join(temp, "hook-ran");
      for (const hook of [
        "post-index-change",
        "pre-commit",
        "commit-msg",
        "post-commit",
        "post-checkout",
        "reference-transaction",
      ]) {
        const file = join(repo, ".git", "hooks", hook);
        writeFileSync(file, `#!/bin/sh\necho ${hook} >> '${marker}'\n`);
        chmodSync(file, 0o755);
      }
      await runSandbox(ctx, ["pull", "--branch", "--yes"]);
      expect(out.join("\n")).toMatch(/Committed as/);
      expect(existsSync(marker)).toBe(false);
    },
  );

  it("removes the worktree and branch when the patch does not fit baseHead, and keeps the patch", async () => {
    checkpoint({ seedEdit: true });
    const failed = await runSandbox(ctx, ["pull", "--branch", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string }) => error,
    );
    expect(failed?.message).toMatch(/does not fit a clean checkout/);
    expect(failed?.userAction).toMatch(/demo sandbox pull without --branch/);
    expect(failed?.userAction).toMatch(/demo sandbox pull --branch again/);
    expect(existsSync(wt())).toBe(false);
    expect(worktrees()).toHaveLength(1);
    expect(git(repo, "branch", "--list", "sandbox/*").toString()).toBe("");
    expect(stored()).toBe(true);
  });

  it("leaves the changes staged when git has no identity to commit with", async () => {
    checkpoint();
    git(repo, "config", "--unset", "user.name");
    git(repo, "config", "--unset", "user.email");
    git(repo, "config", "user.useConfigOnly", "true");
    vi.stubEnv("GIT_CONFIG_GLOBAL", "/dev/null");
    vi.stubEnv("GIT_CONFIG_SYSTEM", "/dev/null");
    vi.stubEnv("GIT_AUTHOR_NAME", "");
    vi.stubEnv("GIT_AUTHOR_EMAIL", "");
    vi.stubEnv("GIT_COMMITTER_NAME", "");
    vi.stubEnv("GIT_COMMITTER_EMAIL", "");
    await runSandbox(ctx, ["pull", "--branch", "--yes"]);
    expect(out.join("\n")).toMatch(/staged but not committed/);
    // The path is quoted for the shell, which differs per platform.
    expect(out.join("\n")).toMatch(/git -C \S*repo-sandbox-sess1234\S* commit/);
    expect(git(wt(), "diff", "--cached", "--name-only").toString()).toBe(
      "a.txt\nb.txt\n",
    );
    expect(stored()).toBe(false);
  });

  it("confirm: required refuses --yes and no terminal without leaving a worktree", async () => {
    checkpoint({ confirm: "required" });
    await expect(
      runSandbox(ctx, ["pull", "--branch", "--yes"]),
    ).rejects.toThrow(/requires an interactive review/);
    Object.defineProperty(process.stdin, "isTTY", {
      value: false,
      configurable: true,
    });
    await expect(runSandbox(ctx, ["pull", "--branch"])).rejects.toThrow(
      /no terminal/,
    );
    expect(worktrees()).toHaveLength(1);
    expect(existsSync(wt())).toBe(false);
    expect(stored()).toBe(true);
  });

  it("applies after a y at the prompt and removes everything after an n", async () => {
    checkpoint({ confirm: "required" });
    Object.defineProperty(process.stdin, "isTTY", {
      value: true,
      configurable: true,
    });
    answer.value = "n";
    await runSandbox(ctx, ["pull", "--branch"]);
    expect(out.join("\n")).toMatch(/new branch and worktree were removed/);
    expect(worktrees()).toHaveLength(1);
    expect(git(repo, "branch", "--list", "sandbox/*").toString()).toBe("");
    expect(stored()).toBe(true);
    answer.value = "y";
    await runSandbox(ctx, ["pull", "--branch"]);
    expect(existsSync(join(wt(), "b.txt"))).toBe(true);
    expect(stored()).toBe(false);
  });

  it("is a usage error with --discard, and --help lists the options", async () => {
    await expect(
      runSandbox(ctx, ["pull", "--discard", "--branch"]),
    ).rejects.toThrow(/cannot be combined/);
    await expect(runSandbox(ctx, ["pull", "--wat"])).rejects.toThrow(
      /--branch \[name\]/,
    );
    await runSandbox(ctx, ["pull", "--help"]);
    for (const flag of ["--diff", "--yes", "--branch [name]", "--discard"])
      expect(out.join("\n")).toContain(flag);
  });
});
