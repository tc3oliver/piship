// `<command> sandbox pull` against a real git work tree and real `git diff` output.
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  symlinkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { runSandbox } from "./branded/sandbox.js";
import {
  readRemoteWorkspacePulled,
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "./remote-workspace.js";

// Git for Windows turns LF into CRLF in the work tree by default; these tests compare bytes.
process.env.GIT_CONFIG_COUNT = "1";
process.env.GIT_CONFIG_KEY_0 = "core.autocrlf";
process.env.GIT_CONFIG_VALUE_0 = "false";

let temp: string;
let repo: string;
let state: string;
let out: string[];
let ctx: BrandedContext;

const git = (cwd: string, ...args: string[]) =>
  execFileSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
    { cwd },
  );

beforeEach(() => {
  temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-pull-")));
  repo = join(temp, "repo");
  state = join(temp, "state");
  mkdirSync(repo);
  mkdirSync(state);
  git(repo, "init", "-q");
  writeFileSync(join(repo, "a.txt"), "one\ntwo\n");
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
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(temp, { recursive: true, force: true });
});

/**
 * The checkpoint a sandbox would leave: edit a.txt and add b.txt in a clone, or
 * with `only` just add that one new file. `slot` is the state root it is stored in.
 */
function checkpoint(
  extra = "",
  protectedPaths?: string[],
  options: {
    slot?: string;
    session?: string;
    createdAt?: string;
    only?: string;
    commit?: string;
    pull?: { protectedFiles?: string; confirm?: string };
  } = {},
): void {
  const clone = join(temp, `clone-${options.session ?? "s"}`);
  git(temp, "clone", "-q", repo, clone);
  if (options.only) writeFileSync(join(clone, options.only), "new\n");
  else {
    writeFileSync(join(clone, "a.txt"), "one\nthree\n");
    writeFileSync(join(clone, "b.txt"), "new\n");
  }
  git(clone, "add", "-A");
  const patch = Buffer.concat([
    git(clone, "diff", "--cached", "--binary", "HEAD"),
    Buffer.from(extra),
  ]);
  writeRemoteWorkspaceCheckpoint(options.slot ?? state, repo, patch, {
    session: options.session ?? "s",
    baseHead: null,
    files: 2,
    ...(options.commit ? { checkpointCommit: options.commit } : {}),
    ...(options.createdAt ? { createdAt: options.createdAt } : {}),
    ...(protectedPaths ? { protectedPaths } : {}),
    ...(options.pull ? { pull: options.pull as never } : {}),
  });
}

const SYMLINK =
  "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+x\n\\ No newline at end of file\n";

const parkedSlot = (session: string) =>
  join(state, "sandbox-workspace-parked", session);
const park = (
  session: string,
  only: string,
  createdAt: string,
  extra = "",
  protectedPaths?: string[],
) =>
  checkpoint(extra, protectedPaths, {
    slot: parkedSlot(session),
    session,
    createdAt,
    only,
  });

describe("sandbox pull", () => {
  it("says so when nothing is stored", async () => {
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch("No sandbox changes are waiting");
  });

  it("shows the diff only with --diff", async () => {
    checkpoint();
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch("run demo sandbox pull --diff");
    expect(out.join("\n")).not.toContain("+three");
  });

  it("prints the full diff with --diff", async () => {
    checkpoint();
    await runSandbox(ctx, ["pull", "--diff", "--yes"]);
    expect(out.join("\n")).toContain("+three");
  });

  it("applies a validated patch with --yes, commits nothing, and archives it", async () => {
    checkpoint();
    const head = git(repo, "rev-parse", "HEAD").toString();
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\nthree\n");
    expect(readFileSync(join(repo, "b.txt"), "utf8")).toBe("new\n");
    expect(git(repo, "rev-parse", "HEAD").toString()).toBe(head);
    const paths = remoteWorkspacePaths(state, repo);
    expect(existsSync(paths.patch)).toBe(false);
    expect(readdirSync(paths.applied)).toHaveLength(2);
    // The plain apply touches the work tree only.
    expect(git(repo, "diff", "--cached", "--name-only").toString()).toBe("");
    expect(out.join("\n")).toMatch("nothing was staged or committed");
  });

  /** A modification of `file` (committed as `before` in a clone) the way a sandbox would send it. */
  function modification(file: string, before: string, after: string): Buffer {
    const clone = join(temp, `mod-${file}`);
    git(temp, "clone", "-q", repo, clone);
    writeFileSync(join(clone, file), before);
    git(clone, "add", "-A");
    git(clone, "commit", "-q", "--allow-empty", "-m", "seed");
    writeFileSync(join(clone, file), after);
    git(clone, "add", "-A");
    return git(clone, "diff", "--cached", "--binary", "HEAD");
  }
  const lines = (n: number, edits: Record<number, string> = {}) =>
    Array.from({ length: n }, (_, i) => edits[i + 1] ?? `line${i + 1}`)
      .join("\n")
      .concat("\n");
  const store = (patch: Buffer) =>
    writeRemoteWorkspaceCheckpoint(state, repo, patch, {
      session: "m",
      baseHead: null,
      files: 1,
    });

  it("keeps an unstaged host edit in the same file and stages nothing", async () => {
    writeFileSync(join(repo, "big.txt"), lines(40));
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "big");
    store(modification("big.txt", lines(40), lines(40, { 35: "SANDBOX" })));
    writeFileSync(join(repo, "big.txt"), lines(40, { 2: "MINE" }));
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(readFileSync(join(repo, "big.txt"), "utf8")).toBe(
      lines(40, { 2: "MINE", 35: "SANDBOX" }),
    );
    expect(git(repo, "diff", "--cached", "--name-only").toString()).toBe("");
    expect(out.join("\n")).toMatch("apply cleanly");
  });

  it("applies an edit to a seeded file that is untracked on the host", async () => {
    store(modification("seed.txt", "s1\ns2\n", "s1\nS2\n"));
    writeFileSync(join(repo, "seed.txt"), "s1\ns2\n");
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(readFileSync(join(repo, "seed.txt"), "utf8")).toBe("s1\nS2\n");
    expect(git(repo, "diff", "--cached", "--name-only").toString()).toBe("");
  });

  it("changes nothing and keeps the user's content when an unstaged edit overlaps", async () => {
    checkpoint();
    writeFileSync(join(repo, "a.txt"), "one\nmine\n");
    const failed = await runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string; code?: string }) => error,
    );
    expect(failed?.message).toMatch(/nothing was changed/);
    expect(failed?.userAction).toMatch(/demo sandbox pull again/);
    expect(failed?.userAction).toContain("latest.patch");
    expect(failed?.userAction).not.toMatch(/git apply --3way/);
    expect(failed).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\nmine\n");
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(true);
  });

  it("says before the prompt that a staged overlap will conflict", async () => {
    checkpoint();
    writeFileSync(join(repo, "a.txt"), "one\nmine\n");
    git(repo, "add", "a.txt");
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /conflicts/,
    );
    expect(out.join("\n")).toMatch(
      "needs a 3-way merge and will conflict in: a.txt",
    );
  });

  it("says when the branch moved since the session started", async () => {
    checkpoint();
    const clone = remoteWorkspacePaths(state, repo);
    const meta = JSON.parse(readFileSync(clone.meta, "utf8"));
    writeFileSync(
      clone.meta,
      JSON.stringify({ ...meta, baseHead: "abc1234deadbeef" }),
    );
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch(
      /Your branch has moved since the session started \(abc1234 -> [0-9a-f]{7}\)/,
    );
  });

  it("refuses with the stored patch path and a policy code", async () => {
    checkpoint(SYMLINK);
    const failed = await runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string }) => error,
    );
    expect(failed).toMatchObject({ code: "POLICY_DENIED" });
    expect(failed?.userAction).toContain("latest.patch");
  });

  it("refuses without a terminal and without --yes, leaving the tree alone", async () => {
    checkpoint();
    Object.defineProperty(process.stdin, "isTTY", {
      value: false,
      configurable: true,
    });
    await expect(runSandbox(ctx, ["pull"])).rejects.toMatchObject({
      message: expect.stringMatching(/no terminal/),
      userAction: "Review the changes, then run demo sandbox pull --yes",
    });
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
  });

  it("refuses the whole patch when one entry is bad, applying nothing", async () => {
    checkpoint(SYMLINK);
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /refused as a whole/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
  });

  it("skips a protected path the checkpoint names and applies the rest", async () => {
    checkpoint("", ["b.txt"]);
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch("Skipped 1 protected file: b.txt");
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\nthree\n");
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(false);
  });

  it("skips .git files in a mixed patch", async () => {
    checkpoint(
      "diff --git a/.git/config b/.git/config\nnew file mode 100644\n--- /dev/null\n+++ b/.git/config\n@@ -0,0 +1 @@\n+x\n",
    );
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(readFileSync(join(repo, "b.txt"), "utf8")).toBe("new\n");
    expect(out.join("\n")).toMatch("Skipped 1 protected file: .git/config");
  });

  // NTFS has no file names with ? or *.
  it.skipIf(process.platform === "win32")(
    "matches glob characters in a protected path literally",
    async () => {
      // Protecting "b[1].txt" must not skip "b1.txt", and "a*" style names must not widen.
      const clone = join(temp, "glob");
      git(temp, "clone", "-q", repo, clone);
      for (const name of [
        "b[1].txt",
        "b1.txt",
        "q?.txt",
        "qz.txt",
        "star*.txt",
        "starx.txt",
      ])
        writeFileSync(join(clone, name), "n\n");
      git(clone, "add", "-A");
      writeRemoteWorkspaceCheckpoint(
        state,
        repo,
        git(clone, "diff", "--cached", "--binary", "HEAD"),
        {
          session: "g",
          baseHead: null,
          files: 6,
          protectedPaths: ["b[1].txt", "q?.txt", "star*.txt"],
        },
      );
      await runSandbox(ctx, ["pull", "--yes"]);
      for (const name of ["b1.txt", "qz.txt", "starx.txt"])
        expect(existsSync(join(repo, name))).toBe(true);
      for (const name of ["b[1].txt", "q?.txt", "star*.txt"])
        expect(existsSync(join(repo, name))).toBe(false);
      expect(out.join("\n")).toMatch("Skipped 3 protected files");
    },
  );

  it("refuses a rename outright, applying nothing", async () => {
    writeRemoteWorkspaceCheckpoint(
      state,
      repo,
      Buffer.from(
        "diff --git a/a.txt b/prot.txt\nsimilarity index 100%\nrename from a.txt\nrename to prot.txt\n",
      ),
      { session: "r", baseHead: null, files: 1 },
    );
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /refused as a whole.*rename or copy header/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
  });

  it("refuses the whole patch with policy protectedFiles: refuse and names the files", async () => {
    checkpoint("", ["b.txt"], { pull: { protectedFiles: "refuse" } });
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /policy refuses a patch that touches protected files.*b\.txt/,
    );
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
  });

  it("an invalid pull policy value reads as the stricter setting", async () => {
    checkpoint("", ["b.txt"], { pull: { protectedFiles: "bogus" } });
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /policy refuses/,
    );
    checkpoint("", undefined, { session: "s2", pull: { confirm: "bogus" } });
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /interactive review/,
    );
  });

  it("confirm: required rejects --yes and without a terminal, and prompts otherwise", async () => {
    checkpoint("", undefined, { pull: { confirm: "required" } });
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /requires an interactive review/,
    );
    Object.defineProperty(process.stdin, "isTTY", {
      value: false,
      configurable: true,
    });
    await expect(runSandbox(ctx, ["pull"])).rejects.toThrow(/no terminal/);
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
  });

  it("--discard deletes the stored changes", async () => {
    checkpoint();
    await runSandbox(ctx, ["pull", "--discard"]);
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(false);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
  });

  it("rejects unknown flags and a project that is not a git tree", async () => {
    await expect(runSandbox(ctx, ["pull", "--force"])).rejects.toThrow(/Usage/);
    vi.spyOn(process, "cwd").mockReturnValue(temp);
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /git work tree/,
    );
  });

  it("reports a conflict as it is: markers in the tree, patch kept", async () => {
    checkpoint();
    writeFileSync(join(repo, "a.txt"), "one\nmine\n");
    git(repo, "add", "a.txt");
    const failed = await runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string }) => error,
    );
    expect(failed?.message).toMatch(/conflicts in 1 file: a\.txt/);
    expect(failed?.message).toMatch(/other files are applied and staged/);
    expect(failed?.userAction).toMatch(/will not apply it again/);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toContain("<<<<<<<");
    expect(readFileSync(join(repo, "b.txt"), "utf8")).toBe("new\n");
    const paths = remoteWorkspacePaths(state, repo);
    expect(existsSync(paths.patch)).toBe(true);
    expect(existsSync(paths.applied)).toBe(false);
  });

  it("refuses to apply a conflicted patch again, even after the merge is committed, until --discard", async () => {
    checkpoint();
    writeFileSync(join(repo, "a.txt"), "one\nmine\n");
    git(repo, "add", "a.txt");
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /conflicts in 1 file/,
    );
    writeFileSync(join(repo, "a.txt"), "one\nresolved\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "resolved");
    const again = await runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string }) => error,
    );
    expect(again?.message).toMatch(/already applied this patch with conflicts/);
    expect(again?.userAction).toMatch(/demo sandbox pull --discard/);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\nresolved\n");
    expect(git(repo, "status", "--porcelain").toString()).toBe("");
    // A newer session's patch in the same slot is not blocked by the old marker, and clears it.
    checkpoint("", undefined, { session: "s2", only: "n.txt" });
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(readFileSync(join(repo, "n.txt"), "utf8")).toBe("new\n");
    const paths = remoteWorkspacePaths(state, repo);
    expect(existsSync(paths.patch)).toBe(false);
    expect(existsSync(`${paths.patch}.conflicted`)).toBe(false);
  });

  it("does not quote git's per-file success lines in a failure that changed nothing", async () => {
    // a.txt's edit is relative to content the host never had; 0.txt is new and fits.
    const clone = join(temp, "clone-stale");
    git(temp, "clone", "-q", repo, clone);
    writeFileSync(join(clone, "a.txt"), "unseen\ntwo\n");
    git(clone, "commit", "-qam", "seed");
    writeFileSync(join(clone, "a.txt"), "unseen\nthree\n");
    writeFileSync(join(clone, "0.txt"), "new\n");
    git(clone, "add", "-A");
    writeRemoteWorkspaceCheckpoint(
      state,
      repo,
      git(clone, "diff", "--cached", "--binary", "HEAD"),
      { session: "stale", baseHead: null, files: 2 },
    );
    const failed = await runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error) => error,
    );
    expect(failed?.message).toMatch(/nothing was changed/);
    expect(failed?.message).toMatch(/a\.txt: patch does not apply/);
    expect(failed?.message).not.toMatch(/Applied patch to|Falling back/);
    expect(existsSync(join(repo, "0.txt"))).toBe(false);
  });

  it("keeps the patch and says nothing was applied when git refuses it", async () => {
    checkpoint();
    writeFileSync(join(repo, "b.txt"), "in the way\n");
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /nothing was changed/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(true);
  });

  /** A patch that edits a.txt, then creates each `created` path (all new, content "new"). */
  function editAndCreate(created: string[]): Buffer {
    const clone = join(temp, `ec-${Math.random().toString(16).slice(2)}`);
    git(temp, "clone", "-q", repo, clone);
    writeFileSync(join(clone, "a.txt"), "one\nthree\n");
    for (const name of created) {
      mkdirSync(dirname(join(clone, name)), { recursive: true });
      writeFileSync(join(clone, name), "new\n");
    }
    git(clone, "add", "-A");
    return git(clone, "diff", "--cached", "--binary", "HEAD");
  }
  const storeEc = (patch: Buffer) =>
    writeRemoteWorkspaceCheckpoint(state, repo, patch, {
      session: "ec",
      baseHead: null,
      files: 2,
    });
  const failure = async () =>
    runSandbox(ctx, ["pull", "--yes"]).then(
      () => undefined,
      (error: Error & { userAction?: string; code?: string }) => error,
    );

  describe("a write that cannot succeed", () => {
    it("refuses a new file whose path is an existing directory, before writing", async () => {
      storeEc(editAndCreate(["b.txt"]));
      mkdirSync(join(repo, "b.txt"));
      writeFileSync(join(repo, "b.txt", "keep"), "mine\n");
      const failed = await failure();
      expect(failed?.message).toMatch(/a directory with that name exists/);
      expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
      expect(readFileSync(join(repo, "b.txt", "keep"), "utf8")).toBe("mine\n");
    });

    it("refuses a new file below an existing file, before writing", async () => {
      storeEc(editAndCreate(["notes/x"]));
      writeFileSync(join(repo, "notes"), "a file\n");
      const failed = await failure();
      expect(failed?.message).toMatch(/exists on this machine as a file/);
      expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
      expect(readFileSync(join(repo, "notes"), "utf8")).toBe("a file\n");
    });

    it.skipIf(
      process.platform === "win32" ||
        (process.getuid !== undefined && process.getuid() === 0),
    )(
      "puts every file back when a later write fails, and says why",
      async () => {
        storeEc(editAndCreate(["sub/z.txt"]));
        mkdirSync(join(repo, "sub"));
        chmodSync(join(repo, "sub"), 0o555);
        try {
          const failed = await failure();
          expect(failed?.message).toMatch(/put back exactly as they were/);
          expect(failed?.message).toMatch(/z\.txt/);
          expect(failed?.message).not.toMatch(/Falling back/);
          expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
          expect(existsSync(join(repo, "sub", "z.txt"))).toBe(false);
          expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(
            true,
          );
        } finally {
          chmodSync(join(repo, "sub"), 0o755);
        }
      },
    );
  });

  describe("the listing before the prompt", () => {
    it("shows full paths, unicode as text, created files and mode changes", async () => {
      const long = `.github/workflows/${"very-long-name-".repeat(6)}checker.yml`;
      const clone = join(temp, "listing");
      git(temp, "clone", "-q", repo, clone);
      mkdirSync(join(clone, ".github", "workflows"), { recursive: true });
      writeFileSync(join(clone, long), "name: x\n");
      writeFileSync(join(clone, "ä.txt"), "x\n");
      writeFileSync(join(clone, "rtl\u202eexe.txt"), "x\n");
      if (process.platform !== "win32") chmodSync(join(clone, "a.txt"), 0o755);
      git(clone, "add", "-A");
      writeRemoteWorkspaceCheckpoint(
        state,
        repo,
        git(clone, "diff", "--cached", "--binary", "HEAD"),
        { session: "ls", baseHead: null, files: 4 },
      );
      await runSandbox(ctx, ["pull", "--yes"]);
      const text = out.join("\n");
      expect(text).toContain(`created  ${long}`);
      expect(text).toContain("ä.txt");
      expect(text).not.toContain("\u202e");
      expect(text).toContain("rtl?exe.txt");
      if (process.platform !== "win32")
        expect(text).toContain("(mode 100644 => 100755)");
    });

    it("caps the list at 50 files and says how to see the rest", async () => {
      storeEc(editAndCreate(Array.from({ length: 52 }, (_, i) => `f${i}.txt`)));
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(out.join("\n")).toMatch(
        /and 3 more; use demo sandbox pull --diff/,
      );
    });
  });

  it("names the unreadable record and lets --discard clear it", async () => {
    checkpoint();
    const paths = remoteWorkspacePaths(state, repo);
    writeFileSync(paths.meta, "{ not json");
    const failed = await failure();
    expect(failed?.message).toContain(paths.meta);
    expect(failed?.message).toMatch(/unreadable/);
    expect(failed?.userAction).toMatch(/demo sandbox pull --discard/);
    // The patch is the only copy: say where it is before offering --discard.
    expect(failed?.userAction).toContain(
      `copy ${paths.patch} somewhere safe first`,
    );
    await runSandbox(ctx, ["pull", "--discard"]);
    expect(existsSync(paths.patch)).toBe(false);
    expect(existsSync(paths.meta)).toBe(false);
  });

  describe("pulled marker", () => {
    const commit = "a".repeat(40);
    it("is left after a successful pull, naming the session's commit", async () => {
      checkpoint("", undefined, { commit });
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(readRemoteWorkspacePulled(state, repo, "s")).toBe(commit);
      expect(readRemoteWorkspacePulled(state, repo, "other")).toBeUndefined();
    });
    it("is not left by --discard or by a failed pull", async () => {
      checkpoint("", undefined, { commit });
      await runSandbox(ctx, ["pull", "--discard"]);
      expect(readRemoteWorkspacePulled(state, repo, "s")).toBeUndefined();
      checkpoint(SYMLINK, undefined, { commit, session: "s3" });
      await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow();
      expect(readRemoteWorkspacePulled(state, repo, "s3")).toBeUndefined();
    });
    it("ignores a damaged commit id in the checkpoint", async () => {
      checkpoint("", undefined, { commit: "not-hex" });
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(readRemoteWorkspacePulled(state, repo, "s")).toBeUndefined();
    });
  });

  describe.skipIf(process.platform === "win32")("host symlinks", () => {
    it("refuses a patch that retargets a tracked symlink", async () => {
      symlinkSync("t", join(repo, "link"));
      git(repo, "add", "-A");
      git(repo, "commit", "-q", "-m", "link");
      const patch = Buffer.from(
        "diff --git a/link b/link\n--- a/link\n+++ b/link\n@@ -1 +1 @@\n-t\n\\ No newline at end of file\n+/etc/hosts\n\\ No newline at end of file\n",
      );
      writeRemoteWorkspaceCheckpoint(state, repo, patch, {
        session: "l",
        baseHead: null,
        files: 1,
      });
      await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
        /never writes through or over a symlink/,
      );
      expect(readlinkSync(join(repo, "link"))).toBe("t");
    });

    it("refuses a new file below an untracked symlinked directory", async () => {
      const outside = join(temp, "outside");
      mkdirSync(outside);
      symlinkSync(outside, join(repo, "d"));
      const patch = Buffer.from(
        "diff --git a/d/x b/d/x\nnew file mode 100644\n--- /dev/null\n+++ b/d/x\n@@ -0,0 +1 @@\n+x\n",
      );
      writeRemoteWorkspaceCheckpoint(state, repo, patch, {
        session: "l",
        baseHead: null,
        files: 1,
      });
      await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
        /symbolic link/,
      );
      expect(existsSync(join(outside, "x"))).toBe(false);
    });
  });

  describe("parked patches", () => {
    it("pulls the oldest parked patch when the slot is empty, then counts the rest", async () => {
      park("late", "late.txt", "2026-01-02T00:00:00.000Z");
      park("early", "early.txt", "2026-01-01T00:00:00.000Z");
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(existsSync(join(repo, "early.txt"))).toBe(true);
      expect(existsSync(join(repo, "late.txt"))).toBe(false);
      expect(out.join("\n")).toMatch(
        "1 more sandbox patch is waiting; run demo sandbox pull again.",
      );
      expect(existsSync(parkedSlot("early"))).toBe(false);
      expect(
        readdirSync(remoteWorkspacePaths(state, repo).applied),
      ).toHaveLength(2);
      out.length = 0;
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(existsSync(join(repo, "late.txt"))).toBe(true);
      expect(out.join("\n")).not.toMatch("waiting");
      expect(existsSync(parkedSlot("late"))).toBe(false);
    });

    it("pulls the main slot first and counts the parked ones", async () => {
      checkpoint();
      park("p1", "p1.txt", "2026-01-01T00:00:00.000Z");
      park("p2", "p2.txt", "2026-01-02T00:00:00.000Z");
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(existsSync(join(repo, "b.txt"))).toBe(true);
      expect(existsSync(join(repo, "p1.txt"))).toBe(false);
      expect(out.join("\n")).toMatch("2 more sandbox patches are waiting");
    });

    it("--discard drops the patch that would have been pulled", async () => {
      park("late", "late.txt", "2026-01-02T00:00:00.000Z");
      park("early", "early.txt", "2026-01-01T00:00:00.000Z");
      await runSandbox(ctx, ["pull", "--discard"]);
      expect(existsSync(parkedSlot("early"))).toBe(false);
      expect(existsSync(parkedSlot("late"))).toBe(true);
      expect(existsSync(join(repo, "early.txt"))).toBe(false);
      expect(out.join("\n")).toMatch("1 more sandbox patch is waiting");
    });

    it("refuses a parked patch with the same validation and its own protected paths", async () => {
      park("bad", "early.txt", "2026-01-01T00:00:00.000Z", SYMLINK);
      await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
        /refused as a whole/,
      );
      expect(existsSync(join(repo, "early.txt"))).toBe(false);
      park("prot", "p.txt", "2026-01-03T00:00:00.000Z", "", ["p.txt"]);
      rmSync(parkedSlot("bad"), { recursive: true, force: true });
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(out.join("\n")).toMatch("Skipped 1 protected file: p.txt");
      expect(existsSync(join(repo, "p.txt"))).toBe(false);
    });

    it("keeps another project's parked patch when removing an emptied one", async () => {
      park("s1", "early.txt", "2026-01-01T00:00:00.000Z");
      const other = join(parkedSlot("s1"), "sandbox-workspace", "otherkey");
      mkdirSync(other, { recursive: true });
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(existsSync(join(repo, "early.txt"))).toBe(true);
      expect(existsSync(other)).toBe(true);
    });

    it("ignores a parked entry that is a file, not a session directory", async () => {
      mkdirSync(join(state, "sandbox-workspace-parked"), { recursive: true });
      writeFileSync(join(state, "sandbox-workspace-parked", "stray"), "x");
      await runSandbox(ctx, ["pull", "--yes"]);
      expect(out.join("\n")).toMatch("No sandbox changes are waiting");
    });
  });

  it("clears an empty stored patch so a parked one can follow", async () => {
    writeRemoteWorkspaceCheckpoint(state, repo, Buffer.alloc(0), {
      session: "s",
      baseHead: null,
      files: 0,
    });
    park("p", "p.txt", "2026-01-01T00:00:00.000Z");
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch("made no changes");
    expect(out.join("\n")).toMatch("1 more sandbox patch is waiting");
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(existsSync(join(repo, "p.txt"))).toBe(true);
  });
});
