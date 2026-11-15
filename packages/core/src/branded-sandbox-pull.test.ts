// `<command> sandbox pull` against a real git work tree and real `git diff` output.
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BrandedContext } from "./branded/context.js";
import { runSandbox } from "./branded/sandbox.js";
import {
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "./remote-workspace.js";

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
    expect(out.join("\n")).toMatch("run sandbox pull --diff");
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
  });

  it("refuses without a terminal and without --yes, leaving the tree alone", async () => {
    checkpoint();
    Object.defineProperty(process.stdin, "isTTY", {
      value: false,
      configurable: true,
    });
    await expect(runSandbox(ctx, ["pull"])).rejects.toThrow(/no terminal/);
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

  it("matches glob characters in a protected path literally", async () => {
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
  });

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
    expect(failed?.message).toMatch(
      /applied with conflicts in 1 file\(s\): a\.txt/,
    );
    expect(failed?.message).toMatch(/other files are applied and staged/);
    expect(failed?.userAction).toMatch(/Do not run sandbox pull again/);
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toContain("<<<<<<<");
    expect(readFileSync(join(repo, "b.txt"), "utf8")).toBe("new\n");
    const paths = remoteWorkspacePaths(state, repo);
    expect(existsSync(paths.patch)).toBe(true);
    expect(existsSync(paths.applied)).toBe(false);
  });

  it("keeps the patch and says nothing was applied when git refuses it", async () => {
    checkpoint();
    writeFileSync(join(repo, "b.txt"), "in the way\n");
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /nothing was applied/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
    expect(existsSync(remoteWorkspacePaths(state, repo).patch)).toBe(true);
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
