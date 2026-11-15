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

/** The checkpoint a sandbox would leave: edit a.txt and add b.txt in a clone. */
function checkpoint(extra = "", protectedPaths?: string[]): void {
  const clone = join(temp, "clone");
  git(temp, "clone", "-q", repo, clone);
  writeFileSync(join(clone, "a.txt"), "one\nthree\n");
  writeFileSync(join(clone, "b.txt"), "new\n");
  git(clone, "add", "-A");
  const patch = Buffer.concat([
    git(clone, "diff", "--cached", "--binary", "HEAD"),
    Buffer.from(extra),
  ]);
  writeRemoteWorkspaceCheckpoint(state, repo, patch, {
    session: "s",
    baseHead: null,
    files: 2,
    ...(protectedPaths ? { protectedPaths } : {}),
  });
}

describe("sandbox pull", () => {
  it("says so when nothing is stored", async () => {
    await runSandbox(ctx, ["pull", "--yes"]);
    expect(out.join("\n")).toMatch("No sandbox changes are waiting");
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
    checkpoint(
      "diff --git a/.git/config b/.git/config\nnew file mode 100644\n--- /dev/null\n+++ b/.git/config\n@@ -0,0 +1 @@\n+x\n",
    );
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /refused as a whole/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
    expect(existsSync(join(repo, "b.txt"))).toBe(false);
  });

  it("refuses a change to a protected path the checkpoint names", async () => {
    checkpoint("", ["b.txt"]);
    await expect(runSandbox(ctx, ["pull", "--yes"])).rejects.toThrow(
      /protected path/,
    );
    expect(readFileSync(join(repo, "a.txt"), "utf8")).toBe("one\ntwo\n");
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
});
