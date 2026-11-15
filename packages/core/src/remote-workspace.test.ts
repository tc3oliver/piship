import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  validateRemoteWorkspacePatch,
  writeRemoteWorkspaceCheckpoint,
} from "./remote-workspace.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-rw-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

function git(cwd: string, ...args: string[]): Buffer {
  return execFileSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@invalid", ...args],
    { cwd },
  );
}

/** A repo with a baseline commit, then `change` applied, and the staged binary diff. */
function realDiff(change: (dir: string) => void): Buffer {
  const dir = join(temp, "repo");
  mkdirSync(dir);
  git(dir, "init", "-q");
  writeFileSync(join(dir, "a.txt"), "one\ntwo\n");
  writeFileSync(join(dir, "old name.txt"), "rename me\nrename me\nrename me\n");
  writeFileSync(join(dir, "bin.dat"), Buffer.from([0, 1, 2, 3]));
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "base");
  change(dir);
  git(dir, "add", "-A");
  return git(dir, "diff", "--cached", "--binary", "--no-renames", "HEAD");
}

/** A patch that is only refused for protected or .git paths is applied without them. */
const skipped = async (
  patch: string | Buffer,
  protectedPaths: string[] = [],
) => {
  const result = await validateRemoteWorkspacePatch(
    Buffer.from(patch),
    protectedPaths,
  );
  expect(result.refused).toEqual([]);
  expect(result.ok).toBe(true);
  return result;
};

const refusal = async (
  patch: string | Buffer,
  protectedPaths: string[] = [],
) => {
  const result = await validateRemoteWorkspacePatch(
    Buffer.from(patch),
    protectedPaths,
  );
  expect(result.ok).toBe(false);
  return result.refused.join("\n");
};

const newFile = (path: string, mode = "100644") =>
  `diff --git a/${path} b/${path}\nnew file mode ${mode}\nindex 0000000..e69de29\n--- /dev/null\n+++ b/${path}\n@@ -0,0 +1 @@\n+x\n`;

describe("validateRemoteWorkspacePatch", () => {
  it("accepts a benign multi-file patch with a binary, a new file and a rename as delete plus add", async () => {
    const patch = realDiff((dir) => {
      writeFileSync(join(dir, "a.txt"), "one\nthree\n");
      writeFileSync(join(dir, "bin.dat"), Buffer.from([9, 8, 7, 0, 255]));
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "src", "new file.ts"), "export {};\n");
      git(dir, "mv", "old name.txt", "renamed.txt");
    });
    const result = await validateRemoteWorkspacePatch(patch);
    expect(result).toMatchObject({ ok: true, refused: [] });
    expect(result.files.sort()).toEqual([
      "a.txt",
      "bin.dat",
      "old name.txt",
      "renamed.txt",
      "src/new file.ts",
    ]);
  });

  it("decodes a C-quoted path before checking it", async () => {
    const patch = realDiff((dir) => writeFileSync(join(dir, "ä.txt"), "x\n"));
    expect(patch.toString("latin1")).toContain('"a/\\303\\244.txt"');
    expect((await validateRemoteWorkspacePatch(patch)).files).toEqual([
      "ä.txt",
    ]);
    expect(
      (await skipped(newFile('".git/config"').replace(/"/g, ""))).skipped,
    ).toEqual([".git/config"]);
    const quoted = `diff --git "a/\\056git/hooks/pre-commit" "b/\\056git/hooks/pre-commit"\nnew file mode 100755\n--- /dev/null\n+++ "b/\\056git/hooks/pre-commit"\n@@ -0,0 +1 @@\n+x\n`;
    expect((await skipped(quoted)).skipped).toEqual([".git/hooks/pre-commit"]);
    expect(await refusal(quoted.replace(/056/g, "004"))).toMatch(
      /control|malformed|\.\.?/,
    );
  });

  it("refuses a real symlink", async () => {
    const patch = realDiff((dir) =>
      symlinkSync("/etc/passwd", join(dir, "ln")),
    );
    expect(await refusal(patch)).toMatch("120000");
  });

  it("refuses a gitlink", async () => {
    expect(await refusal(newFile("sub", "160000"))).toMatch("160000");
    const change = "diff --git a/x b/x\nold mode 100644\nnew mode 120000\n";
    expect(await refusal(change)).toMatch("120000");
  });

  it("refuses absolute, parent, backslash and control-character paths", async () => {
    expect(await refusal(newFile("/etc/passwd").replace("a//", "a/"))).toMatch(
      /absolute|empty/,
    );
    expect(await refusal(newFile("../escape"))).toMatch("'..' path segment");
    expect(await refusal(newFile("dir/../../escape"))).toMatch("'..'");
    expect(await refusal(newFile("a\\b"))).toMatch("backslash");
    expect(await refusal(newFile("C:evil"))).toMatch("absolute");
    expect(await refusal(newFile("bell\u0007"))).toMatch("control");
    const quoted = `diff --git "a/x\\nfoo" "b/x\\nfoo"\nnew file mode 100644\n--- /dev/null\n+++ "b/x\\nfoo"\n@@ -0,0 +1 @@\n+x\n`;
    expect(await refusal(quoted)).toMatch("control");
  });

  it("refuses .git in any case and in Windows aliases", async () => {
    for (const path of [
      ".git/config",
      ".GIT/hooks/x",
      "sub/.Git/x",
      "sub/.git",
      ".git./x",
      "GIT~1/x",
    ])
      expect((await skipped(newFile(path))).skipped).toEqual([path]);
  });

  it("refuses protected paths and everything below them", async () => {
    expect(
      (await skipped(newFile("hooks/pre-commit"), ["hooks"])).skipped,
    ).toEqual(["hooks/pre-commit"]);
    expect((await skipped(newFile(".Husky/x"), [".husky"])).skipped).toEqual([
      ".Husky/x",
    ]);
    expect((await skipped(newFile("config"), ["config"])).skipped).toEqual([
      "config",
    ]);
    expect(
      (
        await validateRemoteWorkspacePatch(Buffer.from(newFile("hooks2/x")), [
          "hooks",
        ])
      ).ok,
    ).toBe(true);
  });

  it("refuses every rename or copy header", async () => {
    const rename = (from: string, to: string, verb = "rename") =>
      `diff --git a/${from} b/${to}\nsimilarity index 100%\n${verb} from ${from}\n${verb} to ${to}\n`;
    for (const patch of [
      rename("a.txt", "b.txt"),
      rename("a.txt", ".git/config"),
      rename(".git/config", "a.txt"),
      rename("a.txt", "b.txt", "copy"),
      "diff --git a/a.txt b/b.txt\nrename old a.txt\nrename new b.txt\n",
    ])
      expect(await refusal(patch)).toMatch("rename or copy header");
  });

  it("refuses a --- name that differs from the +++ name", async () => {
    // Real git deletes .husky/pre-commit and writes README.md; numstat shows only README.md.
    const hunk = "@@ -1,2 +1,3 @@\n hook1\n hook2\n+added\n";
    const patch = `diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/.husky/pre-commit\n+++ b/README.md\n${hunk}`;
    expect(await refusal(patch)).toMatch("different files");
    expect(await refusal(patch, [".husky"])).toMatch("different files");
    const quoted = patch.replace(
      "a/.husky/pre-commit",
      '"a/.husky/pre-commit"',
    );
    expect(await refusal(quoted)).toMatch("different files");
    const same = patch.replace("a/.husky/pre-commit", "a/README.md");
    expect(
      (await validateRemoteWorkspacePatch(Buffer.from(same))).files,
    ).toEqual(["README.md"]);
  });

  it("refuses a ~N path segment (Windows 8.3 short names)", async () => {
    expect(await refusal(newFile("CLAUDE~1/settings.json"))).toMatch("~N");
    expect(await refusal(newFile("sub/HUSKY~12"))).toMatch("~N");
    expect(
      (await validateRemoteWorkspacePatch(Buffer.from(newFile("a~b/x")))).ok,
    ).toBe(true);
  });

  it("does not trust ---/+++ or the diff header alone", async () => {
    const patch = `diff --git a/ok.txt b/ok.txt\nindex 1..2 100644\n--- a/ok.txt\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n`;
    expect(await refusal(patch)).toMatch("different files");
    const hidden = `diff --git a/ok.txt b/ok.txt\nnew file mode 100644\n--- /dev/null\n+++ b/ok.txt\n@@ -0,0 +1 @@\n+x\n${newFile(".git/x")}`;
    const kept = await skipped(hidden);
    expect(kept.skipped).toEqual([".git/x"]);
    expect(kept.files).toEqual(["ok.txt"]);
    expect(
      await refusal("diff --git a/ok b/other\nnew file mode 100644\n"),
    ).toMatch("cannot read the patch");
  });

  it("refuses text that is not a git diff, and oversized patches", async () => {
    expect(await refusal("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")).toMatch(
      "git diff header",
    );
    expect(await refusal("diff --cc x\n")).toMatch("git diff header");
    expect(await refusal(Buffer.alloc(0))).toMatch("git diff header");
    const big = await validateRemoteWorkspacePatch(
      Buffer.from(newFile("a.txt")),
      [],
      { maxBytes: 10 },
    );
    expect(big.ok).toBe(false);
    expect(big.refused[0]).toMatch("larger than 10 bytes");
  });
});

describe("validateRemoteWorkspacePatch parses like git", () => {
  const valid = newFile("ok.txt");
  const plain =
    "--- /dev/null\n+++ b/.claude/settings.json\n@@ -0,0 +1 @@\n+x\n";

  it("refuses a plain diff appended after a finished hunk", async () => {
    expect(await refusal(valid + plain, [".claude"])).toMatch(
      "not a hunk or a header",
    );
    expect(await refusal(valid + plain)).toMatch("not a hunk or a header");
  });

  it("refuses any mode that is not exactly 100644 or 100755", async () => {
    expect(await refusal(newFile("a", "0120000"))).toMatch("0120000");
    expect(await refusal(newFile("a", "100644 "))).toMatch("not 100644");
    expect(await refusal(newFile("a", "100644\r"))).toMatch("not 100644");
    expect(await refusal(newFile("a", "100664"))).toMatch("not 100644");
    expect(
      await refusal(
        newFile("a").replace(
          "index 0000000..e69de29",
          "index 0000000..e69de29 120000",
        ),
      ),
    ).toMatch("120000");
    expect(
      (await validateRemoteWorkspacePatch(Buffer.from(newFile("a", "100755"))))
        .ok,
    ).toBe(true);
  });

  it("refuses unknown header lines, a lone ---, stray text and overlong hunks", async () => {
    expect(
      await refusal(valid.replace("index", "bogus header\nindex")),
    ).toMatch("unrecognized header");
    expect(await refusal("diff --git a/a b/a\n--- a/a\n")).toMatch(
      "without +++",
    );
    expect(await refusal(`${valid}stray\n`)).toMatch("not a hunk");
    expect(await refusal(valid.replace("+x\n", "+x\n+y\n"))).toMatch(
      /not a hunk|longer/,
    );
    expect(await refusal(valid.replace("+x\n", "x\n"))).toMatch(
      "inside a hunk",
    );
  });

  it("reads a hunk line that looks like a header as content, as git does", async () => {
    const content =
      "diff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n--- a/.git/config\n+++ b/.git/config\n";
    const result = await validateRemoteWorkspacePatch(Buffer.from(content));
    expect(result).toMatchObject({ ok: true, files: ["f"] });
  });
});

describe("remote workspace checkpoint", () => {
  it("stores atomically with private modes and reads back", async () => {
    const state = join(temp, "state");
    const root = join(temp, "project");
    mkdirSync(root);
    const patch = Buffer.from(newFile("a.txt"));
    const paths = writeRemoteWorkspaceCheckpoint(state, root, patch, {
      session: "s1",
      baseHead: null,
      files: 1,
    });
    expect(paths.dir).toBe(remoteWorkspacePaths(state, root).dir);
    expect(paths.projectKey).toMatch(/^[0-9a-f]{16}$/);
    if (process.platform !== "win32") {
      expect(statSync(paths.dir).mode & 0o777).toBe(0o700);
      expect(statSync(paths.patch).mode & 0o777).toBe(0o600);
      expect(statSync(paths.meta).mode & 0o777).toBe(0o600);
    }
    const read = readRemoteWorkspaceCheckpoint(state, root);
    expect(read?.patch.equals(patch)).toBe(true);
    expect(read?.meta).toMatchObject({
      version: 1,
      session: "s1",
      baseHead: null,
      files: 1,
    });
    expect(
      readRemoteWorkspaceCheckpoint(state, join(temp, "other")),
    ).toBeUndefined();
  });
});
