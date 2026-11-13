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
  return git(dir, "diff", "--cached", "--binary", "HEAD");
}

const refusal = (patch: string | Buffer, protectedPaths: string[] = []) => {
  const result = validateRemoteWorkspacePatch(
    Buffer.from(patch),
    protectedPaths,
  );
  expect(result.ok).toBe(false);
  return result.refused.join("\n");
};

const newFile = (path: string, mode = "100644") =>
  `diff --git a/${path} b/${path}\nnew file mode ${mode}\nindex 0000000..e69de29\n--- /dev/null\n+++ b/${path}\n@@ -0,0 +1 @@\n+x\n`;

describe("validateRemoteWorkspacePatch", () => {
  it("accepts a benign multi-file patch with a binary, a new file and a rename", () => {
    const patch = realDiff((dir) => {
      writeFileSync(join(dir, "a.txt"), "one\nthree\n");
      writeFileSync(join(dir, "bin.dat"), Buffer.from([9, 8, 7, 0, 255]));
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "src", "new file.ts"), "export {};\n");
      git(dir, "mv", "old name.txt", "renamed.txt");
    });
    const result = validateRemoteWorkspacePatch(patch);
    expect(result).toMatchObject({ ok: true, refused: [] });
    expect(result.files.sort()).toEqual([
      "a.txt",
      "bin.dat",
      "old name.txt",
      "renamed.txt",
      "src/new file.ts",
    ]);
  });

  it("decodes a C-quoted path before checking it", () => {
    const patch = realDiff((dir) => writeFileSync(join(dir, "ä.txt"), "x\n"));
    expect(patch.toString("latin1")).toContain('"a/\\303\\244.txt"');
    expect(validateRemoteWorkspacePatch(patch).files).toEqual(["ä.txt"]);
    expect(refusal(newFile('".git/config"').replace(/"/g, ""))).toMatch(".git");
    const quoted = `diff --git "a/\\056git/hooks/pre-commit" "b/\\056git/hooks/pre-commit"\nnew file mode 100755\n--- /dev/null\n+++ "b/\\056git/hooks/pre-commit"\n@@ -0,0 +1 @@\n+x\n`;
    expect(refusal(quoted)).toMatch("touches .git");
    expect(refusal(quoted.replace(/056/g, "004"))).toMatch(
      /control|malformed|\.\.?/,
    );
  });

  it("refuses a real symlink", () => {
    const patch = realDiff((dir) =>
      symlinkSync("/etc/passwd", join(dir, "ln")),
    );
    expect(refusal(patch)).toMatch("mode 120000");
  });

  it("refuses a gitlink", () => {
    expect(refusal(newFile("sub", "160000"))).toMatch("mode 160000");
    const change = "diff --git a/x b/x\nold mode 100644\nnew mode 120000\n";
    expect(refusal(change)).toMatch("120000");
  });

  it("refuses absolute, parent, backslash and control-character paths", () => {
    expect(refusal(newFile("/etc/passwd").replace("a//", "a/"))).toMatch(
      /absolute|empty/,
    );
    expect(refusal(newFile("../escape"))).toMatch("'..' path segment");
    expect(refusal(newFile("dir/../../escape"))).toMatch("'..'");
    expect(refusal(newFile("a\\b"))).toMatch("backslash");
    expect(refusal(newFile("C:evil"))).toMatch("absolute");
    expect(refusal(newFile("bell\u0007"))).toMatch("control");
    const quoted = `diff --git "a/x\\nfoo" "b/x\\nfoo"\nnew file mode 100644\n--- /dev/null\n+++ "b/x\\nfoo"\n@@ -0,0 +1 @@\n+x\n`;
    expect(refusal(quoted)).toMatch("control");
  });

  it("refuses .git in any case and in Windows aliases", () => {
    for (const path of [
      ".git/config",
      ".GIT/hooks/x",
      "sub/.Git/x",
      "sub/.git",
      ".git./x",
      "GIT~1/x",
    ])
      expect(refusal(newFile(path))).toMatch(".git");
  });

  it("refuses protected paths and everything below them", () => {
    expect(refusal(newFile("hooks/pre-commit"), ["hooks"])).toMatch(
      "protected",
    );
    expect(refusal(newFile(".Husky/x"), [".husky"])).toMatch("protected");
    expect(refusal(newFile("config"), ["config"])).toMatch("protected");
    expect(
      validateRemoteWorkspacePatch(Buffer.from(newFile("hooks2/x")), ["hooks"])
        .ok,
    ).toBe(true);
  });

  it("refuses a rename or copy from or to a refused path", () => {
    const rename = (from: string, to: string, verb = "rename") =>
      `diff --git a/${from} b/${to}\nsimilarity index 100%\n${verb} from ${from}\n${verb} to ${to}\n`;
    expect(refusal(rename("a.txt", ".git/config"))).toMatch(".git");
    expect(refusal(rename(".git/config", "a.txt"))).toMatch(".git");
    expect(refusal(rename("a.txt", "../b"))).toMatch("'..'");
    expect(refusal(rename("a.txt", "x/.git/y", "copy"))).toMatch(".git");
    expect(refusal(rename("a.txt", "hooks/x", "copy"), ["hooks"])).toMatch(
      "protected",
    );
  });

  it("does not trust ---/+++ or the diff header alone", () => {
    const patch = `diff --git a/ok.txt b/ok.txt\nindex 1..2 100644\n--- a/ok.txt\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n`;
    expect(refusal(patch)).toMatch(".git");
    const hidden = `diff --git a/ok.txt b/ok.txt\nnew file mode 100644\n--- /dev/null\n+++ b/ok.txt\n@@ -0,0 +1 @@\n+x\n${newFile(".git/x")}`;
    expect(refusal(hidden)).toMatch(".git");
    expect(refusal("diff --git a/ok b/other\nnew file mode 100644\n")).toMatch(
      "malformed",
    );
  });

  it("refuses text that is not a git diff, and oversized patches", () => {
    expect(refusal("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")).toMatch(
      "git diff header",
    );
    expect(refusal("diff --cc x\n")).toMatch("git diff header");
    expect(refusal(Buffer.alloc(0))).toMatch("git diff header");
    const big = validateRemoteWorkspacePatch(
      Buffer.from(newFile("a.txt")),
      [],
      10,
    );
    expect(big.ok).toBe(false);
    expect(big.refused[0]).toMatch("larger than 10 bytes");
  });
});

describe("remote workspace checkpoint", () => {
  it("stores atomically with private modes and reads back", () => {
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
