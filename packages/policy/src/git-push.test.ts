import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { gitPushResources } from "./index.js";

describe("gitPushResources", () => {
  it.each([
    ["git push origin main", ["origin/main"]],
    ["git push", ["*"]],
    ["git push origin", ["origin/*"]],
    ["git push -u origin feature/x", ["origin/feature/x"]],
    ["git push --force-with-lease origin +main", ["origin/main"]],
    ["git push origin HEAD:refs/heads/release", ["origin/release"]],
    ["git push origin HEAD", ["origin/*"]],
    ["git push origin :old", ["origin/old"]],
    ["git push origin a b", ["origin/a", "origin/b"]],
    ["git push --all origin", ["origin/*"]],
    ["git push -o ci.skip origin main", ["origin/main"]],
    ["git push --repo=upstream", ["upstream/*"]],
    ["git -C ../repo push origin main", ["origin/main"]],
    ["git -c push.default=current push origin dev", ["origin/dev"]],
    ["git --no-pager --git-dir .git push origin main", ["origin/main"]],
    ["/usr/bin/git push origin main", ["origin/main"]],
    [
      '"C:\\Program Files\\Git\\cmd\\git.exe" push origin main',
      ["origin/main"],
    ],
    ["GIT_TRACE=1 git push origin main", ["origin/main"]],
    ["cd repo && git push origin main", ["origin/main"]],
    ["npm test; git push origin main", ["origin/main"]],
    ["git fetch | git push origin main", ["origin/main"]],
    ["(git push origin main)", ["origin/main"]],
    ["git push 'origin' \"main\"", ["origin/main"]],
    ["git status", []],
    ["git log --grep push", []],
    ["echo git push origin main", []],
  ])("%s", (command, expected) => {
    expect(gitPushResources(command)).toEqual(expected);
  });

  // Not recognized, and not claimed: these stay decided by shell.execute.
  it.each([
    "sh -c 'git push origin main'",
    'bash -lc "git push origin main"',
    "git -c alias.p=push p origin main",
    "gp origin main",
    "$GIT push origin main",
    "env git push origin main",
    "./deploy.sh",
    "python -c \"import subprocess; subprocess.run(['git', 'push'])\"",
  ])("does not recognize %s", (command) => {
    expect(gitPushResources(command)).toEqual([]);
  });

  it("is documented as command text only, not a boundary", () => {
    const security = readFileSync(
      new URL("../../../docs/security.md", import.meta.url),
      "utf8",
    );
    expect(security).toContain(
      "`git.push` is recognized from the command text only.",
    );
    for (const wrapper of ["`sh -c 'git push'`", "git alias", "subprocess"])
      expect(security).toContain(wrapper);
    expect(
      readFileSync(
        new URL("../../../docs/manifest.md", import.meta.url),
        "utf8",
      ),
    ).toContain("| `git.push` |");
  });
});
