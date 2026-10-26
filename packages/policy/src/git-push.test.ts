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
    ["git --attr-source HEAD push origin main", ["origin/main"]],
    // A subcommand the shell expands may be push.
    ["git {push,origin} main", ["*"]],
    ["git pu?h origin main", ["*"]],
    ["git p* origin main", ["*"]],
    ["git [p]ush origin main", ["*"]],
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
    // git at any word: over-matching only ever adds a deny or ask.
    ["echo git push origin main", ["origin/main"]],
    ["env git push origin main", ["origin/main"]],
    ["command git push origin main", ["origin/main"]],
    ["sudo git push origin main", ["origin/main"]],
    ["timeout 9 nohup git push origin main", ["origin/main"]],
    ["exec git push origin main", ["origin/main"]],
    ["echo main | xargs git push origin", ["origin/*"]],
    ["if git push origin main; then echo ok; fi", ["origin/main"]],
    ["true; then git push origin main; fi", ["origin/main"]],
    ["for b in a; do git push origin main; done", ["origin/main"]],
    ["{ git push origin main; }", ["origin/main"]],
    ["! git push origin main", ["origin/main"]],
    // A backslash-newline joins the line.
    ["git \\\npush origin main", ["origin/main"]],
    ["git push \\\norigin main", ["origin/main"]],
    // Substitutions run, also inside double quotes.
    ['x="$(git push origin main)"', ["origin/main"]],
    ["x=$(git push origin main)", ["origin/main"]],
    ['echo "`git push origin main`"', ["origin/main"]],
    ["echo `git push origin main`", ["origin/main"]],
    // Substitutions read quotes: a quoted `)` does not close them.
    [`x="$(echo ')'; git push origin main)"`, ["origin/main"]],
    ['x="$(echo ")"; git push origin main)"', ["origin/main"]],
    // A redirection's target, and its file descriptor, are no arguments.
    ["git push origin main>/dev/null", ["origin/main"]],
    ["git push origin main 2>&1 | tee log", ["origin/main"]],
    ["git push origin main </dev/null", ["origin/main"]],
    ["git push <<< x origin main", ["origin/main"]],
    // A heredoc body is data.
    ["git commit -m \"$(cat <<'EOF'\nFix git push gate\nEOF\n)\"", []],
    ["cat <<EOF > notes\ngit push origin main\nEOF\ngit status", []],
    [
      'cat <<-"EOF"\n\tgit push origin main\n\tEOF\ngit push origin dev',
      ["origin/dev"],
    ],
    // `$'...'` is read to its next quote.
    ["git push $'origin' main", ["origin/main"]],
    // A push's arguments are not commands: one push per simple command.
    [
      "git push origin git push upstream x",
      ["origin/git", "origin/push", "origin/upstream", "origin/x"],
    ],
    ["git push origin main; git push origin main", ["origin/main"]],
    // A comment ends at the line end, also inside a substitution.
    ["git push origin  # current branch", ["origin/*"]],
    ["# don't forget\ngit push origin main", ["origin/main"]],
    ["x=$(# note's\ngit push origin main)", ["origin/main"]],
    ["echo a#b; git push origin main", ["origin/main"]],
    // `<<` in arithmetic is a shift, not a heredoc.
    ["echo $((1<<2))\ngit push origin main", ["origin/main"]],
    ['echo "$((1<<2))"\ngit push origin main', ["origin/main"]],
    ["((x <<= 1))\ngit push origin main", ["origin/main"]],
    // A heredoc delimiter is one quoted word.
    ['cat <<"E O F"\nE O F\ngit push origin main', ["origin/main"]],
    ['cat <<"EOF;"\nEOF;\ngit push origin main', ["origin/main"]],
    ["x=`cat <<EOF`\ngit push origin main", ["origin/main"]],
    // A substitution as a redirection target still runs.
    ["echo >$(git push origin main)", ["origin/main"]],
    ['echo >"$(git push origin main)" next', ["origin/main"]],
    // A positional repository wins over --repo, as in git.
    ["git push --repo=x origin main", ["origin/main"]],
    // Text an unended quote or heredoc leaves unread counts as an unnamed push.
    ["cat <<EOF\nnever ended\ngit push origin main", ["*"]],
    ["echo 'unended; git push origin main", ["*"]],
    ['echo "unended; git push origin main', ["*"]],
    ["cat <<EOF\nnever ended", []],
    // `#` after a substitution is part of the word, not a comment.
    ["echo $(true)#; git push origin main", ["origin/main"]],
    ["echo `true`#; git push origin main", ["origin/main"]],
    ["echo $(( 1 ))#; git push origin main", ["origin/main"]],
    ["x=1 # c\ngit push origin main", ["origin/main"]],
    // Arithmetic ends with its own parentheses and never leaks.
    ["((:) ); git push 2>/dev/null origin main", ["origin/main"]],
    [
      "echo $(( $(git push 2>/dev/null origin main; echo 1) ))",
      ["origin/main"],
    ],
    ['echo "$((git push origin main) )"', ["origin/main"]],
    ['echo "$((1<<2))"; git push origin main', ["origin/main"]],
    // A second unended heredoc keeps the first one's unread text.
    ["cat <<A <<B\nx\ngit push origin main", ["*"]],
    // `<<` inside `${...}` is no heredoc.
    // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion is the input
    ["echo ${x:1<<2}\ngit push origin main\n2}", ["origin/main"]],
    // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion is the input
    ["echo ${x:-$(git push origin main)}", ["origin/main"]],
    // A quoted string is data, not a command.
    ['echo "git push origin main"', []],
    ['git commit -m "fix git push"', []],
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
    "./deploy.sh",
    "python -c \"import subprocess; subprocess.run(['git', 'push'])\"",
  ])("does not recognize %s", (command) => {
    expect(gitPushResources(command)).toEqual([]);
  });

  it("stays linear and bounded on hostile input", () => {
    for (const [command, bound] of [
      ["git push ".repeat(8_000), 1],
      ["a; ".repeat(350_000), 0],
      [`git push origin ${"b ".repeat(100_000)}`, 1],
      ['"$('.repeat(10_000), 1],
      [`${"$(".repeat(10_000)}git push origin main`, 1],
      [`git${" -C git".repeat(20_000)}`, 1],
      ["git -C git ".repeat(20_000), 0],
    ] as const) {
      const started = performance.now();
      const resources = gitPushResources(command);
      expect(performance.now() - started).toBeLessThan(1500);
      expect(resources.length).toBeLessThanOrEqual(64);
      if (bound === 0) expect(resources).toEqual([]);
      else expect(resources.length).toBeGreaterThan(0);
    }
    // Past the limits, the target is unnamed.
    expect(gitPushResources('"$('.repeat(10_000))).toEqual(["*"]);
    expect(gitPushResources(`git${" -C git".repeat(20_000)}`)).toEqual(["*"]);
    expect(
      gitPushResources(
        Array.from({ length: 65 }, (_, i) => `git push origin b${i}`).join(";"),
      ),
    ).toEqual(["*"]);
  });

  it("is documented as command text only, not a boundary", () => {
    const security = readFileSync(
      new URL("../../../docs/security.md", import.meta.url),
      "utf8",
    );
    expect(security).toContain(
      "`git.push` is recognized from the command text only, by a best-effort parser of shell syntax: a `git.push` rule is not a guarantee",
    );
    for (const wrapper of [
      "`sh -c 'git push'`",
      "a git alias (`git -c alias.p=push p`)",
      "a quoted command string",
      "`$GIT push`",
      "a script or Makefile that pushes",
      "a Python or Node subprocess",
    ])
      expect(security).toContain(wrapper);
    expect(
      readFileSync(
        new URL("../../../docs/manifest.md", import.meta.url),
        "utf8",
      ),
    ).toContain("| `git.push` |");
  });
});
