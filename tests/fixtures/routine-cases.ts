// One table of shell commands and what each profile decides. The developer
// column is the seeded permission provider of examples/developer (its own
// grammar, personal-grade); the routine column is the built-in
// `piship.routine@1` pack run through PiShip's policy engine with shell
// containment enforced. Only the commands both profiles can be asked about
// share a row: the developer provider allows more (docker, rm, gh, ...), by
// design. `afterWp2` is the routine verdict once command matching strips safe
// wrappers, redirects and `cd` prefixes; until then those rows ask.
export type Verdict = "allow" | "ask" | "deny";

export interface RoutineCase {
  readonly command: string;
  readonly developer: Verdict | undefined;
  readonly routine: Verdict;
  readonly afterWp2?: Verdict;
  readonly note?: string;
}

const row = (
  command: string,
  developer: Verdict | undefined,
  routine: Verdict,
  note?: string,
  afterWp2?: Verdict,
): RoutineCase => ({
  command,
  developer,
  routine,
  ...(note === undefined ? {} : { note }),
  ...(afterWp2 === undefined ? {} : { afterWp2 }),
});

export const ROUTINE_CASES: readonly RoutineCase[] = [
  row("git status", "allow", "allow"),
  row("git diff HEAD~1", "allow", "allow"),
  row("git log --oneline -5", "allow", "allow"),
  row("git checkout -b fix", "allow", "allow"),
  row("npm test", "allow", "allow"),
  row("npm run build", "allow", "allow"),
  row("pnpm install", "allow", "allow"),
  row("yarn test", "allow", "allow"),
  row("npx vitest run", "allow", "allow"),
  row("pytest -q", "allow", "allow"),
  row("uv sync", "allow", "allow"),
  row("cargo build --release", "allow", "allow"),
  row("go test ./...", "allow", "allow"),
  row("make test", "allow", "allow"),
  row("cat README.md", "allow", "allow"),
  row("rg foo src", "allow", "allow"),
  row("git clean -n", "allow", "ask", "the pack names no git clean"),
  row("git restore --staged src/app.ts", "allow", "ask", "not in the pack"),
  row("tsc --noEmit", "allow", "ask", "only through npx or pnpm exec"),
  row("eslint src", "allow", "ask", "only through npx or pnpm exec"),
  row("mkdir -p build", "allow", "ask"),
  row("rm file.txt", "allow", "ask", "the pack never allows rm"),
  row("docker compose up -d", "allow", "ask", "docker is never in the pack"),
  row("gh pr view 12", "allow", "ask", "gh is never in the pack"),
  row("cd src && npm test", "allow", "ask", "chained", "allow"),
  row("FOO=1 npm test", undefined, "ask", "env prefix", "ask"),
  row("npm test 2>&1", "allow", "ask", "redirect", "allow"),
  row("sudo ls", "ask", "ask"),
  row("rm -rf build", "ask", "ask"),
  row("find . -name x -delete", "ask", "ask"),
  row("git reset --hard HEAD~1", "ask", "ask"),
  row("git clean -fd", "ask", "ask"),
  row("git push --force origin main", "ask", "ask"),
  row("git push -f origin main", "ask", "ask"),
  row("git branch -D feature", "ask", "ask"),
  row("npm publish", "ask", "ask"),
  row("npm install -g typescript", "ask", "ask"),
  row("docker push img", "ask", "ask"),
  row("curl https://example.com", "ask", "ask"),
  row("curl http://localhost:3000/health", "ask", "ask"),
  row("git restore src/app.ts", "ask", "ask"),
  row("git checkout -- src/app.ts", "ask", "ask"),
  row("git -C . reset --hard HEAD", "ask", "ask"),
  row("ssh host", "ask", "ask"),
  row("unknown-tool --flag", "ask", "ask"),
  row("gh api /user", "ask", "ask"),
  // Prefix rules that must not stretch.
  row("git difftool -x calc", undefined, "ask", "X ** is not X**"),
  row("git diff; rm -rf ~", undefined, "ask", "chained"),
  row("git status && curl https://example.com", undefined, "ask", "chained"),
  row("git diff $(curl https://example.com)", undefined, "ask", "substitution"),
  row("rg --pre ./script foo", undefined, "ask", "rg --pre runs a command"),
  row("rg --pre=./script foo", undefined, "ask", "rg --pre=CMD spelling"),
  row("fd --exec rm", undefined, "ask", "fd --exec spelling"),
  row("fd -X rm", undefined, "ask", "fd -X spelling"),
  row("fd -x rm", undefined, "ask", "fd -x runs a command"),
  row("git branch", undefined, "allow"),
  row(
    "git branch feature",
    undefined,
    "ask",
    "creating a branch is not listed",
  ),
  row("git switch -f main", undefined, "ask", "discards changes"),
  row("git checkout --force main", undefined, "ask", "discards changes"),
  row("git switch -c feature", undefined, "allow"),
  row("git commit -m 'change'", undefined, "allow"),
  row("git push origin feature", undefined, "ask"),
  row("npm install", undefined, "allow", "exact text only"),
  row("npm install left-pad", undefined, "ask", "adds a dependency"),
  row("npm run test:unit", undefined, "allow"),
  row("npm run dev", undefined, "ask", "starts a server"),
  row("make install", undefined, "ask"),
  row(" npm test", undefined, "ask", "leading space", "allow"),
];
