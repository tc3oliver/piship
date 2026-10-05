---
name: code-review-targets
description: Resolve what a code review covers (uncommitted changes, a branch against its base, one commit, a pull request, or named files and folders) and report prioritized, actionable findings. Use it with /review, or whenever the user asks for a review of a change.
---

# Reviewing a specific target

`/review` starts a review of "the available work". The command takes free text,
not a target, so this skill is how a review of a branch, a commit, a pull
request, or a set of paths gets its subject. Pick the target from what the user
asked for, say which one you picked in the first line of the answer, and review
only that.

## 1. Resolve the target

| The user asked for | Get the subject with |
| --- | --- |
| Nothing specific, or "my changes" | Uncommitted changes: `git status --short`, then `git diff HEAD` (staged and unstaged). New files are not in the diff: list them with `git ls-files --others --exclude-standard` and read them. |
| Only what is staged | `git diff --cached` |
| A branch, "this branch", or "against main" | Find the base: `git symbolic-ref --short refs/remotes/origin/HEAD`, else `main`, else `master`. Then `git merge-base <base> HEAD`, `git log --oneline <base>..HEAD` for the intent, and `git diff <base>...HEAD` for the change. |
| One commit, or `<sha>` | `git show --stat <sha>`, then `git show <sha>`. For a range `A..B`: `git log --oneline A..B` and `git diff A..B`. |
| A pull request, `#123`, or a PR URL | `gh pr view <n> --json title,body,baseRefName,headRefName,files`, then `gh pr diff <n>`. Add `gh pr view <n> --comments` and `gh pr checks <n>` when the discussion or the CI result matters. If `gh` is missing or not signed in, say so and ask for the branch instead (`git fetch origin pull/<n>/head` brings the PR in without it). |
| Files or folders | Read them as they are. Add `git diff HEAD -- <paths>` when they have uncommitted changes and `git log -p --follow -- <path>` when the history explains them. A request about whole files is a review of their current state, not of a diff. |

Two other rules. A request that names several targets is several reviews:
report them one after the other. A target that cannot be resolved (an unknown
sha, a branch that is not there) is reported as such, never guessed.

## 2. Gather context before judging

- Read each changed file around its hunks, not only the diff lines, and the
  callers and tests a change touches.
- Read the project's instructions (`AGENTS.md`, `CLAUDE.md`) and the stated
  intent: commit messages, the PR body, the user's request.
- Run the cheap checks that apply to the touched code (its tests, its linter,
  `lens_diagnostics` for the files). Do not run a whole suite for a small
  change, and say what you ran.

## 3. Report findings, not a summary

Open with the target and what you checked, in one or two lines. Then the
findings, most severe first:

```
[P1] path/to/file.ts:42 - what is wrong, as behavior someone would observe
Why it matters: the input, state, or caller that triggers it.
Fix: the concrete change, as a short patch when it fits.
```

- `[P0]` certain severe breakage, data loss, or a security issue. `[P1]` likely
  user-facing breakage or a major regression. `[P2]` a limited-scope
  correctness, performance, or maintainability issue. `[P3]` minor but real.
- Every finding names `file:line`, the behavior it affects, and a fix. Drop a
  finding you cannot tie to a code path.
- No general praise, no restating the diff, no style nits a formatter owns.
- If nothing material stands out, say `looks good`, and still say what was
  checked and what was not (for example a file too large to read in full).

## 4. Stay read-only

A review changes nothing. Do not edit files, push, or write to a pull request
(`gh pr review`, `gh pr comment`) unless the user asks for it afterwards.
