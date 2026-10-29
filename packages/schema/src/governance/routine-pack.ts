// The built-in `piship.routine` rule pack: routine, low-risk coding work that
// a managed distribution should not prompt for. A manifest opts in with
// `policy.packs`; parsing appends the expansion after the author's own
// defaults, so the lock, the policy digest, `policy explain` and `piship diff`
// see ordinary rules. Version 1 is frozen: change the data and a new version
// is needed (tests/routine-pack.test.ts pins the digest).
import type { PolicyEffect } from "@piship/contracts";
import type { PolicyRule } from "../governance.js";

export const ROUTINE_PACK = "piship.routine";
export const ROUTINE_PACK_VERSIONS = [1] as const;

type Entry = readonly [
  id: string,
  action: PolicyRule["action"],
  resource: string,
  effect: PolicyEffect,
];

const slug = (text: string) =>
  text
    // `.env` and `.env.*` must not share an ID.
    .replace(/\.\*/g, "-any")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();

/**
 * Shell entries of one group. A command is its exact text; `+` after it also
 * allows arguments (`X` and `X **`: a bare `X**` would let `git diff**` match
 * `git difftool`); text ending in `**` is used as written.
 */
function shell(
  group: string,
  effect: PolicyEffect,
  ...commands: readonly string[]
): Entry[] {
  return commands.flatMap((command): Entry[] => {
    const pair = command.endsWith("+");
    const text = pair ? command.slice(0, -1) : command;
    const id = `${group}.${slug(text)}`;
    return [
      [id, "shell.execute", text, effect],
      ...(pair
        ? [[`${id}.args`, "shell.execute", `${text} **`, effect] as Entry]
        : []),
    ];
  });
}

const paths = (
  group: string,
  action: "filesystem.read" | "filesystem.write",
  effect: PolicyEffect,
  ...resources: readonly string[]
): Entry[] =>
  resources.map((resource) => [
    `${group}.${slug(`${action.slice(11)}-${resource}`)}`,
    action,
    resource,
    effect,
  ]);

/** Entries that need no shell containment. */
const OPEN: readonly Entry[] = [
  ...[
    "read",
    "write",
    "edit",
    "bash",
    "task_start",
    "task_output",
    "task_stop",
    "ask_user",
  ].map((tool): Entry => [`tools.${tool}`, "tool.execute", tool, "allow"]),
  ...paths(
    "fs.secrets",
    "filesystem.read",
    "allow",
    "workspace/**/.env.example",
    "workspace/**/.env.sample",
    "workspace/**/.env.template",
  ),
  ...paths(
    "fs.secrets",
    "filesystem.read",
    "ask",
    "workspace/**/.env",
    "workspace/**/.env.*",
  ),
  ...paths(
    "fs.exec-config",
    "filesystem.write",
    "ask",
    "workspace/**/.envrc",
    "workspace/**/.claude/**",
    "workspace/**/.pi/**",
    "workspace/**/.mcp.json",
    "workspace/**/.vscode/**",
    "workspace/**/.husky/**",
  ),
  ...paths("fs", "filesystem.read", "allow", "workspace/**"),
  ...paths("fs", "filesystem.write", "allow", "workspace/**"),
];

/**
 * Active only under an enforced sandbox: its shell rules need it to contain
 * commands, and `tmp` is the session's private directory only then (without a
 * sandbox it is the whole system temp directory).
 */
const CONTAINED: readonly Entry[] = [
  ...paths("fs", "filesystem.read", "allow", "tmp/**"),
  ...paths("fs", "filesystem.write", "allow", "tmp/**"),
  // A shell command naming a dotenv file asks, as the read tool does. The
  // examples are allowed only as the whole command `cat <example>`: a pattern
  // like `**.env.example` would allow any program that ends in that name.
  // Only an explicit name is seen: a recursive search can still read a dotenv
  // file, and the sandbox is the boundary there.
  ...[
    ["example", "cat .env.example", "allow"],
    ["sample", "cat .env.sample", "allow"],
    ["template", "cat .env.template", "allow"],
    ["after-tab", "**\t.env**", "ask"],
    ["after-equals", "**=.env**", "ask"],
    ["after-space", "** .env**", "ask"],
    ["after-slash", "**/.env**", "ask"],
    ["after-colon", "**:.env**", "ask"],
    ["after-quote", "**'.env**", "ask"],
    ["after-double-quote", '**".env**', "ask"],
  ].map(
    ([name, resource, effect]): Entry => [
      `fs.secrets.shell-${name}`,
      "shell.execute",
      resource as string,
      effect as PolicyEffect,
    ],
  ),
  ...shell("search", "ask", "rg**--pre**", "rg**--hostname-bin**"),
  ...shell(
    "search",
    "allow",
    "rg+",
    "grep+",
    "ls+",
    "pwd+",
    "cat+",
    "head+",
    "tail+",
    "wc+",
    "tree+",
    "diff+",
    "fd",
  ),
  ...shell(
    "git.read",
    "allow",
    "git status+",
    "git diff+",
    "git log+",
    "git show+",
    "git blame+",
    "git rev-parse+",
    "git ls-files+",
    "git merge-base+",
    "git describe+",
    "git branch",
    "git branch --show-current",
    "git branch --list+",
    "git remote -v",
    "git stash list+",
    "git stash show+",
  ),
  ...shell(
    "git.local",
    "ask",
    "git switch**--discard-changes**",
    "git switch** -f**",
    "git switch**--force**",
    "git checkout** -f**",
    "git checkout**--force**",
  ),
  ...shell(
    "git.local",
    "allow",
    "git add+",
    "git commit+",
    "git switch -c**",
    "git checkout -b**",
    "git stash",
    "git stash push+",
  ),
  ...shell(
    "node",
    "allow",
    "npm test+",
    "npm ci+",
    "npm install",
    ...["test", "build", "lint", "typecheck", "check", "format"].flatMap(
      (script) => [
        `npm run ${script}**`,
        `pnpm run ${script}**`,
        `yarn run ${script}**`,
      ],
    ),
    "pnpm test+",
    "pnpm install",
    "pnpm install --frozen-lockfile+",
    "yarn test+",
    "yarn install",
    "yarn install --frozen-lockfile+",
    ...["tsc", "vitest", "eslint", "prettier", "jest"].flatMap((tool) => [
      `npx ${tool}+`,
      `pnpm exec ${tool}+`,
    ]),
  ),
  ...shell(
    "python",
    "allow",
    "pytest+",
    "python -m pytest+",
    "python3 -m pytest+",
    "uv run pytest+",
    "ruff check+",
    "ruff format+",
    "mypy+",
    "pyright+",
    "uv sync+",
    "poetry install+",
    "poetry run pytest+",
  ),
  ...shell(
    "go",
    "allow",
    "go test+",
    "go build+",
    "go vet+",
    "gofmt+",
    "go mod download+",
  ),
  ...shell(
    "rust",
    "allow",
    "cargo test+",
    "cargo build+",
    "cargo check+",
    "cargo clippy+",
    "cargo fmt+",
    "cargo fetch+",
  ),
  ...shell(
    "make",
    "allow",
    "make",
    ...["test", "build", "lint", "check", "fmt", "all"].map(
      (target) => `make ${target}+`,
    ),
  ),
];

/** The rules of one pack version, in the order they are appended. */
export function routineRules(version: number): PolicyRule[] {
  if (version !== 1)
    throw new RangeError(`Unknown ${ROUTINE_PACK} version ${version}`);
  return [...OPEN, ...CONTAINED].map(([id, action, resource, effect]) => ({
    id: `${ROUTINE_PACK}.${id}`,
    action,
    resource,
    effect,
    reason: `${ROUTINE_PACK}@${version}: routine ${id.split(".")[0]} work`,
    ...(CONTAINED.some((entry) => entry[0] === id) ? { contained: true } : {}),
  }));
}
