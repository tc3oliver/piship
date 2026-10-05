// The developer example (examples/developer) built from its committed lock and
// launched: what the vendored packages register, what the seeded permission
// provider allows, asks, and denies for the commands and files of a normal day,
// the launch option that switches its auto-approval on for one session, and
// what pi-code reads from a repository that ships Claude Code configuration.
//
// Nothing here needs a model. Two kinds of check, and the difference matters:
// `--smoke` runs PiShip's real launcher; the probes (tests/helpers/
// developer-probe.mjs) build a Pi SDK session from the built payload's own
// files, because the packages register their tools and read their
// configuration at session start, which `--smoke` does not run.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { branded, launcher } from "../helpers/distribution.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const example = join(root, "examples/developer");
const probe = join(root, "tests/helpers/developer-probe.mjs");
const preload = join(root, "tests/helpers/read-on-exit.cjs");
const windows = process.platform === "win32";
const CONFIG = ["extensions", "pi-permission-system", "config.json"];

/**
 * `piship lock` refuses to resolve packages with npm older than 11, and the
 * one test below that relocks the example needs it. Where npm is older it is
 * skipped with that reason; CI installs npm 11, so there a missing npm 11
 * fails the test instead of skipping it.
 */
const NPM_MAJOR = Number(
  /^(\d+)\./.exec(
    spawnSync("npm", ["--version"], {
      encoding: "utf8",
      shell: process.platform === "win32",
    }).stdout ?? "",
  )?.[1] ?? 0,
);

let temp: string;
let env: NodeJS.ProcessEnv;
let artifact: string;

function run(
  command: string,
  args: readonly string[],
  cwd: string,
  environment: NodeJS.ProcessEnv = env,
) {
  const result = spawnSync(command, [...args], {
    cwd,
    env: environment,
    encoding: "utf8",
    timeout: 600_000,
  });
  return result;
}

function cli(args: readonly string[], cwd = temp) {
  const result = run(process.execPath, [bin, ...args], cwd);
  expect(result.status, `${args.join(" ")}\n${result.stderr}`).toBe(0);
  return result;
}

/** A directory beside the others in `temp`, with its own state and home. */
function area(name: string) {
  const base = join(temp, name);
  const state = join(base, "state");
  const home = join(base, "home");
  const workspace = join(base, "workspace");
  for (const path of [state, home, workspace])
    mkdirSync(path, { recursive: true });
  return {
    base,
    workspace,
    home,
    state,
    agentDir: join(state, "devcode", "agent"),
    env: {
      ...env,
      PISHIP_STATE_HOME: state,
      HOME: home,
      USERPROFILE: home,
    } as NodeJS.ProcessEnv,
  };
}

interface Smoke {
  extensions: number;
  extensionPaths: string[];
  skills: string[];
  instructions: string[];
  tools: { name: string; exposure: string; source: string }[];
  activeTools: string[];
  commands: string[];
  duplicateTools: Record<string, string[]>;
  governance: {
    capabilities: { name: string; effective: string }[];
    resources: {
      kind: string;
      class: string;
      path: string;
      loaded: boolean;
      reason?: string;
    }[];
    project: { origin: string };
  };
}

async function smoke(
  where: ReturnType<typeof area>,
  args: readonly string[] = [],
  environment: NodeJS.ProcessEnv = where.env,
): Promise<Smoke> {
  const result = await branded(
    launcher(artifact, "devcode"),
    [...args, "--smoke"],
    {
      cwd: where.workspace,
      env: environment,
      timeoutMs: 300_000,
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Smoke;
}

function fixtureProject(where: string) {
  mkdirSync(where, { recursive: true });
  cpSync(join(root, "tests/fixtures/developer/claude-project"), where, {
    recursive: true,
  });
  // Stored without their dots: a `.claude` directory in this repository would be
  // ignored by git, and read by any Claude Code session working on it.
  renameSync(join(where, "dot-claude"), join(where, ".claude"));
  renameSync(join(where, "dot-CLAUDE.md"), join(where, "CLAUDE.md"));
  const git = run("git", ["init", "--quiet"], where);
  expect(git.status, git.stderr).toBe(0);
  return realpathSync(where);
}

function probed<T>(
  where: ReturnType<typeof area>,
  mode: string,
  cwd: string,
  extra: readonly string[] = [],
  environment: NodeJS.ProcessEnv = where.env,
): T {
  const result = run(
    process.execPath,
    [probe, mode, artifact, where.agentDir, ...extra],
    cwd,
    environment,
  );
  expect(result.status, `${mode} probe\n${result.stderr}`).toBe(0);
  return JSON.parse(result.stdout.trim().split("\n").at(-1) ?? "") as T;
}

beforeAll(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-e2e-developer-"));
  env = {
    ...process.env,
    PISHIP_INSTALL_HOME: join(temp, "install"),
    PISHIP_BIN_HOME: join(temp, "bin"),
  };
  delete env.PISHIP_BUILD_INPUT;
  // This repository's .npmrc sets engine-strict, and `npm run` and `npx` hand
  // it on to the process they start. pi-browser-use declares Node 24.18 or
  // newer, so a strict install of it fails on the qualified Node 22.19. A
  // person building the example runs the CLI by path, with their own npm
  // configuration, where an engine mismatch is a warning.
  delete env.npm_config_engine_strict;
  // The committed lock is used as it is: `piship lock` is not run.
  cli(["build", join(example, "piship.yaml")]);
  artifact = join(temp, "dist", "devcode");
}, 600_000);

afterAll(() => {
  if (temp) rmSync(temp, { recursive: true, force: true });
});

describe("the built distribution", () => {
  it("vendors exactly the declared packages, and the attribution extension is not among the files it loads", () => {
    const inventory = Object.keys(
      JSON.parse(
        readFileSync(join(artifact, "metadata", "inventory.json"), "utf8"),
      ),
    );
    for (const id of [
      "pi-code",
      "pi-lens",
      "pi-background-tasks",
      "pi-review",
      "pi-browser-use",
      "pi-permission-system",
    ])
      expect(inventory, id).toContain(`pi-packages/${id}/package-lock.json`);
    // The file stays in the package's directory; the lock does not inventory it
    // as an extension, so the launcher never hands it to Pi.
    const lock = JSON.parse(
      readFileSync(join(artifact, "piship.lock"), "utf8"),
    );
    const background = lock.packages.find(
      (item: { id: string }) => item.id === "pi-background-tasks",
    );
    expect(
      background.resources.map((item: { path: string }) => item.path),
    ).toEqual(["dist/extensions/background-tasks.js"]);
  });
});

describe("--smoke", () => {
  let first: Smoke;
  let workspaceArea: ReturnType<typeof area>;

  beforeAll(async () => {
    workspaceArea = area("smoke");
    first = await smoke(workspaceArea);
  }, 300_000);

  it("registers the tools the profile promises, with no name taken twice", () => {
    const names = first.tools.map((tool) => tool.name);
    expect(names).toEqual(
      expect.arrayContaining([
        // pi-code
        "web_search",
        "web_fetch",
        "todo",
        "question",
        "memory",
        "subagent",
        "plan_mode_complete",
        // pi-lens
        "lens_diagnostics",
        "symbol_search",
        "effective_config",
        "project_report",
        "module_report",
        "read_symbol",
        "read_enclosing",
        "pi_lens_activate_tools",
        "ast_grep_search",
        "ast_grep_replace",
        "ast_grep_outline",
        "lsp_navigation",
        // pi-background-tasks, process features only
        "bg_run",
        "bg_status",
        "bg_logs",
        "bg_kill",
        // Pi's own, switched on by runtime.tools
        "codemode",
        "tool_search",
        // PiShip's governed tools
        "read",
        "write",
        "edit",
        "bash",
      ]),
    );
    expect(new Set(names).size).toBe(names.length);
    expect(first.duplicateTools).toEqual({});
    expect(first.activeTools).toEqual(
      expect.arrayContaining(["codemode", "tool_search"]),
    );
  });

  it("does not register what the profile leaves out", () => {
    const names = first.tools.map((tool) => tool.name);
    for (const gone of [
      "bg_delegate",
      "bg_result",
      "bg_run_pi_attested",
      "fusion_reason",
      "fusion_research",
      "fusion_investigate",
      "fusion_validate",
    ])
      expect(names, gone).not.toContain(gone);
    expect(names.filter((name) => name.startsWith("fusion_"))).toEqual([]);
    // pi-code provides these; the packages the profile does not add would
    // register them a second time.
    expect(names).not.toContain("ask_user");
    expect(names.filter((name) => name.startsWith("mcp_"))).toEqual([]);
  });

  it("never loads the extension that makes requests look like Claude Code's", () => {
    expect(
      first.extensionPaths.filter((path) => /attribution/i.test(path)),
    ).toEqual([]);
    expect(
      first.extensionPaths.some((path) =>
        /pi-background-tasks.*background-tasks\.js$/.test(path),
      ),
    ).toBe(true);
    // No tool or command came from it either.
    expect(first.tools.some((tool) => /attribution/i.test(tool.source))).toBe(
      false,
    );
  });

  it("loads every package's extension and the distribution's own skills", () => {
    for (const entry of [
      /pi-code[\\/].*claude-rules\.ts$/,
      /pi-lens[\\/].*dist[\\/]index\.js$/,
      /pi-background-tasks[\\/].*background-tasks\.js$/,
      /pi-review[\\/].*src[\\/]index\.ts$/,
      /pi-browser-use[\\/].*dist[\\/]index\.js$/,
      /pi-permission-system[\\/].*src[\\/]index\.ts$/,
    ])
      expect(
        first.extensionPaths.some((path) => entry.test(path)),
        String(entry),
      ).toBe(true);
    expect(first.skills).toEqual(
      expect.arrayContaining([
        "code-review-targets",
        "pi-lens-ast-grep",
        "browser-policy",
      ]),
    );
    // The skills the profile filters out of its packages.
    for (const gone of [
      "gmail-auth",
      "auth-bootstrap",
      "pi-lens-write-ast-grep-rule",
    ])
      expect(first.skills, gone).not.toContain(gone);
  });

  it("offers the commands of each package, and says where two collide", () => {
    expect(first.commands).toEqual(
      expect.arrayContaining([
        "review",
        "review-back",
        "permission-system",
        "plan",
        "todos",
        "rewind",
        "agents",
        "goal",
        "init",
        "context",
        "memory",
        "bg",
        "jobs",
        "lens-health",
      ]),
    );
    // pi-code's /tasks and pi-background-tasks' /tasks: Pi renames both.
    expect(first.commands).toEqual(
      expect.arrayContaining(["tasks:1", "tasks:2"]),
    );
    expect(first.commands).not.toContain("tasks");
  });

  it("has the permission provider as an effective, locked, certified capability", () => {
    expect(first.governance.capabilities).toContainEqual({
      name: "permissions",
      effective: "yes",
    });
    const lock = JSON.parse(
      readFileSync(join(artifact, "piship.lock"), "utf8"),
    );
    expect(lock.governance.providers).toEqual([
      expect.objectContaining({
        capability: "permissions",
        id: "certified/pi-permission-system",
        class: "certified",
        package: "pi-permission-system",
      }),
    ]);
  });

  it("keeps pi-lens inside the distribution's state, not the user's home", () => {
    expect(existsSync(join(workspaceArea.state, "devcode", "pi-lens"))).toBe(
      true,
    );
    expect(existsSync(join(workspaceArea.home, ".pi-lens"))).toBe(false);
  });

  it("seeds the permission provider's configuration, owner-only, as declared", () => {
    const file = join(workspaceArea.agentDir, ...CONFIG);
    const config = JSON.parse(readFileSync(file, "utf8"));
    const lock = JSON.parse(
      readFileSync(join(artifact, "piship.lock"), "utf8"),
    );
    const [declared] = lock.governance.manifest.resources.packages.find(
      (item: { id: string }) => item.id === "pi-permission-system",
    ).agentFiles;
    expect(config).toEqual(declared.json);
    expect(config.yoloMode).toBe(false);
    expect(config.permission["*"]).toBe("allow");
    expect(config.permission.bash["*"]).toBe("ask");
    expect(config.shellTools).toEqual({
      bg_run: { commandArgument: "command" },
    });
    if (!windows) expect(statSync(file).mode & 0o077).toBe(0);
  });

  it("does not overwrite a configuration the user edited", async () => {
    const where = area("edited");
    await smoke(where);
    const file = join(where.agentDir, ...CONFIG);
    const edited = `${JSON.stringify({ permission: { "*": "ask" } })}\n`;
    writeFileSync(file, edited);
    await smoke(where);
    expect(readFileSync(file, "utf8")).toBe(edited);
  }, 600_000);
});

describe.skipIf(windows)(
  "the seeded permission rules, run by the provider",
  () => {
    // The provider reads `~` from HOME. Neither HOME nor the paths of the cases
    // below that are meant to lie outside the workspace exist, and none is under
    // the OS temp directory, which the profile allows writes to.
    const HOME = "/devcode-probe-home";
    type Verdict = "allow" | "ask" | "deny";
    const cases: [Verdict, string, Record<string, unknown>][] = [
      // Routine work: no prompt.
      ["allow", "bash", { command: "git status" }],
      ["allow", "bash", { command: "git diff HEAD~1" }],
      ["allow", "bash", { command: "git log --oneline -5" }],
      ["allow", "bash", { command: "npm test" }],
      ["allow", "bash", { command: "pnpm install" }],
      ["allow", "bash", { command: "yarn build" }],
      ["allow", "bash", { command: "pytest -x" }],
      ["allow", "bash", { command: "uv run pytest" }],
      ["allow", "bash", { command: "cargo test" }],
      ["allow", "bash", { command: "go test ./..." }],
      ["allow", "bash", { command: "tsc --noEmit" }],
      ["allow", "bash", { command: "eslint . --fix" }],
      ["allow", "bash", { command: "cd src && npm test" }],
      ["allow", "bash", { command: "FOO=1 npm test" }],
      ["allow", "bash", { command: "docker compose up -d" }],
      ["allow", "bash", { command: "git push origin feature-fix" }],
      ["allow", "bash", { command: "curl http://localhost:3000/health" }],
      ["allow", "bash", { command: "rm build.log" }],
      ["allow", "bash", { command: "cat .env.example" }],
      ["allow", "read", { path: "src/index.ts" }],
      ["allow", "read", { path: ".env.example" }],
      ["allow", "read", { path: "tests/fixtures/ca.pem" }],
      ["allow", "read", { path: "/opt/devcode-probe/readme.md" }],
      ["allow", "write", { path: "src/new.ts", content: "x" }],
      ["allow", "write", { path: "README.md", content: "x" }],
      ["allow", "write", { path: "package.json", content: "x" }],
      ["allow", "edit", { path: "src/index.ts", edits: [] }],
      ["allow", "grep", { pattern: "x", path: "src" }],
      [
        "allow",
        "bg_run",
        { name: "dev", command: "npm run dev", isAgent: false },
      ],
      ["allow", "web_fetch", { url: "https://example.com" }],
      ["allow", "browser_navigate_page", { url: "http://localhost:3000" }],
      ["allow", "mcp__github__search_code", { q: "x" }],
      ["allow", "mcp__github__get_issue", { number: 1 }],
      ["allow", "mcp__db__query", { sql: "select 1" }],
      // A person decides.
      ["ask", "bash", { command: "sudo ls" }],
      ["ask", "bash", { command: "rm -rf build" }],
      ["ask", "bash", { command: "rm -r dir" }],
      ["ask", "bash", { command: "cd x && rm -rf y" }],
      ["ask", "bash", { command: "git reset --hard HEAD~1" }],
      ["ask", "bash", { command: "git clean -fd" }],
      ["ask", "bash", { command: "git push --force origin main" }],
      ["ask", "bash", { command: "git push -f origin main" }],
      ["ask", "bash", { command: "git branch -D feature" }],
      ["ask", "bash", { command: "npm publish" }],
      ["ask", "bash", { command: "npm install -g typescript" }],
      ["ask", "bash", { command: "docker compose down -v" }],
      ["ask", "bash", { command: "curl https://example.com" }],
      ["ask", "bash", { command: "unknown-tool --flag" }],
      ["ask", "bash", { command: "bash -c 'echo hi'" }],
      ["ask", "bash", { command: "cat .env" }],
      ["ask", "bash", { command: "echo hi > /opt/devcode-probe/out.txt" }],
      ["ask", "read", { path: ".env" }],
      ["ask", "read", { path: "certs/prod.pem" }],
      ["ask", "write", { path: "/opt/devcode-probe/x.txt", content: "x" }],
      ["ask", "write", { path: "~/.zshrc", content: "x" }],
      ["ask", "write", { path: ".env.local", content: "x" }],
      ["ask", "write", { path: ".mcp.json", content: "{}" }],
      ["ask", "write", { path: ".claude/settings.json", content: "{}" }],
      ["ask", "bg_run", { name: "x", command: "sudo reboot", isAgent: false }],
      ["ask", "browser_evaluate_script", { function: "() => 1" }],
      ["ask", "mcp__github__create_issue", { title: "x" }],
      ["ask", "mcp__github__delete_repo", {}],
      ["ask", "mcp__unknown__frobnicate", {}],
      // A clear secret: never.
      ["deny", "read", { path: "~/.ssh/id_rsa" }],
      // The ask for key files must not outrank the deny for the directory.
      ["deny", "read", { path: "~/.ssh/ec2-keypair.pem" }],
      ["deny", "read", { path: "~/.aws/credentials" }],
      ["deny", "read", { path: "~/.config/gh/hosts.yml" }],
      ["deny", "write", { path: "~/.ssh/authorized_keys", content: "x" }],
      ["deny", "bash", { command: "cat ~/.ssh/id_rsa" }],
      ["deny", "bash", { command: "cat ~/.netrc" }],
      ["deny", "bash", { command: "ssh-add ~/.ssh/id_ed25519" }],
      ["deny", "bash", { command: "gh auth token" }],
      [
        "deny",
        "write",
        {
          path: ".pi/extensions/pi-permission-system/config.json",
          content: "{}",
        },
      ],
    ];

    it("allows the routine, asks for the risky, and denies the clear secrets", async () => {
      const where = area("permissions");
      await smoke(where);
      const file = join(temp, "permission-cases.json");
      writeFileSync(
        file,
        JSON.stringify(cases.map(([, tool, input]) => [tool, input])),
      );
      const results = probed<
        { toolName: string; input: unknown; verdict: Verdict }[]
      >(where, "permissions", where.workspace, [file], {
        ...where.env,
        HOME,
        USERPROFILE: HOME,
      });
      const mismatches = results.flatMap((result, index) => {
        const expected = cases[index];
        return !expected || result.verdict === expected[0]
          ? []
          : [
              `${expected[0]} expected, ${result.verdict} for ${expected[1]} ${JSON.stringify(expected[2])}`,
            ];
      });
      expect(mismatches).toEqual([]);
      expect(results).toHaveLength(cases.length);
    }, 300_000);
  },
);

describe.skipIf(windows)(
  "the launch option that approves every ask for one session",
  () => {
    it("switches the provider's auto-approval on while the launch runs and takes it back", async () => {
      const where = area("yolo");
      await smoke(where);
      const file = join(where.agentDir, ...CONFIG);
      const during = join(where.base, "during.json");
      // Copies the provider's file when the process exits, before PiShip's own
      // exit handler takes the key back.
      const result = await branded(
        launcher(artifact, "devcode"),
        ["--yolo", "--smoke"],
        {
          cwd: where.workspace,
          env: {
            ...where.env,
            NODE_OPTIONS: `--require=${preload}`,
            READ_ON_EXIT_FROM: file,
            READ_ON_EXIT_TO: during,
          },
          timeoutMs: 300_000,
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(readFileSync(during, "utf8")).yoloMode).toBe(true);
      expect(JSON.parse(readFileSync(file, "utf8")).yoloMode).toBe(false);
      const sidecar = JSON.parse(
        readFileSync(join(where.agentDir, ".piship-agent-files.json"), "utf8"),
      );
      expect(sidecar.override).toBeUndefined();
      expect(result.stderr).toMatch(/Notice: .*yolo/i);
    }, 600_000);

    it("is taken back by the next launch when the process was killed before it could", async () => {
      const where = area("yolo-killed");
      await smoke(where);
      const file = join(where.agentDir, ...CONFIG);
      // The state a killed `--yolo` launch leaves: the key on, the override recorded.
      const config = JSON.parse(readFileSync(file, "utf8"));
      writeFileSync(
        file,
        `${JSON.stringify({ ...config, yoloMode: true }, null, 2)}\n`,
      );
      const sidecar = join(where.agentDir, ".piship-agent-files.json");
      const state = JSON.parse(readFileSync(sidecar, "utf8"));
      writeFileSync(
        sidecar,
        JSON.stringify({
          ...state,
          override: {
            path: "extensions/pi-permission-system/config.json",
            key: "yoloMode",
            hadKey: true,
            original: false,
          },
        }),
      );
      await smoke(where);
      expect(JSON.parse(readFileSync(file, "utf8")).yoloMode).toBe(false);
    }, 600_000);
  },
);

describe("doctor", () => {
  it("reports the package environment, the permission file, and the provider", async () => {
    const where = area("doctor");
    const result = await branded(launcher(artifact, "devcode"), ["doctor"], {
      cwd: where.workspace,
      env: where.env,
      timeoutMs: 300_000,
    });
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(result.stdout).toMatch(
      /pi-background-tasks env\s+PI_BG_FEATURES=process/,
    );
    expect(result.stdout).toMatch(
      /pi-lens env\s+PI_LENS_HOME=<state>\/pi-lens/,
    );
    expect(result.stdout).toMatch(
      /pi-permission-system seed file\s+extensions\/pi-permission-system\/config\.json as declared/,
    );
    expect(result.stdout).toMatch(
      /permissions\s+effective via certified\/pi-permission-system/,
    );
  }, 600_000);
});

describe("pi-browser-use", () => {
  /** A Chrome the package can start, found the way a person would look. */
  function chrome(): string | undefined {
    const candidates = [
      process.env.CHROME_PATH,
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    ];
    return candidates.find((path) => path && existsSync(path));
  }

  it.skipIf(!chrome())(
    `starts chrome-devtools-mcp and registers its browser tools on Node ${process.versions.node}`,
    () => {
      const where = area("browser");
      const result = probed<{ tools: string[] }>(
        where,
        "browser",
        where.workspace,
      );
      expect(result.tools).toEqual(
        expect.arrayContaining([
          "browser_navigate_page",
          "browser_take_snapshot",
          "browser_evaluate_script",
          "browser_list_pages",
          "browser_save_artifact",
          "browser_status",
          "browser_doctor",
        ]),
      );
      // The profile and the settings are under ~/.pi, not the distribution's state.
      expect(existsSync(join(where.home, ".pi", "browser-profile"))).toBe(true);
      expect(existsSync(join(where.agentDir, "browser-profile"))).toBe(false);
    },
    300_000,
  );
});

describe.skipIf(windows)(
  "a repository that ships Claude Code configuration",
  () => {
    const MARKERS = [
      "FIXTURE_CLAUDE_MD_MARKER",
      "FIXTURE_IMPORT_MARKER",
      "FIXTURE_RULE_ALWAYS_MARKER",
    ];
    interface Claude {
      commands: string[];
      skills: string[];
      prompt: string;
      scopedRule: string;
      hookMarker: string | null;
    }

    it("is loaded by neither PiShip nor pi-code when the origin is unknown and nobody can be asked", async () => {
      const where = area("claude-closed");
      const project = fixtureProject(join(where.base, "project"));
      const result = await smoke({ ...where, workspace: project });
      // PiShip loads the root CLAUDE.md as an instruction, and nothing else.
      const claude = result.governance.resources.filter(
        (item) => item.kind === "claude",
      );
      expect(claude.map((item) => item.path).sort()).toEqual([
        ".claude/agents",
        ".claude/commands",
        ".claude/hooks",
        ".claude/rules",
        ".claude/settings.json",
        ".claude/skills",
      ]);
      expect(claude.every((item) => !item.loaded)).toBe(true);
      expect(
        result.governance.resources.find((item) => item.path === "CLAUDE.md"),
      ).toMatchObject({ kind: "instructions", loaded: true });
      // pi-code reads PiShip's decision from the trust store and finds none.
      const loaded = probed<Claude>(where, "claude", project);
      expect(loaded.commands).not.toContain("fixture-hello");
      expect(loaded.skills).not.toContain("fixture-skill");
      expect(loaded.prompt).not.toContain("FIXTURE_RULE_ALWAYS_MARKER");
      expect(loaded.hookMarker).toBeNull();
    }, 600_000);

    it("is loaded once policy admits the origin: rules, commands, skills, agents, hooks, CLAUDE.md", async (context) => {
      const reason = `npm ${NPM_MAJOR} cannot lock Pi packages; piship lock requires npm 11 or later`;
      if (process.env.CI) expect(NPM_MAJOR, reason).toBeGreaterThanOrEqual(11);
      context.skip(NPM_MAJOR < 11, reason);
      // A copy of the example that calls this repository a company one, locked
      // here, because the origin is part of the manifest.
      const copy = join(temp, "company-example");
      cpSync(example, copy, {
        recursive: true,
        filter: (source) => !/[\\/](dist|managed\.piship\.yaml)$/.test(source),
      });
      const where = area("claude-open");
      const project = fixtureProject(join(where.base, "project"));
      const manifest = join(copy, "piship.yaml");
      const source = readFileSync(manifest, "utf8");
      const patched = source.replace(
        "  projectTrust:\n    company:\n",
        `  projectTrust:\n    company:\n      match:\n        - path: '${project}/**'\n`,
      );
      expect(patched).not.toBe(source);
      writeFileSync(manifest, patched);
      cli(["lock", manifest]);
      mkdirSync(join(temp, "company-build"), { recursive: true });
      cli(["build", manifest], join(temp, "company-build"));
      const built = join(temp, "company-build", "dist", "devcode");
      const result = await branded(launcher(built, "devcode"), ["--smoke"], {
        cwd: project,
        env: where.env,
        timeoutMs: 300_000,
      });
      expect(result.status, result.stderr).toBe(0);
      const summary = JSON.parse(result.stdout) as Smoke;
      expect(summary.governance.project.origin).toBe("company");
      for (const item of summary.governance.resources.filter(
        (entry) => entry.kind === "claude",
      ))
        expect(item, item.path).toMatchObject({ loaded: true });
      // The same files pi-code loads, with the decision PiShip wrote.
      const loaded = run(
        process.execPath,
        [probe, "claude", built, where.agentDir],
        project,
        where.env,
      );
      expect(loaded.status, loaded.stderr).toBe(0);
      const claude = JSON.parse(
        loaded.stdout.trim().split("\n").at(-1) ?? "",
      ) as Claude;
      expect(claude.commands).toContain("fixture-hello");
      expect(claude.skills).toContain("fixture-skill");
      for (const marker of [...MARKERS, "fixture-agent"])
        expect(claude.prompt, marker).toContain(marker);
      expect(claude.scopedRule).toContain("FIXTURE_RULE_SCOPED_MARKER");
      expect(claude.hookMarker).toBe("FIXTURE_HOOK_MARKER");
    }, 900_000);
  },
);
