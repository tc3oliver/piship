// The developer example (DevCode) and its managed variant, checked as files:
// the manifests parse, the committed lock is current and pins what the
// profile promises, the permission configuration it seeds says what its
// README says, and the release wiring and the docs name it. The built
// distribution and the real provider run in tests/e2e/developer-profile.test.ts.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PI_VERSION, requireCurrentLock } from "@piship/core";
import { type Manifest, readManifest } from "@piship/schema";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const example = join(root, "examples", "developer");
const personalPath = join(example, "piship.yaml");
const managedPath = join(example, "managed.piship.yaml");

const personal = readManifest(personalPath);
const managed = readManifest(managedPath);

function text(...path: string[]): string {
  return readFileSync(join(root, ...path), "utf8");
}

interface LockedPackage {
  id: string;
  class: string;
  version?: string;
  integrity?: string;
  tree: string;
  resources: { path: string }[];
  environment?: Record<string, unknown>;
  agentFiles?: { path: string; mode: string }[];
}

interface Lock {
  runtime: { package: string; version: string };
  packages: LockedPackage[];
  governance: {
    providers: { capability: string; certified?: { integrity: string } }[];
  };
  release: { installScripts: string[]; bundle?: boolean; strip?: boolean };
}

const lock = JSON.parse(text("examples", "developer", "piship.lock")) as Lock;

function packagesOf(manifest: Manifest) {
  return manifest.governance?.resources.packages ?? [];
}

// ------------------------------------------------------------ the seeded file

type Rules = Record<string, string>;
interface Permission {
  permissionReviewLog: boolean;
  debugLog: boolean;
  yoloMode: boolean;
  shellTools: Record<string, { commandArgument: string }>;
  permission: Record<string, string | Rules>;
}

function seeded(manifest: Manifest): Permission {
  const provider = packagesOf(manifest).find(
    (item) => item.id === "pi-permission-system",
  );
  const file = provider?.agentFiles?.find(
    (item) => item.path === "extensions/pi-permission-system/config.json",
  );
  expect(file, "the permission file is declared").toBeDefined();
  return file?.json as Permission;
}

function rules(config: Permission, key: string): Rules {
  const value = config.permission[key];
  expect(typeof value, `${key} is a rule map`).toBe("object");
  return value as Rules;
}

/** The provider's wildcard: `*` is any run of characters, `/` included. */
function wildcard(pattern: string, value: string): boolean {
  const body = pattern
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${body}$`).test(value);
}

/** In a rule map the last matching rule wins; `fallback` when none matches. */
function decide(map: Rules, value: string, fallback = "ask"): string {
  let decision = fallback;
  for (const [pattern, effect] of Object.entries(map))
    if (wildcard(pattern, value)) decision = effect;
  return decision;
}

// ------------------------------------------------------------------ manifests

describe("the developer example manifests", () => {
  it("are DevCode on the current schema, with Pi pinned to the compatible version", () => {
    for (const manifest of [personal, managed]) {
      expect(manifest.schema).toBe("piship/v1alpha6");
      expect(manifest.runtime.pi).toBe(PI_VERSION);
    }
    expect(personal.app).toMatchObject({ id: "devcode", name: "DevCode" });
    expect(personal.deployment.mode).toBe("personal");
    expect(managed.deployment.mode).toBe("managed");
    expect(managed.app.id).toBe("devcode-managed");
  });

  it("have a committed lock that is current and was resolved for the same Pi", () => {
    const current = requireCurrentLock(personalPath) as unknown as Lock;
    expect(current.runtime.version).toBe(PI_VERSION);
    expect(lock.runtime.version).toBe(PI_VERSION);
  });

  it("opt in to the bundled, stripped payload that users install", () => {
    expect(personal.lifecycle?.release).toMatchObject({
      bundle: true,
      strip: true,
    });
    expect(lock.release).toMatchObject({ bundle: true, strip: true });
  });

  it("pins every package to an exact version that the lock resolved", () => {
    const declared = packagesOf(personal);
    expect(declared.map((item) => item.id)).toEqual([
      "pi-code",
      "pi-lens",
      "pi-background-tasks",
      "pi-review",
      "pi-browser-use",
      "pi-permission-system",
    ]);
    for (const item of declared) {
      expect(item.source, item.id).toBe("npm");
      if (item.source !== "npm") continue;
      expect(item.version, item.id).toMatch(/^\d+\.\d+\.\d+$/);
      const locked = lock.packages.find((entry) => entry.id === item.id);
      expect(locked?.version, item.id).toBe(item.version);
      expect(locked?.integrity, item.id).toMatch(/^sha512-/);
    }
  });

  it("leaves out the packages that another one already provides", () => {
    const forbidden = [
      "pi-subagents",
      "pi-web-access",
      "@fradser/pi-memory",
      "pi-mcp-adapter",
      "pi-todo",
      "pi-ask-user",
      "pi-plan",
      "pi-dynamic-workflow",
    ];
    const names = packagesOf(personal).map((item) =>
      item.source === "npm" ? item.package : item.id,
    );
    const source = text("examples", "developer", "piship.yaml");
    for (const name of forbidden) {
      expect(names, name).not.toContain(name);
      expect(source.includes(`package: ${name}`), name).toBe(false);
    }
    expect(lock.packages.map((entry) => entry.id)).not.toEqual(
      expect.arrayContaining(["pi-subagents", "pi-web-access", "pi-memory"]),
    );
  });

  it("never loads the extension that makes requests look like Claude Code's", () => {
    const background = lock.packages.find(
      (entry) => entry.id === "pi-background-tasks",
    );
    expect(background?.resources.map((item) => item.path)).toEqual([
      "dist/extensions/background-tasks.js",
    ]);
    for (const entry of lock.packages)
      for (const resource of entry.resources)
        expect(resource.path, entry.id).not.toMatch(/attribution/i);
    expect(background?.environment).toMatchObject({
      PI_BG_FEATURES: "process",
      PI_BG_DISABLE_UPDATE_CHECK: "1",
    });
    expect(personal.runtime.tools?.exposure).toEqual(
      expect.arrayContaining([
        { pattern: "bg_delegate", exposure: "hidden" },
        { pattern: "bg_result", exposure: "hidden" },
        { pattern: "bg_run_pi_attested", exposure: "hidden" },
        { pattern: "fusion_*", exposure: "hidden" },
      ]),
    );
    expect(personal.runtime.tools).toMatchObject({
      codemode: "on",
      toolSearch: "on",
    });
  });

  it("keeps pi-lens's installs inside the distribution's state", () => {
    const lens = packagesOf(personal).find((item) => item.id === "pi-lens");
    expect(lens?.environment).toEqual({
      PI_LENS_HOME: { statePath: "pi-lens" },
    });
    expect(lens?.filters.skills).toContain("!skills/pi-lens-write-*/**");
    const browser = packagesOf(personal).find(
      (item) => item.id === "pi-browser-use",
    );
    expect(browser?.filters.skills).toEqual(
      expect.arrayContaining([
        "!skills/auth-bootstrap/**",
        "!skills/gmail-auth/**",
      ]),
    );
  });

  it("reviews exactly the install scripts the lock contains", () => {
    expect(personal.lifecycle?.release.installScripts).toEqual([
      "pi-packages/pi-lens/node_modules/@ast-grep/cli@0.45.3",
      "pi-packages/pi-permission-system/node_modules/tree-sitter-bash@0.25.1",
    ]);
    expect(lock.release.installScripts).toEqual(
      personal.lifecycle?.release.installScripts,
    );
  });
});

describe("the permission provider", () => {
  it("is a certified package whose evidence is the locked tree digest", () => {
    const capability = personal.governance?.capabilities.find(
      (item) => item.name === "permissions",
    );
    expect(capability).toMatchObject({
      enabled: true,
      provider: {
        id: "certified/pi-permission-system",
        class: "certified",
        package: "pi-permission-system",
        implements: ["piship.capability/permissions/v1"],
      },
      settings: {
        autoApproveFile: "extensions/pi-permission-system/config.json",
        autoApproveKey: "yoloMode",
      },
    });
    const declared = packagesOf(personal).find(
      (item) => item.id === "pi-permission-system",
    );
    expect(declared?.class).toBe("certified");
    const locked = lock.packages.find(
      (entry) => entry.id === "pi-permission-system",
    );
    expect(locked?.class).toBe("certified");
    expect(declared?.certified?.integrity).toBe(locked?.tree);
    expect(declared?.certified?.pi).toContain(PI_VERSION);
    expect(
      lock.governance.providers.find(
        (entry) => entry.capability === "permissions",
      )?.certified?.integrity,
    ).toBe(locked?.tree);
    expect(locked?.agentFiles).toEqual([
      expect.objectContaining({
        path: "extensions/pi-permission-system/config.json",
        mode: "seed",
      }),
    ]);
  });

  it("seeds a file whose auto-approval key is off and which sees bg_run as a shell", () => {
    const config = seeded(personal);
    expect(config.yoloMode).toBe(false);
    expect(config.debugLog).toBe(false);
    expect(config.shellTools).toEqual({
      bg_run: { commandArgument: "command" },
    });
    expect(config.permission["*"]).toBe("allow");
  });

  it("denies clear secrets by name and never a name a developer needs", () => {
    const paths = rules(seeded(personal), "path");
    const denied = Object.entries(paths).filter(
      ([, effect]) => effect === "deny",
    );
    expect(denied.length).toBeGreaterThan(20);
    for (const [pattern] of denied) {
      // Anchored to a home directory, an absolute location, or one exact file
      // name: never a bare extension or a broad glob.
      expect(pattern, pattern).toMatch(
        /^(~\/|\/|\*\/\.piship\/|\*\/[A-Za-z0-9_.-]+$|\*\.kdbx$)/,
      );
      expect([
        "*",
        "**",
        "*/*",
        "*.json",
        "*.yml",
        "*.yaml",
        "*.toml",
      ]).not.toContain(pattern);
    }
    // What the profile must leave usable, as a path a project would hold.
    for (const path of [
      "/work/app/.env.example",
      "/work/app/.env.sample",
      "/work/app/.env.template",
      "/work/app/tests/fixtures/ca.pem",
      "/work/app/test/fixtures/server.key",
      "/work/app/package.json",
      "/work/app/tsconfig.json",
      "/work/app/.mcp.json",
      "/work/app/.claude/settings.json",
      "/work/app/.github/workflows/ci.yml",
      "/work/app/src/index.ts",
      "/work/app/id_rsa.md",
    ])
      expect(decide(paths, path, "allow"), path).toBe("allow");
    for (const path of [
      "~/.ssh/id_rsa",
      "~/.ssh/config",
      // An ask rule for key files must not outrank a deny for the directory.
      "~/.ssh/ec2-keypair.pem",
      "/work/app/id_ed25519",
      "~/.aws/credentials",
      "~/.config/gh/hosts.yml",
      "~/.netrc",
      "~/Library/Keychains/login.keychain-db",
      "~/.gnupg/private-keys-v1.d/x.key",
    ])
      expect(decide(paths, path, "allow"), path).toBe("deny");
    // Possible secrets ask instead.
    for (const path of [
      "/work/app/.env",
      "/work/app/.env.local",
      "/work/app/certs/prod.pem",
    ])
      expect(decide(paths, path, "allow"), path).toBe("ask");
  });

  it("asks for what changes what runs next, and denies a write to its own rules", () => {
    const writes = rules(seeded(personal), "path_write");
    for (const path of [
      "/work/app/.claude/settings.json",
      "/work/app/.mcp.json",
      "/work/app/.pi/settings.json",
      "/work/app/.git/hooks/pre-commit",
    ])
      expect(decide(writes, path, "allow"), path).toBe("ask");
    expect(
      decide(
        writes,
        "/work/app/.pi/extensions/pi-permission-system/config.json",
        "allow",
      ),
    ).toBe("deny");
  });

  it("lets ordinary development run and asks for the rest of a command", () => {
    const bash = rules(seeded(personal), "bash");
    expect(bash["*"]).toBe("ask");
    for (const command of [
      "git status",
      "git diff HEAD~1",
      "git log --oneline -5",
      "git clean -n",
      "git checkout -b fix",
      "git restore --staged src/app.ts",
      "npm test",
      "npm run build",
      "pnpm install",
      "yarn test",
      "npx vitest run",
      "pytest -q",
      "uv sync",
      "cargo build --release",
      "go test ./...",
      "make test",
      "tsc --noEmit",
      "eslint src",
      "cat README.md",
      "rg foo src",
      "mkdir -p build",
      "rm file.txt",
      "docker compose up -d",
      "gh pr view 12",
    ])
      expect(decide(bash, command), command).toBe("allow");
    for (const command of [
      "sudo ls",
      "rm -rf build",
      "rm -r dir",
      "find . -name x -delete",
      "git reset --hard HEAD~1",
      "git clean -fd",
      "git push --force origin main",
      "git push -f origin main",
      "git branch -D feature",
      "npm publish",
      "npm install -g typescript",
      "docker push img",
      "docker compose down -v",
      "curl https://example.com",
      "curl http://localhost:3000/health",
      "curl https://localhost.attacker.example/path",
      "curl https://example.com/?label=localhost",
      "git restore src/app.ts",
      "git checkout -- src/app.ts",
      "git -C . reset --hard HEAD",
      "git --git-dir=.git clean -fd",
      "ssh host",
      "unknown-tool --flag",
      "gh api /user",
    ])
      expect(decide(bash, command), command).toBe("ask");
    for (const command of [
      "gh auth token",
      "security find-generic-password -s x",
      "security dump-keychain",
    ])
      expect(decide(bash, command), command).toBe("deny");
  });

  it("allows read-style MCP tools and asks for the rest", () => {
    const mcp = rules(seeded(personal), "mcp");
    expect(mcp["*"]).toBe("ask");
    for (const tool of [
      "get_issue",
      "list_repos",
      "search_code",
      "read_file",
      "query",
    ])
      expect(decide(mcp, tool), tool).toBe("allow");
    for (const tool of [
      "create_issue",
      "delete_repo",
      "update_row",
      "push_files",
      "frobnicate",
    ])
      expect(decide(mcp, tool), tool).toBe("ask");
  });

  it("asks before the browser runs script or uploads a file", () => {
    const permission = seeded(personal).permission;
    for (const tool of [
      "browser_evaluate_script",
      "browser_upload_file",
      "browser_switch_mode",
      "browser_setup",
      "browser_reauth",
    ])
      expect(permission[tool], tool).toBe("ask");
  });

  it("asks before a write outside the workspace, except temporary and cache directories", () => {
    const writes = rules(seeded(personal), "external_directory_write");
    expect(decide(writes, "/opt/other/file")).toBe("ask");
    expect(decide(writes, "/tmp/build/out.txt")).toBe("allow");
    expect(decide(writes, "~/.cache/tool/x")).toBe("allow");
    expect(rules(seeded(personal), "external_directory_read")["*"]).toBe(
      "allow",
    );
  });
});

// ------------------------------------------------------------- PiShip policy

/** PiShip's own resource glob: `**` crosses a directory, `*` does not. */
function resource(pattern: string, value: string): boolean {
  const body = pattern
    .replace("~/", "/home/u/")
    .split("**")
    .map((part) =>
      part
        .split("*")
        .map((piece) => piece.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
        .join("[^/]*"),
    )
    .join(".*");
  return new RegExp(`^${body}$`).test(value);
}

describe("the enforced secret rules", () => {
  const enforced = personal.governance?.policy.enforced ?? [];

  it("are deny rules for every governed file action and use no brace group", () => {
    expect(enforced.length).toBeGreaterThanOrEqual(15);
    for (const rule of enforced) {
      expect(rule.id, rule.id).toMatch(/^dev\.secret\./);
      expect(rule.action, rule.id).toBe("filesystem.*");
      expect(rule.effect, rule.id).toBe("deny");
      expect(rule.resource, rule.id).not.toMatch(/[{}]/);
      expect(rule.resource, rule.id).not.toBe("**");
      expect(rule.reason, rule.id).toBeTruthy();
    }
  });

  it("deny no file a project holds", () => {
    for (const path of [
      "/home/u/work/.env.example",
      "/home/u/work/.env",
      "/home/u/work/tests/fixtures/ca.pem",
      "/home/u/work/package.json",
      "/home/u/work/.mcp.json",
      "/home/u/work/.claude/settings.json",
      "/home/u/work/src/config.ts",
    ])
      for (const rule of enforced)
        expect(resource(rule.resource, path), `${rule.id} ${path}`).toBe(false);
    expect(
      enforced.some((rule) => resource(rule.resource, "/home/u/.ssh/id_rsa")),
    ).toBe(true);
    expect(
      enforced.some((rule) => resource(rule.resource, "/home/u/.netrc")),
    ).toBe(true);
  });

  it("allow everything else and ask nothing a second time", () => {
    expect(personal.governance?.policy.default).toBe("allow");
    expect(personal.governance?.policy.userAuto).toBeUndefined();
  });
});

describe("project trust in the personal profile", () => {
  const trust = personal.governance?.policy.projectTrust;
  const claude = [
    "claudeRules",
    "claudeCommands",
    "claudeSkills",
    "claudeAgents",
    "claudeHooks",
  ] as const;

  it("declares all thirteen dimensions for every origin", () => {
    for (const origin of ["company", "external", "unknown"] as const) {
      expect(
        Object.keys(trust?.[origin].dimensions ?? {}).sort(),
        origin,
      ).toEqual([
        "agents",
        "claudeAgents",
        "claudeCommands",
        "claudeHooks",
        "claudeRules",
        "claudeSkills",
        "extensions",
        "hooks",
        "instructions",
        "mcp",
        "passiveContext",
        "providers",
        "skills",
      ]);
    }
  });

  it("loads Claude configuration for a company or external project and asks for an unknown one", () => {
    for (const origin of ["company", "external"] as const)
      for (const name of claude)
        expect(trust?.[origin].dimensions[name], `${origin} ${name}`).toBe(
          "allow",
        );
    for (const name of claude)
      expect(trust?.unknown.dimensions[name], name).toBe("ask");
    for (const origin of ["company", "external", "unknown"] as const) {
      expect(trust?.[origin].dimensions.extensions, origin).toBe("ask");
      expect(trust?.[origin].dimensions.hooks, origin).toBe("deny");
      expect(trust?.[origin].dimensions.providers, origin).toBe("deny");
    }
  });

  it("claims no repository by default", () => {
    expect(trust?.company.match ?? []).toEqual([]);
    expect(trust?.external.match ?? []).toEqual([]);
  });
});

// ----------------------------------------------------------- managed variant

describe("the managed variant", () => {
  const policy = managed.governance?.policy;
  const declared = packagesOf(managed);

  it("asks by default, enforces its denies, and refuses --yolo", () => {
    expect(policy?.default).toBe("ask");
    expect(policy?.userAuto).toBeUndefined();
    const ids = (policy?.enforced ?? []).map((rule) => rule.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        "dev.secret.ssh",
        "dev.secret.aws",
        "dev.shell.sudo",
      ]),
    );
    expect(managed.governance?.sandbox.required).toBe(true);
    expect(managed.runtime.tools).toMatchObject({
      codemode: "off",
      toolSearch: "off",
    });
  });

  it("preserves every personal enforced secret rule and provider credential deny", () => {
    const enforced = policy?.enforced ?? [];
    for (const rule of personal.governance?.policy.enforced ?? [])
      expect(enforced).toContainEqual(rule);
    const personalPaths = rules(seeded(personal), "path");
    const managedPaths = rules(seeded(managed), "path");
    for (const [pattern, effect] of Object.entries(personalPaths))
      if (effect === "deny")
        expect(managedPaths[pattern], pattern).toBe("deny");
    expect(decide(managedPaths, "/work/.env.example", "allow")).toBe("allow");
  });

  it("ships no package of the user class and not the browser or background tasks", () => {
    for (const item of declared)
      expect(["company", "certified"], item.id).toContain(item.class);
    const ids = declared.map((item) => item.id);
    expect(ids).toEqual([
      "pi-code",
      "pi-lens",
      "pi-review",
      "pi-permission-system",
    ]);
    expect(ids).not.toContain("pi-browser-use");
    expect(ids).not.toContain("pi-background-tasks");
  });

  it("filters pi-code's Claude readers and MCP client out, and moves its user scope into the state", () => {
    const code = declared.find((item) => item.id === "pi-code");
    expect(code?.filters.extensions).toEqual(
      expect.arrayContaining([
        "**",
        "!extensions/mcp/**",
        "!extensions/hooks/**",
        "!extensions/env-settings.ts",
      ]),
    );
    expect(code?.environment).toEqual({
      CLAUDE_CONFIG_DIR: { statePath: "claude" },
    });
    expect(
      declared.find((item) => item.id === "pi-lens")?.environment,
    ).toMatchObject({
      PI_LENS_DISABLE_TOOL_INSTALL: "1",
      PI_LENS_DISABLE_LSP_INSTALL: "1",
    });
  });

  it("enforces the provider's file, with its auto-approval off and no setting that turns it on", () => {
    const provider = declared.find(
      (item) => item.id === "pi-permission-system",
    );
    expect(provider?.agentFiles?.map((file) => file.mode)).toEqual(["enforce"]);
    const config = seeded(managed);
    expect(config.yoloMode).toBe(false);
    expect(config.permissionReviewLog).toBe(false);
    const capability = managed.governance?.capabilities.find(
      (item) => item.name === "permissions",
    );
    expect(capability?.provider?.package).toBe("pi-permission-system");
    expect(capability?.settings).toEqual({});
    // Stricter than the personal profile: a tool or command it does not list
    // asks, key material and env files are denied, and a short list of
    // commands runs.
    expect(config.permission["*"]).toBe("ask");
    expect(rules(config, "bash")["*"]).toBe("ask");
    expect(rules(config, "mcp")["*"]).toBe("ask");
    const bash = rules(config, "bash");
    expect(decide(bash, "npm test")).toBe("allow");
    expect(decide(bash, "rm -rf build")).toBe("deny");
    expect(decide(bash, "sudo ls")).toBe("deny");
    expect(decide(bash, "npm install left-pad")).toBe("ask");
    const paths = rules(config, "path");
    expect(decide(paths, "/work/app/.env", "allow")).toBe("deny");
    expect(decide(paths, "/work/app/.env.example", "allow")).toBe("allow");
    expect(decide(paths, "~/.ssh/id_rsa", "allow")).toBe("deny");
  });

  it("declares the five Claude dimensions for every origin: hooks closed, the rest company-approved", () => {
    const trust = policy?.projectTrust;
    for (const origin of ["company", "external", "unknown"] as const) {
      const dimensions = trust?.[origin].dimensions;
      expect(dimensions?.claudeHooks, origin).toBe("deny");
      for (const name of [
        "claudeRules",
        "claudeCommands",
        "claudeSkills",
        "claudeAgents",
      ] as const)
        expect(dimensions?.[name], `${origin} ${name}`).toBe(
          "company-approved",
        );
    }
    // A remote alone is a claim: the matcher also needs the managed source root.
    expect(trust?.company.match).toEqual([
      { remote: "git.company.example/**", path: "/srv/src/**" },
    ]);
  });
});

// ----------------------------------------------------- wiring and the files

describe("the path length of shared Pi package dependencies", () => {
  // `<install home>/apps/devcode/<version>/pi-packages/.shared/<name>@<version>-<12 hex>/<file>`
  // has to stay below Windows' 260 characters. The shared directory's own
  // name is the part this repository decides and the locks name: every
  // package of every Pi package lock of the example, at its locked version.
  // The budget leaves 180 characters for the install home, `apps/devcode/<version>`,
  // and the file inside the package, and none of the locked names comes close.
  const SHARED_DIRECTORY_BUDGET = 80;

  it("keeps the longest shared directory of the locked packages under its budget", () => {
    const longest: { path: string; name: string }[] = [];
    for (const id of readdirSync(join(example, "piship.lock.d", "packages"))) {
      const npmLock = JSON.parse(
        readFileSync(
          join(example, "piship.lock.d", "packages", id, "package-lock.json"),
          "utf8",
        ),
      ) as { packages: Record<string, { version?: string; link?: boolean }> };
      for (const [key, item] of Object.entries(npmLock.packages)) {
        const name = key.split("node_modules/").pop() as string;
        if (!key.startsWith("node_modules/") || !item.version || item.link)
          continue;
        longest.push({
          name: `${name}@${item.version}`,
          path: `pi-packages/.shared/${name.replace("/", "+")}@${item.version}-${"0".repeat(12)}`,
        });
      }
    }
    expect(longest.length).toBeGreaterThan(100);
    longest.sort((a, b) => b.path.length - a.path.length);
    expect(longest[0]?.path.length, longest[0]?.name).toBeLessThanOrEqual(
      SHARED_DIRECTORY_BUDGET,
    );
  });
});

describe("the release wiring and the files that name the example", () => {
  const workflow = text(".github", "workflows", "release-candidate.yml");

  it("builds DevCode in the release candidate workflow beside the other two", () => {
    expect(workflow).toContain("developer:devcode");
    expect(workflow).toContain("demo:acmecode personal:mypi developer:devcode");
    expect(
      workflow.match(/distribution: \[acmecode, mypi, devcode\]/g),
    ).toHaveLength(3);
    // The managed variant is validated, never copied into the build.
    expect(workflow).toContain("managed.piship.yaml");
  });

  it("is registered as an end to end file with a shard weight", () => {
    expect(
      existsSync(join(root, "tests", "e2e", "developer-profile.test.ts")),
    ).toBe(true);
    expect(text("tests", "helpers", "e2e-shards.ts")).toContain(
      '"developer-profile"',
    );
  });

  it("has a README with the known-limits section that the manifest reference links to", () => {
    const readme = text("examples", "developer", "README.md");
    expect(readme).toMatch(/^## Known limits$/m);
    expect(text("docs", "manifest.md")).toContain(
      "examples/developer/README.md#known-limits",
    );
    for (const limit of [
      "CLAUDE_CONFIG_DIR",
      "~/.claude.json",
      "mcp.server.start",
      "settings.json",
      "docs/security.md",
    ])
      expect(readme, limit).toContain(limit);
  });

  it("is listed in the docs that list the examples", () => {
    for (const file of [
      ["README.md"],
      ["docs", "status.md"],
      ["docs", "release", "artifact-contract.md"],
    ])
      expect(text(...file), file.join("/")).toMatch(/DevCode|devcode/);
  });
});

describe("the repository's own words", () => {
  // A name the project never uses. It is built here so that this file does not
  // hold it.
  const forbidden = new RegExp(["mi", "code"].join(""), "i");

  function files(directory: string): string[] {
    return readdirSync(directory).flatMap((name) => {
      const path = join(directory, name);
      return statSync(path).isDirectory() ? files(path) : [path];
    });
  }

  it("does not appear in the example, its tests, or the docs that describe them", () => {
    const paths = [
      ...files(example),
      ...files(join(root, "tests", "fixtures", "developer")),
      ...files(join(root, "docs")),
      join(root, "tests", "e2e", "developer-profile.test.ts"),
      join(root, "tests", "helpers", "developer-probe.mjs"),
      join(root, "README.md"),
      join(root, "README.zh-TW.md"),
      join(root, "CHANGELOG.md"),
      join(root, "CONTRIBUTING.md"),
      join(root, ".github", "workflows", "release-candidate.yml"),
    ];
    const hits = paths.filter(
      (path) =>
        !/\.(png|jpe?g|gif|ico)$/i.test(path) &&
        forbidden.test(readFileSync(path, "utf8")),
    );
    expect(hits).toEqual([]);
  });
});
