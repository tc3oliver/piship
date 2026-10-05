# Developer distribution example

DevCode (`devcode`) is a batteries-included personal distribution on `piship/v1alpha6` for everyday software development. It is meant to be copied and edited. The point of the profile is that ordinary development work never prompts, and that the few actions with a real blast radius do:

- **No prompt for normal work.** Reading, editing, and writing files in the workspace, `grep` and `find`, `git status`, `diff`, and `log`, `npm`, `pnpm`, and `yarn`, `pytest`, `cargo`, `go`, compilers, linters, formatters, local servers, read-style MCP tools, and the tools of the packages below.
- **A prompt for the risky.** `sudo`, recursive deletes, destructive git, writes outside the workspace and outside temporary and cache directories, publishing and signing in, an executable the profile does not know, MCP tools that write, and the browser's script and upload tools.
- **A denial only for clear secrets.** Private keys, credential stores, `~/.ssh`, keychains, `~/.netrc`, `~/.config/gh/hosts.yml`, and the like. The rules name paths, never broad globs, so `.env.example`, a test fixture, and project configuration stay usable. A real `.env` and a non-fixture `.pem` ask.
- **Every default is a default.** A managed distribution built from [`managed.piship.yaml`](managed.piship.yaml) tightens it ([below](#hardening-for-a-company)), and a project's own configuration never loosens it.

It is `deployment.mode: personal` with `identity.mode: none` and Pi's own providers and sign-in, in isolated state at `~/.piship/devcode` (or `$PISHIP_STATE_HOME/devcode`), separate from `~/.pi`. Pi is pinned to 1.0.3.

## What is in it

Six Pi packages, each pinned to an exact version and bound by the lock:

| Package | What it gives the session | Left out |
| --- | --- | --- |
| `pi-code` 1.4.2 | Claude Code compatibility (rules, commands, skills, agents, hooks, `CLAUDE.md`, `.mcp.json`), `web_search` and `web_fetch`, plan mode, `todo`, `question`, `memory`, checkpoints and `/rewind`, `subagent`, `/goal` | Nothing |
| `pi-lens` 4.3.0 | Diagnostics, LSP navigation, ast-grep, formatting and lint feedback after every edit | The two skills about writing pi-lens rules |
| `pi-background-tasks` 2.6.9 | `bg_run`, `bg_status`, `bg_logs`, `bg_kill`; `/bg` and `/jobs` | Its delegate, Fusion, and attested features, and the extension that makes requests look like Claude Code's and reads `~/.claude.json` |
| `pi-review` 1.2.1 | `/review` and `/review-back` | Nothing |
| `pi-browser-use` 0.12.11 | `browser_*` tools over a headless Chrome | The two skills about signing in to Google accounts |
| `@gotgenes/pi-permission-system` 39.0.4 | The permission provider (`certified` class) | Nothing |

It also turns on Pi's Codemode and tool search (`runtime.tools`), ships one instruction file (`resources/AGENTS.md`), and ships one skill (`code-review-targets`).

Deliberately not added, because another package in the set already provides the tool or because the package makes requests look like another product: `pi-subagents`, `pi-web-access`, `@fradser/pi-memory`, `pi-mcp-adapter`, and separate todo, ask-user, plan, and dynamic-workflow extensions. A second package would register a tool name the first one already has; `--smoke` lists every registered tool and reports any such duplicate under `duplicateTools`, and the Portable E2E test asserts that it is empty.

## Requirements

- Node.js 22.19.0 or newer, as for every PiShip distribution. `piship lock` also needs npm 11 or newer and registry access. Building from the committed lock needs the registry too (it installs each package with `npm ci --ignore-scripts`); installing and the headless commands do not.
- `git` for the project-trust and review features. The GitHub CLI `gh` is optional: `/review` of a pull request uses it, and the profile lets it read pull requests, issues, and runs without a prompt.
- A system Chrome for the `browser_*` tools. `pi-browser-use` finds it through `CHROME_PATH` or the usual install locations and downloads no browser. Without Chrome the browser tools are not available and nothing else is affected.
- Node versions. `pi-browser-use` declares `engines.node >=24.18.0`, and PiShip itself is qualified on Node 22.19.0. npm only warns about an engine mismatch (`EBADENGINE`) unless `engine-strict` is on, and the package install PiShip runs takes its npm configuration from the environment it is started in. This repository's `.npmrc` sets `engine-strict=true`, and `npm run` and `npx` hand that on to what they start, so building this example through an npm script on Node 22 fails with `UPDATE_FAILED ... EBADENGINE` for `pi-browser-use`. Run the CLI by path, as in the commands below, or use Node 24.18 or newer; an `engine-strict=true` in your own npm configuration has the same effect on Node 22. On Node 22.19.0 with npm 11.21.0 and `engine-strict` off, the distribution builds and the end to end test passes. In a probe, the package's extension started `chrome-devtools-mcp` and registered all of its `browser_*` tools under Node 22.19.0 and under Node 24.21.0; that covers loading and listing the tools, not every page interaction. Treat Node 24.18 or newer as the package's own requirement.

## Build, install, and run

From the repository root:

```bash
npm ci
npm run build
node packages/cli/dist/bin.js validate examples/developer/piship.yaml
node packages/cli/dist/bin.js build examples/developer/piship.yaml
node dist/devcode/piship.mjs install dist/devcode
~/.local/bin/devcode --version
~/.local/bin/devcode --smoke
~/.local/bin/devcode doctor
~/.local/bin/devcode capabilities
~/.local/bin/devcode
```

The committed `piship.lock` and `piship.lock.d/` are current for this manifest and are used as they are. Run `node packages/cli/dist/bin.js lock examples/developer/piship.yaml` (npm 11 or newer) only after editing `piship.yaml` or a resource: the lock records the sha256 of the resources, each package's tree digest and file inventory, and the permission configuration, and a stale lock stops the build. Never edit it by hand.

`--smoke` starts Pi's real SDK without a model request and prints the registered tools, commands, skills, extension paths, and the governance summary. `doctor` reports the package environment (`PI_LENS_HOME`, `PI_BG_FEATURES`), whether the permission configuration is seeded, edited, or missing, and whether the permission provider is effective. On the first launch, sign in to a model provider as with plain Pi: the credential stays in DevCode's state. Install, uninstall, purge, update, and rollback work as for any distribution (the [personal example](../personal/README.md) walks through them, including Pi's own network use at launch). `updates` here pins no key, so `update` fails closed until you add your own `updates.trust.bootstrap`.

## What runs, what asks, what is denied

The decisions come from the permission provider, configured by the file the manifest seeds ([layers](#how-the-layers-fit)). In every table a rule applies to the command and to the paths it mentions.

### Without a prompt

| Area | What |
| --- | --- |
| Files | `read`, `write`, `edit`, `grep`, `find`, and `ls` in the workspace; reads anywhere outside it (toolchains, sibling repositories, caches) except the denied paths; writes to `/tmp`, the system temporary folders, and `~/.cache` |
| Inspecting | `cat`, `head`, `tail`, `wc`, `diff`, `rg`, `fd`, `jq`, `sed`, `awk`, `ps`, `lsof`, `which`, `echo`, `sleep`, and similar |
| Changing the workspace | `mkdir`, `touch`, `cp`, `mv`, `ln`, `rm` without a recursive flag, `tee`, `chmod` without `-R`, `tar`, `zip`, `patch`, and scripts the project holds (`./...`, `node_modules/.bin/...`, `.venv/bin/...`, `bash x.sh`) |
| Version control | `git` in general, `git clean -n`, and reading `git config`; `gh pr`, `issue`, `repo`, `run`, and `search` reads |
| JavaScript and TypeScript | `node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `deno`, `tsc`, `eslint`, `prettier`, `biome`, `vitest`, `jest`, `playwright`, `vite`, `next`, `turbo`, `esbuild`, and similar |
| Python | `python`, `pytest`, `uv`, `pip`, `poetry`, `pdm`, `tox`, `nox`, `ruff`, `black`, `mypy`, `pyright`, and similar |
| Other languages | `cargo`, `go`, `java`, `mvn`, `gradle`, `dotnet`, `ruby`, `bundle`, `php`, `composer`, `swift`, `flutter`, `dart`, `make`, `cmake`, `gcc`, `clang`, and similar |
| Containers | `docker ps`, `build`, `compose`, `exec`, `run`, `logs`, `inspect`, `pull`, and the like |
| MCP | `get_*`, `list_*`, `search_*`, `read_*`, `find_*`, `describe_*`, `fetch_*`, `query*`, and similar read-style tools, and the MCP status tools |
| Everything else the packages add | `web_search`, `web_fetch`, `todo`, `question`, `memory`, `subagent`, pi-lens tools, `bg_*`, and `browser_*` except the five below |

### Asks

| Area | What |
| --- | --- |
| Privilege | `sudo`, `doas`, `su`, `pkexec` |
| Bulk deletes | `rm -r`, `rm -rf`, `rm --recursive`, `find ... -delete`, `chmod -R` |
| Destructive git | `reset --hard`, `clean` (not the dry run), `push --force`, `-f`, `--delete`, `--mirror`, `branch -D`, `checkout -f`, `checkout` of existing paths, `restore` (except `--staged`), `stash drop` and `clear`, `reflog expire`, `filter-branch`, `remote add` and `set-url`, and `git config` writes |
| Publishing and signing in | `npm publish` and `login`, global installs (`-g`), `cargo publish`, `twine`, `docker push` and `login`, `docker ... prune`, `rm -f`, `--privileged`, and `down -v`, `gh api` |
| Outside the workspace | A write or edit outside it, except the temporary and cache directories above |
| Settings that change what runs next | A write to `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks/`, `.mcp.json`, `.pi/settings.json`, `.pi/extensions/`, `.git/hooks/`, and `.git/config` |
| Unknown executables | Any command not listed above, for example `ssh`, `scp`, `kubectl`, `terraform`, `brew`, `apt`, and `curl` and `wget` HTTP requests |
| Possible secrets | A read or write of `.env` and `.env.*` (not `.example`, `.sample`, `.template`, or `.dist`), and of `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, and `.keystore` files that are not under a `fixtures`, `fixture`, `__fixtures__`, `testdata`, `test`, `tests`, or `spec` directory |
| MCP that changes things | A tool whose name holds `create`, `update`, `delete`, `remove`, `write`, `replace`, `execute`, `merge`, `push`, `send`, `deploy`, or `drop`, and any tool the list does not recognize |
| Browser | `browser_evaluate_script`, `browser_upload_file`, `browser_switch_mode`, `browser_setup`, and `browser_reauth` |

### Denied

- Private keys, credential stores, and keychains for every tool, shell command, and path a command mentions: `~/.ssh`, `id_rsa`, `id_ed25519` and the other key names, `~/.gnupg`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.cargo/credentials`, `~/Library/Keychains`, `*.kdbx`, `/etc/shadow`, and the credentials of this distribution (`~/.pi/agent/auth.json`, `~/.pi/browser-profile`, the state's `auth.json` and `secrets`).
- The commands that print a credential: `gh auth token`, `security find-*`, `security dump-keychain`, `security export`, `aws configure get`.
- A write by the agent to `.pi/extensions/pi-permission-system/`, so a session cannot rewrite its own rules.
- The same secret paths a second time, as eighteen `dev.secret.*` rules in `policy.enforced` for PiShip's governed `read`, `write`, and `edit`. Those hold in every layer, and neither a project file, a user rule, nor `--yolo` relaxes them.

The profile does not deny `.env`, `.env.example`, `*.pem`, `*.key`, `.mcp.json`, `package.json`, or anything under `tests/fixtures`. The Portable E2E test runs about seventy cases of this table through the real provider, and the unit test checks that no deny rule matches those names.

## `--yolo`

`devcode --yolo` starts a session in which the asks above are approved without a prompt. A personal distribution always allows it. For this profile it does two things, and only for that session:

- PiShip's own `--yolo`: every `ask` PiShip's policy would put to you is approved. This profile's `policy.default` is `allow`, so there is little to approve.
- The permission provider's own auto-approval: the manifest names the provider's file and key (`autoApproveFile`, `autoApproveKey: yoloMode`), so PiShip sets `yoloMode` to `true` in `<state>/agent/extensions/pi-permission-system/config.json` for the launch. Without that, `--yolo` could not reach a prompt the provider raises itself, which is nearly all of them here. The file is put back when the process exits, when `/auto off` ends yolo, and at the next launch if the process was killed. A change you make with `/permission-system` during the session is kept.

Denials do not change: the provider's deny rules and the enforced policy rules still apply. The status line shows `YOLO`, and `/auto off` ends it. The Portable E2E test checks that the key is on during a launch and off after it, and that a killed launch is repaired by the next one.

## How the layers fit

1. **PiShip policy** (`policy.enforced`, in the manifest). The `dev.secret.*` denies for governed file tools. They are in the lock, cannot be relaxed, and win over every other layer.
2. **The permission provider** (`@gotgenes/pi-permission-system`, `certified` class). Decides each tool call, each bash command and the paths it mentions, each MCP call, and each path any tool touches. It is declared through `capabilities.permissions` with `provider.package: pi-permission-system`, so its class and review evidence come from the package: the `integrity` in the manifest is the tree digest the lock records, and the capability is effective only while the files match.
3. **Its configuration** is the `agentFiles` entry of that package: `extensions/pi-permission-system/config.json`, with `mode: seed`. A seed is written once, owner-only, and a copy you edited is kept. A later DevCode release replaces the file only while it is still exactly what DevCode wrote. Edit it by hand or with `/permission-system`; `devcode doctor` shows whether it is seeded, edited, or missing. In `enforce` mode (the managed variant) the file is rewritten at every launch, so an edit does not outlive one.

In the rule maps, the last matching rule wins. A broad rule comes first and its exceptions after it, so the order of keys in the file is part of the policy. The secret denies are last in the `path` map for that reason: the ask for `*.pem` above them cannot outrank the deny for `~/.ssh`, so `~/.ssh/ec2-keypair.pem` stays denied. A bare `path` rule covers both reads and writes; `path_write`, `external_directory_read`, and `external_directory_write` narrow it.

The two layers are not redundant. PiShip's rules cover its own governed tools only, and the provider covers shell commands and the other packages' tools. `policy.default` is `allow` so that PiShip does not ask a second time for a command the provider already decided.

## Claude Code compatibility

`pi-code` reads Claude Code configuration: `CLAUDE.md`, `.claude/rules`, `commands`, `skills`, `agents`, `hooks`, `settings.json`, and `.mcp.json`. PiShip decides it by where the project came from, with five dimensions (`claudeRules`, `claudeCommands`, `claudeSkills`, `claudeAgents`, `claudeHooks`) beside the eight older ones. The manifest declares all thirteen for all three origins:

| Origin | The five Claude dimensions | `agents`, `mcp` | `extensions` | `hooks`, `providers` |
| --- | --- | --- | --- | --- |
| `company` | `allow` | `allow` | `ask` | `deny` |
| `external` | `allow` | `allow` | `ask` | `deny` |
| `unknown` | `ask` | `ask` | `ask` | `deny` |

`passiveContext`, `instructions`, and `skills` are `allow` for every origin. A repository you cloned today is `unknown`, so the project's Claude configuration is asked about once per launch before it loads, and nothing loads when nobody can be asked (a headless run). A repository is `company` or `external` only when you say so:

```yaml
policy:
  projectTrust:
    company:
      match:
        - path: "/home/you/src/**"
        - remote: "git.example.com/you/**"
    external:
      match:
        - remote: "git.example.com/other-org/**"
```

`path` is a glob over the absolute project root and `remote` a glob over the normalized `host/path` of the `origin` remote; a matcher with both needs both. A `remote` alone is a claim, because a checkout declares its own remote. Edit the copy, run `piship lock`, and rebuild. `company` is for your own repositories, `external` for third-party ones you have decided to read.

To close the part that runs commands, set `claudeHooks` to `deny` for all three origins (or `ask` for the first two). The profile admits hooks for `company` and `external` projects because the same files configure Claude Code for them, and hooks run with your privileges. The fixture used by the tests (`tests/fixtures/developer/claude-project`) ships a rule, a scoped rule, a command, a skill, an agent, an import, and a `SessionStart` hook, and the Portable E2E test checks that all of it is loaded for a `company` project and none of it for an `unknown` project in a headless run.

### Not governed

This is a short statement of limits that are also in [security](../../docs/security.md#project-configuration-that-an-extension-loads-itself) and [manifest](../../docs/manifest.md#claude-code-project-configuration). They apply to this profile as written:

- pi-code's **user scope** is not governed. It reads `~/.claude` (or `CLAUDE_CONFIG_DIR`), `~/.claude.json`, installed Claude plugins, and its own managed-settings file, whatever the project's trust is. They are your files, not the project's. The managed variant sets `CLAUDE_CONFIG_DIR` to a directory in the state and filters pi-code's readers out.
- pi-code's **own MCP client** starts the servers named in `.mcp.json`, `.pi/mcp.json`, and your files itself. Those starts are not `mcp.server.start` decisions, are not limited by `exposure`, and do not run in a sandbox. `mcp.mode: explicit` and `mcp.project: deny` in this manifest govern PiShip's MCP and do not reach pi-code's.
- An **admitted `.claude/settings.json`** can run hooks, inject environment variables, and run a status-line command with your privileges, outside the sandbox. PiShip decides by dimension and by whether the file exists, never by what it contains.

## Review targets

`/review` takes free text, not a target: the `pi-review` command has no arguments for a branch, a commit, a pull request, or a file list. The `code-review-targets` skill is how a review gets a subject. Ask in words ("review this branch against main", "review commit abc123", "review PR 42", "review src/auth") and the skill tells the model how to resolve each: uncommitted changes, a branch against its merge base, one commit or a range, a pull request through `gh`, or named files. Nothing is passed to `/review` as a flag. `/review` starts a new branch of the conversation for the review, and `/review-back` returns to the reviewed branch with the findings in the editor.

## Codemode, tool search, and MCP

`runtime.tools.codemode` and `toolSearch` are `"on"`, so the model can script several tool calls in one step and discover deferred tools. A call a script makes is a normal tool call and goes through the permission provider and the policy as any other ([architecture](../../docs/architecture.md)). The Portable E2E test registers `codemode` and `tool_search` but does not run a script.

pi-code brings its own MCP client, and the profile keeps it: it is how a developer's `.mcp.json` works. That is the limit listed above. `pi-mcp-adapter` is not added, because it would register the same tools a second time.

## Background tasks

`bg_run`, `bg_status`, `bg_logs`, and `bg_kill` run long-lived commands (a dev server, a watcher). The package is configured with `PI_BG_FEATURES=process`, which leaves out its delegate, Fusion, and attested features, and `PI_BG_DISABLE_UPDATE_CHECK=1`. `exposure` hides `bg_delegate`, `bg_result`, `bg_run_pi_attested`, and `fusion_*` as well, so none registers even if a later package version changes its default. The package's Claude Code attribution extension is not in the package filter, so it is never loaded, and the lock inventory does not list it.

The permission provider sees `bg_run` through `shellTools`: its `command` argument is matched as a bash command, so `bg_run` of `npm run dev` runs and `bg_run` of `sudo ...` asks. `bg_run` still runs outside PiShip's sandbox and governed `bash` ([limits](#known-limits)).

Pi renames a command two packages register: pi-code's `/tasks` and the background package's `/tasks` appear as `/tasks:1` and `/tasks:2`.

## The browser

`pi-browser-use` starts `chrome-devtools-mcp` and a headless Chrome at the start of a session and registers the `browser_*` tools. The five that act with a logged-in profile or run script ask ([asks](#asks)); the profile's own browser files are denied to the agent.

- Its profile (`~/.pi/browser-profile`) and its settings are under `~/.pi`, not under DevCode's state: it ignores `PISHIP_STATE_HOME`. `purge` does not remove them, and the example's rules deny the agent that profile because it holds logged-in sessions.
- It reads a project's `.pi/settings.json`, including `executablePath`, when the project is trusted. A repository that sets `executablePath` there makes the browser tools start a different program. A write by the agent to `.pi/settings.json` asks (above); a file the repository already ships is read as it is.
- `chrome-devtools-mcp` checks for a newer release when it starts, and no environment variable in this profile switches that off.
- The two skills that walk through signing in to Google accounts (`auth-bootstrap`, `gmail-auth`) are filtered out.

## pi-lens

`pi-lens` runs diagnostics and formatters after an edit, and gives the model navigation tools. Its behavior on the network is the part to know:

- It **installs** linters and language servers on first use, into `PI_LENS_HOME`, which the manifest points at `<state>/pi-lens`: the install stays inside DevCode's state, and `purge` removes it. The installs come from package registries and GitHub releases.
- It resolves a **GitHub token** for those release downloads. In pi-lens 4.3.0's source it runs `gh auth token` or reads `GH_TOKEN` or `GITHUB_TOKEN`, and sends the token as an authorization header to `api.github.com`. This is the package's own process, not a command the model ran, so the deny on `gh auth token` above (for the agent's bash) does not apply to it. This comes from reading the source, not from captured traffic.
- It fetches **tree-sitter grammar files** from `unpkg.com`.
- To stop all installs, set `PI_LENS_DISABLE_TOOL_INSTALL=1` and `PI_LENS_DISABLE_LSP_INSTALL=1`, as [`managed.piship.yaml`](managed.piship.yaml) does. It then uses only what is already on the machine. To keep the token out of it, do not sign in with `gh` and do not export `GH_TOKEN` or `GITHUB_TOKEN`.

## Hardening for a company

[`managed.piship.yaml`](managed.piship.yaml) is the same profile as a managed distribution. It is validated by the test suite but not locked or built, because a company supplies its own identity provider, credential broker, and gateway: copy it next to your own resources, set those, and run `piship lock`. What changes, and why:

- `policy.default: ask`, and `userAuto` is not declared, so `--yolo` is refused. The secret denies are enforced rules, and a `sudo` deny is added.
- The packages are `company` class, because a managed distribution denies the `user` class. The package trust stays strict.
- `pi-browser-use` and `pi-background-tasks` are not shipped. The browser keeps a logged-in profile under `~/.pi`, and `bg_run` starts commands outside the sandbox and the shell policy.
- `pi-code` keeps its tools and loses its readers of Claude Code configuration (MCP client, hooks, `env` settings, rules, commands, skills, imports, output styles) by a package filter, and its `CLAUDE_CONFIG_DIR` is moved into the state.
- `pi-lens` installs nothing and uses what the machine has. Codemode is off, because a managed distribution must give every tool a script can reach an explicit policy rule.
- The permission configuration is `enforce` mode: rewritten at every launch. `permissionReviewLog` is off.
- All five Claude dimensions are declared for all three origins: `claudeHooks` is `deny`, and the other four are `company-approved`, which admits no project content until the company declares `allow` for an origin it trusts. Its `company.match` combines `remote` with `path`.
- The sandbox is required. The default HTTP dispatcher admits declared hosts only; child processes require organization egress controls.

## Known limits

- **User scope of pi-code.** `~/.claude`, `CLAUDE_CONFIG_DIR`, `~/.claude.json`, and Claude plugins load whatever the project's trust is, and are not decided by PiShip. See [Claude Code compatibility](#not-governed) and [security](../../docs/security.md#project-configuration-that-an-extension-loads-itself).
- **pi-code's MCP client** starts MCP servers itself, bypassing `mcp.server.start` and the sandbox.
- **An admitted `.claude/settings.json`** can run hooks, environment, and a status-line command. PiShip decides by dimension and by presence, not by content. Set `claudeHooks: deny` to close it.
- **The permission provider's project file.** In personal mode, once a project is trusted, the provider reads `.pi/extensions/pi-permission-system/config.json` from the repository over the seeded one, and a repository can change its rules for that project. The `path_write` deny stops the agent writing that file. The provider withholds an untrusted project's file by its own code (`includeProjectScope` follows the session's trust flag); that was read in the package and not exercised here. PiShip's enforced secret denies are not affected.
- **The sandbox does not reach everything.** With `sandbox.required: true` in a copy on Linux or macOS, `bash` and `!` commands run inside it. `bg_run`, the browser, and each package's own file access do not.
- **The review log holds command strings.** `permissionReviewLog` is `true` in this profile, and the provider writes each decision with the command under `<state>/agent/extensions/pi-permission-system/logs/`. A secret typed on a command line ends up there. It is off in the managed variant.
- **`--yolo` in a managed distribution** that declares `policy.userAuto: allowed` and names a provider's auto-approval key approves the provider's own asks as well as PiShip's. The example declares neither.
- **Browser state** is in `~/.pi`, not in DevCode's state, and the browser's update check cannot be turned off here ([the browser](#the-browser)).
- **pi-lens** installs tools and uses a GitHub token ([pi-lens](#pi-lens)).
- **Seeded configuration is a default.** `seed` keeps a file you edited. A rule that must hold goes in `enforce` mode or in `policy.enforced`, as the managed variant does.
- **Node.** `pi-browser-use` declares Node 24.18 or newer. On Node 22.19.0 it was only checked to load and register its tools, and a strict engine check (`engine-strict=true`, which this repository's `.npmrc` sets and npm scripts pass on) stops the build there ([requirements](#requirements)).

## Install scripts

The build installs each package with `--ignore-scripts`, and PiShip never runs a dependency's install script. `release.installScripts` lists the two a reviewer read for this lock, each pinned by package path and version, so a release that gains another one fails:

- `@ast-grep/cli@0.45.3` (a dependency of `pi-lens`): a `postinstall` that hard-links or copies the platform binary from its own optional package over the package's `ast-grep` shim. It reads files inside `node_modules`, runs nothing, and uses no network. Without it the shim still resolves the binary at run time.
- `tree-sitter-bash@0.25.1` (a dependency of the permission provider): an `install` of `node-gyp-build`, which loads a native binding from `prebuilds/` and compiles from source only when none matches. The provider loads the package's WebAssembly parser through `web-tree-sitter` and never the native binding.

## What the tests cover

- `tests/developer-example.test.ts` (unit tier) checks both manifests parse, the committed lock is current, every package version is exact, the packages the profile does not add are absent, the certified provider's integrity equals the locked tree digest, the permission configuration is well formed and denies no name a developer needs, the managed variant, the release wiring, and that the example has no private product name.
- `tests/e2e/developer-profile.test.ts` (Portable E2E tier) builds the distribution from the committed lock and runs: the payload inventory; `--smoke` tools, commands, skills, and duplicate-free registration; the effective, locked provider; `PI_LENS_HOME` in the state; the seeded file, owner-only and never overwritten once edited; about seventy allow, ask, and deny cases through the real provider; `--yolo` setting and restoring the provider key, and recovering from a killed launch; `doctor`; the browser tools (skipped without Chrome); and a Claude Code fixture repository, closed for an unknown origin and loaded for a matched company origin.
- `packages/schema`, `packages/core`, and `packages/pi` carry the unit tests of the `environment` and `agentFiles` fields ([manifest](../../docs/manifest.md#what-a-package-is-given-environment-and-files)), the lock and diff of them, and the package-provider capability.
- The Release candidate workflow builds DevCode twice per target, compares the payload files by SHA-256, and runs the offline `--smoke` and `doctor` on the release.

Not verified: a real model session with these tools (no model request was made); a Codemode script through the provider; a page interaction in the browser beyond starting it and listing its tools; Windows, where the permission, `--yolo`, and Claude fixture cases are skipped; the managed variant built and launched against a real identity provider, broker, and gateway; and the behavior of an untrusted repository's `.pi/extensions/pi-permission-system/config.json` end to end.

Shell HTTP clients always ask, including loopback requests: wildcard command rules cannot validate every URL host or safely handle multiple destinations. Git commands starting with global options also ask because their subcommand cannot be classified by these command patterns. `env` and `timeout` wrappers ask; direct commands and shell variable assignments retain their ordinary decisions. Safe wrapper normalization requires upstream provider support.
