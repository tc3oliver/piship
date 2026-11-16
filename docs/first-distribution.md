# Your first distribution

This page takes you from nothing to an installed, branded Pi command: `init`, `validate`, `test`, `build`, `install`. It builds a personal distribution, which signs in with Pi's own providers; a company distribution adds identity, a credential broker, and a gateway ([enterprise integration](enterprise-integration.md)). The commands below were run in this order on a clean checkout.

You need Node.js 22.19 or newer (and npm 11 or newer once you add Pi packages, for `piship lock`) and a PiShip checkout that has been built once:

```bash
git clone https://github.com/tc3oliver/piship ~/src/piship
cd ~/src/piship && npm ci && npm run build
```

On Windows, in PowerShell (these lines also work in Windows PowerShell 5.1, which has no `&&` and passes `~` to git unexpanded):

```powershell
git clone https://github.com/tc3oliver/piship "$HOME\src\piship"
cd "$HOME\src\piship"; npm ci; npm run build
```

## Run the CLI by path

PiShip is not published to npm, so there is no `piship` command on your machine. Run the CLI as `node <checkout>/packages/cli/dist/bin.js`. Do not try `npx` or `npm exec` with the name: they look it up on the public registry and run an unrelated package. Define a shell function so the rest of this page can write `piship` (a variable such as `PISHIP="node …"` does not run in zsh, the macOS default shell, which does not split it into words):

```bash
piship() { node "$HOME/src/piship/packages/cli/dist/bin.js" "$@"; }
```

The "Next:" lines the CLI prints already name the command that is running, so you can also copy them as they are.

`piship --help` lists the commands, and `piship help <command>` (or `<command> --help`) lists that command's options, one line each. A mistyped option is named in the error before the usage line.

On Windows, define the same function in PowerShell:

```powershell
function piship { node "$HOME\src\piship\packages\cli\dist\bin.js" @args }
```

An installed command is `%USERPROFILE%\.local\bin\<name>.cmd`, which cmd.exe and PowerShell both run; there is no `.ps1`, so the PowerShell execution policy does not apply. When that folder is not on `PATH`, `install` prints a PowerShell line that adds it for new terminals. Git for Windows turns LF into CRLF by default, which would make `piship.lock` stale on a clone, so `init` writes a `.gitattributes` that keeps LF.

## 1. Create it

```bash
mkdir -p ~/agents && cd ~/agents
piship init ./my-agent
```

In PowerShell:

```powershell
mkdir "$HOME\agents"; cd "$HOME\agents"
piship init ./my-agent
```

This writes `my-agent/piship.yaml` and `my-agent/resources/AGENTS.md`. The directory name becomes the distribution id and the command name, so it must start with a lowercase letter and use only lowercase letters, digits, and single hyphens. For a directory that does not follow that, such as `my_agent`, name the distribution yourself:

```bash
piship init ./my_agent --id my-agent
```

Without `--id` the error suggests the id to use. `init` writes a personal distribution; `--managed` writes a company template that asks for anything unlisted and opts into the `piship.routine@1` rule pack, so routine work (workspace edits, tests, builds, read-only git, search) does not prompt once `sandbox.required` is true. The template ships with `sandbox.required: false`, so until you set it every shell command (`git status`, `npm test`) asks; `validate` and `lock` warn about this, and the built command's `policy explain shell.execute "git status"` (`dist/<id>/bin/<id> policy explain …` before install; `piship policy` is not a command and says so) lists the pack rule that is inactive.

A personal distribution bundles Pi's search tools, `fd` and `rg` (`runtime.searchTools`), which `piship lock` downloads from GitHub. So `init` first checks, with a request of at most 3 seconds that follows `HTTPS_PROXY` and `NO_PROXY`, that github.com answers from where it runs. If it does not (an intranet without GitHub access, say), `init` leaves out `runtime.searchTools` and `https://github.com` in `release.sources`, so the first `lock` needs no download, and says so on stderr. It checks registry.npmjs.org the same way and only says so on stderr when it does not answer, because the first build needs it (step 3). Pi's `@` file completion and its find and grep tools then need `fd` and `rg` on `PATH`. Add the two entries later to bundle them ([bundled search tools](manifest.md#bundled-search-tools-v1alpha6)).

The manifest does not state `runtime.pi`. Left out, the build uses the Pi version this PiShip pins, so a PiShip upgrade does not break the manifest. State it only to refuse any other Pi.

## 2. Validate it

```bash
piship validate my-agent/piship.yaml
```

`validate` reads the manifest and its resources and writes nothing. Every command that takes a manifest (`validate`, `lock`, `build`, `test`, `dev`) also takes its directory (`my-agent`), and with no argument uses `./piship.yaml`; options may come before or after it. It reports every problem it finds in one run, each with the line and column in the YAML, and suggests a fix for the common mistakes: a misspelled field names the nearest valid one, an unquoted `version: 1.0` says to quote it, and `schema: piship/v2` names the current schema. Warnings do not fail it: an unused entry under `variables`, a setting that fails on some machines, and a declared skill that Pi would skip (a skills directory with no `SKILL.md`, or a `SKILL.md` without a description) are printed on stderr and the exit code stays 0.

## 3. Test it

```bash
piship test my-agent/piship.yaml
```

`test` builds the distribution into `dist/my-agent` under the directory you ran it in and starts its command headlessly in an isolated state directory. It ends with `Personal acceptance passed`, a short summary of what Pi loaded, and a `Next:` line naming `build` and the install command.

The first build or test downloads the runtime packages from the npm registry (registry.npmjs.org, or the registry npm is configured to use), which can take a few minutes; later builds use the cache. In a terminal it shows each step as it goes, such as `Installing the runtime packages (npm ci; needs npm registry access, up to 10 minutes)...`; without a terminal (a script or CI) it still prints that one line on stderr before npm starts, and `release` likewise before its npm audit.

The first time, there is no `piship.lock` yet, so `test` writes one and says so (`Created <path>/piship.lock: none existed, so nothing was reviewed yet`). The lock records the digest of every resource and the pinned runtime; review it, and commit it with `piship.yaml`.

## 4. Edit and repeat

`dev` runs the same isolated build and opens the command interactively; `dev --smoke` runs it headlessly.

```bash
piship dev my-agent/piship.yaml
```

To add to the distribution, put the file under `resources/` and declare it in `piship.yaml` under its trust class (`user` in a personal distribution). Paths start with `./` and stay inside the distribution directory:

```yaml
resources:
  instructions:
    user: [./resources/AGENTS.md]            # one Markdown file
  skills:
    user: [./resources/skills]               # skill directories, each with a SKILL.md
  extensions:
    user: [./resources/extensions/hello.ts]  # a file, or a directory with index.ts
  packages:                                  # Pi packages from npm, git, or a local path
    - { id: web, source: npm, package: "<npm name>", version: 1.2.3, class: user }
mcp:
  mode: explicit                             # `off`, the template's value, declares no server
  servers:
    notes:
      transport: stdio
      module: ./resources/mcp/notes-server.mjs
models:
  default: anthropic/claude-sonnet-4-5       # provider/model, as Pi lists it
  allowed: [anthropic/claude-sonnet-4-5]
policy:
  defaults:
    - { id: ask-push-main, action: git.push, resource: origin/main, effect: ask }
```

Each field is described in the manifest reference: [resources](manifest.md#resources-and-trust-classes), [Pi packages](manifest.md#pi-packages-v1alpha6), [MCP](manifest.md#mcp), [models](manifest.md#access-fields-v1alpha2-and-later), and [policy](manifest.md#policy). The [personal example](../examples/personal/piship.yaml) declares instructions, skills, an extension, prompts, a theme, and an MCP server. `test` reports what loaded (`resources  instructions 1, skills 1, extensions 1, ...` and one line per MCP server), and the built command's `policy explain <action> <resource>` shows which rule decides an action (`dist/<id>/bin/<command> policy explain git.push origin/main`).

After you change `piship.yaml` or a resource, run `dev` or `test` again. A lock that no longer matches is relocked for you (`Relocked <path>/piship.lock`). With Pi packages declared, that happens only while no package input changed (a package declaration, `packageTrust`, the release settings, or a stored package lockfile): packages are resolved over the network and pinned in the lock, so after such a change `dev` and `test` stop and ask you to run `lock` yourself. Bundled `fd` and `rg` are read from PiShip's download cache when the old lock pins them, so they do not stop it:

```bash
piship lock my-agent/piship.yaml
```

Run `lock` whenever you add or change a package, and check what changed in the lock before you commit it.

## 5. Build it

```bash
piship build my-agent/piship.yaml
```

`build` and `release` never write a lock for you: they require one that matches the manifest and its resources, and stop with `Lockfile is stale` or `Lockfile missing` otherwise. Run `test` or `lock` first. `build` also runs the supply-chain gates that `dev` and `test` skip. It prints that the result is an unqualified local build: it is not audited, has no SBOM, and is not signed. That is right for yourself. For something to hand to other people, build a qualified release with `release` ([release guide](release.md)).

## 6. Install it

```bash
node dist/my-agent/piship.mjs install dist/my-agent
```

The payload carries its own copy of the manager, so you run `piship.mjs` from the build output. Pass the build output, not the source directory: `install my-agent` from the directory above the source says to build it first and names `dist/my-agent`, and so does `doctor my-agent` unless a distribution with that id is installed, which it then checks. Install places the command in `~/.local/bin` (set `PISHIP_BIN_HOME` to change it) and tells you if that directory is not on your `PATH`. State that `test` created is adopted by the first install, so no flag is needed. On Linux these paths do not follow XDG: the install goes to `~/.local/share/piship`, the command to `~/.local/bin`, and state to `~/.piship/<id>` whatever `XDG_DATA_HOME`, `XDG_STATE_HOME`, or `XDG_BIN_HOME` say; set `PISHIP_INSTALL_HOME`, `PISHIP_BIN_HOME`, and `PISHIP_STATE_HOME` to move them (only the download cache follows `XDG_CACHE_HOME`).

On Windows the line `install` prints adds `%USERPROFILE%\.local\bin` to `PATH` for new terminals only, so open a new terminal before you run `my-agent`, or run `& "$HOME\.local\bin\my-agent.cmd"` in this one.

```bash
my-agent --help
my-agent
```

A personal distribution signs in inside Pi: run `my-agent` and use `/login`. A managed distribution instead needs its runtime variables set and a `my-agent login`; the install prints which.

To install a rebuilt copy over the one you have, run the install again with `--replace`; its state is kept.

Remove it with `node dist/my-agent/piship.mjs uninstall my-agent` (add `--purge --yes` to delete its state too). Uninstall keeps the state and prints the `purge` command that deletes it; after a release installed with its `install.sh`, that command names the extracted release's own `piship.mjs` while the directory is still there. Once nothing is left in them, uninstall and purge also remove the empty `apps` and `receipts` folders and, at their default locations, `~/.local/share/piship` and `~/.piship`. Commands that take an id (`uninstall`, `purge`, `update`) want `my-agent`, not a path: given `my-agent/piship.yaml` they say so and name the manifest's `app.id`.

## Where to go next

- Change what the agent loads or may do: [manifest reference](manifest.md).
- Ship it to other people with signed updates: [release guide](release.md).
- A company distribution with sign-in, a gateway, and a sandbox: [enterprise integration](enterprise-integration.md) and the [company demo](../examples/demo-company/README.md).
- Something failed: [troubleshooting](troubleshooting.md) lists every error code and what to do.
