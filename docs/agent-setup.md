# Setting up a distribution with a coding agent

This page is written for a coding agent (Claude Code, Codex, Pi, or similar) that a person has asked to set up a PiShip distribution. A person can follow it too. The [README](../README.md#set-it-up-with-your-coding-agent) has the prompt that points an agent here.

A distribution is either **personal** (one person, no company services) or **managed** (a company rolls it out behind its own sign-in, broker, and gateway). The two share the first questions and the completion checklist; everything else is a separate branch below. Work through steps 1 to 8 in order to set up a new distribution; to move an existing one to a newer PiShip, use [step 9](#9-upgrade-an-existing-distribution) instead. Stop and ask the person whenever a step needs a value you do not have; never invent a URL, client ID, model ID, repository host, or company name.

## Rules

- **No secrets in files or commands.** `piship.yaml`, `piship.lock`, `piship.lock.d/`, and `resources/` are committed, and the schema rejects secret-looking values anyway. Never put an API key, client secret, token, password, or private signing key in them, in a shell command, or in your reply. Endpoints go in as runtime variables (`${NAME}`) or plain URLs (`https`, or `http` on loopback, or on an internal host for an endpoint the person explicitly opted in with `httpTransport: http-allowed`). Keys are typed by the person at the branded command's own prompts (`login`, `sandbox login`, Pi's `/login`), never by you.
- **Leave the person's existing setup alone.** Do not read, change, or delete `~/.pi`, and do not uninstall or overwrite another installed distribution. A distribution keeps its own state under `~/.piship/<id>`.
- **Ask before installing.** `install` writes a command into `~/.local/bin`. Say what it will add and get a yes first. The same goes for `uninstall`, `purge`, and editing a shell profile.
- **Run the CLI by path.** PiShip is not on npm. Use `node <piship>/packages/cli/dist/bin.js`; npx or `npm exec` would fetch an unrelated package from the public registry.
- **Always pass the mode.** Run `init` with `--personal` or `--managed`, never without a flag, so the mode is a decision the person made.
- **Do not create release keys on your own.** `piship keygen` makes a key future updates are signed with. Run it only when the person asks, and tell them where the private key is so they can move it somewhere safe; it is never committed.
- **Report what you could not check.** If a command fails or a step was skipped, say so with the error. Do not describe a distribution as working until the [completion checklist](#6-setup-completion-checklist) passes.

## 1. Get PiShip

Clone it outside the person's project, where they agree (the default here is `~/src/piship`), and build it:

```bash
git clone https://github.com/tc3oliver/piship.git ~/src/piship
cd ~/src/piship && npm ci && npm run build
```

It needs Node.js 22.19.0 or newer (`node --version`), and npm 11 or later (`npm install -g npm@11`) to lock a distribution that declares Pi packages. Below, `piship` means `node ~/src/piship/packages/cli/dist/bin.js`.

## 2. Ask the person

Ask the shared questions and the questions of the person's branch; if they have not said which branch, ask question S1 first. Say that any question can be answered "not sure yet"; collect those as open items instead of guessing. Do not paste the whole list as one message:

- If your harness has a structured question tool (Claude Code's `AskUserQuestion`, for example), ask the questions that have a fixed set of answers with it: a few per call, each with its options and the recommended one first. Examples are S1, S10, S12, S13, M8 user auto, M9 network, M11 required, and M12 now or later.
- Ask for values the person must type (URLs, tenant and client IDs, group IDs, model IDs and limits) as text, at most three at a time.
- Wait for each batch of answers before asking the next. At the end, show the open items.

### Shared questions

- **S1. Mode.** Personal (just me, no company services) or managed (a company rolls it out)?
- **S2. Name and command.** Product name and the command people will type, for example `AcmeCode` and `acmecode` (lowercase letters, digits, hyphens). Optional: a one-line banner and a theme.
- **S3. Repository.** Where the distribution repository should live (not inside the PiShip clone).
- **S4. Instructions.** What the agent should always know: coding conventions, main repositories, things it must never do. This becomes `resources/AGENTS.md`.
- **S5. Skills.** Existing skills to ship with it, and where they are now.
- **S6. Extensions.** Pi extensions to ship with it, and where they are now.
- **S7. Prompts and themes.** Prompt templates or themes to ship with it.
- **S8. Operating systems.** macOS, Linux, Windows. Windows has no native sandbox.
- **S9. MCP** (optional). MCP servers the agent should use: name, URL or command, and which tools. For an internal server, also whether it is served without HTTPS and whether it identifies the user by a request header (which header, and which identity claim such as the username).
- **S10. Sandbox** (optional for personal). Should commands the agent runs be contained, and must a launch fail when the sandbox is unavailable?
- **S11. Updates and rollback.** Is installing a new build by hand enough, or should installed copies update from a signed channel, with rollback to the previous release?
- **S12. Prompt cache warming** (optional). PiShip keeps Pi's prompt cache warming off unless the distribution says otherwise; v0.8 sessions warmed it. Keep it off, or `streaming` or `idle`? May users change it?
- **S13. Codemode and tools** (optional). Should the agent run scripts that call its tools (Pi's Codemode: `off`, `on`, or `only`), and should tool search be on? Is any tool to be hidden from the model, or only discoverable on demand?
- **S14. Pi packages** (optional). Pi packages to ship (npm, git, or a local directory): the source, an exact version or full commit, and the class (`user`, `company`, or `certified`). The machine that runs `piship lock` needs npm 11 and access to the registry or git host.
- **S15. Data retention and session export** (optional). How long may sessions, audit logs, and cache stay on a machine, and which of them should `logout` delete? May users export sessions (`/share`, `/export`, `/bug`)?

### Personal branch

A personal distribution needs no OIDC provider, credential broker, company gateway, or audit collector.

- **P1. Model access**, one of:
  - Pi's own sign-in and providers (the default);
  - an OpenAI-compatible endpoint that needs a key (kept in the distribution's own secret store);
  - a local OpenAI-compatible endpoint with no key (llama.cpp, Ollama, vLLM, LM Studio);
  - a self-hosted model server on another machine.

  For anything but Pi's providers: the base URL, the model IDs it serves, and each model's context window and maximum output tokens.
- **P2. Personal resources.** Answers S4 to S7 go under the `user` class.
- **P3. Sandbox.** Off or required (S10).
- **P4. MCP.** The personal servers from S9, if any.
- **P5. Signed updates** (optional, only if S11 asked for them): where the channel will be hosted. The person runs their own signing key. Does the update host have HTTPS? If not, may updates be fetched over plain HTTP from that internal host? (Integrity is still guaranteed by signatures; default: HTTPS only.) This is about the update channel only: OIDC, the broker, and the gateway each have their own opt-in (M1 to M3).

### Managed branch

- **M1. OIDC.** Issuer URL and the client ID of a **public** client (PKCE, no client secret). Its allowed redirect URIs must include the loopback `redirectUri` in the manifest, by default `http://127.0.0.1:8765/callback`. Does the broker need an `audience` or extra scopes? Is the identity provider served over HTTPS? If not, it can be opted in with `identity.oidc.httpTransport: http-allowed`, but sign-in tokens, including the refresh token, then travel unencrypted; recommend an internal CA instead. (Default: HTTPS only.)
- **M2. Broker.** Credential broker endpoint and its revoke endpoint. Is it served over HTTPS? If not, is it on an internal host, and does the company accept that the identity token and the issued credential travel unencrypted? (Default: HTTPS only.)
- **M3. Gateway.** LLM gateway base URL, and whether it speaks `openai-completions` (the default) or `openai-responses`. Is it served over HTTPS? If not (such as `http://10.20.30.40:4000/v1`), does the company accept that the credential and every prompt travel unencrypted on the LAN? (Default: HTTPS only.)
- **M4. Model governance.** The model IDs people may use, which one is the default, and each model's context window and maximum output tokens.
- **M5. Runtime variables.** Endpoints as runtime variables set on each machine (the template's default) or fixed `https` URLs in the manifest? How will the variables reach each machine?
- **M6. Proxy and enterprise CA.** A company proxy or CA bundle, if the network needs one, and the bundle's path on each machine.
- **M7. Project trust.** Which repositories count as company projects: the git host and organization (for example `git.acme.example/platform/**`) and, ideally, where they are checked out. Everything else is unknown, and its `AGENTS.md`, skills, and MCP files are not loaded.
- **M8. Policy.** Shell commands to always allow, always deny, or ask about. Anything unmatched asks the person. Also ask whether any rule is meant for web requests, browsers, sub-agents, or memory: PiShip cannot enforce those, so a `deny` or `ask` rule on them needs the person's explicit acknowledgement.
  - **User auto.** May users turn on auto mode themselves (every `ask` becomes `allow` for that user, `deny` and enforced rules still apply, and auto-approved actions are audited)? Default: no.
- **M9. Sandbox.** The OS sandbox on each machine, or a remote one (a CubeSandbox or other E2B-compatible service, Kubernetes Agent Sandbox, or the company's own adapter)? For a remote one: its API URL, template or pool, working directory, and how it authenticates. Should commands in it reach the network (with `deny`, `npm install`, `pip install`, and `git fetch` fail inside it)? Extra paths the agent may write, or must never read?
- **M10. Governed MCP.** The approved servers from S9 and the tools each may expose.
- **M11. Audit.** An audit collector URL, and whether a launch must fail when it is unreachable.
- **M12. Managed update source** (can wait until the first version works): where releases will be hosted, and who holds the release signing keys. Does the update host have HTTPS? If not, may updates be fetched over plain HTTP from that internal host? (Integrity is still guaranteed by signatures; default: HTTPS only.) This is about the update channel only: OIDC, the broker, and the gateway each have their own opt-in (M1 to M3).
- **M13. Search tools.** Should each release ship `fd` and `rg`, so Pi's find and grep tools and `@` file completion work on machines that do not have them installed? A managed launch never downloads them. Default: yes, unless every machine already has both on `PATH`. Any version the company has reviewed, or PiShip's defaults?

## 3. Create the repository

```bash
piship init <directory> --personal
piship init <directory> --managed
```

Run exactly one, matching S1. `--personal` and `--managed` together are refused. `init` writes `piship.yaml` and `resources/AGENTS.md` into an empty or new directory. The [manifest reference](manifest.md) describes every field; the [personal example](../examples/personal/piship.yaml), its [local-model variant](../examples/personal/local-model/piship.yaml), the [developer example](../examples/developer/piship.yaml) (six Pi packages, a permission provider, and its [hardened managed variant](../examples/developer/managed.piship.yaml)), and the [demo company manifest](../examples/demo-company/piship.yaml) are complete examples to copy from.

The managed template validates as generated. Every company-specific endpoint in it is a runtime variable named after the directory (`ACME_AGENT_OIDC_ISSUER` and so on, listed with a comment at the top of `variables`), and its model is a placeholder, `example/coder`, that must be replaced before the first build is handed out. Its updates stay disabled until an update source and its signing trust are configured.

## 4. Where each answer goes

### Shared

| Answer | Field | Watch out for |
| --- | --- | --- |
| S2 Name, command | `app.id`, `app.name`, `app.command`; optional `app.banner`, `app.theme` | `init` uses the directory name for all three; keep `app.version: 1.0.0` for the first release |
| S4 Instructions | `resources/AGENTS.md` | Write it in the person's words |
| S5–S7 Skills, extensions, prompts, themes | Copy them under `resources/`, then list them in `resources.skills`, `resources.extensions`, `resources.prompts`, `resources.themes` | Personal: the `user` class. Managed: the `company` class. Paths start with `./` and stay inside the repository |
| S8 Operating systems | `release.targets` | Only needed for `piship release` |
| S10 Sandbox | `sandbox.required`, `sandbox.network.mode`, `sandbox.filesystem` | `required: true` stops the launch when the sandbox is missing, which on Windows is always. A declared path list replaces the defaults: restate them, as the demo manifest does |
| S11 Updates | `updates.source` and the update trust fields | See [step 7](#7-signed-updates-and-rollback) |
| S12 Cache warming | `runtime.cacheWarming.mode` (`off`, `streaming`, `idle`) and `userOverride` | Omitted means `off` (v0.8 warmed through Pi's default). A managed distribution enforces the mode; a declared mode is enforced unless `userOverride: true` |
| S13 Codemode, tools | `runtime.tools.codemode` (`off`, `on`, `only`), `toolSearch` (`off`, `on`), and `exposure` (a map of `<tool glob>` to `direct`, `model-only`, `codemode`, `deferred`, or `hidden`) | Off by default. A managed distribution with Codemode on needs a `tool.execute` policy rule for `read`, `write`, `edit`, and `bash`, or `validate` fails with `POLICY_DENIED`. A policy `deny` on a tool hides it from the model |
| S14 Pi packages | `resources.packages[]` (`id`, `source: npm`, `git`, or `local`, `class`) and `packageTrust` | `piship lock` needs npm 11 and network access. A registry other than npmjs must be listed in `release.sources`, or `lock` fails the `source` gate. Managed needs a full commit SHA for git and `packageTrust.local.paths` for local. Commit `piship.lock.d/` ([manifest](manifest.md#pi-packages-v1alpha6)) |
| S15 Retention, export | `data.sessions.retention`, `data.audit.retention`, `data.cache.retention` (for example `30d`), `data.purge.onLogout`, and `data.export.<resource>` (`public`, `local`, `support`) | Audit retention is a minimum, and `purge.onLogout` may not name `audit`. `data.purge.onUninstall` is recorded but `uninstall` does not apply it. PiShip cannot block `/share` or `/export`, so a managed `data.export.public: deny` needs `"session.export:public"` in `policy.acknowledgeUnenforced` ([manifest](manifest.md#session-export)) |

### Personal

| Answer | Field | Watch out for |
| --- | --- | --- |
| P1 Pi's providers | `credential.provider: pi-native`, `inference.provider: pi-native` (the template's default) | The person signs in with Pi's `/login` inside the command; the key stays in the distribution's state, not `~/.pi` |
| P1 Endpoint with a key | `credential.provider: local-secret` with `storage.provider: system`, `inference.provider: openai-compatible`, `inference.baseUrl`, `models` | Copy the [local-model variant](../examples/personal/local-model/piship.yaml); the person types the key at `<command> login` |
| P1 Local endpoint, no key | As above with `credential.provider: none` and no `storage` | `http` is allowed only on loopback |
| P1 Self-hosted model | As above; `inference.baseUrl` is the server's `https` URL, or a runtime variable | Every allowed model needs a catalog entry with `name`, `contextWindow`, `maxOutputTokens`; `tools: true` for tool-calling models |
| P3 Sandbox | `sandbox.required: false` (no sandbox) or `true` | |
| P4 Personal MCP | `mcp.mode: allowlist`, `mcp.servers.<id>` with `transport`, `url` or `module`/`command`, and `tools` as an exposure map: `<tool>: direct` for each tool the person named, then `"*": hidden` | Only servers the person named. `tools.allow` and `tools.deny` are v1alpha5 syntax and fail `validate` |
| P5 Update host without HTTPS | `updates.transport: https` (default, omit it) or `http-allowed` | `http-allowed` only with `updates.trust.bootstrap`, and only for a private or internal host (an RFC 1918 address, a single-label name that is not a public TLD, or a name such as `*.internal`, `*.lan`, `*.local`); a public host fails `validate`. It changes nothing for any other endpoint |

### Managed

| Answer | Field | Watch out for |
| --- | --- | --- |
| M1 OIDC | `identity.oidc.issuer`, `clientId`, `redirectUri`, `scopes`, `audience` | `scopes` must include `openid`; no `clientSecret` |
| M2 Broker | `credential.broker.endpoint`, `revokeEndpoint`; `credential.broker.httpTransport: http-allowed` only for a broker without HTTPS | It must follow the [broker contract](enterprise-integration.md#credential-broker-http-broker). `http-allowed` accepts plain HTTP only to a private or internal host (a public one fails `validate`), for the broker's own origin; tell the person what travels unencrypted ([security](security.md#plain-http-to-internal-endpoints)) |
| M3 Gateway | `inference.baseUrl`, `inference.api`; `inference.httpTransport: http-allowed` only for a gateway without HTTPS | As for M2. The credential is replayable by anyone on the network path until it expires, so also suggest a short key lifetime. An MCP server with `credential: runtime` on the gateway's origin still needs HTTPS |
| M4 Models | `models.default`, `models.allowed`, `models.catalog.<id>` | Replace `example/coder`. Every allowed ID needs a catalog entry. The template's `distribution.models` rule (`model.select` on `<app.id>/**`) covers them; to narrow it, write `<app.id>/<model>` |
| M5 Runtime variables | `variables` plus `${NAME}`, or plain `https` URLs | Every `${NAME}` used must be listed in `variables`, and every listed name used. Names that look like secrets are rejected |
| M6 Proxy, CA | `network.proxy.inheritEnvironment`, `network.tls.additionalCA` | An absolute path on each machine |
| M7 Project trust | `policy.projectTrust.company.match` with `remote` and `path` | `remote` alone is only a claim; pair it with `path` |
| M8 Policy | `policy.enforced` (cannot be relaxed) or `policy.defaults`, action `shell.execute` | `allow` rules do not match commands with `;`, `&&`, pipes, or `$`; `deny` rules always match. The template's `policy.default` is `ask` and allows only instructions: add `policy.defaults` allow rules for `skill.load`, `extension.load`, and `resource.load` on `company:**`, as the demo does, or each one asks at every launch and is denied in headless runs. A managed `deny` or `ask` rule on an action PiShip cannot enforce (`web.request`, `browser.execute`, `agent.invoke`, `memory.*`, or `network.connect` without a required `deny` sandbox) fails `validate` with `POLICY_UNENFORCEABLE`: ask the person to drop it, or list it as `"<action>:<resource>"` in `policy.acknowledgeUnenforced` and tell them it is not enforced |
| M8 User auto | `policy.userAuto: off \| allowed` | Leave it out (`off`) unless the answer was yes. `allowed` lets each user run `<command> auto on` or `/auto on`: an `ask` from `policy.defaults` or `policy.default` is then approved without a prompt and audited. Put any `ask` that must keep its prompt in `policy.enforced`. It also gates the `--yolo` launch option, which approves the same asks for one session and stores nothing. Managed only; a personal manifest rejects it, and a personal user can always start with `--yolo` ([user auto mode](manifest.md#user-auto-mode)) |
| M9 Sandbox | `sandbox.required`, `sandbox.provider`, `endpoint`, `template`, `workdir`, `user`, `credential` | CubeSandbox: `provider: e2b-compatible`, `user: root`, a `workdir` under `/root`. Only shell commands run remotely; the sandbox must mount or sync the workspace ([sandbox](sandbox.md#workspace)) |
| M10 Governed MCP | `mcp.servers.<id>` (the template's `mcp.mode` is already `allowlist`) | Also add allow rules for `mcp.server.start` (the server ID) and `mcp.tool.call` (`<server>:<tool>`), as the demo does. A server host must be allowed by the private-only network policy. Limit a server's tools with a `tools` exposure map (`<tool>: direct`, then `"*": hidden`), not `tools.allow`. An internal server without HTTPS on a private host takes `httpTransport: http-allowed` (not with `credential: runtime`; `validate` warns the traffic is unencrypted); a server that identifies the user by a header takes `headers: { <Header>: { identityClaim: preferred_username } }` (or `sub`, the stable key), never a literal value ([manifest](manifest.md#mcp-plain-http-and-identity-headers-v1alpha6)) |
| M11 Audit | an `audit.sinks` entry with `id`, `type: http`, `url`, `required` | The template keeps a local file sink and shows the collector entry as a comment |
| M12 Update source | `updates.source` and the update trust fields | See [step 7](#7-signed-updates-and-rollback) |
| M12 Update host without HTTPS | `updates.transport: https` (default, omit it) or `http-allowed` | `http-allowed` only with `updates.trust.bootstrap`, and only for a private or internal host (an RFC 1918 address, a single-label name that is not a public TLD, or a name such as `*.internal`, `*.corp`, `*.lan`); a public host fails `validate`. Every other endpoint has its own `httpTransport` (M2, M3, M10; OIDC, audit sinks, and the sandbox too), and needs HTTPS without it ([manifest](manifest.md#plain-http-update-channel-v1alpha5)) |
| M13 Search tools | `runtime.searchTools: { mode: bundled }`, optionally `fd: "<version>"` and `rg: "<version>"`; add `https://github.com` to `release.sources` | `piship lock` needs network access to download the upstream archives for every `release.targets` entry. Commit only `piship.lock`; the archives stay in PiShip's download cache ([manifest](manifest.md#bundled-search-tools-v1alpha6)) |

Then `piship config explain <directory>/piship.yaml` shows the effective configuration and where each value comes from.

## 5. Validate, lock, and build

```bash
piship validate <directory>/piship.yaml
piship lock <directory>/piship.yaml
piship build <directory>/piship.yaml
```

Fix what `validate` reports and run it again until it says the manifest is valid. For a managed distribution it lists the runtime variables the command needs at launch; it only notes, and does not fail, when they are unset in your shell. `build` writes the payload to `dist/<id>` under the **current directory**, so run it from the distribution repository, not from the PiShip clone. Add `dist/` to that repository's `.gitignore`.

`piship test <directory>/piship.yaml` builds and runs the branded offline smoke before anything is installed. It creates the distribution's state directory and marks it as created by `test`, so the first `install` after it adopts that state without extra flags.

`test` launches with the distribution's credential, so a `local-secret` or managed distribution needs a stored key or sign-in first, or it fails with `CREDENTIAL_REQUIRED`. Run `piship test` once to create the state, then have the person sign in with the built command, `dist/<id>/bin/<command> login`, run in the directory where you ran `piship test` (run that from the distribution repository), since `dist/` is written under the directory `build` or `test` runs in (`dist\<id>\bin\<command>.cmd` on Windows), and run `piship test` again. The key lands in the same state the installed command uses, and `install` still adopts it. With `storage.provider: system` on Linux, `login` needs an unlocked Secret Service and `secret-tool` (often missing under WSL or over SSH) and otherwise fails with `SECRET_STORE_UNAVAILABLE`; ask the person whether to switch to `storage: {provider: file}`, then lock and build again.

## 6. Setup completion checklist

Setup is not complete until each applicable check below passes. Report each one as passed, failed (with the error), or not applicable.

1. **Validate:** `piship validate <directory>/piship.yaml` says the manifest is valid.
2. **Lock:** `piship lock <directory>/piship.yaml` wrote `piship.lock`.
3. **Build:** `piship build <directory>/piship.yaml` built `dist/<id>`.
4. **Install** (ask first):

   ```bash
   node dist/<id>/piship.mjs install dist/<id>
   ```

   State that `piship test` created is adopted automatically. If install fails with `State already exists`, that state was not created by `piship test` (an earlier install, say): ask the person before adding `--use-existing-state` to keep it. If `~/.local/bin` is not on the person's `PATH`, tell them; do not edit their shell profile without asking.
5. **Runtime auth and configuration:**
   - **Managed:** set every variable `validate` listed in the environment that starts the command, then the person signs in in their browser with `~/.local/bin/<command> login`. With `sandbox.credential: stored`, the person also runs `~/.local/bin/<command> sandbox login` and types the sandbox key there. An IDE or desktop launcher does not read the shell profile.
   - **Personal with a key (`local-secret`):** the person runs `~/.local/bin/<command> login` and types the key.
   - **Personal without a key (`none`):** nothing to sign in; the endpoint must be running.
   - **Personal with Pi's providers:** the person starts `~/.local/bin/<command>` and signs in with `/login`, then picks a model with `/model`.
6. **Doctor:** `~/.local/bin/<command> doctor` (or `piship doctor <id>`) passes. If it fails, look up the error code in [troubleshooting](troubleshooting.md). For a managed distribution, `~/.local/bin/<command> policy explain <action> <resource>` shows which rule decides a given action, the quickest way to check the governance answers.
7. **Model smoke:** `~/.local/bin/<command> --smoke-model` sends one acceptance prompt to the selected model (`models.default`, or the one picked with `/model`) and must pass. (`~/.local/bin/<command> --smoke` checks everything but the model request.) Before install, `piship test <directory>/piship.yaml --model-request` runs the same request from the build.
8. **Session resume:** the person starts `~/.local/bin/<command>` in a project, sends a message, quits, and starts it again in the same project: the conversation continues, because the command resumes the project's most recent session by itself (`--new-session` starts a new one). The interactive command needs a terminal, so ask the person to do this and to tell you what they saw.

If a signed update source is configured, also check update and rollback before handoff ([step 7](#7-signed-updates-and-rollback)).

## 7. Signed updates and rollback

Only when the person asked for it (S11, P5, or M12). A personal distribution may run its own self-managed signed channel; a managed one uses the company's update source. Follow the [release guide](release.md) and the [owner workflow](release/owner-workflow.md), which describe the update trust fields of the current manifest schema:

1. The key holders run `piship keygen --encrypt` (a root key and a channel key; a personal distribution may use one key for both) and keep the private keys out of the repository. `piship trust-root init` prints the `updates.trust.bootstrap` block for the manifest from their public keys; the channel URL goes in `updates.source` (a runtime variable or an `https` URL).
2. `piship release`, `piship verify-release`, and `piship sign-channel` produce the signed artifacts the person uploads to the update source. Later key changes are published with `piship trust-root next` ([key runbook](release/key-runbook.md)), never by editing the bootstrap of a new release.
3. Before handoff, install one release, publish a newer one, and check:

   ```bash
   ~/.local/bin/<command> update --check
   ~/.local/bin/<command> update
   ~/.local/bin/<command> rollback
   ```

   `update --from <dir|url>` reads a channel that is not yet at `updates.source`. `piship update <id>` and `piship rollback <id>` do the same from PiShip. After the rollback, `doctor` passes and the session from check 8 still resumes.

## 8. Hand over

Tell the person, briefly:

- the mode, the command to run, and for a managed distribution the variables to set on each machine;
- what to commit: `piship.yaml`, `piship.lock`, `resources/`, and, when the distribution declares Pi packages, `piship.lock.d/` and any local package directory (not `dist/`, never a private key);
- the completion checklist with each result, the open items from step 2, and anything you could not check;
- for a managed distribution, that their identity provider, broker, and gateway must follow the [enterprise integration contract](enterprise-integration.md).

## 9. Upgrade an existing distribution

When the person already has a distribution built with an earlier PiShip and wants the new one, update PiShip first, then the distribution. Nothing here changes an installed machine until it installs the rebuilt release.

1. Update the PiShip checkout to the release they want and rebuild it: `cd ~/src/piship && git fetch --tags && git checkout <tag> && npm ci && npm run build`.
2. In the distribution repository, keep the current lock for comparison: `cp piship.lock previous.lock` (the name must end in `.lock`).
3. Set `runtime.pi` to the Pi version the new PiShip pins: `1.0.2` for v0.9.0 and v0.9.1, `1.0.3` for v0.11.0 and on `main`. A v0.8 distribution pins `1.0.0`, and `validate`, `lock`, and `build` refuse it with `Pi 1.0.0 is not available in this PiShip build`. Also add the new Pi version to the `pi` list of each `certified` resource's evidence (`resources.<kind>.certified[].pi`) once the person has reviewed it against that Pi. A certified resource whose evidence does not list the running Pi is not loaded (`certified for Pi 1.0.0; running Pi 1.0.3`), and nothing fails at `validate` or `build`.
4. Run `piship migrate piship.yaml --check`. It writes nothing, prints every change, and answers `migratable` (exit 0), `requires review` (exit 1: one change alters an effective decision, or a value needs the person), or `cannot migrate` (exit 3); for a v0.8 manifest it always does, because the cache-warming change is always reported. Show the person each reported change and ask how to keep it. From v0.8 to v0.10 there are up to three ([migration guide](manifest.md#migrating-from-v1alpha5-to-v1alpha6)): prompt cache warming is `off` unless `runtime.cacheWarming.mode: streaming` is set, an MCP server whose new class `policy.resourceTrust` does not allow no longer starts, and a build is bundled and stripped unless `release.bundle` and `release.strip` are `false`.
5. Run `piship migrate piship.yaml --write` and apply the person's answers.
6. Run `piship validate piship.yaml`. A managed `deny` or `ask` rule on an action PiShip cannot enforce fails it with `POLICY_UNENFORCEABLE` ([enforcement status](manifest.md#enforcement-status)); ask the person whether to list the rule in `policy.acknowledgeUnenforced` or remove it.
7. Run `piship lock piship.yaml`, then `piship diff previous.lock piship.lock`, and read the diff with the person. A high-risk entry, such as the Pi runtime change, needs their confirmation. Delete `previous.lock` afterwards. If `release.vulnerabilities.allow` lists GHSA-qhr7-859c-m2p7 or GHSA-6j4f-fj2g-mc7p (an earlier version of this guide had agents copy them from the demo manifest), remove those entries: Pi 1.0.2 and later ship the fixed `brace-expansion`, and an unused exception would let the same advisory ID pass unnoticed until 2026-12-31.
8. Rebuild and rerun the [completion checklist](#6-setup-completion-checklist). With a signed update source, publish the new release and check update and rollback as in [step 7](#7-signed-updates-and-rollback): an installation's state files are read as they are and never rewritten, so a rollback to the previous release still reads them.
9. Commit `piship.yaml`, `piship.lock`, and `piship.lock.d/` if the distribution declares Pi packages.
