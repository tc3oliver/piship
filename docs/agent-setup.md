# Setting up a distribution with a coding agent

This page is written for a coding agent (Claude Code, Codex, Pi, or similar) that a person has asked to set up a PiShip distribution. A person can follow it too. The [README](../README.md#set-it-up-with-your-coding-agent) has the prompt that points an agent here.

Work through the steps in order. Stop and ask the person whenever a step needs a value you do not have; never invent a URL, client ID, model ID, repository host, or company name.

## Rules

- **No secrets in files or commands.** `piship.yaml`, `piship.lock`, and `resources/` are committed, and the schema rejects secret-looking values anyway. Never put an API key, client secret, token, password, or private signing key in them, in a shell command, or in your reply. Endpoints go in as runtime variables (`${NAME}`) or plain URLs (`https`, or `http` on loopback). Keys are typed by the person at the branded command's own prompts (`login`, `sandbox login`), never by you.
- **Leave the person's existing setup alone.** Do not read, change, or delete `~/.pi`, and do not uninstall or overwrite another installed distribution. A distribution keeps its own state under `~/.piship/<id>`.
- **Ask before installing.** `install` writes a command into `~/.local/bin`. Say what it will add and get a yes first. The same goes for `uninstall`, `purge`, and editing a shell profile.
- **Run the CLI by path.** PiShip is not on npm. Use `node <piship>/packages/cli/dist/bin.js`; npx or `npm exec` would fetch an unrelated package from the public registry.
- **Do not create release keys on your own.** `piship keygen` makes the key every future update is signed with. Run it only when the person asks, and tell them where the private key is so they can move it somewhere safe; it is never committed.
- **Report what you could not check.** If a command fails or a step was skipped, say so with the error. Do not describe a distribution as working until `doctor` passes.

## 1. Get PiShip

Clone it outside the person's project, where they agree (the default here is `~/src/piship`), and build it:

```bash
git clone https://github.com/tc3oliver/piship.git ~/src/piship
cd ~/src/piship && npm ci && npm run build
```

It needs Node.js 22.19.0 or newer (`node --version`). Below, `piship` means `node ~/src/piship/packages/cli/dist/bin.js`.

## 2. Ask the person

Ask in one message, grouped as below, and wait for the answers. Say that any question can be answered "not sure yet"; collect those as open items instead of guessing.

**Everyone**

1. Personal (just me, no company services) or managed (a company rolls it out)?
2. Product name and the command people will type, for example `AcmeCode` and `acmecode` (lowercase letters, digits, hyphens). Optional: a one-line banner and a theme.
3. Where the distribution repository should live (not inside the PiShip clone).
4. What the agent should always know: coding conventions, main repositories, things it must never do. This becomes `resources/AGENTS.md`.
5. Existing skills, extensions, or prompt templates to ship with it, and where they are now.
6. Which operating systems people use: macOS, Linux, Windows. Windows has no native sandbox.

**Personal**

7. Pi's own sign-in and providers (the default), or a local or self-hosted OpenAI-compatible server? For a server: its base URL, the model IDs it serves, and whether it needs a key.

**Managed: sign-in, credentials, models**

7. OIDC issuer URL and the client ID of a **public** client (PKCE, no client secret). Its allowed redirect URIs must include the loopback `redirectUri` in the manifest, by default `http://127.0.0.1:8765/callback`. Does the broker need an `audience` or extra scopes?
8. Credential broker endpoint, and its revoke endpoint if it has one.
9. LLM gateway base URL, and whether it speaks `openai-completions` (the default) or `openai-responses`.
10. The model IDs people may use, which one is the default, and each model's context window and maximum output tokens.
11. Endpoints as runtime variables (set on each machine) or fixed `https` URLs in the manifest?
12. A company CA bundle or proxy, if the network needs one.

**Managed: governance**

13. Which repositories count as company projects: the git host and organization (for example `git.acme.example/platform/**`) and, ideally, where they are checked out. Everything else is treated as unknown, and its `AGENTS.md`, skills, and MCP files are not loaded.
14. Shell commands to always allow, always deny, or ask about. Anything unmatched asks the person.
15. Sandbox: the OS sandbox on each machine, or a remote one (a CubeSandbox or other E2B-compatible service, Kubernetes Agent Sandbox, or the company's own adapter)? For a remote one: its API URL, template or pool, working directory, and how it authenticates.
16. Should commands in the sandbox reach the network? With `deny`, `npm install`, `pip install`, and `git fetch` fail inside it. Any extra paths the agent may write, or must never read?
17. MCP servers: name, URL or command, and which tools are allowed.
18. An audit collector URL, and whether a launch must fail when it is unreachable.

**Managed: rollout** (can wait until the first version works)

19. Where releases will be hosted (the update source URL), and who holds the release signing key.

## 3. Where each answer goes

Start from the template, then edit it:

```bash
piship init <directory>             # personal
piship init <directory> --managed   # managed
```

`init` writes `piship.yaml` and `resources/AGENTS.md`. The [manifest reference](manifest.md) describes every field; the [demo company manifest](../examples/demo-company/piship.yaml) and the [personal example](../examples/personal/piship.yaml) are complete examples to copy from.

| Answer | Field | Watch out for |
| --- | --- | --- |
| 2 Name, command | `app.id`, `app.name`, `app.command`; optional `app.banner`, `app.theme` | Keep `app.version: 1.0.0` for the first release |
| 4 Instructions | `resources/AGENTS.md` | Write it in the person's words |
| 5 Skills, extensions, prompts | Copy them under `resources/`, then list them in `resources.skills`, `resources.extensions`, `resources.prompts` | Managed: under the `company` class. Personal: under `user`. Paths start with `./` and stay inside the repository. Managed: the template's `policy.default` is `ask` and it only allows instructions, so also add `policy.defaults` allow rules for `skill.load`, `extension.load`, and `resource.load` (prompts, themes) on `company:**`, as the demo does; otherwise each one asks at every launch and is denied in headless runs |
| 7 Personal, Pi providers | `credential.provider: pi-native`, `inference.provider: pi-native` (the personal template's default) | The person signs in with Pi's `/login` inside the command; the key stays in the distribution's state |
| 7 Personal, local server | `inference.provider: openai-compatible`, `inference.baseUrl`, `models`; `credential.provider: local-secret` with a key, `none` without | Copy [`examples/personal/local-model`](../examples/personal/local-model/piship.yaml) |
| 7 OIDC | `identity.oidc.issuer`, `clientId`, `redirectUri`, `scopes`, `audience` | `scopes` must include `openid`; no `clientSecret` |
| 8 Broker | `credential.broker.endpoint`, `revokeEndpoint` | It must follow the [broker contract](enterprise-integration.md#credential-broker-http-broker) |
| 9 Gateway | `inference.baseUrl`, `inference.api` | |
| 10 Models | `models.default`, `models.allowed`, `models.catalog.<id>` | Every allowed ID needs a catalog entry with `name`, `contextWindow`, `maxOutputTokens`; `tools: true` for tool-calling models. The template's `distribution.models` rule (`model.use` on `<app.id>/**`) already covers them; to narrow it, write `<app.id>/<model>` |
| 11 Endpoints | `variables` plus `${NAME}`, or plain URLs (`https`, or `http` on loopback) | Every `${NAME}` used must be listed in `variables` |
| 12 CA, proxy | `network.tls.additionalCA`, `network.proxy.inheritEnvironment` | An absolute path on each machine |
| 13 Company repositories | `policy.projectTrust.company.match` with `remote` and `path` | `remote` alone is only a claim; pair it with `path` |
| 14 Shell rules | `policy.enforced` (cannot be relaxed) or `policy.defaults`, action `shell.execute` | `allow` rules do not match commands with `;`, `&&`, pipes, or `$`; `deny` rules always match |
| 15 OS sandbox | `sandbox.required` | `true` stops the launch when the sandbox is missing, which on Windows is always |
| 15 Remote sandbox | `sandbox.provider`, `endpoint`, `template`, `workdir`, `user`, `credential` | CubeSandbox: `provider: e2b-compatible`, `user: root`, a `workdir` under `/root`. Only shell commands run remotely; the sandbox must mount or sync the workspace ([sandbox](sandbox.md#workspace)) |
| 16 Sandbox network, paths | `sandbox.network.mode`, `sandbox.filesystem.write.allow`, `sandbox.filesystem.read.deny` | A declared list replaces the defaults: restate them, as the demo manifest does |
| 17 MCP | `mcp.servers.<id>` with `transport`, `url` or `module`/`command`, `tools.allow` | Only servers the person named. Managed: also add allow rules for `mcp.server.start` (the server ID) and `mcp.tool.call` (`<server>:<tool>`), as the demo does |
| 18 Audit | `audit.sinks` entry with `id`, `type: http`, `url`, `required` | |
| 19 Rollout | `updates.source`, `updates.trust.keys` | Public keys only. See step 6 |

## 4. Validate, lock, and build

```bash
piship validate <directory>/piship.yaml
piship lock <directory>/piship.yaml
piship build <directory>/piship.yaml
```

Fix what `validate` reports and run it again until it says the manifest is valid. It also lists the runtime variables the command needs at launch. `build` writes the payload to `dist/<id>` under the current directory.

## 5. Install and check

Ask first, then:

```bash
node dist/<id>/piship.mjs install dist/<id>
```

Then, depending on the distribution:

- **Managed:** set every variable `validate` listed in the shell that starts the command, then the person signs in in their browser:

  ```bash
  export <NAME>=<value>
  ~/.local/bin/<command> login
  ```

  With `sandbox.credential: stored`, the person also runs `~/.local/bin/<command> sandbox login` and types the sandbox key there.
- **Personal with `local-secret`:** the person runs `~/.local/bin/<command> login` and types the key.
- **Personal with Pi's providers:** the person starts the command and signs in with `/login`.

Then run `~/.local/bin/<command> doctor`. It must pass before you call the setup done. If it fails, look up the error code in [troubleshooting](troubleshooting.md). `~/.local/bin/<command> policy explain <action> <resource>` shows which rule decides a given action, which is the quickest way to check the governance answers.

If `~/.local/bin` is not on the person's `PATH`, tell them; do not edit their shell profile without asking.

## 6. Rolling it out to other people

Only when the person asks for it. Follow the [release guide](release.md):

1. The key holder runs `piship keygen` and keeps the private key out of the repository. Its public key goes in `updates.trust.keys`, and the update URL in `updates.source`.
2. Copy the `release.vulnerabilities.allow` entries from the [demo company manifest](../examples/demo-company/piship.yaml). Pi pins a `brace-expansion` version with a reviewed advisory exception until 2026-12-31 ([#129](https://github.com/tc3oliver/piship/issues/129)); without the entries `piship release` stops at the vulnerability gate.
3. `piship release`, `piship verify-release`, and `piship sign-channel` produce the signed artifacts the person uploads to the update source.

## 7. Hand over

Tell the person, briefly:

- the command to run, and the variables to set for a managed distribution;
- what to commit: `piship.yaml`, `piship.lock`, and `resources/` (not `dist/`, never a private key);
- the open items from step 2, and anything you could not check;
- for a managed distribution, that their identity provider, broker, and gateway must follow the [enterprise integration contract](enterprise-integration.md).
