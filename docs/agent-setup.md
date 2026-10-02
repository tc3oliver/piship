# Setting up a distribution with a coding agent

This page is written for a coding agent (Claude Code, Codex, Pi, or similar) that a person has asked to set up a PiShip distribution. A person can follow it too. The [README](../README.md#set-it-up-with-your-coding-agent) has the prompt that points an agent here.

Work through the steps in order. Stop and ask the person whenever a step needs a value you do not have; never invent a URL, client ID, model ID, or company name.

## Rules

- **No secrets in files or commands.** `piship.yaml`, `piship.lock`, and `resources/` are committed, and the schema rejects secret-looking values anyway. Never put an API key, client secret, token, or password in them, in a shell command, or in your reply. Endpoints go in as runtime variables (`${NAME}`) or plain `https` URLs. A key for a personal `local-secret` distribution is typed by the person at `<command> login`, never by you.
- **Leave the person's existing setup alone.** Do not read, change, or delete `~/.pi`, and do not uninstall or overwrite another installed distribution. A distribution keeps its own state under `~/.piship/<id>`.
- **Ask before installing.** `install` writes a command into `~/.local/bin`. Say what it will add and get a yes first. The same goes for `uninstall` and `purge`.
- **Run the CLI by path.** PiShip is not on npm. Use `node <piship>/packages/cli/dist/bin.js`; npx or `npm exec` would fetch an unrelated package from the public registry.
- **Report what you could not check.** If a command fails or a step was skipped, say so with the error. Do not describe a distribution as working until `doctor` passes.

## 1. Get PiShip

Clone it outside the person's project, where they agree (the default here is `~/src/piship`), and build it:

```bash
git clone https://github.com/tc3oliver/piship.git ~/src/piship
cd ~/src/piship && npm ci && npm run build
```

It needs Node.js 22.19.0 or newer (`node --version`). Below, `piship` means `node ~/src/piship/packages/cli/dist/bin.js`.

## 2. Ask the person

Ask these together, in one message, and wait for the answers.

**Everyone:**

1. Personal (just me, no company services) or managed (a company rolls it out)?
2. The product name and the command people will type, for example `AcmeCode` and `acmecode`. The command and ID are lowercase letters, digits, and hyphens.
3. Where the distribution repository should live (not inside the PiShip clone).
4. What the agent should always know: coding conventions, the main repositories, things it must never do. This becomes `resources/AGENTS.md`.
5. Should a missing OS sandbox stop the agent from running commands (`sandbox.required: true`), or only warn?

**Personal only:**

6. Pi's own sign-in and providers (the default), or a local or self-hosted OpenAI-compatible server? For a server: its base URL and the model IDs it serves.

**Managed only.** If the person does not know an answer, list the open items at the end instead of guessing:

6. The OIDC issuer URL and the client ID of a **public** client (PKCE, no client secret). Its allowed redirect URI must include the loopback `redirectUri` you put in the manifest, by default `http://127.0.0.1:8765/callback`.
7. The credential broker endpoint, and its revoke endpoint if it has one. The broker must implement the [broker contract](enterprise-integration.md#credential-broker-http-broker).
8. The LLM gateway base URL, and whether it serves `openai-completions` (the default) or `openai-responses`.
9. The model IDs people may use, which one is the default, and each model's context window and maximum output tokens.
10. Whether endpoints should be runtime variables (set on each machine) or fixed `https` URLs in the manifest.
11. MCP servers, if any: name, URL, and which tools are allowed.
12. Company CA bundle or proxy, if the network needs one.

## 3. Create and fill in the manifest

```bash
piship init <directory>             # personal
piship init <directory> --managed   # managed
```

This writes `piship.yaml` and `resources/AGENTS.md`. Then edit them with the answers:

- `app`: `id`, `name`, `command`. Keep `version: 1.0.0` for a first release.
- Managed: `identity.oidc`, `credential.broker`, `inference.baseUrl` (and `inference.api` if the gateway uses responses), and either runtime variables or plain URLs. `variables` must list every `${NAME}` used.
- `models`: every ID in `allowed` needs a `catalog` entry with `name`, `contextWindow`, and `maxOutputTokens`; set `tools: true` for models that can call tools. `default` must be in `allowed`. Update the `distribution.models` policy rule's `resource` to match the model IDs.
- `sandbox.required`, from question 5.
- `mcp.servers`, only for servers the person named, with an explicit tool allowlist.
- `network.tls.additionalCA` for a CA bundle, as an absolute path on the machine.
- `resources/AGENTS.md`: the instructions from question 4, in the person's words.

Every field is described in the [manifest reference](manifest.md); the [demo company manifest](../examples/demo-company/piship.yaml) is a complete example.

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

For a managed distribution, the runtime variables must be set in the shell that starts the command, then the person signs in in their browser:

```bash
export <NAME>=<value>    # each variable validate listed
~/.local/bin/<command> login
~/.local/bin/<command> doctor
```

For a personal one with a `local-secret` key, the person runs `~/.local/bin/<command> login` and types the key there. Then run `~/.local/bin/<command> doctor`. `doctor` must pass before you call the setup done. If it fails, look up the error code in [troubleshooting](troubleshooting.md).

If `~/.local/bin` is not on the person's `PATH`, tell them; do not edit their shell profile without asking.

## 6. Hand over

Tell the person, briefly:

- the command to run, and the variables to set for a managed distribution;
- what to commit: `piship.yaml`, `piship.lock`, and `resources/` (not `dist/`);
- any open items from step 2, and anything you could not check;
- for a managed distribution, that their identity provider, broker, and gateway must follow the [enterprise integration contract](enterprise-integration.md), and that rolling it out to other people goes through [releases and signed update channels](release.md).
