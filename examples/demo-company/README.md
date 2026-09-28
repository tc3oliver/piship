# Demo company distribution example

AcmeCode is a fictional managed distribution on `piship/v1alpha4`. It signs users in with OIDC, obtains a runtime credential from an `http-broker`, and sends inference to an OpenAI-compatible gateway with a three-model allowlist, an enforced theme, and private-only networking. On top of that access layer it declares governance: a company policy, trust-classed resources, a governed MCP server, a Plan/Build workflow, a required OS sandbox, and audit. It also declares signed release channels and a release policy. It contains no private data or credentials. The endpoints are `ACMECODE_*` runtime variables, so the lock stays machine-independent.

The managed surface, governance, and the release lifecycle are **candidates**: all are verified with the deterministic local fixtures below, not with a live identity provider or gateway. See [status](../../docs/status.md) for the current evidence and [compatibility](../../docs/compatibility.md) for the Pi contract.

## What the demo shows

- **Policy.** `acme-engineering@1` defaults to `ask`. Enforced rules deny reading `~/.ssh/**` and calling `docs:delete_*`; defaults allow the gateway models, skill, instruction, and extension loading, workspace reads, tool calls, and the handbook MCP server and tools, and ask before workspace writes and shell commands. Headless runs have no approval channel, so every `ask` becomes deny there.
- **Resources by trust class.** Company instructions, skills, and the `enterprise-context` extension; a certified `release-notes` skill whose tree digest is checked at lock and launch; and the builtin `piship-ask-user` and `piship-workflow` extensions.
- **Project trust.** Repositories whose origin is on `git.acme.example` and that are checked out under `/srv/src` are company projects. The origin remote alone is only a claim, so the matcher requires both ([manifest](../../docs/manifest.md)); change `path` in a copy to where your managed checkouts live. Every other workspace is unknown and keeps the managed defaults (no project extensions, hooks, agents, MCP, or providers).
- **Governed MCP.** `resources/mcp/docs-server.mjs` is a small handbook server started over stdio with `expectedServerName: acme-docs`. It offers `search`, `get_document`, and `delete_document`. The first two reach the model as `mcp__docs__search` and `mcp__docs__get_document`. `delete_document` is on the server's tool list but denied by the enforced policy, so it is never offered to the model and a call to it never reaches the server.
- **Plan and Build.** Sessions start in Plan mode: the model can read and search the handbook but cannot write, edit, or run commands. `/build` switches to Build mode, where tools follow the policy; `/plan` switches back.
- **Sandbox.** `sandbox.required: true` with network `deny`, `~/.ssh`, `~/.aws`, and `~/.gnupg` hidden, and writes limited to the workspace and a private temp directory. `bash`, `!` commands, and the MCP stdio server run inside it. The launch fails with `SANDBOX_UNAVAILABLE` if it cannot be enforced.
- **Audit.** An optional local file sink records metadata-only events in the distribution state under `logs/audit.jsonl`.
- **Release channels.** Users start on `stable` and may switch to `candidate`; `dev` is not allowed. Update metadata is read from `${ACMECODE_UPDATE_SOURCE}`, the previous release is retained for rollback, and releases are built for Linux x64, macOS arm64, and Windows x64 from `https://registry.npmjs.org` packages, failing on `high` or `critical` advisories. The example pins no release key (`updates.trust.keys: []`), so `update` fails until an owner adds one.

## Deterministic local path

`fixtures/local-services.mjs` starts a loopback OIDC provider, credential broker, and gateway. It auto-approves every sign-in for a fictional demo user and returns canned replies. It is test infrastructure, not a real identity provider, and not evidence of a live integration.

The demo uses the system secret store (`credential.storage.provider: system`). On Linux this needs a running, unlocked Secret Service and `secret-tool`; macOS uses Keychain and Windows uses Credential Manager. Without one, `login` fails with `SECRET_STORE_UNAVAILABLE`. To use the plaintext file fallback instead, edit a copy of this example to set `storage: {provider: file, acknowledgePlaintext: true}`; the example itself does not opt in.

The required sandbox needs bubblewrap (`bwrap`) with unprivileged user namespaces on Linux, or `/usr/bin/sandbox-exec` on macOS. Windows has no sandbox adapter, so the demo refuses to start there with `SANDBOX_UNAVAILABLE`; to try the rest of the demo on Windows, set `sandbox.required: false` in a copy.

In a first terminal, from the repository root with Node.js 22.19.0 or newer:

```bash
npm ci
npm run build
node examples/demo-company/fixtures/local-services.mjs
```

It prints `export ACMECODE_...=...` lines (`set` lines on Windows) and keeps running. Pass `--port <n>` for a fixed port. In a second terminal, paste those lines, then:

```bash
npm exec -- piship validate examples/demo-company/piship.yaml
npm exec -- piship lock examples/demo-company/piship.yaml
npm exec -- piship build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode --version
~/.local/bin/acmecode login
~/.local/bin/acmecode --smoke
~/.local/bin/acmecode --smoke-model
~/.local/bin/acmecode models
~/.local/bin/acmecode --model acme/review --smoke   # MODEL_UNAVAILABLE: not entitled
~/.local/bin/acmecode doctor
~/.local/bin/acmecode config explain
~/.local/bin/acmecode capabilities
~/.local/bin/acmecode policy explain mcp.tool.call docs:delete_document
~/.local/bin/acmecode policy explain filesystem.read ~/.ssh/id_ed25519 --json
~/.local/bin/acmecode policy explain shell.execute "git status"
~/.local/bin/acmecode logout
node dist/acmecode/piship.mjs uninstall acmecode
```

`login` prints the sign-in URL and opens a browser; the fixture approves it at once and redirects to `http://127.0.0.1:8765/callback`, so that port must be free. Set `PISHIP_NO_BROWSER=1` to only print the URL. Before `login`, `--smoke` fails with `IDENTITY_REQUIRED`. `--smoke` checks Pi startup, declared resources, the read tool, session resume, and the access summary without a model call, and adds a `governance` summary: policy, project origin, sandbox level and planes, workflow mode, capabilities, resource decisions, MCP servers and their exposed tools, and audit state. `--smoke-model` sends one prompt through the fixture gateway. The declared `enterprise-context` extension adds a `demo_context` tool that reads the token-free enterprise context. `config set theme light` is refused because the theme is enforced; `config set model acme/general` is permitted.

What to look for:

- `doctor` adds Policy, Project, Resources, Capabilities, Sandbox, and MCP and audit sections. On Linux with bubblewrap, the sandbox line reads `enforced (linux-bubblewrap: filesystem-read-deny, filesystem-write-allowlist, network-deny, environment-filter)`, proven by a live probe, and `mcp docs` is `healthy (stdio; 2 tool(s))`. The certified skill shows `integrity verified`.
- `capabilities` shows `permissions` and `workflow` effective through their builtin providers; `checkpoint`, `subagents`, `code-intel`, and `acp` are not supported in this release.
- `policy explain mcp.tool.call docs:delete_document` prints `DENIED` by the enforced rule `acme.docs.destructive`, with the default `acme.docs.read` allow listed as another matching rule. `filesystem.read ~/.ssh/id_ed25519` is denied by `acme.secrets.read` with enforcement `sandbox` when the sandbox is enforced. `shell.execute "git status"` needs approval under `acme.shell`.
- In the interactive TUI (`~/.local/bin/acmecode`), the session starts in Plan mode. Ask for a plan that searches the handbook; writes and commands are refused until you type `/build`. In Build mode, writes and commands ask for approval, and approved `!` commands run inside the sandbox: `!cat ~/.ssh/config` finds nothing to read and `!curl https://example.org` has no network.

To try the user and project layers, write rules to `~/.piship/acmecode/config/policy.json` (or `$PISHIP_STATE_HOME/acmecode/config/policy.json`) or to `.piship/policy.json` in a project. This is a managed distribution, so both files are narrowing only: a user or project rule can tighten a default such as `acme.shell` from `ask` to `deny`, their `allow` rules are ignored and reported, and neither can relax the enforced rules. `policy explain` shows which layer decided.

Every branded command resolves the `ACMECODE_*` variables at launch, so keep them set in that shell. The fixture keeps its sessions in memory: after restarting it, run `login` again. `logout` revokes the credential and tokens at the fixture, clears local secrets, and keeps sessions; `node dist/acmecode/piship.mjs purge acmecode --yes` removes the state, including the audit log, and deletes the secret-store entries it references (best effort, without revoking) after uninstall.

## Release, update, and rollback

This walkthrough plays both the owner and the user on one machine, with a local directory as the channel. `ACMECODE_UPDATE_SOURCE` is read only by `update`, never at launch, so the steps above work without it. Run these commands from the repository root, and work in a copy of the example so the demo stays unchanged.

1. As the owner, create a release key outside the repository. `keygen` refuses to overwrite a file or to write inside a git work tree unless the path is git-ignored, and prints the public key and fingerprint:

   ```bash
   cp -r examples/demo-company /tmp/acmecode
   mkdir -p ~/acme-keys
   npm exec -- piship keygen ~/acme-keys/release.pem --id acme-release-2026
   ```

2. Replace `keys: []` under `updates.trust` in the copied `piship.yaml` with the printed entry. Only the public key goes in the manifest; the private key stays out of the repository, CI logs, and any shared location:

   ```yaml
   updates:
     trust:
       keys:
         - id: acme-release-2026
           publicKey: MCowBQYDK2VwAyEA...
   ```

3. Lock, build a release for this machine, and verify it. On Windows set `sandbox.required: false` first; a release that requires the sandbox is refused for `win32-x64`. The dependency scan needs registry access:

   ```bash
   npm exec -- piship lock /tmp/acmecode/piship.yaml
   npm exec -- piship release /tmp/acmecode/piship.yaml
   npm exec -- piship verify-release dist/releases/acmecode-1.0.0-<target>.tar.gz
   ```

4. Install it from the extracted release with its own script (`install.ps1` on Windows), which verifies it again first. Uninstall any earlier `acmecode` install first, and pass `--use-existing-state` to keep its state:

   ```bash
   tar -xzf dist/releases/acmecode-1.0.0-<target>.tar.gz -C /tmp
   sh /tmp/acmecode-1.0.0-<target>/install.sh
   ```

5. Change `app.version` in `/tmp/acmecode/piship.yaml` to `1.1.0`, lock, and release again. Sign it into the stable channel directory, then point the installed command at it:

   ```bash
   npm exec -- piship sign-channel /tmp/acme-channel dist/releases/acmecode-1.1.0-<target>.tar.gz \
     --channel stable --key ~/acme-keys/release.pem --key-id acme-release-2026
   export ACMECODE_UPDATE_SOURCE=/tmp/acme-channel
   ```

6. As the user:

   ```bash
   ~/.local/bin/acmecode update --check    # 1.1.0 is available, signed by acme-release-2026
   ~/.local/bin/acmecode update            # verified, then activated; 1.0.0 is retained
   ~/.local/bin/acmecode doctor            # Supply Chain and Update sections
   ~/.local/bin/acmecode rollback          # back to 1.0.0; sessions kept, credentials not restored
   ```

`<target>` is this machine's `linux-x64`, `darwin-arm64`, or `win32-x64`. To serve the channel to others, publish the channel directory over HTTPS and set `ACMECODE_UPDATE_SOURCE` to its URL; `--from <dir|url>` overrides it for one run. Re-sign the channel with `sign-channel` before its metadata expires (30 days by default). See [release](../../docs/release.md) for what each step verifies and the release checklist.

## Authorized live path

To try AcmeCode against real services you are authorized to use, set the same variables before `login`:

| Variable | Value |
| --- | --- |
| `ACMECODE_OIDC_ISSUER` | Issuer URL of an OIDC provider |
| `ACMECODE_OIDC_CLIENT_ID` | A public native client (no secret) with Authorization Code + PKCE S256 and the registered redirect `http://127.0.0.1:8765/callback` |
| `ACMECODE_CREDENTIAL_BROKER_URL` | A service implementing the [http-broker protocol](../../docs/credentials.md#http-broker-protocol) |
| `ACMECODE_CREDENTIAL_REVOKE_URL` | Its revoke endpoint |
| `ACMECODE_LLM_GATEWAY_URL` | An OpenAI-compatible gateway base URL that serves `GET /models` and the allowed model IDs |
| `ACMECODE_UPDATE_SOURCE` | Optional, read only by `update`: the HTTPS URL of a channel directory signed with a key pinned in your copy |

All URLs must use HTTPS. Managed mode is always private-only, so OIDC endpoints that discovery returns on other hosts, and any Streamable HTTP MCP server or HTTP audit sink on another host, must be added to `network.allowHosts`, and an enterprise CA goes in `network.tls.additionalCA`; make these changes, and any model ID changes, in a copy, then lock and build it. The project has not yet recorded such a live run.
