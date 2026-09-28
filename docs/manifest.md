# Experimental manifest and lock

Three alpha schemas are accepted. All remain experimental, and unknown fields are rejected.

- `piship/v1alpha1` is the v0.1 personal contract. It accepts only `deployment.mode: personal`, uses Pi-native providers and auth in isolated state, and rejects credential fields and `${...}` substitutions. The [personal example](../examples/personal/piship.yaml) uses it.
- `piship/v1alpha2` adds access configuration for `managed` and `personal` distributions.
- `piship/v1alpha3` keeps the v1alpha2 access fields and adds governance: trust-classed resources, capabilities, policy, MCP, sandbox, and audit. The [demo company example](../examples/demo-company/piship.yaml) is a managed v1alpha3 manifest.

## Common fields

Required fields are `schema`, `app.id`, `app.name`, `app.command`, `app.version`, `runtime.pi`, and `deployment.mode`. `app.banner` and `app.theme` are optional. `app.theme` selects a built-in or declared custom theme through Pi's public interactive API. `resources` can declare instruction files and skill, extension, prompt, or theme roots (in v1alpha3, grouped by trust class; see below). IDs and commands use safe lowercase names; `app.version` is a distribution semver independent of PiShip and Pi versions. Resource paths start with `./`, stay inside the manifest directory, and may not contain symlinks.

## Access fields (v1alpha2 and v1alpha3)

| Field | Values |
| --- | --- |
| `deployment.mode` | `managed` or `personal` |
| `variables` | Names allowed in `${NAME}` runtime references (see below) |
| `identity.mode` | `none`, `oidc`, or `adapter` |
| `identity.oidc` | `issuer`, `clientId`, `flow: authorization_code_pkce` (only value), `scopes` (default `[openid, profile, email]`; must include `openid`), optional `audience`, and `redirectUri`, a loopback `http://127.0.0.1:<port>/<path>` or `[::1]` URI. `clientSecret` is rejected: native clients are public |
| `identity.adapter` | `./` path to an `.mjs` or `.js` module that default-exports an `IdentityProvider` factory |
| `credential.provider` | `http-broker`, `local-secret`, `pi-native`, `none`, or `adapter` |
| `credential.broker` | `endpoint` and optional `revokeEndpoint` (with `http-broker` only) |
| `credential.adapter` | `./` module path (with `adapter` only) |
| `credential.storage` | `provider: system` (default) or `file`, and `acknowledgePlaintext` (default `false`). Not allowed with `pi-native` or `none` |
| `credential.refresh.beforeExpiry` | Duration such as `30s`, `5m`, or `1h` (default `5m`) |
| `inference.provider` | `openai-compatible` or `pi-native` |
| `inference.baseUrl`, `api`, `liveCatalog` | For `openai-compatible`: gateway base URL, `openai-completions` (default) or `openai-responses`, and whether to query `GET {baseUrl}/models` at launch (default `false`) |
| `models.default` | Default model ID; must be in `models.allowed` |
| `models.allowed` | Distribution allowlist. For `pi-native`, entries use `provider/model` |
| `models.catalog.<id>` | `name`, `contextWindow`, `maxOutputTokens`, optional `input` (`text`, `image`), `reasoning`, `tools`, `streaming`, and `policyTags` |
| `config.enforced`, `config.defaults` | Values for `model`, `theme`, and `thinkingLevel` (`off`, `minimal`, `low`, `medium`, `high`, `xhigh`). Use `models.default` rather than `config.defaults.model` |
| `config.userOverridable` | Keys users may set; defaults to every key not enforced |
| `network.proxy.inheritEnvironment` | Honor `HTTP(S)_PROXY` and `NO_PROXY` (default `true`) |
| `network.tls.additionalCA` | PEM bundle paths added to the default trust roots |
| `network.publicFallback` | `deny` or `allow`; managed requires `deny` |
| `network.privateOnly`, `network.allowHosts` | Restrict PiShip-managed and in-process `fetch` requests to declared endpoint hosts plus `allowHosts` |

Secret-looking fields such as `credential.apiKey`, `credential.secret`, `credential.token`, `identity.oidc.clientSecret`, and `network.tls.rejectUnauthorized` or `insecure` are rejected. The schema cannot detect every secret placed in an otherwise allowed string.

## Validation rules

Managed mode requires:

- `identity.mode` `oidc` or `adapter`
- `credential.provider` `http-broker` or `adapter`
- `inference.provider: openai-compatible` with a non-empty `models.allowed`, catalog metadata for every allowed model, and `models.default`
- `network.publicFallback: deny`
- `acknowledgePlaintext: true` when `credential.storage.provider` is `file`

In both modes, `http-broker` needs an identity; `pi-native` credentials and `pi-native` inference must be chosen together; catalog entries must also be allowed; an enforced key cannot also be user-overridable; and an enforced `model` must equal `models.default`. `identity`, `credential`, `inference`, `network`, `variables`, `models.allowed`, and `models.catalog` can never be user-overridable.

A personal manifest defaults to `identity.mode: none` with `pi-native` credentials and inference. It may instead use `local-secret` or `none` credentials with an `openai-compatible` endpoint, including a local model server. The personal file store does not require `acknowledgePlaintext`.

## piship/v1alpha3 governance fields

Every governance section is optional; the defaults below apply when it is omitted, and several depend on `deployment.mode`. Governance fields never hold secrets: secret-looking keys, credential-looking environment variable names, and values shaped like tokens or private keys are rejected. What each control actually enforces is described in [security](security.md#governance).

### Resources and trust classes

Each resource kind (`instructions`, `skills`, `extensions`, `prompts`, `themes`) maps a trust class to entries:

```yaml
resources:
  skills:
    company: [./resources/skills]
    user: [./resources/my-skills]
    certified:
      - path: ./resources/certified/release-notes
        id: release-notes
        version: 1.0.0
        source: https://example.org/acme/release-notes
        integrity: sha256-<64 hex characters>
        license: MIT
        pi: ["0.87.1"]
        platforms: [linux, darwin]   # optional; empty means any
  extensions:
    builtin: [piship-ask-user, piship-workflow]
```

- `company`, `user`, and `certified` are the declarable classes. A path has exactly one class, and roots of different classes may not nest.
- `builtin` is valid only under `extensions` and names PiShip-maintained extensions: `piship-ask-user` (an `ask_user` tool that asks the person for a choice or approval) and `piship-workflow` (Plan/Build mode).
- `upstream` (resources that ship with the pinned Pi package) and `project` (resources discovered in the workspace, governed by `policy.projectTrust`) cannot be declared.
- A flat v1alpha2-style list is rejected; `piship migrate` converts it.

A certified entry carries review evidence: `id`, `version` (SemVer), `source`, `integrity`, `license` (SPDX expression), `pi` (the exact Pi versions it was reviewed against; required), and optional `platforms` (`linux`, `darwin`, `win32`). `integrity` is `sha256-` plus the SHA-256 of the sorted lines `<relative path> NUL <file sha256> LF` for every file under the root, so it is stable across checkouts and operating systems. `piship lock` fails if the computed digest differs, and the branded command recomputes it from the installed payload before loading the resource. Certified trees, and trees of non-builtin capability providers, may not contain a `package.json` with install-time scripts (`preinstall`, `install`, `postinstall`, `prepare`, `preprepare`, `postprepare`, or `prepublish`). A certified resource whose `pi` or `platforms` do not include the running Pi version and platform is not loaded.

### Capabilities

`capabilities` configures named capability contracts, each with `enabled`, an optional `provider`, and string `settings` (lowerCamelCase keys):

| Capability | Contract | This release |
| --- | --- | --- |
| `permissions` | `piship.capability/permissions/v1` | Implemented by `builtin/permissions`; enabled by default |
| `workflow` | `piship.capability/workflow/v1` | Implemented by `builtin/workflow`; disabled by default |
| `checkpoint`, `subagents`, `code-intel`, `acp` | `piship.capability/<name>/v1` (`subagents` uses `agents`) | Known but not implemented: reported as `supported: no` and never effective |

A provider `id` is `<class>/<name>` with class `builtin`, `certified`, `company`, or `user`; `upstream` is rejected because Pi ships no capability providers. A builtin provider declares only its `id`. Other providers declare `version`, `implements` (contract IDs such as `piship.capability/workflow/v1`), and a `./` `path` to their Pi extension; a certified provider adds the certified evidence fields. An enabled capability without a provider uses the builtin provider when one exists.

The builtin workflow reads three settings: `defaultMode` (`plan`, the default, or `build`), `planPrompt`, and `buildPrompt`. The prompts are appended to the system prompt for the current mode; built-in defaults are used when they are omitted.

The branded `capabilities [--json]` command reports six axes per capability (`supported`, `resolved`, `enabled`, `compatible`, `healthy`, `effective`) with a reason for every `no`. A non-builtin provider's extension is loaded only when its capability is effective: its provider class is trusted, its files match the lock, and its contract major version, Pi version, and platform match.

### Policy

| Field | Default | Values |
| --- | --- | --- |
| `policy.id` | `app.id` | Lowercase ID; decisions report `<id>@<version>` |
| `policy.version` | `1` | Positive integer |
| `policy.default` | `ask` (managed), `allow` (personal) | Effect when no rule matches |
| `policy.adapter` | none | `./` `.mjs` or `.js` module that exports team rules as `rules` or `default` (a list, `{rules: [...]}`, or a function returning one). Narrowing only; a module that fails to load fails the launch with `CONFIG_UNAVAILABLE` |
| `policy.resourceTrust` | every class `allow`, except `user: deny` in managed mode; `project: policy` | `upstream`, `builtin`, `certified`, `company`, `user`: `allow` or `deny`. `project`: `policy` (follow `projectTrust`), `allow` (load project instructions, skills, extensions, prompts, and themes), or `deny` |
| `policy.providerTrust` | same as resource trust, without `project` | Capability-provider trust per class; independent of resource trust |
| `policy.projectTrust` | see below | Project origin matchers and per-dimension effects |
| `policy.enforced` | `[]` | Rules that nothing below can relax |
| `policy.defaults` | `[]` | Distribution rules a user may relax |

A rule has `id` (lowercase, unique across `enforced` and `defaults`), `action`, `resource` (default `**`), `effect` (`allow`, `ask`, or `deny`), and an optional `reason` shown in denials. `action` is one action, a known prefix such as `mcp.*`, or `*`. The actions are `model.use`, `resource.load`, `extension.load`, `skill.load`, `instruction.load`, `provider.load`, `agent.invoke`, `mcp.server.start`, `mcp.tool.call`, `tool.execute`, `shell.execute`, `filesystem.read`, `filesystem.write`, `network.connect`, `memory.read`, `memory.write`, `web.request`, and `browser.execute`. This release evaluates the resources below at runtime; the other actions are accepted in rules and by `policy explain` but no runtime hook evaluates them yet.

| Action | Resource |
| --- | --- |
| `model.use` | `<provider>/<model>`; a managed gateway's provider is the app ID, as in `acmecode/acme/coder` |
| `instruction.load`, `skill.load`, `extension.load`, `resource.load` (prompts, themes) | `<class>:<path>`, such as `company:./resources/skills`, `builtin:piship-workflow`, or `project:AGENTS.md` |
| `mcp.server.start` | Server ID |
| `mcp.tool.call` | `<server>:<tool>` |
| `tool.execute` | Tool name, such as `read`, `bash`, or `mcp__docs__search` |
| `shell.execute` | The command text of the `bash` tool or a user `!` command |
| `filesystem.read`, `filesystem.write` | Absolute path, symlink-resolved, with `/` separators |

Resource globs are anchored and case-sensitive. `*` matches any run of characters except `/`, `:`, and line breaks; `**` matches anything. A trailing `/**` also matches the directory itself (`~/.ssh/**` covers `~/.ssh`), and `/**/` also matches a single `/`. Filesystem rules may start with the path tokens `workspace` (the project root), `~/` (the home directory), and `tmp/` (the session temp directory, or the system one without a sandbox); they are expanded and symlink-resolved like the requested path.

`policy.projectTrust` classifies the workspace. PiShip finds the project root by walking up to a `.git` entry, reads the `origin` remote from the git configuration without running git, and normalizes it to `host/path` (no scheme, user, port, or `.git`). `company.match` and `external.match` list matchers with exactly one of `remote` (a glob over `host/path`) or `path` (a glob over the absolute root); company is checked first, and anything else is `unknown`. Each origin sets eight dimensions to `allow`, `ask`, `deny`, or `company-approved`:

| Dimension | Project items | Managed default (company / external / unknown) | Personal default (company, external / unknown) |
| --- | --- | --- | --- |
| `passiveContext` | `.pi/themes` | allow / allow / allow | allow / allow |
| `instructions` | Root instruction files such as `AGENTS.md` and `AGENTS.override.md`, `.pi/SYSTEM.md`, `.pi/APPEND_SYSTEM.md`, `.pi/prompts`, and `@path` imports | allow / ask / deny | allow / ask |
| `skills` | `.pi/skills`, `.agents/skills` | allow / deny / deny | allow / ask |
| `extensions` | `.pi/extensions` | company-approved / deny / deny | allow / ask |
| `mcp` | `.mcp.json` | company-approved / deny / deny | allow / ask |
| `agents`, `hooks`, `providers` | `.pi/agents`, `.pi/settings.json`, `.piship/providers` | deny | allow (`hooks` deny) / ask (`hooks` deny) |

`company-approved` admits only distribution-approved items: project extensions are never loaded under it, and project MCP definitions may not add servers. This release never loads project agents, hooks, or providers, whatever the dimension says. An `ask` is answered on the terminal before Pi starts; headless launches have no one to ask, so `ask` resolves to deny.

### Local rule files

Two JSON files add rules at launch. Each is a list of rules or `{"rules": [...]}` with the same rule fields.

- `<state>/config/policy.json` holds user rules. For a request, a matching user rule takes the place of the matching distribution default, so a user may relax a default (for example `ask` to `allow`) but never an enforced or team/project rule.
- `.piship/policy.json` in the project holds project restrictions. It is narrowing only: `allow` rules are ignored with a warning in `doctor` and `policy explain` and a `policy.violation` audit event. It is not read if it resolves outside the project root.

### MCP

| Field | Default | Values |
| --- | --- | --- |
| `mcp.mode` | `allowlist` (managed), `explicit` (personal) | `off`, `allowlist` (declared servers only), or `explicit` (declared servers plus trusted project definitions; personal only). `off` may not declare servers |
| `mcp.project` | `deny` (managed), `allow` (personal) | Whether project `.mcp.json` servers may be used in `explicit` mode |
| `mcp.user` | `deny` (managed), `allow` (personal) | Accepted; user-level MCP definitions are not loaded by this release |
| `mcp.servers.<id>` | none | Server ID: lowercase letters, digits, and hyphens, at most 32 |

A server declares `transport`:

- `stdio`: exactly one of `module` (a `./` `.mjs` or `.js` file in the distribution, run with the distribution's Node.js) or `command` (a bare executable name found on `PATH`), plus `args` and `env` (`allow`: variable names inherited from the launch environment; `set`: fixed non-secret values). Credential-looking names are rejected.
- `streamable-http`: `url`, which may be a `${NAME}` runtime reference. The legacy HTTP+SSE transport is rejected.

Other server fields: `credential` (`none`, the default, or `runtime`, which sends the distribution's runtime credential as a bearer; `streamable-http` only), `expectedServerName` (the `serverInfo.name` the server must report, or the start fails), `timeout` (per call, default `30s`), `startupTimeout` (default `10s`), `retry.attempts` (start attempts for retryable failures, default `1`, at most `10`), `required` (default `false`; a required server that is denied or cannot start fails the launch with `MCP_DENIED` or `MCP_UNHEALTHY`), and `tools.allow` / `tools.deny` (exact tool names; deny wins, an empty allow list admits every tool not denied, and a name may not appear in both). Exposed tools are named `mcp__<server>__<tool>`.

### Sandbox

| Field | Default | Values |
| --- | --- | --- |
| `sandbox.required` | `false` | `true` activates the OS sandbox and fails the launch with `SANDBOX_UNAVAILABLE` when it cannot be enforced. With `false`, no OS sandbox is activated |
| `sandbox.filesystem.read.deny` | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.npmrc`, `~/.pi` | Paths hidden from contained processes; the distribution state directory is always added |
| `sandbox.filesystem.write.allow` | `workspace`, `tmp` | The only writable paths; everything else is read-only |
| `sandbox.network.mode` | `deny` when required, otherwise `allow` | `deny` or `allow` only. `allowlist`, `allow`, `allowHosts`, and `hosts` keys are rejected: hostname allowlists are not enforced at this boundary |
| `sandbox.environment.allow` | `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `TZ`, `SHELL`, `TMPDIR` | Variables passed into contained processes; credential-looking names are rejected |

Sandbox paths are `workspace`, `tmp`, `~/...`, or absolute paths, without `.` or `..` segments. `tmp` is a private per-session directory.

### Audit

| Field | Default | Values |
| --- | --- | --- |
| `audit.enabled` | `true` (managed), `false` (personal) | Enabled audit needs at least one sink |
| `audit.sinks` | one optional `file` sink named `local` when enabled | `id`, `type` (`file`, written to `<state>/logs/audit.jsonl`, or `http`, which POSTs event batches to `url`), `url` (`http` only; may be a `${NAME}` runtime reference), and `required` (default `false`) |
| `audit.buffer` | `maxEvents: 1000`, `flushInterval: 2s` | Bounded in-memory buffer per sink |
| `audit.capture` | all `false` | `promptContent`, `responseContent`, `commandText`, `sourceContent`: opt-in content classes. Events are metadata only otherwise |

## Configuration layers

The effective value of `model`, `theme`, and `thinkingLevel` comes from Distribution Enforced, then a permitted User Preference, then Distribution Defaults. An enforced value always wins, and a preference for a key that is enforced or not user-overridable is ignored with a visible notice. Users set preferences with the branded `config set <key> <value>` and `config unset <key>`, stored in `config/preferences.json`. Security-sensitive keys are refused with `POLICY_DENIED`, and a model outside the allowlist with `MODEL_DENIED`. `config set models.allowed a,b` may only narrow the allowlist. `config explain [--json]` prints every effective value with its source, runtime references with whether they resolve, and non-secret identity and credential state. For v1alpha3 it adds distribution-enforced rows for the policy ID and rule counts, `mcp.mode`, `sandbox.required`, `sandbox.network`, and `audit.sinks`.

## Runtime references

`${NAME}` is accepted only in `identity.oidc.issuer`, `identity.oidc.clientId`, `identity.oidc.audience`, `credential.broker.endpoint`, `credential.broker.revokeEndpoint`, `inference.baseUrl`, `network.tls.additionalCA`, and, in v1alpha3, `mcp.servers.<id>.url` and `audit.sinks[].url`. Each name must be listed in `variables`, use uppercase letters, digits, and underscores, and be referenced at least once. Names containing `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `PRIVATE_KEY`, or `SESSION` are rejected: references carry endpoints and identifiers, never secrets.

The manifest and lock keep the unresolved template, so a lock is not machine-specific. The branded command resolves references from its launch environment. A missing or empty variable fails with `CONFIG_UNAVAILABLE`; resolved values may not contain a further `${...}` or control characters, and resolved URLs must use HTTPS except for loopback hosts. `piship validate` lists the variables and notes which are unset in the current shell.

## Commands

```bash
npm exec -- piship init ./my-agent             # personal v1alpha1
npm exec -- piship init ./my-agent --managed   # managed v1alpha2 template
npm exec -- piship validate ./my-agent/piship.yaml
npm exec -- piship migrate ./my-agent/piship.yaml [--write]
npm exec -- piship lock ./my-agent/piship.yaml
npm exec -- piship test ./my-agent/piship.yaml [--model-request]
npm exec -- piship build ./my-agent/piship.yaml
npm exec -- piship config explain <manifest|artifact|id>
node ./dist/my-agent/piship.mjs install ./dist/my-agent
my-agent --version
my-agent --smoke
node ./dist/my-agent/piship.mjs inspect my-agent
node ./dist/my-agent/piship.mjs doctor my-agent
node ./dist/my-agent/piship.mjs uninstall my-agent
node ./dist/my-agent/piship.mjs purge my-agent --yes
```

`dev` builds and starts the interactive branded command with the same resource and state isolation. `test` assembles the artifact and runs the branded `--smoke`: Pi SDK, extension, read-tool, and session checks without a model request. `--model-request` runs `--smoke-model` instead, which sends one acceptance prompt to the selected model. For v1alpha2 and v1alpha3 payloads both need the same runtime variables and, where the distribution requires it, the same prior `login` as the branded command. `inspect` accepts a manifest, artifact directory, or installed ID and includes the static `access` section. `doctor` accepts an artifact directory or installed ID, verifies payload integrity, runs the branded `doctor` report for access-enabled payloads, and launches the smoke. `config explain` explains a manifest directly (without building) using that distribution's state, or runs the branded explanation for an artifact directory or installed ID.

v1alpha2 branded commands add `login`, `logout`, `doctor`, `models`, `version`, `config explain [--json]`, `config set <key> <value>`, `config unset <key>`, `--model <id>`, `--smoke`, and `--smoke-model`. `--smoke` writes a clearly labeled synthetic entry to a separate acceptance session; `--smoke-model` makes a real request to the configured endpoint.

v1alpha3 branded commands add:

- `policy explain <action> <resource> [--json]`: the decision, deciding rule, layer, policy ID, enforcement plane, reason, other matching rules (including ones shadowed by an earlier rule in their layer), and ignored narrowing-only `allow` rules. Filesystem resources are resolved as tools see them: `~` is the home directory and relative paths resolve against the working directory.
- `capabilities [--json]`: the six-axis capability table.
- `doctor` sections for Policy, Project (origin and each discovered project item with its effect), Resources (trust class, integrity, and whether each loads), Capabilities, Sandbox (the containment level proven by a live probe, network mode, and scope), MCP and audit (server health and sink state), and local metrics.
- A `governance` object in the `--smoke` summary: policy ID, project origin, sandbox level, adapter, planes, and network, workflow mode, capability effectiveness, resource load decisions, MCP server states and exposed tools, and audit state.

## Lock

`piship.lock` records the normalized manifest digest, app identity, deployment mode, Pi package and version, PiShip version, committed npm lock digest, resolved package versions and npm integrity strings, declared roots, and SHA-256 hashes for every declared resource. A v1alpha1 manifest produces `piship-lock/v1alpha1`. A v1alpha2 manifest produces `piship-lock/v1alpha2`, which adds a static `access` section with provider modes, unresolved `${NAME}` templates, the model catalog, configuration layers, and network policy, and locks identity and credential adapters as resources of kind `adapters`.

A v1alpha3 manifest produces `piship-lock/v1alpha3`. Each locked resource also records its trust class; capability-provider roots are locked as kind `providers`; the policy adapter and stdio MCP modules are locked as `adapters`. A `governance` section holds the parsed governance intent, each certified root with its evidence and computed tree digest, and each capability provider with its class, version, implemented contracts, and tree digest.

The lock never contains tokens, credentials, or resolved endpoint values. It is deterministic and has no timestamp. Build rejects a stale lock. The packaged file inventory detects changed manifest, lock, resource, adapter, or runtime files before Pi loads. There is no signature or trusted publisher verification.

## Migration

`piship migrate <manifest>` prints a dry-run plan and the migrated YAML; `--write` applies it in place. It migrates step by step to `piship/v1alpha3`; an existing v1alpha3 manifest is left unchanged.

- v1alpha1 to v1alpha2: an equivalent personal profile with `identity.mode: none`, `credential.provider: pi-native`, and `inference.provider: pi-native`. v1alpha1 never had a runnable managed mode, so a v1alpha1 manifest with `deployment.mode: managed` is rejected and must be rewritten with access sections (see `piship init --managed`).
- v1alpha2 to v1alpha3: each flat resource list becomes the `company` class (managed) or `user` class (personal). The new sections are written with values that keep v1alpha2 behavior: `policy.default: allow`; every project origin denies all dimensions except `passiveContext`; `sandbox.required: false`; `audit.enabled: false`; and `mcp.mode: off`. Resource, provider, and project trust and capability defaults then apply (the builtin `permissions` capability is enabled), so review the plan before writing it.

After migrating, regenerate `piship.lock` and rebuild. v1alpha1 remains accepted for personal distributions, and v1alpha2 remains accepted. `piship init --managed` still writes a v1alpha2 template; migrate it to adopt governance.

Earlier checkout-local preview manifests need `app.version` added; `app.banner`, `app.theme`, and `resources.themes` are optional. Regenerate `piship.lock` with the current CLI, then rebuild. Checkout-local output cannot be installed as a portable payload.
