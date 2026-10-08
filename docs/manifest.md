# Manifest and lock

Seven schemas are accepted. `piship/v1` is the stable contract ([stability](#stability)); the six alpha schemas before it are experimental and stay accepted for the [migration window](support-policy.md#manifest-versions-and-the-migration-window). Unknown fields are rejected in every schema. Schema versions change independently of project milestones: v0.5, v0.6, and v0.7 all use `piship/v1alpha4` and `piship-lock/v1alpha4`; v0.8 introduces `piship/v1alpha5` and `piship-lock/v1alpha5`, and v0.9 (v0.9.0) `piship/v1alpha6` and `piship-lock/v1alpha6`, the last alpha schemas before v1, and v0.11 `piship/v1` and `piship-lock/v1` ([version map](status.md#version-map)). While a schema is an alpha, a backward-compatible addition (a new enum value, a new optional lock key) keeps its version; removing or reinterpreting a field, or making one required, needs a new version ([decision 27](decisions.md)); the stable schema follows the same rule with the guarantees of [stability](#stability) ([decision 34](decisions.md)). v0.7 added `sandbox.credential: stored` and two `runtime.stateSchemas` lock keys this way.

- `piship/v1alpha1` is the v0.1 personal contract. It accepts only `deployment.mode: personal`, uses Pi-native providers and auth in isolated state, and rejects credential fields and `${...}` substitutions. The personal example used it in v0.1; it now uses `piship/v1`.
- `piship/v1alpha2` adds access configuration for `managed` and `personal` distributions.
- `piship/v1alpha3` keeps the v1alpha2 access fields and adds governance: trust-classed resources, capabilities, policy, MCP, sandbox, and audit.
- `piship/v1alpha4` is v1alpha3 plus a required `updates` section and an optional `release` section for the production lifecycle ([release](release.md)). Every v1alpha3 field keeps its meaning.
- `piship/v1alpha5` changes only the update-trust contract: `updates.trust.bootstrap`, a versioned update root with separate root and channel signing roles, replaces v1alpha4's `updates.trust.keys` ([update trust](#update-trust-bootstrap-v1alpha5)). Every other v1alpha4 field keeps its meaning. A v0.8 release requires v1alpha5.
- `piship/v1alpha6` adds Pi 1.x-native governance: tool exposure, Codemode and tool search, cache warming, MCP server classes, model types and virtual models, the `data` lifecycle, Pi packages, and `policy.acknowledgeUnenforced` ([v1alpha6 fields](#v1alpha6-fields)). Every v1alpha5 field keeps its meaning except MCP `tools`, which becomes an exposure map; `piship migrate` converts a v1alpha5 manifest without broadening it ([migration](#migrating-from-v1alpha5-to-v1alpha6)). `piship release` accepts v1alpha5, v1alpha6, and v1.
- `piship/v1` is `piship/v1alpha6`, frozen. It has the same fields, defaults, and validation rules, so a v1alpha6 manifest becomes a v1 manifest by changing `schema` and nothing else (`piship migrate` does exactly that, and reports what needs an owner's decision, [below](#migrating-from-v1alpha6-to-v1)). A change to the contract after this point follows [stability](#stability). The [demo company example](../examples/demo-company/piship.yaml) is a managed v1 manifest, and the [personal example](../examples/personal/piship.yaml) and its [local-model variant](../examples/personal/local-model/piship.yaml) are personal v1 manifests, as is the [developer example](../examples/developer/piship.yaml), which also ships a [hardened managed variant](../examples/developer/managed.piship.yaml).

## Stability

`piship/v1` and `piship-lock/v1` are stable. The full compatibility and support contract is the [support policy](support-policy.md); this section is what a manifest author needs.

- **Additive changes stay `piship/v1`.** A new optional field, a new value for an enum, and a new optional lock key can arrive in a minor release. A manifest that does not use them parses, locks to the same bytes, and means the same as before; a lock written before an addition stays current.
- **Breaking changes need a new major schema.** Removing or renaming a field or value, making a field required, narrowing what one accepts, changing a default, or giving a field another meaning is `piship/v2` with its own migration. Nothing reinterprets a `piship/v1` manifest.
- **A security fix is the one exception.** It may reject an input that was unsafe, is listed as a behavior change in the changelog, and is reported by `validate` with the field's path.
- **Defaults are part of the contract.** The defaults of v1alpha6 hold in v1: `release.bundle` and `release.strip` are on unless the manifest says `false`, an omitted `runtime.cacheWarming` is `off`, and an omitted `data` section sweeps nothing. They are applied where they are read and never written into the parsed manifest or the lock, so the digest of an unchanged manifest never moves.
- **Provider versions and capability contracts stay separate.** A provider's SemVer `version` and the `piship.capability/<name>/v1` contract it `implements` are different things; neither changes the manifest schema.
- **`model.use`** stays accepted as an alias of `model.select` in manifests and in `config/policy.json`.

## Common fields

Required fields are `schema`, `app.id`, `app.name`, `app.command`, `app.version`, and `deployment.mode`. `runtime.pi` is optional: left out, the build uses the Pi version this PiShip pins, so a PiShip upgrade does not break the manifest; a manifest that states it must state exactly that pin (`validate` says to remove the line or set the pin). `app.banner` and `app.theme` are optional. `app.theme` selects a built-in or declared custom theme through Pi's public interactive API. `resources` can declare instruction files and skill, extension, prompt, or theme roots (from v1alpha3, grouped by trust class; see below). IDs and commands use safe lowercase names; `app.version` is a distribution semver independent of PiShip and Pi versions. Resource paths start with `./`, stay inside the manifest directory, and may not contain symlinks.

## Access fields (v1alpha2 and later)

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
| `models.catalog.<id>` | `name`, `contextWindow`, `maxOutputTokens`, optional `input` (`text`, `image`), `reasoning`, `tools`, `streaming`, `structuredOutput`, and `policyTags` |
| `config.enforced`, `config.defaults` | Values for `model`, `theme`, and `thinkingLevel` (`off`, `minimal`, `low`, `medium`, `high`, `xhigh`). Use `models.default` rather than `config.defaults.model` |
| `config.userOverridable` | Keys users may set; defaults to every key not enforced |
| `network.proxy.inheritEnvironment` | Honor `HTTP(S)_PROXY` and `NO_PROXY` (default `true`). In a managed distribution, commands the agent runs receive these variables only when this is `true`, and never a proxy URL that embeds credentials ([security](security.md#child-process-network-environment)) |
| `network.tls.additionalCA` | Absolute PEM bundle paths added to the default trust roots, also for hosts reached through a proxy, read on each machine at launch and never packaged; `validate` warns about a relative path. A single bundle is also passed to commands the agent runs as `NODE_EXTRA_CA_CERTS`. Quote a runtime reference in a `[...]` list, `additionalCA: ["${CORP_CA_BUNDLE}"]`: unquoted, `${` is not valid YAML there |
| `network.publicFallback` | `deny` or `allow`; managed requires `deny`, which makes managed launches private-only whatever `network.privateOnly` says |
| `network.privateOnly`, `network.allowHosts` | Restrict PiShip-managed and in-process `fetch` requests to declared endpoint hosts plus `allowHosts`. Each `allowHosts` entry is one exact hostname or IP literal, compared case-insensitively with the URL's host: no wildcard (`*.corp.example`), no suffix match (`corp.example` does not admit `api.corp.example`, and the reverse), no trailing dot, port, scheme, path, or address range, and IPv6 only as `[::1]`; write an internationalized name in its `xn--` form. Anything else fails validation with `Expected a hostname`. The match is on the hostname only: ports and schemes are ignored, so a declared host admits every port on it, and PiShip does not check that a host is a private address or what it resolves to. It is a hostname allowlist, not a network boundary |

The IdP, broker, and gateway these fields point to must implement the [enterprise integration contract](enterprise-integration.md).

Secret-looking fields such as `credential.apiKey`, `credential.secret`, `credential.token`, `identity.oidc.clientSecret`, and `network.tls.rejectUnauthorized` or `insecure` are rejected. Every string value and key is also checked for common secret shapes (`sk-` keys, GitHub, GitLab, and Slack tokens, JWTs, AWS access key IDs, PEM private keys, and `Bearer` or `Basic` credentials); a match fails with the field path and never prints the value. The check cannot detect every secret.

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

These fields apply to `piship/v1alpha4`, `piship/v1alpha5`, and `piship/v1alpha6`; v1alpha6 changes MCP `tools` and adds the fields under [v1alpha6 fields](#v1alpha6-fields). Every governance section is optional; the defaults below apply when it is omitted, and several depend on `deployment.mode`. Governance fields never hold secrets: secret-looking keys, credential-looking environment variable names, and values shaped like tokens or private keys are rejected. What each control actually enforces is described in [security](security.md#governance).

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
        pi: ["1.0.3"]
        platforms: [linux, darwin]   # optional; empty means any
  extensions:
    builtin: [piship-ask-user, piship-workflow]
```

- `company`, `user`, and `certified` are the declarable classes. A path has exactly one class, and roots of different classes may not nest.
- `builtin` is valid only under `extensions` and names PiShip-maintained extensions: `piship-ask-user` (an `ask_user` tool that asks the person for a choice or approval) and `piship-workflow` (Plan/Build mode).
- `upstream` (resources that ship with the pinned Pi package) and `project` (resources discovered in the workspace, governed by `policy.projectTrust`) cannot be declared.
- A flat v1alpha2-style list is rejected; `piship migrate` converts it.

A certified entry carries review evidence: `id`, `version` (SemVer), `source`, `integrity`, `license` (SPDX expression), `pi` (the exact Pi versions it was reviewed against; required), and optional `platforms` (`linux`, `darwin`, `win32`). `integrity` is `sha256-` plus the SHA-256 of the sorted lines `<relative path> NUL <file sha256> LF` for every file under the root, so it is stable across checkouts and operating systems. `piship lock` fails if the computed digest differs, and the branded command recomputes it from the installed payload before loading the resource. Certified trees, and trees of non-builtin capability providers, may not contain a `package.json` with install-time scripts (`preinstall`, `install`, `postinstall`, `prepare`, `preprepare`, `postprepare`, or `prepublish`) or a `binding.gyp`, which makes npm run `node-gyp rebuild` at install. A certified resource whose `pi` or `platforms` do not include the running Pi version and platform is not loaded.

### Capabilities

`capabilities` configures named capability contracts, each with `enabled`, an optional `provider`, string `settings` (lowerCamelCase keys), and optional model `requirements` (`tools`, `structuredOutput`, `minContextWindow`, and `input`). At launch, a selected model whose verified catalog metadata does not meet the requirements of an enabled capability, or whose metadata is unknown, fails with `MODEL_INCOMPATIBLE`; no other model is substituted, and Pi-native models count as unverified:

| Capability | Contract | This release |
| --- | --- | --- |
| `permissions` | `piship.capability/permissions/v1` | Implemented by `builtin/permissions`; enabled by default |
| `workflow` | `piship.capability/workflow/v1` | Implemented by `builtin/workflow`; disabled by default |
| `checkpoint`, `subagents`, `code-intel`, `acp` | `piship.capability/<name>/v1` (`subagents` uses `agents`) | Known but not implemented: reported as `supported: no` and never effective |

A provider `id` is `<class>/<name>` with class `builtin`, `certified`, `company`, or `user`; `upstream` is rejected because Pi ships no capability providers. A builtin provider declares only its `id`. Other providers declare `version`, `implements` (contract IDs such as `piship.capability/workflow/v1`), and a `./` `path` to their Pi extension (or, from v1alpha6, `package: <id>` naming a declared Pi package, see [what a package is given](#what-a-package-is-given-environment-and-files)); a certified provider adds the certified evidence fields. An enabled capability without a provider uses the builtin provider when one exists.

The builtin workflow reads three settings: `defaultMode` (`plan`, the default, or `build`), `planPrompt`, and `buildPrompt`. The prompts are appended to the system prompt for the current mode; built-in defaults are used when they are omitted.

The branded `capabilities [--json]` command reports six axes per capability (`supported`, `resolved`, `enabled`, `compatible`, `healthy`, `effective`) with a reason for every `no`. A non-builtin provider's extension is loaded only when its capability is effective: its provider class is trusted, its files match the lock, and its contract major version, Pi version, and platform match. The policy then decides `provider.load` for the provider ID and `extension.load` for `<class>:<path>`; a denial skips the provider and is reported as `enabled: no`, not as a health failure, so the capability is not effective. `compatible` also checks an enabled capability's `requirements` against the selected model with the same comparison as the launch check, so a running session's report and `MODEL_INCOMPATIBLE` agree. Offline, `capabilities` and `doctor` use the model launch would select from the configuration and its manifest catalog metadata; they can differ from launch when `--model` or a credential entitlement changes the selected model.

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
| `policy.defaults` | `[]` | Distribution rules a personal user may relax; managed user rules only narrow |
| `policy.userAuto` | `off` (absent) | v1alpha5, managed only: `off` or `allowed`. `allowed` lets each user switch on [auto mode](#user-auto-mode), which approves an `ask` from `policy.defaults` or `policy.default` without a prompt; `deny`, `policy.enforced`, and team, project, and the user's own rules are never relaxed. It also lets a user start a session with [`--yolo`](#the---yolo-launch-option), which does the same for that session only and stores nothing. A personal manifest that declares it is rejected: there the user already relaxes `ask` with allow rules in `config/policy.json` |

A rule has `id` (lowercase, unique across `enforced` and `defaults`), `action`, `resource` (default `**`), `effect` (`allow`, `ask`, or `deny`), and an optional `reason` shown in denials. `action` is one action, a known prefix such as `mcp.*`, or `*`. The actions are `model.select` (written `model.use` before v1alpha6, which is still accepted as an alias), `model.dispatch`, `session.export`, `resource.load`, `extension.load`, `skill.load`, `instruction.load`, `provider.load`, `agent.invoke`, `mcp.server.start`, `mcp.tool.call`, `tool.execute`, `shell.execute`, `filesystem.read`, `filesystem.write`, `network.connect`, `memory.read`, `memory.write`, `web.request`, and `browser.execute`. This release evaluates the actions below at runtime. `agent.invoke`, `memory.read`, `memory.write`, `web.request`, `browser.execute`, and `network.connect` (unless a required sandbox has `network.mode: deny`) have no runtime seam: they are accepted in rules and by `policy explain`, report `unsupported`, and a managed `deny` or `ask` rule naming one fails `validate` with `POLICY_UNENFORCEABLE` ([enforcement status](#enforcement-status)).

| Action | Resource |
| --- | --- |
| `model.select` | `<provider>/<model>`; a managed gateway's provider is the app ID, as in `acmecode/acme/coder` |
| `model.dispatch` | `<provider>/<model>` of the physical model a request is sent to; without a `model.dispatch` rule for it, `model.select` decides |
| `instruction.load`, `skill.load`, `extension.load`, `resource.load` (prompts, themes) | `<class>:<path>`, such as `company:./resources/skills`, `builtin:piship-workflow`, or `project:AGENTS.md` |
| `provider.load` | Capability provider ID, such as `company/flow`; its extension is then decided as `extension.load` with `<class>:<path>` |
| `mcp.server.start` | Server ID |
| `mcp.tool.call` | `<server>:<tool>` |
| `tool.execute` | Tool name, such as `read`, `bash`, or `mcp__docs__search` |
| `shell.execute` | The command text of the `bash` tool or a user `!` command. `allow` and `ask` rules are prefix hints: they do not match a command with a shell metacharacter (`;` `&` `\|` `$` `` ` `` `<` `>` `(` `)`, a line break, `^`, `%`) that the pattern does not spell out, except the bare `**`; `deny` rules always match. An `ask` from `policy.enforced`, a team or project rule, or a managed user's own rule still applies to such a chained command (`git push**` keeps its prompt for `git push origin main; true`); it only ever adds an `ask` to the strictest-wins result |
| `filesystem.read`, `filesystem.write` | Absolute path, symlink-resolved, with `/` separators |
| `session.export` | `public`, `local`, or `support` ([session export](#session-export)) |

Resource globs are anchored and case-sensitive. `*` matches any run of characters except `/`, `:`, and line breaks; `**` matches anything. A trailing `/**` also matches the directory itself (`~/.ssh/**` covers `~/.ssh`), and `/**/` also matches a single `/`. Filesystem rules may start with the path tokens `workspace` (the project root), `~/` (the home directory), and `tmp/` (the session temp directory, or the system one without a sandbox); they are expanded and symlink-resolved like the requested path.

`policy.projectTrust` classifies the workspace. PiShip finds the project root by walking up to a `.git` entry, reads the `origin` remote from the git configuration without running git, and normalizes it to `host/path` (no scheme, user, port, or `.git`). `company.match` and `external.match` list matchers with `remote` (a glob over `host/path`), `path` (a glob over the absolute root), or both, in which case both must match; company is checked first, and anything else is `unknown`. The remote comes from the checkout's own git configuration, so `remote` alone is a claim, not proof; in managed distributions combine it with `path`, as in `{ remote: "git.acme.example/**", path: "/srv/src/**" }`. Each origin sets eight dimensions to `allow`, `ask`, `deny`, or `company-approved` (five optional [Claude Code dimensions](#claude-code-project-configuration) follow):

| Dimension | Project items | Managed default (company / external / unknown) | Personal default (company, external / unknown) |
| --- | --- | --- | --- |
| `passiveContext` | `.pi/themes` | allow / allow / allow | allow / allow |
| `instructions` | Root instruction files such as `AGENTS.md` and `AGENTS.override.md`, `.pi/SYSTEM.md`, `.pi/APPEND_SYSTEM.md`, `.pi/prompts`, and `@path` imports | allow / ask / deny | allow / ask |
| `skills` | `.pi/skills`, `.agents/skills` | allow / deny / deny | allow / ask |
| `extensions` | `.pi/extensions` | company-approved / deny / deny | allow / ask |
| `mcp` | `.mcp.json` | company-approved / deny / deny | allow / ask |
| `agents`, `hooks`, `providers` | `.pi/agents`, `.pi/settings.json`, `.piship/providers` | deny | allow (`hooks` deny) / ask (`hooks` deny) |

`company-approved` admits only distribution-approved items: project extensions are never loaded under it, and project MCP definitions may not add servers. This release never loads project agents, hooks, or providers, whatever the dimension says. An `ask` is answered on the terminal before Pi starts; headless launches have no one to ask, so `ask` resolves to deny. All the items of one project that ask are covered by one question, and in a personal distribution the answer can be kept ([remembered answers](#claude-code-project-configuration)). The user's [auto mode](#user-auto-mode) never answers these project trust prompts: they decide whether to trust a workspace's content, not whether to run an action.

### Claude Code project configuration

A repository that already works with Claude Code holds `CLAUDE.md`, `.claude/rules`, `.claude/commands`, `.claude/skills`, `.claude/agents`, hooks (declared in `.claude/settings.json`, with scripts often under `.claude/hooks`), and often `.mcp.json`. Pi's own project discovery is off in a distribution, and PiShip itself loads none of this except the root `CLAUDE.md`, an `instructions` item as before. A distribution that includes an extension for it, such as the [pi-code](https://www.npmjs.com/package/pi-code) package, gets it loaded by that extension, which reads the files itself once Pi reports the project as trusted. PiShip owns that answer, so a project's own `.claude/` never admits itself under company policy ([security](security.md#project-trust)). Five optional dimensions, set per origin like the eight above, decide it:

| Dimension | Project items, found in every directory from the working directory up to the project root | Managed default (company / external / unknown) | Personal default (company / external / unknown) |
| --- | --- | --- | --- |
| `claudeRules` | `.claude/rules`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/output-styles` | company-approved / deny / deny | allow / allow / ask |
| `claudeCommands` | `.claude/commands` | company-approved / deny / deny | allow / allow / ask |
| `claudeSkills` | `.claude/skills` | company-approved / deny / deny | allow / allow / ask |
| `claudeAgents` | `.claude/agents` | company-approved / deny / deny | allow / allow / ask |
| `claudeHooks` | `.claude/hooks`, `.claude/settings.json`, `.claude/settings.local.json` | deny / deny / deny | allow / allow / ask |

- **Optional.** A dimension the manifest does not declare takes the default above when the project is evaluated. It is not written to the parsed policy or the lock, so the lock of an existing distribution does not change, and `piship diff` reads an undeclared one as its default (declaring the default is no change) and reports a changed one like any other dimension. Personal mode loads the configuration of a company or external project without a prompt and asks for an unknown one, once per launch unless you keep the answer; managed mode loads none of it until the company declares `allow` for an origin it trusts, because `company-approved` admits no project content here (an extension's code cannot be held to an allowlist). `policy.resourceTrust.project: deny` denies all five, and `allow` admits rules; Claude commands, skills, agents, and hooks still require their own dimension.
- **Admitted as a unit.** Pi gives an extension one answer per session, never one per kind. PiShip therefore admits the configuration an extension reads as a whole: the five kinds above, `.mcp.json` and `.pi/mcp.json` (the `mcp` dimension), and `.pi/agents` (`agents`), which pi-code reads under the same answer. Each is looked for in every directory from the working directory up to the project root, where an extension finds the nearest one. Every item found must be admitted: one that is denied, or `company-approved`, leaves all of them unloaded. `claudeHooks` covers `.claude/settings.json` and `settings.local.json` because Claude hooks, `env`, and a status-line command are declared there, and PiShip does not read them; a project that has a settings file stays closed while `claudeHooks` is `deny`.
- **Per item.** Each item is then decided as `resource.load` with the resource `project:<path under the project root>`, such as `project:.claude/hooks` or `project:packages/app/.claude/rules`, so `policy.enforced`, `policy.defaults`, `policy.default`, and a project's narrowing-only `.piship/policy.json` apply to it: `{ id: no-project-hooks, action: resource.load, resource: "project:**/.claude/hooks", effect: deny }` keeps hooks out whatever the dimension says. An `ask` dimension asks once for the whole configuration, on the terminal before Pi starts; headless, it resolves to deny.
- **Remembered.** In a personal distribution the terminal question offers `a` (always) and `never` besides yes and no. The answer is kept in `config/project-trust.json` in the distribution state (owner-only), keyed by the canonical project root, with a digest of the files it covered, so a changed file asks again. It only replaces the question of an `ask`: a `deny`, a policy rule, or a project that is not asked about is decided as before, and a managed distribution always asks and keeps nothing. A kept answer also answers a headless launch. `<command> config trust list` shows the answers, and `config trust forget [<path>|--all]` removes them; deleting the file does the same.
- **Nothing found.** A personal project with no such configuration is trusted. A managed one is trusted only when policy admits all five dimensions for its origin, because an extension can search where PiShip did not (the main checkout of a linked worktree, a directory below the working directory) and PiShip cannot prove nothing is there.
- **Recorded.** Each item produces a `resource.load` or `resource.denied` audit event (`detail.kind` `claude` or `extension-config`, `detail.dimension`), and the unit produces one more for `project:.claude` with `detail.seam: project-trust`. `--smoke` lists the items under `governance.resources` with the reason each did not load. `doctor` shows each item in the Project group and, last, `project trust for extensions` with the static decision. A launch that leaves project files unloaded prints one line naming them and how to trust them, once per project until those files change.

A company that trusts its own repositories and wants rules, commands, skills, and agents to work, but not hooks, declares:

```yaml
policy:
  projectTrust:
    company:
      match: [{ remote: "git.acme.example/**", path: "/srv/src/**" }]
      claudeRules: allow
      claudeCommands: allow
      claudeSkills: allow
      claudeAgents: allow
      claudeHooks: deny   # the default: a project with hooks or a settings file stays closed
  defaults:
    - { id: project-claude, action: resource.load, resource: "project:**/.claude/**", effect: allow }
```

The seam reaches only an extension that asks Pi whether the project is trusted. What PiShip does and does not enforce, including the user-scope files pi-code reads and the MCP servers it starts itself, is in [security](security.md#project-trust). For a managed distribution that includes pi-code 1.4.2, also leave out its MCP client, which starts the servers named in `~/.claude.json`, the distribution's `<state>/agent/mcp.json`, plugins, and (when trusted) the project outside PiShip's `mcp.server.start` decisions, exposure, and sandbox, and, when no hooks should run at all, its hooks extension:

```yaml
resources:
  packages:
    - id: pi-code
      source: npm
      package: pi-code
      version: 1.4.2
      registry: https://registry.company.example
      class: company
      # Package filters match the paths of the entry files inside the package.
      extensions: ["!extensions/mcp/**"]   # add "!extensions/hooks/**" to run no Claude hooks
```

`piship lock` writes the resulting extension inventory into `piship.lock`; review it there, since a later pi-code release can lay its files out differently.

### Local rule files

Two JSON files add rules at launch. Each is a list of rules or `{"rules": [...]}` with the same rule fields.

- `<state>/config/policy.json` holds user rules. In personal mode, where the local owner owns the policy, a matching user rule takes the place of the matching distribution default, so a user may relax a default (for example `ask` to `allow`) but never an enforced or team/project rule. In managed mode user rules are narrowing only, like project restrictions: they can tighten any decision, and `allow` rules are ignored with a warning in `doctor` and `policy explain` and a `policy.violation` audit event.
- `.piship/policy.json` in the project holds project restrictions. It is narrowing only: `allow` rules are ignored with a warning in `doctor` and `policy explain` and a `policy.violation` audit event. It is not read if it resolves outside the project root.

A managed user cannot widen the policy with these files. The one user-controlled relaxation is auto mode (and its session-only form, [`--yolo`](#the---yolo-launch-option)), and only where the distribution allows it.

### User auto mode

With `policy.userAuto: allowed` (v1alpha5, managed), each user may switch auto mode on for themselves with the branded `auto on`, `auto off`, and `auto status`, or `/auto on`, `/auto off`, and `/auto` inside a session. While it is on:

- An `ask` decided by a `policy.defaults` rule or by `policy.default` is approved without a prompt, in an interactive session and headless (where it would otherwise resolve to deny). Each one is recorded as a `policy.auto_approved` audit event with the same metadata as the action's own event, and the action's own event records `decision: approved` with `approval: auto`.
- `deny` is never changed. An `ask` from `policy.enforced`, the team adapter, a project restriction, or the user's own `config/policy.json` still prompts: those rules were written to keep the prompt. Project trust prompts and the built-in denials (the state directory, git control files, Plan mode, the sandbox) are not policy decisions and are not affected.
- `policy explain` shows such a decision as `AUTO-APPROVED`, effect `ask (auto-approved by user)` (`"autoApproved": true` with `--json`); `doctor` shows the switch in the Policy group; `config explain` adds a `policy.userAuto` row with the user's state.

Switching it on is recorded as `policy.auto_enabled` (`detail.source`: `command` or `session`) before it changes, so a required audit sink that does not take the event leaves auto mode off (`AUDIT_UNAVAILABLE`: "Auto mode was not switched on, because its audit was not recorded"); `/auto on` delivers the event to the sinks before it switches. Switching it off only restores prompts, so a failing audit sink never blocks it: the switch changes first, and `policy.auto_disabled` is recorded best effort, with a warning when it is not. A session that starts with auto mode on records `policy.auto_enabled` with `detail.source: state`, so a switch turned on without an event (an `auto.json` edited by hand) still leaves one. `policy explain` reports `AUTO-APPROVED` only for the actions a session decides itself (tool calls, shell commands, file access, resource, extension, and provider loads, and MCP servers and tools): a mid-session `model.select` switch accepts only a model approved at start, and `network.connect`, `web.request`, `browser.execute`, `memory.*`, and `agent.invoke` have no runtime hook for auto mode to approve. With `policy.userAuto` absent or `off`, `auto on` and `/auto on` fail with `POLICY_DENIED`, and nothing else changes. The switch is stored in `<state>/config/auto.json`, bound to the signed-in principal (its principal binding): when another identity signs in, auto mode is reset to off, as the model selection is cleared, and stays off even if the first identity signs in again. Turn it on after signing in. The branded `auto on` takes effect at the next start; `/auto` applies at once. It applies only while the running release allows it: after an update to a release with `policy.userAuto: off`, a stored switch has no effect, and `doctor` and `auto status` say so. `uninstall` keeps it with the rest of the state and `purge` deletes it. Personal mode has no stored auto mode: relax a default with an allow rule in `config/policy.json`, or start one session with [`--yolo`](#the---yolo-launch-option).

### The `--yolo` launch option

`<command> --yolo` starts a session in which every `ask` the policy would put to the person is approved without a prompt, for that session only. It is for the developer who should not be interrupted for routine work, and it keeps the administrator's control: `deny` is never changed, and nothing is stored, so the next start asks again. It is a leading option, accepted in any order with `--model` and `--new-session`. Put it before `--smoke` or `--smoke-model`, for example `<command> --yolo --smoke`. With `--help`, `--version`, or a subcommand it means nothing and fails with `CONFIG_INVALID` before anything starts; a distribution that declares no policy (before v1alpha3) refuses it the same way, since nothing there asks for approval.

- Personal: every `ask` is approved, whichever rule wrote it: a default, `policy.default`, an enforced rule, or your own rule in `config/policy.json`. A `deny` from any layer and the built-in denials (the state directory, git control files, Plan mode, the sandbox) stay in force. No `auto.json` preference is written; a declared provider bridge temporarily changes its own configuration and records session ownership.
- Managed: it works only where the manifest declares `policy.userAuto: allowed`. Otherwise it fails at startup with `POLICY_DENIED` ("--yolo is not allowed: this distribution does not allow auto-approval (policy.userAuto is off)"), before sign-in, the sandbox, or Pi starts. Where it is allowed it acts as [auto mode](#user-auto-mode) does for that session: an `ask` from `policy.defaults` or `policy.default` is approved, and an `ask` from `policy.enforced`, the team adapter, a project restriction, or the user's own rules keeps its prompt. It writes no `auto.json`, and a stored auto mode is neither needed nor changed.
- Project trust prompts are not policy decisions, so `--yolo` does not answer them, as auto mode does not.
- Headless, with `--smoke` or `--smoke-model`, the same rules apply: an `ask` is approved instead of resolving to deny, and a `deny` stays a denial.
- It is visible: PiShip prints a `Notice:` line before the session starts, the status line shows `YOLO`, and the session opens with a warning notice. `/auto` (or `/auto status`) says that yolo is on, and `/auto off` ends it for the rest of the session; in a managed session `/auto off` also clears a stored auto mode, as it always does. The `--smoke` summary has `"yolo": true` under `governance`.
- It is audited: the session records `policy.auto_enabled` with `detail.source: yolo` when it starts (and `detail.providerAutoApprove: true` when the provider bridge is active), `policy.loaded` with `detail.yolo: true`, and every approval as `policy.auto_approved` with `detail.approval: auto` and `detail.autoSource: yolo` (the stored auto mode leaves no `autoSource`; `detail.source` already names a tool call's origin, so it is not reused). `/auto off` records `policy.auto_disabled`.

- It reaches a permission provider that declares how. A distribution whose `permissions` capability names `autoApproveFile` and `autoApproveKey` ([a package provider](#what-a-package-is-given-environment-and-files)) has that key set to `true` in the provider's own file for the launch: the provider's own prompts are approved too, which PiShip cannot do for a prompt the provider raises itself. The file is put back when the process exits, when `/auto off` ends yolo, and by the next launch when the process was killed; a `/permission-system` setting changed during the session is kept, except the auto-approval key, which is restored again at exit. Ordinary sessions may share the agent directory, but the provider reads one settings file, so a `--yolo` session and an ordinary one cannot run together: the later launch is refused with the action to take (close the other session, or start both the same way), and changes no provider configuration. Two `--yolo` sessions share the key: it stays on until the last of them exits, and `/auto off` in one of them says the provider's approvals stay on until the other ends. A session holds its place until it exits, including after `/auto off`. This restriction does not apply when no provider bridge is declared. A provider settings command can save its stale auto-approval value after `/auto off` and resume its own approvals within that session; exit and restart without `--yolo` to keep its prompts restored. PiShip's own yolo remains off. Without those settings `--yolo` changes only PiShip's own asks, and a provider's prompts stay. In a managed distribution that allows `--yolo` and declares the key, the provider's own `ask` rules are approved as well, including ones the company meant to keep, so declare the key only where that is acceptable.

### MCP

| Field | Default | Values |
| --- | --- | --- |
| `mcp.mode` | `allowlist` (managed), `explicit` (personal) | `off`, `allowlist` (declared servers only), or `explicit` (declared servers plus trusted project definitions; personal only). `off` may not declare servers |
| `mcp.project` | `deny` (managed), `allow` (personal) | Whether project `.mcp.json` servers may be used in `explicit` mode |
| `mcp.user` | `deny` (managed), `allow` (personal) | Accepted; user-level MCP definitions are not loaded by this release |
| `mcp.servers.<id>` | none | Server ID: lowercase letters, digits, and hyphens, at most 32 |

A server declares `transport`:

- `stdio`: exactly one of `module` (a `./` `.mjs` or `.js` file in the distribution, run with the distribution's Node.js) or `command` (a bare executable name found on `PATH`), plus `args` and `env` (`allow`: variable names inherited from the launch environment; `set`: fixed non-secret values). Credential-looking names are rejected.
- `streamable-http`: `url`, which may be a `${NAME}` runtime reference resolved from the launch environment at startup. An unset variable fails a required server with `CONFIG_UNAVAILABLE` and marks an optional one failed (`MCP_UNHEALTHY`). Project `.mcp.json` URLs are never interpolated. The legacy HTTP+SSE transport is rejected. The URL is `https`, plain `http` on loopback, or plain `http` to a private or internal host unless `httpTransport: https` is set (v1alpha6); `headers` sends claims of the signed-in identity ([MCP plain HTTP and identity headers](#mcp-plain-http-and-identity-headers-v1alpha6)).

Other server fields: `credential` (`none`, the default, or `runtime`, which sends the distribution's runtime credential as a bearer; `streamable-http` only, and only when the server URL has the same origin as `inference.baseUrl`, otherwise the server fails to start), `expectedServerName` (the `serverInfo.name` the server must report, or the start fails), `timeout` (per call, default `30s`), `startupTimeout` (default `10s`), `retry.attempts` (start attempts for retryable failures, default `1`, at most `10`), `required` (default `false`; a required server that is denied or cannot start fails the launch with `MCP_DENIED` or `MCP_UNHEALTHY`), and, up to v1alpha5, `tools.allow` / `tools.deny` (exact tool names; deny wins, an empty allow list admits every tool not denied, and a name may not appear in both; v1alpha6 replaces them with `class`, `exposure`, and an exposure map in `tools`, see [v1alpha6 fields](#v1alpha6-fields)). Exposed tools are named `mcp__<server>__<tool>`. A required `streamable-http` server that can never start is rejected by `validate`, `lock`, and `build`: a plain `url` whose host a private-only network policy refuses (always private-only in managed mode; declare the host in `network.allowHosts`), or `credential: runtime` with a plain `url` on another origin than a plain `inference.baseUrl`, or with no runtime credential at all. When a runtime variable is involved, or the server is optional, `validate` prints a warning instead ([company setup](enterprise-integration.md#company-setup)).

### Sandbox

| Field | Default | Values |
| --- | --- | --- |
| `sandbox.required` | `false` | `true` activates the sandbox and fails the launch with `SANDBOX_UNAVAILABLE` when it cannot be enforced. With `false`, no sandbox is activated |
| `sandbox.provider` | `native` | `native` (bubblewrap on Linux, Seatbelt on macOS), `custom`, `e2b-compatible`, or `kubernetes-agent-sandbox`. A non-native provider requires `sandbox.required: true`. The lock omits the field for `native` |
| `sandbox.adapter`, `endpoint`, `router`, `namespace`, `template`, `workdir`, `user`, `credential` | none | Backend settings, each accepted only by the providers that use it; `endpoint` and `router` accept runtime references, `user` (e2b-compatible only; default `user`, `root` for CubeSandbox) names the sandbox user, and `credential` is `none`, `runtime` (the inference runtime credential, only on its origin), or `stored` (the sandbox credential a person stores with `<command> sandbox login`, bound to the user and the endpoint origins; needs `endpoint`). See [sandbox backends](sandbox.md#credentials) |
| `sandbox.filesystem.read.deny` | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.npmrc`, `~/.pi` | Paths hidden from contained processes; the distribution state directory is always added. A declared list replaces this default list, it does not extend it: restate every default you want to keep |
| `sandbox.filesystem.write.allow` | `workspace`, `tmp` | The only writable paths; everything else is read-only |
| `sandbox.network.mode` | `deny` when required, otherwise `allow` | `deny` or `allow` only. `allowlist`, `allow`, `allowHosts`, and `hosts` keys are rejected: hostname allowlists are not enforced at this boundary |
| `sandbox.environment.allow` | `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `TZ`, `SHELL`, `TMPDIR` | Variables passed into contained processes; credential-looking names are rejected. A declared list replaces this default list, it does not extend it |

Each of the three lists is taken as written. A declared `read.deny`, `write.allow`, or `environment.allow` is the complete list, so `deny: [~/.ssh]` leaves `~/.aws`, `~/.kube`, `~/.docker`, `~/.azure`, and the rest of the defaults readable. This lets a distribution drop a default on purpose (a Kubernetes distribution that lets `kubectl` read `~/.kube`), and it is why [`examples/demo-company`](../examples/demo-company/piship.yaml) and the [reference distribution](../examples/enterprise-reference/piship.yaml) restate every default before adding their own. The lock records the effective lists (`governance.sandbox.filesystem` and `environment` in `piship.lock`).

Sandbox paths are `workspace`, `tmp`, `~/...`, or absolute paths, without `.` or `..` segments. `tmp` is a private per-session directory; the package-manager caches (`npm_config_cache`, `XDG_CACHE_HOME`, `PIP_CACHE_DIR`, `GOCACHE`) point into it unless the environment allowlist passes your own. A contained command that fails on a read-only path, a hidden path, or a host the network mode denies ends with one line naming the path or host and the key above that decides it. A `custom` adapter module is locked and packaged like other adapters.

### Audit

| Field | Default | Values |
| --- | --- | --- |
| `audit.enabled` | `true` (managed), `false` (personal) | Enabled audit needs at least one sink |
| `audit.sinks` | one optional `file` sink named `local` when enabled | `id`, `type` (`file`, written to `<state>/logs/audit.jsonl`, or `http`, which POSTs event batches to `url`), `url` (`http` only; may be a `${NAME}` runtime reference), and `required` (default `false`) |
| `audit.buffer` | `maxEvents: 1000`, `flushInterval: 2s` | Bounded in-memory buffer per sink |
| `audit.capture` | all `false` | `promptContent`, `responseContent`, `commandText`, `sourceContent`: opt-in content classes. Events are metadata only otherwise |

### Pi packages (v1alpha6)

`resources.packages` declares Pi packages (`source: npm`, `git`, or `local`) with a declarable trust class and Pi's own object-form filters (`extensions`, `skills`, `prompts`, `themes`: globs with `!`, `+`, and `-`; `[]` selects none; an omitted kind selects all). PiShip resolves and vendors them; Pi never installs a package, because Pi's installer runs npm lifecycle scripts. The settings PiShip gives Pi never contain `packages`.

```yaml
resources:
  packages:
    - { id: company-platform, source: npm, package: "@company/pi-platform", version: 1.4.2, registry: https://registry.company.example, class: company }
    - { id: pi-security, source: git, repository: https://git.company.example/platform/pi-security, ref: <40-hex commit>, class: company, themes: [] }
    - { id: team, source: local, path: ./packages/team, class: user }
packageTrust:
  npm: { requireIntegrity: true }
  git: { hosts: [git.company.example], requireCommitSha: true }
  local: { paths: [./packages] }
```

- `piship lock` resolves each package to an immutable identity: an npm exact version and `dist.integrity` (personal manifests may declare a range, never a dist-tag or alias), a full git commit SHA (a branch or tag only in personal, and never an abbreviated SHA), or a local content digest. A git source must be an https URL on a host in `packageTrust.git.hosts` when set; shorthands, ssh, scp-form, `git://`, and `file://` sources are refused. A local path stays inside the distribution directory and inside `packageTrust.local.paths` (managed default: none), with no `..` and no symlink out. `piship validate` and `piship lock` reject a managed manifest that sets `packageTrust.npm.requireIntegrity` or `packageTrust.git.requireCommitSha` to `false`.
- The lock generates one npm lockfile per package with `npm install --package-lock-only --ignore-scripts --omit=peer --omit=dev --legacy-peer-deps` over a generated npm root that lists only the package (npm) or its `dependencies` and `optionalDependencies` (git, local), and stores it beside the lock in `piship.lock.d/packages/<id>/package-lock.json` with that `package.json`. Commit the directory with `piship.lock`. `--legacy-peer-deps` keeps npm from resolving peers at all: Pi's docs have packages declare the host-provided Pi packages as peers, and with `--omit=peer` alone npm would still resolve Pi's whole dependency tree into the lockfile.
- Before npm runs, a git or local package's own `dependencies` and `optionalDependencies`, and an npm package's published ones, must each be an exact version or a semver range: a git, `github:`, file, link, alias, tarball, or dist-tag spec is refused there, because npm fetches a git dependency by cloning it and running its `prepare` under that repository's npm configuration despite `--ignore-scripts`. Every npm call also gets a `--git` that refuses to run, and `npm_config_ignore_scripts=true` and `npm_config_git` in its environment, so an `npm install` npm nests to prepare a fetched dependency runs no script either. `piship lock` needs npm 11 or later to resolve packages and refuses an older npm (Node 22 bundles npm 10, which runs a git dependency's `prepare` despite `--ignore-scripts`; run `npm install -g npm@11`); `piship build` works with any npm. A git package is fetched with `transfer.fsckObjects`, archived with `core.autocrlf=false` and `core.eol=lf` and a repository attributes file that turns off end-of-line conversion, filters, `ident`, `export-subst`, and re-encoding, so the vendored files are the committed bytes. A git or local package may contain no symlink and no `node_modules` in any spelling the filesystem folds to it at any depth (a local package's `node_modules` is never copied; a variant such as `Node_Modules` or `node_moduleſ` is refused), checked before its `package.json` is read; after `npm ci`, every installed directory under `node_modules` must be an entry of the package lockfile, so a tarball cannot ship modules of its own.
- Across the whole closure, every entry must be an exact version from a pinned registry tarball with sha512 integrity (unless `packageTrust.npm.requireIntegrity: false`, personal only), with no `npm:` alias, link, `file:`, `workspace:`, or git dependency, no URL with userinfo or a query, and no host-provided package (`@earendil-works/pi-*`, `typebox`) in any `dependencies` or vendored.
- The closure then passes the release gates: its origins must be in `release.sources`, and a dependency with an npm lifecycle script or a `binding.gyp` must be reviewed, either by PiShip or in `release.installScripts` as `pi-packages/<id>/node_modules/<name>@<version>` (v1alpha6). A git or local package whose own root has a `preinstall`, `install`, or `postinstall` script or a `binding.gyp` needs the same review, as `pi-packages/<id>/package@<commit>` (git) or `pi-packages/<id>/package@<tree digest>` (local). The install-script review applies at `piship lock` and `piship build` whether or not the manifest has `lifecycle.release`; the source gate needs its `release.sources`. PiShip never runs the script either way.
- A `certified` package's evidence must match the lock: its `integrity` is the package's locked `tree` digest (an npm package may also give its registry integrity), and for an npm package its `version` is the locked version. At launch a certified package whose evidence no longer matches the lock fails with `INTEGRITY_FAILED`, and on a Pi version or platform its evidence does not list, its files are not loaded.
- `piship build` re-fetches exactly what the lock pins (git with `git archive <sha>`, never a checkout), installs the stored lockfile with `npm ci --ignore-scripts --omit=peer --legacy-peer-deps --no-bin-links` into `pi-packages/<id>/` in the payload, and requires the same version or commit, integrity, tree digest, file count, and resource inventory. The vendored files are in the payload inventory and the SBOM.
- `piship release` re-checks every stored lockfile against the lock and audits each one with `npm audit` under `release.vulnerabilities` (asking `release.vulnerabilities.registry` when set, else the package's registry). A managed release fails when no audit endpoint answers; a personal one records a warning. Results and scan times are in `vulnerabilities.json` under `packages`.
- At launch each locked resource file is checked against its sha256 and decided on its own (`extension.load`, `skill.load`, or `resource.load` with the resource `<class>:packages/<id>/<path>`) before it enters Pi's loader, and audit records carry `detail.package` (`<id>@<version|commit|local>`). That check covers the inventory's entry files only; the modules they import (the package's other files and its vendored `node_modules`) are bound by the tree digest and lockfile at build, not rechecked per package at launch. A `pi` manifest entry that is absolute, a drive-letter or UNC path, or uses a backslash is refused at lock.

Credentials for a private registry or repository come only from npm or git configuration in the build environment; a URL with credentials is refused and never recorded.

#### What a package is given: environment and files

Two optional fields of a package entry hand it what it needs around its code. Both are additive: a manifest that declares neither parses, locks, and diffs exactly as before. The [developer example](../examples/developer/piship.yaml) uses them for six packages, and its [hardened variant](../examples/developer/managed.piship.yaml) shows a company setting the same fields stricter.

```yaml
resources:
  packages:
    - id: pi-lens
      source: npm
      package: pi-lens
      version: 4.3.0
      class: user
      environment:
        PI_LENS_HOME: { statePath: pi-lens }   # <state>/pi-lens, resolved on each machine
        PI_LENS_DISABLE_TOOL_INSTALL: "1"
    - id: pi-permission-system
      source: npm
      package: "@gotgenes/pi-permission-system"
      version: 39.0.4
      class: certified
      certified: { ... }
      agentFiles:
        - path: extensions/pi-permission-system/config.json
          mode: seed          # or enforce
          json:
            permission: { "*": allow, bash: { "*": ask, "rm -rf *": ask } }
```

- **`environment`.** A map from variable name to a non-secret value: a quoted string, or `{ statePath: <relative path> }`, a path below the distribution's state directory that the launch resolves (letters, digits, dots, hyphens, and underscores in each segment, no traversal). A name is uppercase words joined by at least one underscore (`PI_BG_FEATURES`, never `PATH` or `HOME`), is not credential-looking (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, and the other names a runtime variable cannot have), and is not one PiShip, the process, or the network policy own: `PISHIP_*`, `PI_*`, `ELECTRON_RUN_AS_NODE`, `BASH_ENV`, `PROMPT_COMMAND`, `XDG_*_HOME`, `JDK_JAVA_OPTIONS`, `NODE_*`, `LD_*`, `DYLD_*`, `SSL_*`, `CURL_*`, `REQUESTS_*`, `GIT_*`, `SSH_*`, `NPM_CONFIG_*`, `PIP_*`, and the proxy variables. A value is a plain string: no runtime reference, no secret shape (the manifest's secret check applies), and a number or a boolean must be quoted. The only `PI_*` exceptions are `PI_LENS_*` for the npm package `pi-lens` and `PI_BG_*` for `pi-background-tasks`, checked against the package identity. Two packages may name the same variable only at the same value.
- **When it applies.** The launch sets each variable on the process before Pi imports a package, and sets them again after a managed launch has removed the shell's `PI_*` and credential variables, so a managed value is never one the shell chose. A declared value replaces the shell's value in every mode, which is what makes a managed value one a user cannot override; a personal user who wants another value builds their own distribution. A variable reaches the extension in the Pi process. It does not reach a child process whose launcher passes only its own environment (the MCP SDK's stdio transport passes a fixed list), so a package that starts such a child needs the setting elsewhere ([the developer example's limits](../examples/developer/README.md#known-limits) name the one case).
- **`agentFiles`.** A list of at most eight JSON documents PiShip writes into Pi's agent directory (`<state>/agent`), where an extension keeps its own configuration. `path` is `extensions/<file>.json` or `extensions/<name>/<file>.json`, relative to the agent directory; `json` is an object of at most 64 KiB, and its keys keep the order you wrote, which matters to a configuration that reads its rules last-match-wins. No two packages write the same file, and the secret check applies to every string. The files are written owner-only through an atomic replace, never through a link.
- **`mode`.** `seed` (the default) writes the file when it is absent and replaces it on a later release only while it is still exactly what PiShip last wrote, a fact recorded in `<state>/agent/.piship-agent-files.json`; a file the user edited, or one that was there before, is kept, and `doctor` says so. `enforce` rewrites the file at every launch, so a user's edit does not outlive one. Use `enforce` where the file is part of the policy.
- **The lock.** `packages[].environment` records the variables as declared (a state path stays relative), and `packages[].agentFiles` records each file's `path`, `mode`, and the `sha256` of the exact bytes written; the content itself is in `governance.manifest`, and a launch refuses a lock whose parts disagree (`LOCK_INVALID`). The stale-lock check recomputes the digest from the declaration, so reordering a file's rules, which the manifest's canonical digest ignores, still reads as stale.
- **`piship diff`.** A new, changed, or removed variable is medium (low when removed); a new file or a changed `sha256` is high, a file no longer written is low, and a changed `mode` is medium (high when a user's edits now outlive a launch). `doctor` lists each variable in the Governance group and each file with its state: as declared, edited by the user and kept, or missing and written at the next launch.

A capability provider can be one of these packages. Instead of a `./` `path`, a non-builtin provider declares `package: <id>`, which must name a declared package of the same trust class:

```yaml
capabilities:
  permissions:
    enabled: true
    provider:
      id: certified/pi-permission-system
      version: 39.0.4
      implements: [piship.capability/permissions/v1]
      package: pi-permission-system
    settings:
      autoApproveFile: extensions/pi-permission-system/config.json
      autoApproveKey: yoloMode
```

The provider takes its class and its review evidence from the package, so a certified provider declares none of its own; its extension files are the package's `extensions`, loaded through the provider (after `provider.load` and each file's `extension.load` decision) and not with the package's other files. The capability is effective only while the package's files match the lock, its trust class and evidence admit it, and the policy allows the provider and each of its extension files; otherwise it is reported as not effective and its extensions are not loaded, with PiShip's own policy still in force. `autoApproveFile` and `autoApproveKey` are the only provider settings besides `workflow`'s: they name a top-level boolean in one of the provider package's own `agentFiles` that switches the provider's own session-wide auto-approval on. They go together and need a package provider. `<command> --yolo` ([below](#the---yolo-launch-option)) sets that key for the one launch, and the file is put back when the process exits, when `/auto off` ends yolo, and by the next launch if the process was killed before it could.

#### TypeScript packages: `pretranspile`

A package published as TypeScript source, whose files import each other as `./x.js` while only `x.ts` exists, makes Pi's loader try about eleven file names for every such import, and each extension loads through its own loader, so a package with many extensions repeats the work for each one: about 98,000 failed file lookups per start for pi-code 1.4.2 (41,000 with `JITI_EXTENSIONS` narrowed to `[".js",".ts"]`), which an antivirus scanner on Windows makes slow. `pretranspile: true` on the package entry has `piship build` and `piship release` write each TypeScript module that the package's extensions import as JavaScript beside it (`internal/values.ts` gets `internal/values.js`), so the import names a file that exists.

```yaml
resources:
  packages:
    - id: pi-code
      source: npm
      package: "pi-code"
      version: 1.4.2
      class: company
      pretranspile: true
```

- **Off by default.** A package without the field, or with `false`, builds exactly as before; neither is recorded. `true` is recorded in the lock as `packages[].pretranspile`, so turning it on or off needs `piship lock`, and `piship diff` reports the change (medium).
- **What is written.** Only the package's own `.ts` and `.mts` modules (not its `node_modules`, not declarations) that the import graph of its declared extension files reaches by a static or dynamic `import`, one `.js` (or `.mjs`) file per module in the same directory, with esbuild's transform (format `esm`, target `esnext`, no source maps, no tsconfig read from the package). Type-only imports are erased, JSON stays JSON, `import.meta`, top-level `await`, and relative paths keep their meaning. A module that already has a JavaScript sibling is left as it is. The extension files themselves are never written: the lock's SHA-256 values and what Pi loads by path are unchanged.
- **What fails.** A reached module that is CommonJS as esbuild reads it (`export =`), calls `require` on a module of the closure, does not parse, or whose output Node cannot read as an ES module (a decorator, which esbuild passes through at the `esnext` target) fails the build with `CONFIG_INVALID` and writes nothing; remove `pretranspile` from that package. So does a package for which nothing would be written or kept (no reached TypeScript module of its own). `module.exports` and `exports.x = ...` are not detected (esbuild reads such a TypeScript file as an ES module): the file is written as it is, and an ES module import of it then does not get the exports it assigned. Do not enable `pretranspile` for a package whose reached TypeScript modules assign `module.exports`. The build reports `pi package pretranspile: <package>: <N> modules written`.
- **Older runtimes.** A runtime built before the field (checked against v0.12.0) does not read such a manifest or lock, at any step: `piship validate` and `piship lock` stop with `invalid field at resources.packages[0].pretranspile ...: Unknown field pretranspile`, `verify-release` of the new release fails with `INTEGRITY_FAILED: Release verification: invalid field at ... Unknown field pretranspile` and an action that reads "Do not install this artifact; obtain it again from the trusted source", and `<command> update` on an installed v0.12.0 distribution, from a signed channel offering the new release, fails the same way with exit status 1 before it installs anything. The installation is left as it was: the old release stays current, `doctor` is healthy, and no staged release remains. The error text does not say that the runtime is too old, so the action it gives is misleading here. An installation on an older runtime needs a fresh install to take a release that enables `pretranspile`, as with any addition the installed runtime does not know ([support policy](support-policy.md)).
- **Integrity.** The written files are payload files: they are in the payload inventory, so `doctor` and the install check them like any other file, and a release built twice from the same inputs has the same bytes. They are not in the package's locked tree digest, which pins the vendored package as npm installed it.
- **What changes at run time.** The extension files still load through Pi's loader, which now finds `./x.js` at once and loads that file instead of transpiling `x.ts`. Under Pi 1.0.3 the loader still evaluates each module once per extension (it does not use Node's own module loader unless `JITI_TRY_NATIVE` is set), so module state is shared no more than before. A loader that imports the JavaScript natively would load each module once per process and share its state across extensions and across `/reload`; a package that keeps state at module level should be tested with that in mind. A distribution that sets `JITI_EXTENSIONS` for the package can keep it: the two combine ([performance](performance.md#typescript-pi-packages)).

### Bundled search tools (v1alpha6)

Pi's find and grep tools and its `@` file completion run `fd` and `rg` (ripgrep). A managed launch runs Pi offline (`PI_OFFLINE=1`), so Pi never downloads them, and without them on `PATH` it prints `fd not found. Offline mode enabled, skipping download.` and falls back to slower behavior. `runtime.searchTools` makes both tools release content instead:

```yaml
runtime:
  pi: "1.0.3"
  searchTools:
    mode: bundled     # the only mode
    fd: "10.5.0"      # optional; PiShip's default when omitted
    rg: "15.2.0"      # optional; PiShip's default when omitted
release:
  sources: [https://registry.npmjs.org, https://github.com]
```

- `piship init --personal` writes `runtime.searchTools: { mode: bundled }` and `https://github.com` in `release.sources` only when github.com answers (any HTTP status) to a request of at most 3 seconds from the machine that runs `init`, through the proxy and trust roots `lock` would use. When it does not, `init` omits both, prints a note on stderr, and the first `lock` needs no download; add them later to bundle the tools. `PISHIP_INIT_PROBE=reachable` or `unreachable` replaces the request (a test hook). `--managed` never writes the field.
- `mode: bundled` is required; `fd` and `rg` are optional exact upstream versions (`x.y.z`, quoted in YAML). Without a version PiShip uses its default, fd 10.5.0 and ripgrep 15.2.0 in this version. Both tools are always bundled. Without `runtime.searchTools` nothing changes in the lock: no entry, the same digests, and Pi uses `fd` and `rg` from `PATH` if there are any.
- **Without `runtime.searchTools`, Pi downloads the tools on first use, and a personal launch no longer waits for it.** Pi's interactive start waits for a download of any missing `fd` or `rg` before it takes a key: about 30 seconds on a fast link, and as long as the network takes to fail on one that blocks GitHub. So when a personal distribution bundles neither tool and neither is in Pi's tool directory or on `PATH`, the launch runs Pi offline (`PI_OFFLINE=1` for that process): Pi says the tool was not found and starts at once, without file-name autocomplete or `rg` in the shell until the tool is installed or bundled. The launch records the names in the startup note `tool_downloads_deferred` (`PISHIP_DEBUG_TIMING=1`) and `doctor` warns. `PISHIP_ALLOW_TOOL_DOWNLOAD=1` leaves the download to Pi; a `PI_OFFLINE` you set yourself is kept as it is. A managed launch is offline already and a distribution that bundles the tools is untouched. The `personal` and `developer` examples bundle both, so their users get the tools without a download.
- The source is the official upstream release archive at that exact version, https://github.com/sharkdp/fd and https://github.com/BurntSushi/ripgrep, for each target in `release.targets`: the `musl` builds on Linux, the Apple builds on macOS, and the `msvc` zip on Windows. Its origin, `https://github.com`, must be in `release.sources`, or `piship lock`, `piship build`, and `piship release` fail the `source` gate. A lock entry that is not the official archive URL for its tool, version, and target fails the same gate.
- `piship lock` downloads each archive through PiShip's managed fetch (the `HTTP(S)_PROXY` and `NO_PROXY` of the lock environment when `network.proxy.inheritEnvironment` allows it, and the `network.tls.additionalCA` bundles that resolve there; never the private-only launch policy, since the owner's machine locks), following redirects only over https to GitHub's release asset hosts. Archives are kept in PiShip's download cache, `PISHIP_CACHE_HOME`, else `piship` under `XDG_CACHE_HOME`, `%LOCALAPPDATA%`, or `~/.cache`, under `search-tools/`. A cached archive is reused only when the existing lock already pins it (the same official URL and digest), so a relock is reproducible and works offline; any other cached file is downloaded again. The lock records, per tool, the `version`, the upstream `source`, and per target the archive `url`, its `sha256-` digest (`archive`), the executable's path inside it (`entry`), the executable's `sha256-` digest (`binary`), and its `size`; `digests.searchTools` covers them. The stale-lock check reads only the lock, never the cache or the network.
- The archive is read in memory with the release extractor's path rules: any link, device, or other non-regular entry, a path with `..`, an absolute or drive path, a backslash, or a duplicate fails the whole archive, and exactly one executable of the tool's name must sit at its root or in its single top-level directory.
- `piship build` and `piship release` refuse a lock whose archive URL is not the official one (`LOCK_INVALID`, before any download or cache read; the stale-lock check also reports it), take the archive for the build target from the cache (downloading it again when it is missing or differs), require the archive, the executable path, and the executable to match the lock, and write the executable to `tools/fd` and `tools/rg` (`tools/fd.exe` and `tools/rg.exe` on Windows), mode 0755 on POSIX, with the upstream license files beside it in `tools/licenses/<tool>/`. These files are in the payload inventory, so a changed or missing executable fails the launch, `verify-release`, and `repair` checks with `INTEGRITY_FAILED` like any payload file, and each tool is a package of the release SBOM (`pkg:github/...`, the archive's SHA-256). A build for a target the lock has no entry for fails with `LOCK_INVALID`.
- At launch, before Pi is imported, the branded command points Pi's agent directory at the distribution's state (`PI_CODING_AGENT_DIR=<state>/agent`; Pi fixes its tool directory when it is imported). It then checks each payload executable against the lock and copies it to `<state>/agent/bin`, the directory Pi's tools manager searches before `PATH`, unless an identical copy is already there; a different file, link, or directory there is replaced. A user's own `fd` or `rg` on `PATH` (or in `~/.pi/agent/bin`) is never used, and Pi still runs offline. `--smoke` runs Pi's own find and grep tools against the payload, so a tool Pi cannot locate fails the smoke, and its summary lists the tools. A problem with a bundled tool (a lock without an entry for the platform, a payload file that is missing, an agent directory that cannot be written) does not stop the command: it prints a one-line warning and goes on without that tool, and `--version` and `--help` do not touch the tools at all. A payload executable that does not match the lock is never copied or run, and a copy in `<state>/agent/bin` that is not the pinned one is removed, so Pi cannot run it either.
- `doctor` shows each bundled tool and its version in the Supply Chain group, and fails when Pi's tool directory does not hold the pinned executable; `config explain` shows `runtime.searchTools` with the versions; `piship diff` reports adding a tool, a different upstream source, or different archive or executable bytes at the same version as high risk, a removed tool (Pi then falls back to the user's own `fd` or `rg` on `PATH`), a version change, or an added target as medium, and a removed target as low.

## Lifecycle fields (v1alpha4)

`piship/v1alpha4` and later (`piship/v1alpha5`, `piship/v1alpha6`) require `updates` and accept an optional `release`; both are rejected in earlier schemas. What they control is described in [release](release.md). The example uses the v1alpha5 and v1alpha6 form; v1alpha4 differs only in `updates.trust` ([below](#update-trust-bootstrap-v1alpha5)).

```yaml
variables: [ACME_UPDATE_SOURCE]
updates:
  channel: stable
  channels: [stable, candidate]
  source: ${ACME_UPDATE_SOURCE}
  rollback: true
  trust:
    bootstrap:
      version: 1
      expires: 2027-10-01T00:00:00Z
      keys:
        - id: acme-root-primary
          publicKey: MCowBQYDK2VwAyEA...   # base64 Ed25519 public key from piship keygen
        - id: acme-channel-2026
          publicKey: MCowBQYDK2VwAyEA...
      roles:
        root: { keyIds: [acme-root-primary], threshold: 1 }
        channel: { keyIds: [acme-channel-2026], threshold: 1 }
release:
  targets: [linux-x64, darwin-arm64, win32-x64]
  sources: [https://registry.npmjs.org]
  vulnerabilities:
    failOn: high
    allow:
      - id: GHSA-xxxx-xxxx-xxxx
        reason: Not reachable from the packaged runtime
        expires: 2026-12-31
```

| Field | Default | Values |
| --- | --- | --- |
| `updates.channel` | `stable` | Channel for new installs: `stable`, `candidate`, or `dev` |
| `updates.channels` | `[<channel>]` | Channels a user may select with `update --channel`; unique and must include `updates.channel` |
| `updates.source` | none | Where channel metadata and archives are read: an `https` URL, an `http` URL on `127.0.0.1`, `localhost`, or `[::1]` (or, unless `updates.transport: https`, on a private or internal host), or a `${NAME}` runtime reference. Resolved only when `update` runs; without it, `update` needs `--from`. No credentials, query string, or fragment |
| `updates.transport` | `http-allowed` | v1alpha5: `https` forces HTTPS-only (plain HTTP on loopback aside); `http-allowed`, the default, admits plain HTTP to a private or internal host ([below](#plain-http-update-channel-v1alpha5)). Locked only when declared |
| `updates.rollback` | `true` | Retain the previous release on update so `rollback` can return to it |
| `updates.trust.bootstrap` | none | v1alpha5: the update root a fresh installation starts from ([below](#update-trust-bootstrap-v1alpha5)). Without it the distribution is update-disabled |
| `updates.trust.keys` | `[]` | v1alpha4 only: pinned release keys: `id` (lowercase letters, digits, dots, and hyphens, unique) and `publicKey` (base64 of the 44-byte Ed25519 SubjectPublicKeyInfo DER). Any one key signs channels. With no keys, no update can be verified, so `update` fails |
| `release.strip` | `true` (v1alpha6) | v1alpha6: remove source maps and TypeScript declarations from the payload, which a running Node process never reads. `false` keeps them. Earlier schemas cannot set it and never strip ([performance](performance.md)) |
| `release.bundle` | `true` (v1alpha6) | v1alpha6: bundle the runtime JavaScript into a few files while preserving public module shims, native/WASM assets and declared resources. `false` builds the unbundled layout (about 7,000 files for the personal example, from 117 bundled) and is the opt-out for a distribution that needs it. Earlier schemas cannot set it and never bundle. A bundled payload carries the authoring inputs as one compressed snapshot that only `build`, `release`, `dev`, and `test` expand (into a digest-keyed cache outside the installed runtime), so it can still author another distribution ([performance](performance.md)). It also covers the vendored Pi packages: a closure that is bundle-safe is bundled below its locked extension files, identical dependencies several packages hold are shared, and everything else keeps its vendored files, with the reasons recorded in `metadata/pi-package-footprint.json` ([performance](performance.md#pi-package-dependencies-and-closures)); `false` keeps every package's own vendored tree |
| `release.targets` | `[linux-x64, darwin-arm64, win32-x64]` | Non-empty, unique subset of `linux-x64`, `linux-arm64`, `darwin-arm64`, `darwin-x64`, `win32-x64`. Only the three defaults pass the release `target` gate in this version |
| `release.sources` | `[https://registry.npmjs.org]` | Approved package origins, for npm packages and (v1alpha6) [bundled search tools](#bundled-search-tools-v1alpha6), which need `https://github.com`: `https`, no path, query, fragment, or credentials; non-empty and unique |
| `release.vulnerabilities.failOn` | `high` | `low`, `moderate`, `high`, or `critical`: the lowest severity that blocks a release |
| `release.vulnerabilities.allow` | `[]` | Reviewed exceptions: `id` (advisory ID such as a GHSA ID, unique), `reason` (at most 240 characters), and `expires` (a real calendar date, `YYYY-MM-DD`; the exception applies through that day) |

Only public keys go in the manifest; secret-looking field names are rejected. When `release` is omitted, its defaults are applied and locked, except `release.bundle` and `release.strip`. A v1alpha6 manifest that leaves them out builds a bundled, stripped payload, but the parsed manifest and the lock leave the keys out as written, so the digest of a manifest or lock written before this default is unchanged and a newer PiShip still verifies the payload of an older one. Write `release.bundle: false` and `release.strip: false` to build the unbundled layout; the lock then records them. A bundled payload can still author another distribution: its compressed authoring snapshot is expanded on first use by `build`, `release`, `dev`, and `test`, and never by a launch, `install`, `update`, or `rollback`.

### Update trust bootstrap (v1alpha5)

`updates.trust.bootstrap` is static release configuration: the update root a fresh installation trusts first. It is not the current trust of an installation that already exists: an installed client keeps its own current root and advances it only through signed `root/<N+1>.json` files in the update source, so changing the bootstrap of a later release changes nothing for installed clients ([trust root](release/trust-root.md#installation-trust-state)). Generate the block from public keys with `piship trust-root init` rather than by hand, and publish later roots with `piship trust-root next` ([owner workflow](release/owner-workflow.md#signing-a-channel)).

| Field | Values |
| --- | --- |
| `version` | Root version, an integer from 1 |
| `expires` | UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` (fractional seconds allowed) |
| `keys` | 1 to 32 entries of `id` and `publicKey`, with the v1alpha4 key rules. Key IDs are unique, one ID cannot name two public keys, and one public key is listed under one ID only, so a threshold counts distinct keys |
| `roles.root` | `keyIds` (non-empty, unique, each listed in `keys`) and `threshold` (an integer from 1 to the number of `keyIds`): the keys that sign the next update root |
| `roles.channel` | The same shape: the keys that sign channel metadata. `update` trusts these keys only |

Rules beyond the field checks:

- With `updates.source` set and no bootstrap, no update can be verified. `piship validate` warns and `update` fails closed; `piship release` still builds the release, which is update-disabled, as it would be with no source.
- With neither `updates.source` nor a bootstrap, the distribution is update-disabled.
- A managed distribution whose root and channel roles name the same key gets a `piship validate` warning, and `piship release` refuses it (gate `trust`) until the roles use distinct keys. A managed production distribution keeps its root key offline, separate from the channel release key. A personal distribution may share one key between both roles.

### Plain-HTTP update channel (v1alpha5)

The update channel may be served over plain HTTP from an internal host, such as an intranet nginx without a certificate, with no setting: a private or internal host is admitted by default, and `updates.transport: http-allowed` only spells that out. `updates.transport: https` forces HTTPS-only for the channel, so an owner can tighten it: plain HTTP is then accepted only on loopback. A v1alpha4 manifest has no `transport` field, and its `updates.source` stays `https` or loopback.

- It covers only the update channel: channel metadata and signatures, `root/<N>.json` files, and release archives, read by `update` (including `update --from <url>`). OIDC, the credential broker, the gateway, MCP servers, audit sinks, and remote sandboxes follow their own `httpTransport`, with the same default and the same hosts ([MCP](#mcp-plain-http-and-identity-headers-v1alpha6), [the others](#plain-http-to-internal-endpoints-v1alpha6)); this field changes none of them.
- The host must be private or internal: loopback, an IP address in 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, or fe80::/10, a single-label name that is not a public top-level domain, or a name ending in `.internal`, `.local`, `.lan`, `.corp`, `.home.arpa`, or `.intranet`. A single label of two letters (a country-code TLD such as `io`, `ai`, or `co`) or a common generic TLD (`com`, `net`, `org`, `dev`, `app`, and a few more) is public; the list is short on purpose, not the public suffix list. A public host is a `piship validate` error, and a `${NAME}` source (or `--from` URL) that resolves to one fails with `NETWORK_DENIED` before any request. Only the name is judged, not DNS: a single label is completed with the machine's DNS search domains, so `http://updates/` reaches whatever `updates.<search domain>` resolves to, and an internal-looking name can resolve to a public address. Making sure the name resolves to an internal address on every client is the owner's responsibility; a fully qualified internal name (`updates.corp.internal`) avoids the search-domain dependence.
- A plain-HTTP `updates.source` beyond loopback, and `http-allowed` written explicitly, require `updates.trust.bootstrap`; without it `piship validate` fails. Signature thresholds, archive digests, the channel sequence floor, expiry, and root refresh are verified exactly as over HTTPS ([security](security.md#releases-and-updates)).
- The configured proxy policy still applies, except that a plain-HTTP request is refused through a proxy that is not itself a private or internal host ([below](#plain-http-to-internal-endpoints-v1alpha6)); plain HTTP needs no CA setting. Redirects stay within the source's origin, and an `https` source is never redirected to plain HTTP.
- `config explain` shows the effective transport (`http-allowed` or `https`), `piship validate` prints it when declared, `piship diff` reports a change between `https` and plain HTTP (loosening is high risk), `doctor` warns `source  http (integrity by signature only)`, and an update or check over plain HTTP is audited with `transport: http`.

### Update trust from v1alpha4

v1alpha4 trusts every key in `updates.trust.keys` to sign channels. `piship migrate` keeps those keys as a compatibility trust set: every key goes into both the root and the channel role with threshold 1 ([migration](#migration)). That is exactly as strong as before; it does not invent an offline root key, and for a managed distribution it is the shared-key case that `piship release` refuses until the owner splits the roles.

## v1alpha6 fields

`piship/v1alpha6` keeps every v1alpha5 field and adds the fields below. Unknown fields are still rejected, so no earlier schema accepts them.

| Field | Default | Values |
| --- | --- | --- |
| `runtime.tools.codemode` | `off` | `off`, `on`, or `only`: Pi's Codemode, loaded by PiShip without the script `models` global. Nested calls go through the same policy hook as top-level calls |
| `runtime.tools.toolSearch` | `off` | `off` or `on`: Pi's tool search for `deferred` tools |
| `runtime.tools.exposure` | none (every tool `direct`) | A map of tool globs (`A-Z a-z 0-9 _ . - *`, at most 128 characters) to `direct`, `model-only`, `codemode`, `deferred`, or `hidden`. The most specific glob wins; two globs of equal specificity that can match the same tool fail `validate` and `lock` |
| `runtime.cacheWarming.mode` | `off` | `off`, `streaming`, or `idle`: Pi's prompt cache warming. Pi's own default is `streaming` |
| `runtime.cacheWarming.userOverride` | `false` | Whether a user preference may override the distribution's mode |
| `runtime.searchTools.mode` | none (not bundled) | `bundled`: ship pinned `fd` and `rg` in the payload for Pi's find, grep, and `@` completion ([below](#bundled-search-tools-v1alpha6)) |
| `runtime.searchTools.fd`, `runtime.searchTools.rg` | PiShip's default (fd 10.5.0, ripgrep 15.2.0) | An exact upstream release version, `x.y.z` |
| `runtime.verifyAtLaunch` | `false` (unset) | `false`: a launch hashes `piship.lock` (which carries `policy.enforced`) against the digest the install receipt recorded (skipped for a build directory, another install home, an unreadable receipt, or an installation recorded before the receipt carried it), checks that each resource the lock lists is still a regular file, and a bundled payload may use a V8 compile cache. `true`: a launch runs the full payload verification, the inventory check `doctor` runs, and keeps no compile cache. The digest checks that admit a Pi package's entry files and a certified resource always run ([performance](performance.md#what-the-consumer-path-does-now)) |
| `mcp.servers.<id>.class` | `company` (managed), `user` (personal) | The server's trust class, decided by `policy.resourceTrust` like a resource of that class |
| `mcp.servers.<id>.exposure` | `direct` | The exposure of the server's tools |
| `mcp.servers.<id>.tools` | none | An exposure map of tool globs, as `runtime.tools.exposure`, such as `get_*: deferred` or `delete_*: hidden`. It replaces v1alpha5's `tools.allow` / `tools.deny`, which v1alpha6 rejects |
| `mcp.servers.<id>.httpTransport` | `http-allowed` | `https` or `http-allowed` (`streamable-http` only): `https` forces HTTPS-only (plain HTTP on loopback aside); `http-allowed`, the default, admits plain HTTP to a private or internal host ([below](#mcp-plain-http-and-identity-headers-v1alpha6)) |
| `inference.httpTransport` | `http-allowed` | `https` or `http-allowed`: `https` forces `inference.baseUrl` to be https; the default also admits plain HTTP to a private or internal host ([below](#plain-http-to-internal-endpoints-v1alpha6)) |
| `credential.broker.httpTransport` | `http-allowed` | The same for `credential.broker.endpoint` and `revokeEndpoint` |
| `identity.oidc.httpTransport` | `http-allowed` | The same for `identity.oidc.issuer` and every endpoint its discovery document names; the redirect stays a loopback URI |
| `audit.sinks[].httpTransport` | `http-allowed` | The same for one `http` sink's `url` |
| `sandbox.httpTransport` | `http-allowed` | The same for `sandbox.endpoint` and `sandbox.router` of a remote provider; the endpoint is https-only with `sandbox.credential: runtime` |
| `mcp.servers.<id>.headers` | none | `streamable-http` only: request headers whose value is a claim (`sub`, `preferred_username`, or a verified `email`) of the signed-in OIDC identity, as `<Header-Name>: { identityClaim: <claim> }` ([below](#mcp-plain-http-and-identity-headers-v1alpha6)) |
| `models.catalog.<id>.type` | `chat` | `chat`, `classifier`, or `image`. A non-chat model names its `api`; an `image` model lists its `output` (`text`, `image`) |
| `models.catalog.<id>.virtual` | none | `router` (the declared extension that registers the virtual model: its `./` path, a certified extension ID, or `package:<id>`) and `routes`, the closed set of physical catalog entries it may route to |
| `data.<class>.retention` | none (not swept) | For `sessions`, `audit`, `cache`, and `temp`: a duration such as `30d` or `12h`. Audit retention is a minimum, the others maximums; there is no user retention preference yet, so the declared value applies ([limits](security.md#audit)) |
| `data.purge.onLogout` | `[]` | Data classes `logout` deletes; may not name `audit` |
| `data.purge.onUninstall` | `none` | `none` or `all`: recorded in the lock and shown by `doctor`, not yet acted on (`uninstall` keeps state either way; `purge` deletes it) |
| `data.export.<resource>` | none | `allow`, `ask`, or `deny` for `public`, `local`, or `support`: sugar for a distribution-enforced `session.export` rule |
| `policy.acknowledgeUnenforced` | `[]` | `"<action>:<resource>"` keys of `deny` or `ask` rules on an action no runtime seam enforces; a managed distribution needs the entry, or `validate` fails with `POLICY_UNENFORCEABLE` |
| `resources.packages` | `[]` | Pi packages, each with `id`, `source` (`npm` with `package`, `version`, and an optional https `registry`; `git` with an https `repository` and `ref`; `local` with a `./` `path`), `class`, `certified` evidence for a certified package, resource filters per kind, and optionally `environment` and `agentFiles` ([below](#what-a-package-is-given-environment-and-files)) and `pretranspile` ([below](#typescript-packages-pretranspile)) |
| `capabilities.<name>.provider.package` | none | A declared package of the provider's trust class as the provider, instead of a `./` `path`; with the `permissions` settings `autoApproveFile` and `autoApproveKey` ([below](#what-a-package-is-given-environment-and-files)) |
| `packageTrust` | managed: npm integrity, full commit SHAs, no local paths; personal: npm integrity | `npm.requireIntegrity`, `git.hosts`, `git.requireCommitSha`, `local.paths` |
| `release.vulnerabilities.registry` | the configured registry | An https registry URL that `npm audit` asks for advisories |
| `release.installScripts` | `[]` | Reviewed install scripts in Pi package closures, as `pi-packages/<id>/node_modules/<name>@<version>`; PiShip never runs the script either way |

Policy gains the actions `model.select` (the v1alpha5 `model.use`, still accepted as an alias), `model.dispatch`, and `session.export` ([Policy](#policy)).

Exposure, Codemode, tool search, cache warming, model dispatch and virtual routes, Pi packages ([below](#pi-packages-v1alpha6)), bundled search tools ([below](#bundled-search-tools-v1alpha6)), `data.sessions`, `data.audit` and `data.cache` retention, `data.purge.onLogout`, `data.export`, and `policy.acknowledgeUnenforced` are enforced in v0.9.0. `data.purge.onUninstall` and `data.temp.retention` are parsed, locked and shown by `doctor`, but nothing acts on them: `uninstall` always keeps state, and PiShip's temporaries are removed by the abandoned-temporaries sweep ([architecture](architecture.md#temporary-directories)).

### MCP plain HTTP and identity headers (v1alpha6)

A `streamable-http` server may reach an internal MCP server that has no certificate, with no setting, and a second field lets it identify the user by a request header:

```yaml
mcp:
  servers:
    tickets:
      transport: streamable-http
      url: http://10.20.30.40/mcp
      headers:
        X-Company-User: { identityClaim: preferred_username }
network:
  allowHosts: [10.20.30.40]
```

Plain HTTP to a private or internal host is admitted by default (`httpTransport: http-allowed` spells that out), the same hosts as the [plain-HTTP update channel](#plain-http-update-channel-v1alpha5): loopback, an IP address in 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, or fe80::/10, a single-label name that is not a public top-level domain, or a name ending in `.internal`, `.local`, `.lan`, `.corp`, `.home.arpa`, or `.intranet`. Only the name is judged, never DNS.

- `httpTransport: https` forces this server to `https` (plain HTTP on loopback only), so an owner can tighten it; it is recorded in the lock, which changes the digests of a manifest that sets it. An absent field adds nothing to the lock.
- A public host fails `validate`. A `${NAME}` URL is checked once it resolves at launch: a public plain-HTTP host fails the server's start (a required server fails the launch with `MCP_UNHEALTHY`). An `https` URL is always accepted.
- `credential: runtime` is never sent over plain HTTP: with it the URL must be `https` (or loopback), and `http-allowed` written explicitly beside it fails `validate`.
- The private-only network policy applies unchanged: in managed mode the host must be in `network.allowHosts`. Only this server's requests may use plain HTTP; every other endpoint keeps the loopback-only rule.
- `validate` warns, on one line shared with the other plain-HTTP endpoints, that the server's traffic is unencrypted, and separately when the host is a `.local` or single-label name, which mDNS or the DNS search domains resolve and another device can spoof (use an IP address or a fully qualified name under `.internal` or `.corp`). `config explain` shows the effective `mcp.servers.<id>.httpTransport`, `doctor` shows a server it reached over plain HTTP as `plain HTTP, unencrypted`, and `piship diff` reports a change between `https` and plain HTTP (loosening is high risk), or adding a server that uses plain HTTP, as high risk.
- Tool results can be altered on the network path and reach the model, and a configured private `HTTP_PROXY` sees the traffic in clear, while a proxy that is not a private host is refused (list the host in `NO_PROXY` to reach it directly). See [security](security.md#mcp).

`headers` maps a header name to `{ identityClaim: <claim> }`, where the claim is `sub`, `preferred_username`, or `email` of the signed-in OIDC identity, taken from the ID token at login. `sub` is the stable key; `preferred_username` and `email` are only as trustworthy as the identity provider's policy on who may change them. `email` is sent only when the identity also has `email_verified: true`, or the server fails to start; Microsoft Entra ID usually omits `email_verified`, so with Entra use `preferred_username`, which in a work tenant is the administrator-managed UPN.

- It needs `identity.mode: oidc`; otherwise `validate` fails. Only identity claims are accepted: no literal value and no environment variable, so a user cannot send another user's name by editing a value.
- One to 8 headers. A header name is an HTTP token of at most 64 characters, and names are unique ignoring case. Authentication, cookie, framing, hop-by-hop, proxy, method-override, and MCP transport headers are refused in any case, by `validate` and again by the transport: `Accept`, `Accept-Encoding`, `Authorization`, `Connection`, `Content-Encoding`, `Content-Length`, `Content-Type`, `Cookie`, `Expect`, `Forwarded`, `Host`, `Keep-Alive`, `Last-Event-ID`, `Mcp-Protocol-Version`, `Mcp-Session-Id`, `Origin`, `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `Set-Cookie`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `User-Agent`, `Via`, `WWW-Authenticate`, `X-HTTP-Method`, `X-HTTP-Method-Override`, `X-Method-Override`, `X-Real-IP`, and any `Sec-` or `X-Forwarded-` header.
- The claim is the one of the identity the launch activated, held in memory. A claim that is missing, not a string, empty, padded with spaces, longer than 256 characters, or not printable ASCII (CR, LF, and other control characters included) fails the server's start: an optional server is marked failed (`MCP_UNHEALTHY`) and a required one fails the launch.
- Each request checks the stored identity metadata (no secret store or identity provider call). After a logout, or when another user signs in while a session runs, that session's requests to the server fail with the reason (signed out, or another identity signed in) rather than send a claim; the server's health stays as it was. The next launch uses the new user's claims.
- The value is identity data: the lock, `doctor`, and `config explain` show only the header and claim names, and audit events and metrics record nothing about identity headers. The names are part of the lock's `mcp` digest, and `piship diff` reports a header added to a server or declared by an added server.
- The header is not authentication. The claims are kept in a file in the user's state directory, which the user can edit, and the server receives nothing it could verify; it trusts the client and the network path ([security](security.md#mcp)). Prefer https.

`piship migrate` needs nothing for these fields, and earlier schemas reject them.

### Plain HTTP to internal endpoints (v1alpha6)

Every other network endpoint has the same `httpTransport` as an MCP server, declared per endpoint, with the same default: a company that runs its gateway, broker, identity provider, audit collector, or sandbox service on an internal host without TLS needs no setting, and writes `httpTransport: https` on an endpoint to forbid plain HTTP there:

```yaml
identity:
  mode: oidc
  oidc:
    issuer: http://keycloak.corp.internal/realms/acme
    clientId: acmecode
    redirectUri: http://127.0.0.1:8765/callback
credential:
  provider: http-broker
  broker:
    endpoint: http://10.20.30.40:8080/v1/llm-credential
    revokeEndpoint: http://10.20.30.40:8080/v1/revoke
inference:
  provider: openai-compatible
  baseUrl: http://10.20.30.40:4000/v1
audit:
  sinks:
    - { id: collector, type: http, url: http://10.20.30.41:9000/events }
network:
  allowHosts: [10.20.30.41]
```

Every endpoint here is plain HTTP to a private host with no setting. To forbid plain HTTP on one of them, write `httpTransport: https` beside it (for example `inference: { provider: openai-compatible, baseUrl: https://gateway.corp.internal/v1, httpTransport: https }`); `validate` then refuses an `http://` URL there, and a `${NAME}` URL that resolves to one fails at launch.

| Field | What may be plain HTTP | What then travels unencrypted |
| --- | --- | --- |
| `inference.httpTransport` | `inference.baseUrl` | The gateway credential (a bearer) on every request, and every prompt, file excerpt, tool result, and response |
| `credential.broker.httpTransport` | `credential.broker.endpoint`, `revokeEndpoint` | The identity access token PiShip presents, and the gateway credential the broker issues |
| `identity.oidc.httpTransport` | The issuer, and each endpoint its discovery document names (authorization, token, JWKS, revocation, end session) | The authorization code, ID and access tokens, and the refresh token. The authorization page the browser opens may be plain HTTP too |
| `audit.sinks[].httpTransport` | That sink's `url` | Audit events, including any captured content |
| `sandbox.httpTransport` | `sandbox.endpoint`, `sandbox.router` (and, for e2b-compatible, its command host `<port>-<id>.<domain>` under the endpoint's domain) | Commands, their output, files sent to the sandbox, and a `stored` sandbox credential |

The rules are the MCP server's ([above](#mcp-plain-http-and-identity-headers-v1alpha6)), for each endpoint separately:

- Without the field, or with `http-allowed` (the same thing), nothing is added to the lock, so an existing lock's digests are the same. `httpTransport: https` is recorded, so a manifest that sets it has a new lock digest and needs `piship lock` again. An older schema has no field to write: it takes the default, and a distribution that needs https-only moves to v1alpha6.
- Only a private or internal host is accepted over plain HTTP; a public one fails `validate`. A `${NAME}` URL is checked again when it resolves at launch, and a public plain-HTTP host then fails with `CONFIG_INVALID` (access endpoints), `AUDIT_UNAVAILABLE` or a dropped optional sink (audit), or `SANDBOX_UNAVAILABLE` (sandbox). URLs with credentials are refused, and redirects are still not followed.
- Plain HTTP is admitted only for that endpoint's own origin (scheme, host, and port), on the fetch its client uses. Another private host, another port on the same host, and every other endpoint keep the loopback-only rule. A credential adapter keeps the base fetch, which admits plain HTTP to loopback only. For OIDC, the identity client admits the issuer's origin, then, once discovery has run, the origins of the private endpoints it names; a plain-HTTP endpoint on a public host is refused, the browser's authorization endpoint included.
- Pi's model requests go through the process dispatcher. With a private-only policy (every managed launch, or `network.privateOnly`), an `inference.baseUrl` that is plain HTTP to a private host (the default) makes it admit plain HTTP to the gateway's origin for every in-process request, an extension's `fetch` included, and to no other host. Without a private-only policy (a personal distribution by default) the process dispatcher checks no destination at all, as before; only the proxy rule below applies to the gateway's origin.
- A plain-HTTP request is sent to an `HTTP_PROXY` in clear, so a plain-HTTP request is refused with `NETWORK_DENIED` when it would go through a proxy that is not itself a private or internal host; `NO_PROXY` is honored as the proxy agent applies it. Add the host to `NO_PROXY` to reach it directly. `doctor` reports a plain-HTTP host that would be refused this way. This applies to every endpoint, MCP servers and `updates.transport` included.
- For e2b-compatible, the command host is matched by name (`<digits>-<id>.<domain>` on port 80, where the domain is the endpoint's host without a leading `api.`), because the sandbox ID is known only once the sandbox exists. An IP-literal endpoint has no such domain, so its command host cannot be reached over plain HTTP; use a name under `.internal` or `.corp`.
- The private-only network policy applies unchanged; in managed mode a governance host still needs `network.allowHosts`.
- `identity.oidc.redirectUri` stays a loopback URI. `credential: runtime` on an MCP server and `sandbox.credential: runtime` stay refused with plain HTTP, whatever the default: the gateway credential goes over plain HTTP only to the gateway itself, even when the MCP server or sandbox shares the gateway's origin.
- `validate` prints one warning line that lists each endpoint whose URL is plain HTTP and what then travels unencrypted (a `${NAME}` URL is listed only when `http-allowed` is written, since what it resolves to is known only at launch), and warns separately about a `.local` or single-label host name. `config explain` shows each endpoint's effective transport (`http-allowed` or `https`), `doctor` shows each endpoint that resolves to plain HTTP by host, and `piship diff` reports a change between `https` and plain HTTP as high risk when it loosens.

What this costs is in [security](security.md#plain-http-to-internal-endpoints): prefer https, and keep the gateway credential's lifetime short.

`updates.transport` predates these fields and keeps its name; it is the same setting for the update channel.

### Enforcement status

Every action has a reported status, derived from the runtime seam table in `@piship/policy`: `enforced` (the control plane, an enforced sandbox, or the gateway prevents it), `audit-only` (observed and recorded, not prevented), or `unsupported` (no runtime seam: neither prevented nor recorded). Pi has no capability discovery API, so the table is static data proven by the compatibility tests, and `piship-lock/v1alpha6` records it with the Pi version and a digest. Against Pi 1.0.x, `web.request`, `browser.execute`, `agent.invoke`, and `memory.*` are `unsupported`, and so is `network.connect` without a required deny sandbox. A managed `deny` or `ask` rule naming an unsupported action exactly fails `validate` and the release `policy` gate with `POLICY_UNENFORCEABLE` unless `policy.acknowledgeUnenforced` lists it; a personal one warns. `policy.default`, `*`, and `<prefix>.*` rules never count ([security](security.md#governance)).

### Session export

`session.export` has three resources:

| Resource | Covers | Status against Pi 1.0.x |
| --- | --- | --- |
| `public` | `/share` and any upload leaving the machine | `unsupported`: the Radius path is closed (no `radius` credential is issued, and a gateway distribution with the ID `radius` is refused with `RADIUS_PROVIDER_RESERVED`), but `/share` falls back to a GitHub gist through the host `gh` CLI, outside PiShip |
| `local` | `/export` to a local file | `unsupported` by construction: session files are readable under `<state>/sessions` |
| `support` | A support bundle or bug report | `enforced` where Pi runs offline (`PI_OFFLINE=1`, which every managed launch sets), so Pi's `/bug` upload is closed; `unsupported` in personal mode |

The lock's `sessionExportStatus` and `doctor` always report all three, whatever the manifest declares, so leaving the rule out does not hide a gap. A managed `public: deny` needs `"session.export:public"` in `policy.acknowledgeUnenforced`.

## Configuration layers

The effective value of `model`, `theme`, and `thinkingLevel` comes from Distribution Enforced, then a permitted User Preference, then Distribution Defaults. An enforced value always wins, and a preference for a key that is enforced or not user-overridable is ignored with a visible notice. Users set preferences with the branded `config set <key> <value>` and `config unset <key>`, stored in `config/preferences.json`. Security-sensitive keys are refused with `POLICY_DENIED`, and a model outside the allowlist with `MODEL_DENIED`. `config set models.allowed a,b` may only narrow the allowlist. `config explain [--json]` prints every effective value with its source, runtime references with whether they resolve, and non-secret identity and credential state. For v1alpha3 and later it adds distribution-enforced rows for the policy ID and rule counts, `policy.userAuto` (managed mode, with this user's [auto mode](#user-auto-mode) state), `mcp.mode`, `sandbox.required`, `sandbox.network`, and `audit.sinks`.

## Runtime references

`${NAME}` is accepted only in `identity.oidc.issuer`, `identity.oidc.clientId`, `identity.oidc.audience`, `credential.broker.endpoint`, `credential.broker.revokeEndpoint`, `inference.baseUrl`, `network.tls.additionalCA`, in v1alpha3 and v1alpha4 `mcp.servers.<id>.url`, `audit.sinks[].url`, `sandbox.endpoint`, and `sandbox.router`, and from v1alpha4 `updates.source`. Each name must be listed in `variables`, and use uppercase letters, digits, and underscores. A variable that nothing references is a `validate` warning, not an error. Names containing `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `PRIVATE_KEY`, or `SESSION` are rejected: references carry endpoints and identifiers, never secrets.

The manifest and lock keep the unresolved template, so a lock is not machine-specific. The branded command resolves references from its launch environment. A missing or empty variable fails with `CONFIG_UNAVAILABLE`; resolved values may not contain a further `${...}` or control characters, and resolved URLs must use HTTPS except for loopback hosts (or, for an endpoint not set to [`httpTransport: https`](#plain-http-to-internal-endpoints-v1alpha6), a private or internal host). `updates.source` is resolved only when `update` runs, not at launch; its resolved value must pass the same URL checks or be an absolute local directory (`--from` also accepts a relative directory). `piship validate` lists the variables launch needs separately from those only `update` reads, and notes which are unset in the current shell. The branded command reads only its own process environment, so a variable set in a shell profile does not reach an IDE or desktop launch; a plain `https` URL needs no variable ([company setup](enterprise-integration.md#plain-urls-or-runtime-variables)).

## Commands

```bash
node packages/cli/dist/bin.js init ./my-agent --personal  # personal piship/v1 (identity none, pi-native)
node packages/cli/dist/bin.js init ./my-agent --managed   # managed piship/v1 template
node packages/cli/dist/bin.js init ./my_agent --id my-agent  # the directory name is not a valid id
node packages/cli/dist/bin.js validate ./my-agent/piship.yaml
node packages/cli/dist/bin.js migrate ./my-agent/piship.yaml [--write | --check]
node packages/cli/dist/bin.js lock ./my-agent/piship.yaml
node packages/cli/dist/bin.js test ./my-agent/piship.yaml [--model-request] [--json]
node packages/cli/dist/bin.js build ./my-agent/piship.yaml
node packages/cli/dist/bin.js config explain <manifest|artifact|id>
node ./dist/my-agent/piship.mjs install ./dist/my-agent   # adopts the state test created
my-agent --version
my-agent --smoke
node ./dist/my-agent/piship.mjs inspect my-agent [--json]
node ./dist/my-agent/piship.mjs doctor my-agent [--json]
node ./dist/my-agent/piship.mjs uninstall my-agent
node ./dist/my-agent/piship.mjs purge my-agent --yes
my-agent logout                                                      # a managed one: revoke the credential first
node ./dist/my-agent/piship.mjs uninstall my-agent --purge --yes   # both in one command
```

`uninstall` keeps state. `purge <id> --yes` deletes it after the uninstall, and `uninstall <id> --purge --yes` does both in one command, for a user whose only PiShip is the installed release; both delete the secret-store entries the state references, and a secret that cannot be deleted fails the command before anything is removed ([install layout](architecture.md#canonical-payload)). Neither revokes anything, so both refuse while the distribution is signed in: run `<command> logout` first ([logout and revocation](security.md#logout-and-revocation)).

v1alpha4 adds `release`, `verify-release`, `reproducibility`, `diff`, `keygen`, `sign-channel`, `update`, `rollback`, and `migrate-check`, and v1alpha5 adds `trust-root init` and `trust-root next` for the update root; see [release](release.md).

`piship --help` lists every command with a one-line summary, and `piship <command> --help` (or `-h`) prints that command's usage; `--help` is never read as a file name or an argument.

`validate` also runs the resource, certified-integrity, and provider-integrity checks of `lock` without writing a lock. `dev` builds and starts the interactive branded command with the same resource and state isolation; `dev --smoke` runs it headlessly with `--smoke` and prints the JSON result. `test` assembles the artifact and runs the branded `--smoke`: Pi SDK, extension, read-tool, and session checks without a model request. It runs against the distribution's real state directory. When that state did not exist before, `test` (and `dev`) marks it as created by them (`.piship-test-state.json`, `piship-test-state/v1`), and the first `install` of the same distribution adopts it without `--use-existing-state` and removes the marker. State that existed before, or that an install has already owned, still needs `--use-existing-state`. `--model-request` runs `--smoke-model` instead, which sends one acceptance prompt to the selected model. `test` prints a short summary of the smoke (Pi version, session, resources, model, governance); `--json` prints the smoke's JSON summary alone. For v1alpha2 and later payloads both need the same runtime variables and, where the distribution requires it, the same prior `login` as the branded command. `inspect` accepts a manifest, artifact directory, or installed ID and prints a short summary; `inspect --json` prints the locked `app`, `deployment`, `runtime`, `resources`, static `access` and `governance` sections, `artifact`, and `state` as JSON, for scripts. `doctor` accepts an artifact directory or installed ID, verifies payload integrity, runs the branded `doctor` report for access-enabled payloads, and launches the smoke, then prints a short summary; `doctor --json` prints `{ distribution, healthy, report, smoke }`, where `report` holds the branded report's lines and `smoke` the smoke's JSON summary. `config explain` explains a manifest directly (without building) using that distribution's state, with the same schema and governance rows as the branded explanation, or runs the branded explanation for an artifact directory or installed ID.

v1alpha2 branded commands add `login`, `logout`, `doctor [--json]`, `models`, `version`, `config explain [--json]`, `config set <key> <value>`, `config unset <key>`, `--model <id>`, `--smoke`, and `--smoke-model`. `--smoke` writes a clearly labeled synthetic entry to a separate acceptance session; `--smoke-model` makes a real request to the configured endpoint. Every distribution's branded command also accepts `--new-session`, which starts a new Pi session instead of continuing the project's most recent one: a launch also does this by itself, with a notice, when the most recent session is damaged or over 64 MiB ([sessions](architecture.md#sessions)). Without `--smoke`, `--smoke-model`, or a subcommand, the branded command starts the interactive Pi session, which needs a terminal: with stdin or stdout not a terminal it fails at once with `CONFIG_INVALID`. There is no non-interactive prompt or print mode.

v1alpha3 and later branded commands add:

- `policy explain <action> <resource> [--json]`: the decision, deciding rule, layer, policy ID, enforcement plane, reason, other matching rules (including ones shadowed by an earlier rule in their layer), and ignored narrowing-only `allow` rules. Filesystem resources are resolved as tools see them: `~` is the home directory and relative paths resolve against the working directory.
- `capabilities [--json]`: the six-axis capability table.
- `auto on | auto off | auto status` (managed): the user's [auto mode](#user-auto-mode), where `policy.userAuto` allows it; `/auto` inside a session.
- `--yolo` (a leading option, also with `--smoke`): approves every `ask` for that session only, where a personal distribution always allows it and a managed one needs `policy.userAuto: allowed` ([`--yolo`](#the---yolo-launch-option)).
- `doctor` groups for Resources (trust class, integrity, and whether each loads), Policy, Project (origin, each discovered project item with its effect, and the static project trust for extensions that load `.claude/*`), Capabilities, Sandbox (provider, the containment level proven by a live probe, isolation `local`, `remote`, or `none`, network mode, and scope), Workspace (effective consistency, declared mode, verification state, whether it is a complete coding-agent workspace, and how git control files are protected; a shared or synchronized remote workspace shows `pending`, since doctor never runs the check), MCP (server health), and Audit (the audit state, each sink's type, requirement, target shown as `local file` or the HTTP host only, state, and delivered, pending, and dropped counts, an undelivered required event at the end of doctor's session, and local metrics).
- A `governance` object in the `--smoke` summary: policy ID, project origin, sandbox level, adapter, planes, and network, workflow mode, capability effectiveness, resource load decisions, MCP server states and exposed tools, and audit state.

Branded commands of installed distributions add `update [--channel <name>] [--from <dir|url>] [--check] [--accept-review]` and `rollback`, and `doctor` fills its Release and Update groups ([update lifecycle](release/update-lifecycle.md#updating-and-rolling-back)). `update` needs a v1alpha4 or later release with update trust: the installation's update root, started from the release's `updates.trust.bootstrap` (or v1alpha4 `updates.trust.keys`) at install ([installation trust state](release/trust-root.md#installation-trust-state)).

### Doctor report

`doctor` prints its groups in one fixed order and leaves out a group that has nothing to report: Distribution, Supply Chain, Identity, Credential, Inference, Gateway, Resources, Policy, Governance, Project, Capabilities, Sandbox, Workspace, MCP, Secret Store, Audit, Network, Release, Update. `✓` is a passed check, `!` a warning, `-` information, and `✗` a failure; any failure makes `doctor` exit non-zero after it has printed the whole report. `doctor --json` prints the same checks as `{ title, failed, groups: [{ group, checks: [{ status, label, value }] }] }`, with `status` one of `ok`, `warn`, `fail`, and `info`, sanitized like the text report.

| Group | Shows |
| --- | --- |
| Identity | Identity mode, whether a session is signed in, and the configured issuer. A stored session is `✓` only when activation used it: `✗` when activation could not use it, `!` when activation failed before reaching it. The OIDC issuer gets one unauthenticated request on every run: `✓` when it answers; when it does not, `!` while the stored session still works and `✗` when activation failed; `-` when doctor did not reach it (a workload identity). No claim of the session (subject, name, email, groups) is shown. |
| Credential | Provider, state or remaining validity, and, in managed mode, that ambient credentials are removed. Never a value, reference, or credential ID. |
| Inference | Provider, activation, and the allowed and default models. |
| Gateway | The managed endpoint's origin and whether its model list answers. The list is the gateway's own: it shows the gateway reachable and the credential accepted, not that a model provider behind the gateway answers. |
| Secret Store | The store PiShip keeps secrets in; the plaintext file store is a warning. |
| Network | TLS verification, the outbound policy, whether a proxy is active (as `scheme://host:port`, never with credentials) and whether `NO_PROXY` is set (never its value), how many enterprise CA bundles are declared, and the network environment the agent's commands (the `bash` tool) receive. In managed mode that is the approved variables, listed by name, and each proxy, CA, or TLS variable that is withheld, by name and reason; in personal mode it is not restricted. MCP stdio servers get only their own `env.allow`. |
| Release | Whether the running payload is a verified release artifact, a payload directory, or a build directory. |
| Supply Chain | The verified manifest, lock, and payload inventory, each bundled search tool with its version (`✗` when Pi's tool directory does not hold the pinned executable), and certified resources. |

Every line is sanitized before it is printed: URL credentials, queries, and fragments are removed, and known secret values and token shapes are redacted, whatever an error message holds.

`doctor` has a Governance group for a governed distribution: the manifest schema (for `piship/v1alpha5`, a suggestion to run `piship migrate <manifest> --check`, then `--write`); the seam table's Pi version, with a warning when it differs from the running Pi; the enforced actions as N of M, with a line per `unsupported` action; Codemode, deferred tools, tool exposure, and the extension tools resolved at launch; virtual models; Pi packages (how many are vendored, integrity verified by doctor, and a line per package); the cache warming mode (a v1alpha6 lock without one shows `off`); runtime mutation (enforced per turn; a blocked runtime fails `doctor`); data retention and purge; and a warning when an installed older release predates the data contract, so a rollback to it would stop the retention sweep. The Policy group always shows the session export status of `public`, `local`, and `support`, and each `POLICY_UNENFORCEABLE` rule, acknowledged or not.

For a governed distribution, `doctor` opens one governed session as a launch does, with the same network policy, the same child network environment, and the signed-in principal, so MCP servers start and the audit sinks receive real events. That session is recorded in audit like a short launch (`session.start`, `policy.loaded`, the resource, provider, and MCP decisions, any credential acquisition activation needed, and `session.end`). Delivering those events is what shows that the sinks work. A required sink that does not take every event makes `doctor` fail with `AUDIT_UNAVAILABLE` in the Audit group; the rest of the report is still printed.

## Lock

`piship.lock` records the normalized manifest digest, app identity, deployment mode, Pi package and version, PiShip version, committed npm lock digest, resolved package versions and npm integrity strings, declared roots, and SHA-256 hashes for every declared resource. A v1alpha1 manifest produces `piship-lock/v1alpha1`. A v1alpha2 manifest produces `piship-lock/v1alpha2`, which adds a static `access` section with provider modes, unresolved `${NAME}` templates, the model catalog, configuration layers, and network policy, and locks identity and credential adapters as resources of kind `adapters`.

A v1alpha3 manifest produces `piship-lock/v1alpha3`. Each locked resource also records its trust class; capability-provider roots are locked as kind `providers`; the policy adapter and stdio MCP modules are locked as `adapters`. A `governance` section holds the parsed governance intent, each certified root with its evidence and computed tree digest, and each capability provider with its class, version, implemented contracts, and tree digest.

A v1alpha4 manifest produces `piship-lock/v1alpha4`, which keeps every v1alpha3 field and adds:

| Field | Content |
| --- | --- |
| `runtime.packages[].resolved` | The npm lock's source URL for each package, checked against `release.sources` by `piship release` |
| `runtime.packages[].installScript` | `true` when npm reports lifecycle scripts for the package; `piship release` stops unless PiShip reviewed that package and version |
| `runtime.stateSchemas` | The local state schemas this PiShip version reads (`state`, `identity`, `credential`, `preferences`, `metrics`, `audit`, `sandboxCredential`, `credentialIssuance`), used by the migration check. A release that lists no key for a class reads none of it, so an update or rollback to it clears the credential classes among them |
| `digests` | `sha256-<hex>` of the canonical JSON (sorted keys) of `resources` (kind, path, and hash of each locked resource), `policy`, `capabilities` (capabilities, providers, and certified evidence), `mcp`, `sandbox`, `audit`, and `access` |
| `updates` | The parsed `updates` section, including the pinned public keys |
| `release` | The `release` section with defaults applied |

A v1alpha5 manifest produces `piship-lock/v1alpha5`, which keeps every v1alpha4 field and changes two:

| Field | Content |
| --- | --- |
| `manifest.sha256` | The canonical manifest digest: `sha256-<64 lowercase hex>` of the canonical JSON (sorted keys) of the parsed manifest, so YAML comments, key order, flow or block style, and line endings never change it, and any semantic change does. Older locks keep the bare hex SHA-256 of the parsed manifest's JSON |
| `updates.trust.bootstrap` | The exact validated bootstrap root (`version`, `expires`, `keys`, `roles`), or no `bootstrap` when updates are disabled. It is only the bootstrap trust of a fresh installation |

A v1alpha6 manifest produces `piship-lock/v1alpha6`, which keeps every v1alpha5 field and adds:

| Field | Content |
| --- | --- |
| `runtimeTools` | `runtime.tools` with defaults applied (`codemode`, `toolSearch`, `exposure` rules), which a launch applies. A v1alpha5 lock has none and launches with Codemode and tool search off and every tool direct |
| `tools` | the exposure of PiShip's own tools resolved against `runtime.tools.exposure`, and each declared MCP server's rules as `<server>:<glob>` (its default as `<server>:*`). Extension tools register at run time and are checked at launch, never locked. Two exposure globs of equal specificity that can match the same tool fail the lock, and in managed mode so does Codemode while a PiShip tool it can reach has no policy rule for `tool.execute` |
| `virtualModels` | Each virtual model with its router and the closed set of its physical routes |
| `enforcement` | The runtime seam evidence: the Pi version the seam table was proven against, the per-action table, and a `sha256-` digest that also covers the per-resource seams |
| `data` | The data lifecycle contract version (`piship-data/v1`) and the manifest's `data` section, which the sweeps and the audit rotation read at run time |
| `sessionExportStatus` | The status of `public`, `local`, and `support`, always recorded |
| `cacheWarming` | `runtime.cacheWarming` as parsed (`mode`, `userOverride`); absent when the manifest has none, which a launch takes as `off`, enforced for a managed distribution only |
| `packages` | Each Pi package's resolved identity, tree digest, file count, stored lockfile digest, and resource inventory ([below](#pi-packages-v1alpha6)) |
| `searchTools` | Each bundled search tool's upstream version and source, and per release target the archive URL and digest, the executable's path in the archive, its digest, and its size; with `digests.searchTools`. Absent without `runtime.searchTools` ([bundled search tools](#bundled-search-tools-v1alpha6)) |

A `piship/v1` manifest produces `piship-lock/v1`, which has exactly the content of `piship-lock/v1alpha6`: the same keys with the same meanings, and the same canonical `sha256-` manifest digest over the parsed manifest (which names its schema, so the digest of a v1alpha6 manifest is the same value it always was, and a v1 manifest has its own). The only differences are the two schema ids (`schema` and `manifest.schema`) and that digest. See [lock stability](#lock-stability).

A v1alpha6 manifest with Pi packages records each one in `packages` (source, class, canonical source URL without userinfo, npm version and integrity or git commit, `tree` digest and file count of the package's own files, the sha256 of its stored npm lockfile, the expanded resource inventory with each file's sha256, and the optional dependencies each release target installs) and adds `digests.packages`. The stale-lock check is offline: it re-reads the stored lockfiles and recomputes local package digests, and never reaches a registry or repository ([Pi packages](#pi-packages-v1alpha6)).

Packages that the npm lock records without an integrity value (local workspace packages and a few nested packages) are not listed in `runtime.packages`. `piship diff <before> <after>` compares the locks of two manifests, lock files, payloads, releases, or installed IDs ([owner workflow](release/owner-workflow.md#reviewing-a-change)). Between v1alpha6 locks it also compares `runtimeTools`, each tool's exposure, the seam evidence, the data contract and declared `data`, `sessionExportStatus`, virtual models, Pi packages, bundled search tools, and `cacheWarming`. A new package or bundled search tool, a change of a package's source, URL, version, commit, integrity, or tree, a search tool's different source or different bytes at the same version, a widened package class, widened exposure (such as `hidden`, `deferred`, or `codemode` to `direct`), an enforcement downgrade, and an export that becomes allowed are high risk; a cache warming change, a removed search tool, a search tool version change or added target, and an added `policy.acknowledgeUnenforced` entry are medium. The `model.use` to `model.select` rename is not reported as a change.

### Lock stability

`piship-lock/v1` is stable on the terms of [stability](#stability), and the [support policy](support-policy.md#lock-reader-compatibility-and-relock-rules) holds the reader and relock rules.

- **What it fixes.** The runtime identity and version, the PiShip version, each resource's resolution and SHA-256, each provider's resolution and capability contract, the integrity of every package, the static policy (`policy`, `capabilities`, `mcp`, `sandbox`, `audit`, and `access` with their digests), and the other static facts of the distribution: the release and update inputs, the enforcement evidence, and the data contract.
- **What it never holds.** The current user's entitlement, a runtime credential or token, a resolved endpoint or variable value, live gateway state, and the state of a remote MCP server. Those are read when the distribution runs, and the lock has only the `${NAME}` references to them.
- **Readers.** A newer PiShip verifies the lock of a release an older PiShip built, without relocking it, and does not change its digest. A lock key added later is optional, and a reader that does not know it ignores it.
- **Relock.** A lock is rewritten only by `piship lock`. After `piship migrate --write` the lock is stale (its manifest digest and schema ids differ) and `build` refuses it until it is relocked.
- **The payload is not the lock.** Deduplicating or bundling the files of a payload changes the files on disk and nothing the lock records: it describes the logical dependency graph.

The lock never contains tokens, credentials, private keys, or resolved endpoint values. It is deterministic and has no timestamp. Build rejects a stale lock. For a lock of `piship/v1alpha4` or later, `piship build` also runs the release `source` and `install-script` gates ([owner workflow](release/owner-workflow.md)); `dev` and `test` do not. The packaged inventory is verified by `doctor`, `verify-release`, and a launch that sets `runtime.verifyAtLaunch: true`, with `INTEGRITY_FAILED` for changed files and `LOCK_INVALID` for inconsistent manifest or npm lock bindings. Every launch reads the target and the distribution lock required to boot and hashes the lock, which carries `policy.enforced`, against the digest the install receipt recorded, so a changed lock fails the launch with `INTEGRITY_FAILED`; that check is skipped for a build directory, another install home, an unreadable receipt, and an installation recorded before the receipt carried the digest. It scans the rest of the inventory only with `runtime.verifyAtLaunch: true` (v1alpha6), which runs the full payload verification at launch and keeps no V8 compile cache; without it a bundled payload may keep that cache in the distribution's state. Install and update hash the archive and each file in the same pass that extracts them and compare the results with the signed or bound inventory before the receipt is written; release/CI owns supply-chain qualification. The lock itself is not signed; releases are verified through signed channel metadata and build provenance ([release](release.md)).

## Migration

`piship migrate <manifest>` prints a dry-run plan and the migrated YAML; `--write` applies it in place. It migrates step by step to `piship/v1`; an existing v1 manifest is left unchanged. Migration is deterministic and idempotent, and never broadens what the distribution allows. It never rewrites a value that only the owner can decide: it leaves the value as written and reports it for review.

`piship migrate <manifest> --check` is read-only: it reads the manifest, writes nothing (not the manifest, not the lock, not a temporary file beside it), and prints one of three results, with each change and each item to review.

| Result | Meaning | Exit |
| --- | --- | --- |
| `migratable` | The migration changes no effective decision and nothing needs the owner. `--write` is safe to run | 0 |
| `requires review` | The migration can run, but it changes an effective decision (such as the cache warming and bundling defaults of v1alpha5) or leaves a value for the owner: a Pi pin this PiShip does not carry, the expiry an earlier migration wrote into a bootstrap root, or a managed bootstrap whose root and channel roles share a key. Each item is listed on standard error | 1 |
| `cannot migrate` | The manifest does not parse, names a schema PiShip does not know, or a step refuses it (for example a v1alpha5 MCP tool filter with a glob, which could outrank a deny). The reason is on standard error and nothing is changed | 3 |

A manifest that is already `piship/v1` prints `Already piship/v1; nothing to migrate.` and exits 0. Exit 2 is a usage error.

- v1alpha1 to v1alpha2: an equivalent personal profile with `identity.mode: none`, `credential.provider: pi-native`, and `inference.provider: pi-native`. v1alpha1 never had a runnable managed mode, so a v1alpha1 manifest with `deployment.mode: managed` is rejected and must be rewritten with access sections (see `piship init --managed`).
- v1alpha2 to v1alpha3: each flat resource list becomes the `company` class (managed) or `user` class (personal). The new sections are written with values that keep v1alpha2 behavior: `policy.default: allow`; every project origin denies every dimension, including `passiveContext` (project themes), since v1alpha2 loaded no project resources; `sandbox.required: false`; `audit.enabled: false`; and `mcp.mode: off`. Resource, provider, and project trust and capability defaults then apply (the builtin `permissions` capability is enabled), so review the plan before writing it.
- v1alpha3 to v1alpha4: adds `updates: {channel: stable, channels: [stable], rollback: true}` with no `source` and no trust keys, so updates stay disabled until a source and at least one key are added. `release` is not written; its defaults apply (the three evidenced targets, `https://registry.npmjs.org`, and `failOn: high`). Nothing else changes.
- v1alpha4 to v1alpha5: `updates.trust.keys` becomes `updates.trust.bootstrap` with `version: 1`, a fixed `expires: 2027-10-01T00:00:00Z`, the same keys (comments kept), and every key in both the root and the channel role with threshold 1: the legacy keys as a compatibility trust set, never a stronger split. For a managed distribution the plan warns that managed rollout requires an explicit root / channel split, and `piship validate` and the release `trust` gate keep reporting it until the owner splits the roles. With no keys, `updates.trust` is removed and no key is invented, so the distribution stays update-disabled; an `updates.source` is kept, and update keeps failing closed until a bootstrap is added.
- v1alpha5 to v1alpha6: see [below](#migrating-from-v1alpha5-to-v1alpha6).
- v1alpha6 to v1: see [below](#migrating-from-v1alpha6-to-v1).

After migrating, regenerate `piship.lock` and rebuild. v1alpha1 remains accepted for personal distributions, and v1alpha2, v1alpha3, and v1alpha4 remain accepted but cannot build a release; v1alpha5, v1alpha6, and v1 can. `piship init` writes `piship/v1` in both modes, with no MCP servers, `sandbox.required: false`, and updates disabled until `updates.source` and `updates.trust.bootstrap` are set; the managed template leaves project items from external and unknown workspaces unloaded, while the personal template loads a project’s own instructions and skills (asking for an unknown origin), asks before project extensions and `.mcp.json` servers, keeps hooks, agents, and providers denied, and bundles `fd` and `rg` (`runtime.searchTools`, which `piship lock` downloads, so it needs network access to github.com); the managed template also sets `policy.default: ask` with allow rules for its models, company instructions, and workspace reads, and a local audit sink.

### Migrating from v1alpha5 to v1alpha6

v1alpha5 manifests keep loading on v0.9 once `runtime.pi` names the Pi version v0.9 pins (`1.0.2` for v0.9.0 and v0.9.1, `1.0.3` for v0.11.0, v0.12.0, and on main; a v0.8 manifest pins `1.0.0`, which v0.9 refuses), and an installation's state files (`config/policy.json`, `auto.json`, the audit logs) are read as they are and never rewritten, so a rollback to v0.8.1 still reads them. Migrate when you want a v1alpha6 field:

1. Run `piship migrate piship.yaml --check`. It prints every change and exits non-zero when one changes an effective decision.
2. Review the plan, then run `piship migrate piship.yaml --write`.
3. Run `piship validate`, `piship lock`, and `piship diff` against the previous lock, then rebuild.

The step writes:

- `policy.enforced[]` and `policy.defaults[]` rules with `action: model.use` become `model.select`: the same rule. `model.use` stays accepted as an alias, in manifests and in `config/policy.json`, normalized at parse time.
- Each MCP server gets `class: company` (managed) or `class: user` (personal), now decided by `policy.resourceTrust` for that class, and `exposure: direct`, the v0.8 behavior (Pi's own `mcp.json` default does not apply).
- `tools.allow` / `tools.deny` become an exposure map that keeps the same tools visible: an allowed tool is `direct`, a denied tool `hidden`, and with an allowlist `"*": hidden`. An empty filter is removed. v1alpha5 filters list exact names; a filter entry with `*` is refused rather than migrated, because a glob could outrank a deny.
- No `data` section is written, so no retention sweep runs, as in v0.8.

Three effective changes are reported by `--check`:

- An omitted `runtime.cacheWarming` is `off`, while v0.8 sessions warmed the prompt cache through Pi's default (`streaming`). v0.9 applies this to every governed lock, including a v1alpha5 manifest that is not migrated (it cannot declare the field), so migrate and set `runtime.cacheWarming.mode: streaming` to keep warming.
- A server whose new class `policy.resourceTrust` does not allow would no longer start. Allow the class or remove the server before migrating.
- An omitted `release.bundle` and `release.strip` are `true` in v1alpha6, so a build is a bundled, stripped payload (far fewer files, with its authoring inputs kept as one compressed snapshot), while v1alpha5 built an unbundled one. Set both to `false` to keep that.

The migration never broadens: every value it writes keeps the v0.8 decision. Independently of the schema, `validate` on v0.9 reports a managed `deny` or `ask` rule on an action without a runtime seam (such as `web.request`) as `POLICY_UNENFORCEABLE`. Only v1alpha6 accepts `policy.acknowledgeUnenforced`, so such a rule is either acknowledged after migrating or removed ([enforcement status](#enforcement-status)).

### Migrating from v1alpha6 to v1

v1 freezes v1alpha6, so this step has nothing to convert. It changes the `schema` line and nothing else: no field is renamed, added, or removed, no default moves, and comments and key order are kept. A migrated manifest means exactly what the v1alpha6 manifest meant, and `piship validate` accepts it with the same warnings.

1. Run `piship migrate piship.yaml --check`. `migratable` means go ahead.
2. Run `piship migrate piship.yaml --write`.
3. Run `piship validate`, `piship lock`, and `piship diff previous.lock piship.lock`. The diff reports the two schema ids as a medium-risk change that needs migration review, and no other change.
4. Rebuild. For an installed distribution, read [updating across a schema](support-policy.md#manifest-versions-and-the-migration-window): publish one release that is built by this PiShip with its manifest still on `piship/v1alpha6` before the first `piship/v1` release.

What `--check` can ask you to review for this step:

- `updates.trust.bootstrap.expires` is `2027-10-01T00:00:00Z`, the fixed value the v1alpha4 to v1alpha5 migration wrote. Set the real expiry; an update refuses an expired root.
- A managed distribution whose bootstrap root and channel roles share a key. `piship release` refuses it until an offline root key is separate from the channel release key.

Both were already reported by earlier steps and by `validate`; the check lists them again because a stable manifest should not carry them. Nothing here is rewritten for you.

Earlier checkout-local preview manifests need `app.version` added; `app.banner`, `app.theme`, and `resources.themes` are optional. Regenerate `piship.lock` with the current CLI, then rebuild. Checkout-local output cannot be installed as a portable payload.

## Differences from the product specification

A maintainer-local product specification (v1.0) guided the design; it is not required for contributions. Where its names or structure differ from what is implemented, this document and the schema in `packages/schema` are authoritative, and the specification is the side expected to change.

| Area | Implemented in PiShip | Product specification |
| --- | --- | --- |
| Identity kind | `identity.mode`: `none`, `oidc`, or `adapter` | `identity.provider` |
| Trust sections | `policy.resourceTrust`, `policy.providerTrust`, and `policy.projectTrust`, nested under `policy` | Top-level trust sections |
| Policy rules | `policy.enforced` and `policy.defaults` rule lists, plus `policy.default` | `permissions.rules` |
| Project origins | `policy.projectTrust.company`, `external`, and `unknown` | `companyRepo` and `externalRepo` |
| Update source | `updates.source`: an `https` URL, a loopback `http` URL (a private-host `http` URL unless `updates.transport: https`), or a `${NAME}` runtime reference; `update --from` also accepts a directory | A symbolic `company` or `self` source |
| State location | `~/.piship/<id>` (or `PISHIP_STATE_HOME`); project restrictions in `.piship/policy.json`; no `app.configDir` or `branding` section | A branded configuration directory |
| Distribution tests | `piship test` builds the payload and runs the branded `--smoke`; no `tests` section | A configured test suite |
| Release provenance | GitHub artifact attestations made by CI, verified with `gh attestation verify`; no `provenance.json` in the archive; `install.sh` and `install.ps1` at the archive root | An embedded provenance file and an `installers/` directory |
| Error codes | `PISHIP_ERROR_CODES` in `@piship/contracts`; a unit test requires every code to have a producing path. Five specification codes that nothing produced are not defined ([below](#removed-error-codes)). `PiShipError` has no `correlationId`, and its JSON form names the sanitized detail `detail` | Also `APPROVAL_REQUIRED`, `RESOURCE_DENIED`, `PROVIDER_UNRESOLVED`, `PROVIDER_UNHEALTHY`, and `SANDBOX_REQUIRED`; `correlationId` and `sanitizedDetail` |

Deferred items in this table are tracked on the [roadmap](roadmap.md#later).

### Removed error codes

| Specification code | What PiShip does instead |
| --- | --- |
| `APPROVAL_REQUIRED` | An `ask` decision prompts the person; without an approval channel (headless) it resolves to deny and is recorded as a denial, unless the user's [auto mode](#user-auto-mode) or [`--yolo`](#the---yolo-launch-option) approves it |
| `RESOURCE_DENIED` | A denied tool call is refused to the model and a denied resource is not loaded, both recorded as denials; a refused command or setting fails with `POLICY_DENIED` |
| `PROVIDER_UNRESOLVED` | Reported on the `resolved` axis of `capabilities`; the capability is not effective |
| `PROVIDER_UNHEALTHY` | Reported on the `healthy` axis; a provider the policy refuses is reported on the `enabled` axis |
| `SANDBOX_REQUIRED` | A required sandbox that cannot be enforced fails with `SANDBOX_UNAVAILABLE` |

Managed distributions must exclude pi-code `!extensions/hooks/**` whenever an origin does not allow `claudeHooks`; PiShip also excludes that package entry point at launch for such an origin. Those sessions keep whole project `.claude` directories read-only, including missing paths, to prevent executable settings from being planted. Managed distributions must exclude `!extensions/mcp/**` because user-level MCP consent bypasses project trust. Managed package permission providers reject project provider overrides and keep project `.pi` directories read-only.
