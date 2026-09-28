# Experimental manifest and lock

Two alpha schemas are accepted. Both remain experimental, and unknown fields are rejected.

- `piship/v1alpha1` is the v0.1 personal contract. It accepts only `deployment.mode: personal`, uses Pi-native providers and auth in isolated state, and rejects credential fields and `${...}` substitutions. The [personal example](../examples/personal/piship.yaml) uses it.
- `piship/v1alpha2` adds access configuration for `managed` and `personal` distributions. The [demo company example](../examples/demo-company/piship.yaml) is a managed v1alpha2 manifest.

## Common fields

Required fields are `schema`, `app.id`, `app.name`, `app.command`, `app.version`, `runtime.pi`, and `deployment.mode`. `app.banner` and `app.theme` are optional. `app.theme` selects a built-in or declared custom theme through Pi's public interactive API. `resources` can declare instruction files and skill, extension, prompt, or theme roots. IDs and commands use safe lowercase names; `app.version` is a distribution semver independent of PiShip and Pi versions. Resource paths start with `./`, stay inside the manifest directory, and may not contain symlinks.

## piship/v1alpha2 access fields

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

A v1alpha2 personal manifest defaults to `identity.mode: none` with `pi-native` credentials and inference. It may instead use `local-secret` or `none` credentials with an `openai-compatible` endpoint, including a local model server. The personal file store does not require `acknowledgePlaintext`.

## Configuration layers

The effective value of `model`, `theme`, and `thinkingLevel` comes from Distribution Enforced, then a permitted User Preference, then Distribution Defaults. An enforced value always wins, and a preference for a key that is enforced or not user-overridable is ignored with a visible notice. Users set preferences with the branded `config set <key> <value>` and `config unset <key>`, stored in `config/preferences.json`. Security-sensitive keys are refused with `POLICY_DENIED`, and a model outside the allowlist with `MODEL_DENIED`. `config set models.allowed a,b` may only narrow the allowlist. `config explain [--json]` prints every effective value with its source, runtime references with whether they resolve, and non-secret identity and credential state.

## Runtime references

`${NAME}` is accepted only in `identity.oidc.issuer`, `identity.oidc.clientId`, `identity.oidc.audience`, `credential.broker.endpoint`, `credential.broker.revokeEndpoint`, `inference.baseUrl`, and `network.tls.additionalCA`. Each name must be listed in `variables`, use uppercase letters, digits, and underscores, and be referenced at least once. Names containing `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `PRIVATE_KEY`, or `SESSION` are rejected: references carry endpoints and identifiers, never secrets.

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

`dev` builds and starts the interactive branded command with the same resource and state isolation. `test` assembles the artifact and runs the branded `--smoke`: Pi SDK, extension, read-tool, and session checks without a model request. `--model-request` runs `--smoke-model` instead, which sends one acceptance prompt to the selected model. For v1alpha2 payloads both need the same runtime variables and, where the distribution requires it, the same prior `login` as the branded command. `inspect` accepts a manifest, artifact directory, or installed ID and includes the static `access` section. `doctor` accepts an artifact directory or installed ID, verifies payload integrity, runs the branded `doctor` report for access-enabled payloads, and launches the smoke. `config explain` explains a manifest directly (without building) using that distribution's state, or runs the branded explanation for an artifact directory or installed ID.

v1alpha2 branded commands add `login`, `logout`, `doctor`, `models`, `version`, `config explain [--json]`, `config set <key> <value>`, `config unset <key>`, `--model <id>`, `--smoke`, and `--smoke-model`. `--smoke` writes a clearly labeled synthetic entry to a separate acceptance session; `--smoke-model` makes a real request to the configured endpoint.

## Lock

`piship.lock` records the normalized manifest digest, app identity, deployment mode, Pi package and version, PiShip version, committed npm lock digest, resolved package versions and npm integrity strings, declared roots, and SHA-256 hashes for every declared resource. A v1alpha1 manifest produces `piship-lock/v1alpha1`. A v1alpha2 manifest produces `piship-lock/v1alpha2`, which adds a static `access` section with provider modes, unresolved `${NAME}` templates, the model catalog, configuration layers, and network policy, and locks identity and credential adapters as resources of kind `adapters`. The lock never contains tokens, credentials, or resolved endpoint values. It is deterministic and has no timestamp. Build rejects a stale lock. The packaged file inventory detects changed manifest, lock, resource, adapter, or runtime files before Pi loads. There is no signature or trusted publisher verification.

## Migration

`piship migrate <manifest>` prints a dry-run plan and the migrated YAML; `--write` applies it in place. It converts a `piship/v1alpha1` manifest into an equivalent `piship/v1alpha2` personal profile: `identity.mode: none`, `credential.provider: pi-native`, and `inference.provider: pi-native`. An existing v1alpha2 manifest is left unchanged. Migration covers personal manifests only: v1alpha1 never had a runnable managed mode, so a v1alpha1 manifest with `deployment.mode: managed` is rejected and must be rewritten as v1alpha2 with its access sections (see `piship init --managed`). After migrating, regenerate `piship.lock` and rebuild. v1alpha1 remains accepted for personal distributions.

Earlier checkout-local preview manifests need `app.version` added; `app.banner`, `app.theme`, and `resources.themes` are optional. Regenerate `piship.lock` with the current CLI, then rebuild. Checkout-local output cannot be installed as a portable payload.
