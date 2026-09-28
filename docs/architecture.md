# Architecture

PiShip is an open-source, company-first distribution and governance framework for branded Pi-based coding agents. Pi owns the agent loop, TUI, sessions, tools, model/runtime behavior, and extension execution. PiShip owns the distribution layer: manifest/configuration, pinned runtime, resources, reproducible payload, identity/credential/inference integration, and progressively policy/trust and lifecycle/release. Distribution repositories own their brand and declared resources. Pi source is neither forked nor patched.

v0.1 delivered the portable personal foundation. v0.2 adds managed access and configuration as a preview: enterprise identity, organization-issued runtime credentials, an explicit inference gateway, model governance, and layered configuration. v0.3 adds governance as a preview for `piship/v1alpha3`: policy, resource, provider, and project trust, capabilities, governed MCP, an OS sandbox for tool subprocesses, and audit. Production lifecycle remains a later milestone. See [compatibility](compatibility.md) for what is verified.

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Manifest, lock, payload, installation, access orchestration | PiShip |
| Identity provider, credential broker, inference gateway | The organization (PiShip integrates, it does not become one) |
| Brand and selected resources | Distribution repository |

## Packages

| Package | Responsibility |
| --- | --- |
| `@piship/schema` | Validates `piship/v1alpha1`, `piship/v1alpha2`, and `piship/v1alpha3`, runtime references, and step-wise alpha migration |
| `@piship/contracts` | Separate `IdentityProvider`, `CredentialProvider`, `SecretStore`, and `InferenceProvider` contracts; the policy decision and audit event contracts; `SecretValue` redaction; `PiShipError` codes; managed network policy |
| `@piship/policy` | Policy engine and rule precedence, glob and path matching, `policy explain` rendering, project identification and resource discovery, resource and provider trust, capability state |
| `@piship/audit` | Metadata-first audit log with file and HTTP sinks, the failure matrix, and local metrics |
| `@piship/sandbox` | OS sandbox adapters (Linux bubblewrap, macOS Seatbelt), profile resolution, the live containment probe, and contained process spawning |
| `@piship/mcp` | Governed MCP client: stdio and Streamable HTTP transports, server start and tool call authorization, tool exposure |
| `@piship/identity` | OIDC Authorization Code + PKCE login for native public clients ([identity](identity.md)) |
| `@piship/credentials` | Credential providers, platform secret stores, and the runtime credential lifecycle ([credentials](credentials.md)) |
| `@piship/inference` | OpenAI-compatible and Pi-native inference binding and the effective model catalog ([inference](inference.md)) |
| `@piship/core` | Lock (including certified tree digests and provider evidence), payload assembly and verification, install ownership, access orchestration (`DistributionAccess`), layered configuration |
| `@piship/pi` | The only direct Pi dependency; builds the governed Pi runtime, the governance session, governed tools, builtin extensions, and branded commands through public SDK exports |
| `@piship/cli` | Presents `piship` commands |

`identity`, `credentials`, and `inference` depend only on `contracts` and may not import each other; only `core` connects them, through `IdentitySession`, `CredentialRef`, and `ModelDefinition`. `policy`, `audit`, `sandbox`, and `mcp` are governance leaves: `policy` may import `contracts` and `schema`; `audit` and `sandbox` only `contracts`; `mcp` `contracts` and `sandbox`, so stdio servers spawn through the sandbox. `core` may import `policy` and `audit`; `pi` composes all four; `cli` may import `policy`. `scripts/check-boundaries.mjs` enforces these imports and the rule that only `packages/pi` imports Pi.

## Canonical payload

`piship build` creates `dist/<id>` from package-owned build inputs prepared with `@piship/core`, using `npm ci --omit=dev` and exact locked dependencies. It does not infer the PiShip source repository from its module path. The payload contains `node_modules` (including Pi and PiShip), `bin/`, declared `resources/` and adapters, the exact source `piship.yaml` and `piship.lock`, `package-lock.json`, and `metadata/target.json` and `metadata/inventory.json`. The inventory covers the canonical lock and all payload files. The launcher checks the recorded target and integrity before entering Pi and resolves only packages inside this directory. A machine must have Node.js 22.19.0 or newer installed separately. Build-time registry access may be needed; installation and launch do not fetch Node, Pi, or packages. The payload includes upstream package notices. It is the same unit future release verification and updates must consume.

The payload includes `piship.mjs`, so installation and diagnostics need no source checkout. `node <payload>/piship.mjs install <payload>` copies this payload into `~/.local/share/piship/apps/<id>/<version>` and writes a command shim in `~/.local/bin` by default. Set `PISHIP_INSTALL_HOME` and `PISHIP_BIN_HOME` to choose other user-writable locations. Add the bin directory to `PATH` yourself; PiShip does not edit shell profiles. The receipt in `<install-home>/receipts/<id>.json` records owned paths. Name, command, existing install, and pre-existing state collisions fail. `--use-existing-state` explicitly adopts state during install. `uninstall` removes the receipt, shim, and payload; `purge <id> --yes` separately deletes the selected state after uninstall.

## Managed launch flow

For a `piship/v1alpha2` payload the branded command:

1. Verifies payload integrity and the pinned Pi version, as in v0.1.
2. Refuses to run if `NODE_TLS_REJECT_UNAUTHORIZED=0`.
3. Resolves the allowlisted `${NAME}` runtime references from the launch environment; a missing value fails with `CONFIG_UNAVAILABLE`.
4. In managed mode, removes ambient credential variables (and proxy variables unless inherited) from the process environment, then applies the proxy and CA policy.
5. Loads the identity session from state, refreshing it when it is about to expire; without one it fails with `IDENTITY_REQUIRED`.
6. Ensures a runtime credential: reuses a valid one, refreshes before expiry, or acquires one from the broker.
7. Builds the effective model catalog (distribution ∩ entitlement ∩ live gateway ∩ user narrowing) and resolves the selected model; it never substitutes another model.
8. Creates a Pi `ModelRuntime` with an in-memory credential store and no `models.json` or `auth.json`, registers one provider named after the app ID, and governs it so only allowed models are visible, selectable, and callable.
9. Publishes the token-free enterprise context for extensions and starts Pi.

`login`, `logout`, `doctor`, `models`, and `config` are branded subcommands handled before Pi starts. Personal `piship/v1alpha1` payloads keep the v0.1 path: Pi-native providers and auth in isolated state.

## Governed launch flow

A `piship/v1alpha3` payload runs the access steps above for its deployment mode, then `GovernanceSession.open` establishes the controls in this order before Pi starts. Any mandatory control that fails stops the launch.

1. Audit: opens the sinks; an unreachable required sink fails with `AUDIT_UNAVAILABLE`.
2. Project: finds the project root and origin remote, classifies the origin, and discovers project resource candidates.
3. Sandbox: when required, selects the platform adapter and proves it with a live probe; otherwise fails with `SANDBOX_UNAVAILABLE`.
4. Policy engine: enforced rules, team adapter rules, project restrictions, distribution defaults, and user rules, with the proven containment.
5. Declared resources: trust class, certified integrity and compatibility, then `*.load` policy; builtin extensions likewise.
6. Project resources: project trust dimension, resource trust, then policy.
7. MCP: authorizes and starts servers and lists their tools.
8. Capabilities and providers: computes the six capability axes and adds effective non-builtin provider extensions.

The selected model is then decided as `model.use`, and Pi starts with only the admitted resources, the governed tools, and PiShip's inline extensions. When the session ends, PiShip records `session.end`, stops MCP servers, removes the session temp directory, and flushes audit. `doctor`, `policy explain`, and `capabilities` inspect the same state without starting MCP servers or asking for approvals.

Governance uses these public Pi seams:

- `createAgentSession` with `noTools: "builtin"` and `customTools`: governed `read`, `write`, `edit`, and `bash` built with `createReadToolDefinition`, `createWriteToolDefinition`, `createEditToolDefinition`, and `createBashToolDefinition` and their `operations` hooks, plus MCP tools.
- `DefaultResourceLoader`, which receives only admitted instruction, skill, extension, prompt, and theme paths.
- Extension events: `tool_call` (policy and Plan mode, able to block), `user_bash` (governed operations for `!` commands), `before_agent_start` (Plan or Build prompt), `before_provider_request` (model request audit), and `session_start`.
- `registerTool` for `ask_user` and `registerCommand` for `/plan` and `/build`; the extension context's `hasUI`, `ui.confirm`, `ui.select`, `ui.setStatus`, and `ui.notify` for approvals and mode display.

## State

State defaults to `~/.piship/<id>` or `PISHIP_STATE_HOME/<id>`. The state path depends on the distribution ID, so relocation or reinstallation can resume the same session. State is never copied into the payload.

| State path | Scope and sensitivity | Retention and clearing |
| --- | --- | --- |
| `agent/` | Pi config, model metadata, and, for Pi-native auth, Pi's local auth file; sensitive. Managed runtimes do not write `auth.json` or `models.json` | Kept by uninstall; selected distribution purge deletes it |
| `identity/session.json` | Non-secret identity metadata (subject, issuer, display claims, expiry) and a secret-store reference; no tokens | Cleared by `logout`; purge deletes it |
| `credentials-metadata/inference.json` | Non-secret runtime credential metadata (`piship-credential-metadata/v1`): generation reference, credential ID, expiry, entitled models; no secret | Cleared by `logout`; purge deletes it |
| `config/preferences.json` | User preferences (`piship-preferences/v1`) | Kept by uninstall and logout; purge deletes it |
| `config/policy.json` | Optional user policy rules (v1alpha3); may relax distribution defaults only | Kept by uninstall and logout; purge deletes it |
| `secrets/` | Only with the explicit file fallback: owner-only plaintext secret files. Unused with a platform secret store | Cleared by `logout`; purge deletes it |
| `sessions/user/` | Interactive Pi sessions; may contain private project content | Kept by uninstall and logout; purge deletes it |
| `sessions/acceptance/` | Labeled smoke session | Kept by uninstall and logout; purge deletes it |
| `cache/` | Reserved per-distribution cache | Kept by uninstall; purge deletes it |
| `logs/` | v1alpha3 audit file sink `audit.jsonl` (metadata-first events) and local counters `metrics.json`; may be sensitive | Kept by uninstall; purge deletes it |
| `data/` | Reserved runtime-generated data | Kept by uninstall; purge deletes it |

Secrets held in a platform secret store live outside this directory, keyed by distribution ID; `logout` deletes them, while `purge` removes only files under the state directory. Run `logout` before `purge`. These paths have no automatic migration; reinstalling the same distribution ID reuses them. Pi's resource loader disables ambient extension, skill, prompt, theme, and context discovery and receives only declared packaged paths. The working directory remains the user's project; its `.pi` resources are not distribution resources. For v1alpha3, project resources that project trust admits are passed to the loader explicitly. An enforced sandbox denies contained processes read access to the whole state directory.

See [manifest](manifest.md), [compatibility](compatibility.md), [security](security.md), [identity](identity.md), [credentials](credentials.md), and [inference](inference.md).
