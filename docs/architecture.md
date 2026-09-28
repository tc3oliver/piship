# Architecture

PiShip is an open-source, company-first distribution and governance framework for branded Pi-based coding agents. Pi owns the agent loop, TUI, sessions, tools, model/runtime behavior, and extension execution. PiShip owns the distribution layer: manifest/configuration, pinned runtime, resources, reproducible payload, identity/credential/inference integration, and progressively policy/trust and lifecycle/release. Distribution repositories own their brand and declared resources. Pi source is neither forked nor patched.

v0.1 delivered the portable personal foundation. v0.2 adds managed access and configuration as a preview: enterprise identity, organization-issued runtime credentials, an explicit inference gateway, model governance, and layered configuration. Governance/security policy and production lifecycle remain later milestones. See [compatibility](compatibility.md) for what is verified.

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Manifest, lock, payload, installation, access orchestration | PiShip |
| Identity provider, credential broker, inference gateway | The organization (PiShip integrates, it does not become one) |
| Brand and selected resources | Distribution repository |

## Packages

| Package | Responsibility |
| --- | --- |
| `@piship/schema` | Validates `piship/v1alpha1` and `piship/v1alpha2`, runtime references, and alpha migration |
| `@piship/contracts` | Separate `IdentityProvider`, `CredentialProvider`, `SecretStore`, and `InferenceProvider` contracts; `SecretValue` redaction; `PiShipError` codes; managed network policy |
| `@piship/identity` | OIDC Authorization Code + PKCE login for native public clients ([identity](identity.md)) |
| `@piship/credentials` | Credential providers, platform secret stores, and the runtime credential lifecycle ([credentials](credentials.md)) |
| `@piship/inference` | OpenAI-compatible and Pi-native inference binding and the effective model catalog ([inference](inference.md)) |
| `@piship/core` | Lock, payload assembly and verification, install ownership, access orchestration (`DistributionAccess`), layered configuration |
| `@piship/pi` | The only direct Pi dependency; builds the governed Pi runtime and branded commands through public SDK exports |
| `@piship/cli` | Presents `piship` commands |

`identity`, `credentials`, and `inference` depend only on `contracts` and may not import each other; only `core` connects them, through `IdentitySession`, `CredentialRef`, and `ModelDefinition`. `scripts/check-boundaries.mjs` enforces these imports and the rule that only `packages/pi` imports Pi.

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

## State

State defaults to `~/.piship/<id>` or `PISHIP_STATE_HOME/<id>`. The state path depends on the distribution ID, so relocation or reinstallation can resume the same session. State is never copied into the payload.

| State path | Scope and sensitivity | Retention and clearing |
| --- | --- | --- |
| `agent/` | Pi config, model metadata, and, for Pi-native auth, Pi's local auth file; sensitive. Managed runtimes do not write `auth.json` or `models.json` | Kept by uninstall; selected distribution purge deletes it |
| `identity/session.json` | Non-secret identity metadata (subject, issuer, display claims, expiry) and a secret-store reference; no tokens | Cleared by `logout`; purge deletes it |
| `credentials-metadata/inference.json` | Non-secret runtime credential metadata (`piship-credential-metadata/v1`): generation reference, credential ID, expiry, entitled models; no secret | Cleared by `logout`; purge deletes it |
| `config/preferences.json` | User preferences (`piship-preferences/v1`) | Kept by uninstall and logout; purge deletes it |
| `secrets/` | Only with the explicit file fallback: owner-only plaintext secret files. Unused with a platform secret store | Cleared by `logout`; purge deletes it |
| `sessions/user/` | Interactive Pi sessions; may contain private project content | Kept by uninstall and logout; purge deletes it |
| `sessions/acceptance/` | Labeled smoke session | Kept by uninstall and logout; purge deletes it |
| `cache/` | Reserved per-distribution cache | Kept by uninstall; purge deletes it |
| `logs/` | Reserved per-distribution diagnostics; may be sensitive | Kept by uninstall; purge deletes it |
| `data/` | Reserved runtime-generated data | Kept by uninstall; purge deletes it |

Secrets held in a platform secret store live outside this directory, keyed by distribution ID; `logout` deletes them, while `purge` removes only files under the state directory. Run `logout` before `purge`. These paths have no automatic migration; reinstalling the same distribution ID reuses them. Pi's resource loader disables ambient extension, skill, prompt, theme, and context discovery and receives only declared packaged paths. The working directory remains the user's project; its `.pi` resources are not distribution resources.

See [manifest](manifest.md), [compatibility](compatibility.md), [security](security.md), [identity](identity.md), [credentials](credentials.md), and [inference](inference.md).
