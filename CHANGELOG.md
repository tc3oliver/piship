# Changelog

All notable changes to this project are documented in this file. Each section is a project milestone; the manifest and lock schema each milestone uses is listed in the [version map](docs/status.md#version-map). No milestone has been published to npm or as a GitHub Release, and every package is still versioned `0.1.0`.

## Unreleased (v0.6)

Preview milestone; not published to npm.

### Changed

- Project consolidation in progress; see [docs/roadmap.md](docs/roadmap.md).
- Documentation: a single [status page](docs/status.md) for what current `main` supports and the evidence behind it; stale CI tier, schema, and revocation claims corrected; the manifest guide lists its differences from the product specification.
- Documentation: the release guide is split into [owner workflow](docs/release/owner-workflow.md), [artifact contract](docs/release/artifact-contract.md), and [update lifecycle](docs/release/update-lifecycle.md) pages; `docs/release.md` is an index that maps every former section to its new location.
- Documentation: an [enterprise integration contract](docs/enterprise-integration.md) lists the IdP, credential broker, and OpenAI-compatible gateway endpoints PiShip calls, with a LiteLLM example under `examples/enterprise-litellm/`.
- This changelog is organized by milestone.
- **Behavior change:** `doctor` shows the effective outbound state on one `outbound` line in place of the `public fallback` and `private-only` lines. When private-only is in effect, the line is a ✓ that lists the declared hosts. Personal mode without private-only shows a neutral informational line, and the old ✓ "allowed (personal owner policy)" is gone.
- **Contract change:** `@piship/contracts` no longer exports the error codes `APPROVAL_REQUIRED`, `PROVIDER_UNHEALTHY`, `PROVIDER_UNRESOLVED`, `RESOURCE_DENIED`, and `SANDBOX_REQUIRED` (removed from `PISHIP_ERROR_CODES` and `PiShipErrorCode`); no code path produced them. Headless `ask` resolves to deny, denied tools and resources are refused and audited as denials (refused commands and settings use `POLICY_DENIED`), provider problems are reported on the `resolved`, `enabled`, and `healthy` capability axes, and a required sandbox that cannot be enforced fails with `SANDBOX_UNAVAILABLE`. A unit test now requires every remaining code to have a producing path. The manifest guide records the difference from the product specification ([removed error codes](docs/manifest.md#removed-error-codes)).
- **Contract change:** `modelRequirementGaps`, `incompatibleCapabilities`, and `ModelIncompatibility` moved from `@piship/core` to `@piship/policy`, which also exports `ModelEvidence`; `@piship/core` no longer exports them and adds `configuredModel`. `@piship/policy` drops `CapabilityStateInput.modelToolSupport` and `TOOL_DEPENDENT_CAPABILITIES` (no caller passed them) and adds `CapabilityStateInput.model` and `policyDenied`.

### Security

- **Behavior change:** In managed mode, user policy rules in `<state>/config/policy.json` are narrowing only, like team and project rules. A user `allow` rule is ignored and reported in `doctor` and `policy explain` and recorded as a `policy.violation` audit event. User `ask` and `deny` rules join the strictest-effect comparison, so they can tighten a decision but never relax a distribution default or `policy.default`. Personal mode is unchanged: there, a matching user rule still takes the place of the distribution default.
- **Behavior change:** Project resource directories (`.pi/skills`, `.agents/skills`, `.pi/prompts`, `.pi/extensions`, `.pi/themes`, `.pi/agents`, `.piship/providers`) are now walked, following links that stay inside the project root, up to 50,000 entries and 32 levels deep. A directory is treated like a top-level link that leaves the root when any link inside it leaves the root, or when it is too large or too deep to check: executable items are denied, and other items are evaluated as unknown origin. `doctor` names the offending entry or limit. The walk runs at launch and does not detect links created afterward.
- **Security**: If the `tool_call` policy decision throws (for example, because the audit buffer is full), the tool call is blocked. The model sees a sanitized reason that names only the error code, and the block is recorded as `tool.denied`. Before this fix, Pi 0.87.1 already refused the call but passed the unredacted error message to the model. A compatibility test now pins Pi's refusal.
- **Behavior change:** `@piship/contracts` now holds the only redaction pattern set. `redact` now also removes GitHub, GitLab, Slack, AWS, and Google API tokens, standalone `Basic` credentials whose value looks like base64 (so text like "basic authentication" is kept), JWT shapes without the `eyJ` prefix, and PEM private keys. Before, only audit events removed these shapes. JWT matching starts only at the beginning of a token run, so adversarial output can no longer make redaction quadratic. As a result, MCP tool results sent to the model, stderr, error messages, `doctor`, and `config explain` are also redacted more thoroughly. `redactValue` redacts `token`, `cookie`, `passwd`, `client_secret`, and `bearer` keys too (new export `SECRET_KEY_PATTERN`). `scrubText` in `@piship/audit` is now the same function as `redact`.
- **Behavior change:** A `credential: runtime` Streamable HTTP MCP server receives the runtime credential only when its URL has the same origin (scheme, host, and port) as `inference.baseUrl`, the gateway the credential is issued for. A server on any other origin fails to start with `MCP_UNHEALTHY` before the credential is read. A required server therefore fails the launch.
- **Behavior change:** In managed mode, `network.publicFallback: deny` is now enforced. Managed mode requires `deny`, so every managed launch is private-only, whatever `network.privateOnly` says. The managed fetch and the Pi process's default dispatcher accept only the issuer, broker, and gateway hosts, `network.allowHosts`, and, for update commands, the `updates.source` host. Managed distributions with Streamable HTTP MCP servers or HTTP audit sinks on other hosts must list those hosts in `network.allowHosts`. `config explain` shows the effective `network.privateOnly`, and `doctor` warns about any HTTP MCP server or HTTP audit sink whose host is not declared. Undeclared hosts are never allowed implicitly.

### Fixed

- **Behavior change:** `update` validates the resolved `updates.source` (after `${NAME}` resolution) and `--from` with the same rules as the manifest: `https`, or `http` on `127.0.0.1`, `localhost`, or `[::1]`, with no credentials, query string, or fragment. Other schemes (`ftp:`, `file:`, public `http:`) are refused with `NETWORK_DENIED` instead of being read as a local directory. A local directory resolved from `updates.source` must be absolute; `--from` still accepts a relative directory. The manifest validation hint now lists the accepted forms.
- The inference gateway now parses `Retry-After` HTTP-dates as well as seconds, using one shared `parseRetryAfter` from `@piship/contracts` (also used by the credential broker). Error output (`formatError`) shows `Retry after: <n> s` when an error carries a positive wait.
- **Behavior change:** `piship keygen` refuses to write the private key inside a git work tree unless the path is git-ignored; `--force-in-worktree` overrides this explicitly. When git is missing or exits with an error, a `.git` entry in any parent directory counts as a work tree.
- **Behavior change:** `piship migrate` from `piship/v1alpha2` writes `passiveContext: deny` for every project origin. v1alpha2 never loaded project themes (its resource loader ran with `noThemes` against the distribution directory), so the old `allow` started loading `.pi/themes` after migration. Manifests already migrated keep what they declare.
- **Behavior change:** `piship purge <id> --yes` also deletes the platform secret-store entries (identity token bundles, runtime credentials, including orphaned and pending generations) that the distribution's identity and credential metadata reference. Deletion is best effort: failures are printed as warnings and the state directory is still removed.
- An OIDC request that times out now fails with a retryable `GATEWAY_UNREACHABLE` instead of `IDENTITY_INVALID`, and a gateway model-list probe that times out (while connecting or reading the body) fails with a retryable `GATEWAY_UNREACHABLE` instead of an uncoded error.
- **Behavior change:** identity claims returned by an identity adapter are filtered to the same allowlist as OIDC (`sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, `groups`; scalar or string-array values only) before they are written to `identity/session.json`.
- **Behavior change:** the cross-process credential and identity lock is no longer force-broken after 90 s while its holder is alive. The holder refreshes the lock as a heartbeat and before each blocking secret-store command; only a lock left unrefreshed for 75 s is broken (moved aside atomically and re-checked first), a holder releases only its own lock, and a waiter that runs out of time fails with a retryable `CREDENTIAL_ACQUIRE_FAILED`.
- `policy explain` no longer claims that non-allow decisions on the `audit-only` plane are "observed and recorded"; it states that no runtime hook evaluates the action, so it is not enforced.
- **Behavior change:** Launch-time payload verification throws `PiShipError` instead of a plain `Error`: a payload file that differs from the inventory fails with `INTEGRITY_FAILED`, and a lock that no longer matches the packaged manifest or npm lock fails with `LOCK_INVALID`, as at the release gate. Messages are unchanged apart from the code prefix; update and rollback metrics and audit record these codes instead of the generic `UPDATE_FAILED` or `ROLLBACK_FAILED` when the active payload fails verification.
- **Behavior change:** A capability whose provider the policy refuses is reported as `enabled: no` instead of `healthy: no` in `capabilities`, `doctor`, and the session's capability state.
- **Behavior change:** The `compatible` capability axis checks an enabled capability's model `requirements` against the selected model with the same comparison as the launch-time `MODEL_INCOMPATIBLE` check, so a running session's report and launch agree. Offline, `capabilities` and `doctor` use the model launch would select from the configuration and its manifest catalog metadata; they can differ from launch when `--model` or a credential entitlement changes the selected model.

## v0.5

Preview milestone; not published to npm. Commit `03c33cf` (#16), "close governance, access, supply-chain, and personal-profile gaps". Schema unchanged: `piship/v1alpha4` and `piship-lock/v1alpha4`.

### Added

- `MODEL_INCOMPATIBLE` when a model does not meet a capability's model requirements.
- Accurate `credential.acquire`, `credential.refresh`, `credential.revoke`, and logout audit events.
- `validate` runs the lock-time integrity checks without writing a lock; `dev --smoke` with diff and dev E2E coverage.
- The personal reference distribution on `piship/v1alpha4` with a user-managed MCP server and signed updates, with personal lifecycle and local-model E2E scenarios.
- Per-seam Pi compatibility tests for each public API PiShip depends on.
- The weaker of the distribution's surface and the `lifecycle` surface is recorded in `release.json`; local metrics are metadata-only.

### Changed

- Plan mode is an allowlist of `read` and `ask_user`.
- Streamable HTTP MCP URLs resolve runtime references.
- Actions without a runtime hook report `audit-only`.
- `init` writes `piship/v1alpha4`.
- `SecretValue` normalization, cross-process identity refresh, a Windows file-store ACL, and `azp` tests.
- CI evidence tiers: pull requests run the fast merge gate; the full Portable E2E runs nightly and on demand; Release candidate qualification runs manually before a release. Recorded in `AGENTS.md` and `CONTRIBUTING.md`.
- CI execution time (#15): the lifecycle E2E is split into independent parallel scenarios over shared immutable release fixtures, E2E files run in parallel, release-candidate consumer jobs reuse one trusted CLI artifact, and tamper tests use a single extraction. Portable E2E went from about 8m40s to about 4m17s and the release candidate from 4m18s to 3m07s, with no coverage removed.

### Security

- Git control files and hooks are protected from governed tools and inside the OS sandbox.
- Best-effort remote revocation and full local secret cleanup when update, rollback, or migration clears credentials.
- Whole-manifest secret scanning.
- Supply chain: registry integrity for nested Pi packages, a `source` gate for packages without integrity, and a registry signature gate (`npm audit signatures`).

No three-target Portable E2E or Release Candidate run is recorded on `03c33cf`; see [docs/status.md](docs/status.md#recorded-evidence).

## v0.4

Preview milestone; not published to npm. Commit `7077086` (#14), "add production release lifecycle". Introduces `piship/v1alpha4` and `piship-lock/v1alpha4`.

### Added

- A required `updates` section (channel, allowed channels, source, rollback, pinned Ed25519 release keys) and an optional `release` section (targets, approved package sources, vulnerability threshold, and expiring exceptions), with `piship migrate` from v1alpha3.
- `piship-lock/v1alpha4` with package sources and install-script flags, static digests of resources, policy, capabilities, MCP, sandbox, audit, and access, the update and release inputs, and the state schemas the release reads.
- `piship release`: failing gates for stale locks, unapproved sources, missing integrity, unreviewed install scripts, unsupported Pi, policy conflicts, missing certification, a required sandbox without an adapter, unevidenced targets, failed release tests, and blocking `npm audit` findings; output is one deterministic `.tar.gz` per target wrapping the unchanged payload with `release.json`, an SPDX 2.3 SBOM, third-party notices, the scan result, checksums, and `install.sh`/`install.ps1`.
- `piship verify-release`, `piship reproducibility` (per-target payload equality report), and `piship diff` (release-impact changes with risk and required tests).
- Signed update channels: `piship keygen` and `piship sign-channel` write `stable`, `candidate`, or `dev` metadata signed with Ed25519, with expiry and a monotonic sequence that clients use to refuse replays.
- Branded `update [--check] [--channel] [--from] [--accept-review]` and `rollback`, also reachable as `piship update|rollback <id>`: signature, digest, and release verification, a launch check, and a non-mutating migration check before one atomic activation; a retained known-good release; non-secret state snapshots; credentials cleared and reacquired, never snapshotted or restored. `piship migrate-check` runs the migration check alone.
- Supply Chain and Update sections in `doctor`, `runtime.update` and `runtime.rollback` audit events, lifecycle outcome counters in local metrics, and the `UPDATE_FAILED` and `ROLLBACK_FAILED` error codes.
- A release-candidate CI workflow that builds each evidenced target twice, verifies on a fresh job, and creates and verifies GitHub artifact attestations; artifacts stay as workflow artifacts and nothing is published.

### Changed

- The demo company example is a managed `piship/v1alpha4` distribution with a governed handbook MCP server, Plan/Build workflow, a required sandbox, and stable and candidate update channels read from `ACMECODE_UPDATE_SOURCE`; it pins no release key.
- Installation uses a versioned `piship-install/v1` receipt, a per-distribution `launch.mjs` that starts the active release, and one directory per retained release. `piship install` also accepts a release directory or archive. Installs made by earlier versions still run and uninstall, but need a reinstall for update and rollback.

## v0.3

Preview milestone; not published to npm. Commit `07adb72` (#13), "add governance and security baseline". Introduces `piship/v1alpha3` and `piship-lock/v1alpha3`.

### Added

- Resources declared by trust class (`company`, `certified`, `user`, and `builtin` extensions); certified entries carry review evidence and a tree digest checked at lock and launch, and install-time npm scripts are rejected.
- A layered policy engine (Enforced, then narrowing-only team and project rules, then Defaults or User rules) with `control-plane`, `sandbox`, and `audit-only` enforcement planes, and a branded `policy explain <action> <resource> [--json]`. Headless `ask` resolves to deny.
- Project trust by git origin or path, with per-dimension effects, symlink and instruction-import confinement to the project root, and narrowing-only `.piship/policy.json`. User rules in `<state>/config/policy.json` may relax distribution defaults only.
- Capability contracts with the builtin `permissions` and Plan/Build `workflow` providers, a six-axis `capabilities [--json]` report, and the builtin `piship-ask-user` extension.
- Governed `read`, `write`, `edit`, and `bash` tools and `!` commands built on Pi's public tool definitions.
- Governed MCP over stdio and Streamable HTTP: server starts and tool calls are authorized, denied tools are never offered, and `expectedServerName`, timeouts, retries, and required servers are supported.
- Metadata-first audit with file and HTTP sinks, opt-in content capture, a documented failure matrix (`AUDIT_UNAVAILABLE` for a required sink), and local metrics.
- Governance sections in `doctor`, `config explain`, and the `--smoke` summary; `piship-lock/v1alpha3`; and `piship migrate` to v1alpha3.
- New packages `@piship/policy`, `@piship/audit`, `@piship/sandbox`, and `@piship/mcp`.

### Changed

- The demo company example became a managed `piship/v1alpha3` distribution with a governed handbook MCP server, Plan/Build workflow, and a required sandbox.
- CI (#12): Windows jobs keep temp output and the npm cache on the runner's work drive and disable Defender real-time scanning; formatting, lint, typecheck, and boundary checks run once on Ubuntu; the live secret-store tests move to their own path-scoped workflow; superseded pull request runs are cancelled.

### Security

- An OS sandbox for tool subprocesses and MCP stdio servers, proven by a live probe: bubblewrap on Linux and Seatbelt on macOS. Windows has no adapter; a required sandbox fails closed with `SANDBOX_UNAVAILABLE`. Network mode is `deny` or `allow` only.

## v0.2

Preview milestone; not published to npm. Commit `c023aa4` (#11), "add managed access and configuration preview". Introduces `piship/v1alpha2` and `piship-lock/v1alpha2`. The managed surface is verified with local fixtures only; live identity and gateway checks remain for the maintainer.

### Added

- The `piship/v1alpha2` schema for managed and personal distributions, with allowlisted runtime references and a static lock `access` section; `piship migrate` upgrades v1alpha1 personal manifests.
- Separate identity, credential, secret-store, and inference packages (`@piship/contracts`, `@piship/identity`, `@piship/credentials`, `@piship/inference`): OIDC Authorization Code + PKCE login; credential providers `http-broker`, `local-secret`, `pi-native`, `none`, and `adapter`; platform secret stores with a crash-safe refresh lifecycle; and an OpenAI-compatible gateway binding with an intersected model catalog.
- Layered configuration with `config explain`, and branded `login`, `logout`, `doctor`, `models`, and `config` commands.
- The demo company example, which runs against deterministic local fixtures.

### Changed

- The `yaml` dependency moved to 2.9.1 (#10).

### Security

- The Pi runtime is governed so managed distributions expose only allowed models and never inherit ambient provider credentials.

## v0.1

Preview milestone; not published to npm. Commits `0251289` through `6b2be68` (#9), "deliver v0.1.0 portable personal distributions". Introduces `piship/v1alpha1` and `piship-lock/v1alpha1`.

### Added

- The repository foundation, package metadata, and repository links; Pi compatibility and release boundaries (#4); evidence-based pull request conventions (#5); and the project positioning (#6).
- The first runnable PiShip distribution (#7): a pinned Pi runtime with declared-only resources and personal mode.
- The portable personal distribution core (#9): a portable pinned Pi payload bound to its OS and CPU, install and uninstall ownership, isolated state, a deterministic lock and file inventory, a branded launcher, declarative personal themes, and a real Pi compatibility smoke. The personal example is supported on Ubuntu x64, macOS arm64, and Windows x64 with Node 22.19.0.

### Changed

- Major npm upgrades are kept in explicit review (#2).
