# Changelog

All notable changes to this project are documented in this file. Each section is a project milestone; the manifest and lock schema each milestone uses is listed in the [version map](docs/status.md#version-map). No milestone has been published to npm or as a GitHub Release, and every package is still versioned `0.1.0`.

## Unreleased (v0.6)

Preview milestone; not published to npm.

- Project consolidation in progress; see [docs/roadmap.md](docs/roadmap.md).

### Changed

- Documentation: a single [status page](docs/status.md) for what current `main` supports and the evidence behind it; stale CI tier, schema, and revocation claims corrected; the manifest guide lists its differences from the product specification.
- Documentation: the release guide is split into [owner workflow](docs/release/owner-workflow.md), [artifact contract](docs/release/artifact-contract.md), and [update lifecycle](docs/release/update-lifecycle.md) pages; `docs/release.md` is an index that maps every former section to its new location.
- This changelog is organized by milestone.

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

External qualification evidence for this milestone is not yet independently qualified; see the [status page](docs/status.md#recorded-evidence).

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
