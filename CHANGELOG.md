# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Governance preview for `piship/v1alpha3` (v0.3, not released). Resources are declared by trust class (`company`, `certified`, `user`, and `builtin` extensions); certified entries carry review evidence and a tree digest checked at lock and launch, and install-time npm scripts are rejected.
- A layered policy engine (Enforced, then narrowing-only team and project rules, then Defaults or User rules) with `control-plane`, `sandbox`, and `audit-only` enforcement planes, and a branded `policy explain <action> <resource> [--json]`. Headless `ask` resolves to deny.
- Project trust by git origin or path, with per-dimension effects, symlink and instruction-import confinement to the project root, and narrowing-only `.piship/policy.json`. User rules in `<state>/config/policy.json` may relax distribution defaults only.
- Capability contracts with the builtin `permissions` and Plan/Build `workflow` providers, a six-axis `capabilities [--json]` report, and the builtin `piship-ask-user` extension.
- Governed `read`, `write`, `edit`, and `bash` tools and `!` commands built on Pi's public tool definitions.
- Governed MCP over stdio and Streamable HTTP: server starts and tool calls are authorized, denied tools are never offered, and `expectedServerName`, timeouts, retries, and required servers are supported.
- An OS sandbox for tool subprocesses and MCP stdio servers, proven by a live probe: bubblewrap on Linux and Seatbelt on macOS. Windows has no adapter; a required sandbox fails closed with `SANDBOX_UNAVAILABLE`. Network mode is `deny` or `allow` only.
- Metadata-first audit with file and HTTP sinks, opt-in content capture, a documented failure matrix (`AUDIT_UNAVAILABLE` for a required sink), and local metrics.
- Governance sections in `doctor`, `config explain`, and the `--smoke` summary; `piship-lock/v1alpha3`; and `piship migrate` to v1alpha3 with behavior-preserving defaults.
- New packages `@piship/policy`, `@piship/audit`, `@piship/sandbox`, and `@piship/mcp`.
- Production lifecycle preview for `piship/v1alpha4` (v0.4, not released): a required `updates` section (channel, allowed channels, source, rollback, pinned Ed25519 release keys) and an optional `release` section (targets, approved package sources, vulnerability threshold, and expiring exceptions), with `piship migrate` from v1alpha3.
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
