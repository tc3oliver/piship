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

### Changed

- The demo company example is a managed `piship/v1alpha3` distribution with a governed handbook MCP server, Plan/Build workflow, and a required sandbox.
