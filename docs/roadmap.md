# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. v0.1, the portable personal foundation, is complete; v0.2 managed access and v0.3 governance are implemented as previews and not released; production lifecycle follows. The personal alpha example builds a portable payload and launches an upstream Pi session after user-writable installation. These milestones describe direction, without dates.

## Done: v0.1 — Distribution core

The personal distribution core includes a portable payload, install/uninstall, state isolation, inspection, diagnostics, a safe tool smoke, and session resume. It is supported on Ubuntu x64, macOS arm64, and Windows x64.

## In progress (preview): v0.2 — Managed access

Implemented: the `piship/v1alpha2` schema with runtime references and migration; separate identity, credential, secret-store, and inference contracts; OIDC Authorization Code + PKCE login; the `http-broker` credential protocol with platform secret stores and a crash-safe refresh lifecycle; an OpenAI-compatible gateway binding with an intersected model catalog; model governance on the pinned Pi runtime; layered configuration with `config explain`; managed network and TLS rules; and branded `login`, `logout`, `doctor`, and `models`. PiShip integrates with an identity provider or gateway; it does not become one.

Status: still a preview, verified only with deterministic local fixtures (a loopback OIDC provider, broker, and gateway) on the pinned Pi public API. No real OIDC provider, gateway, or platform secret store has been verified. Still pending before it can be supported: a live OIDC login, live gateway inference, a real authenticated personal model request, real platform secret-store results, and three-target installed E2E for the managed surface.

## Implemented (preview, not released): v0.3 — Governance

Implemented: the `piship/v1alpha3` schema and migration; a layered policy engine with enforcement planes and `policy explain`; resource, provider, and project trust with certified tree integrity; capability contracts with builtin permissions and a Plan/Build workflow; governed built-in tools and `!` commands; governed MCP over stdio and Streamable HTTP; an OS sandbox for tool subprocesses and MCP stdio servers (Linux bubblewrap, macOS Seatbelt; none on Windows); metadata-first audit with a documented failure matrix; and governance sections in `doctor`, `capabilities`, `config explain`, and `--smoke`. Governance claims match actual enforcement; the limits are listed in [security](security.md#limits).

Status: Linux is tested locally with real bubblewrap and end-to-end local fixtures. macOS and Windows results are pending CI; Windows has no sandbox adapter and fails closed when a sandbox is required. Not yet released.

## Later: v0.4 — Production lifecycle

Add verified release wrappers, update and rollback flows, SBOM, provenance, signing, and migration support around the existing payload. A future release pipeline may use Changesets, GitHub Releases, npm Trusted Publishing via OIDC, and npm provenance after ownership and release policy are settled.
