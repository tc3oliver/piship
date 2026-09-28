# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. v0.1, the portable personal foundation, is complete; v0.2 managed access is in preview; governance/security and production lifecycle follow. The personal alpha example builds a portable payload and launches an upstream Pi session after user-writable installation. These milestones describe direction, without dates.

## Done: v0.1 — Distribution core

The personal distribution core includes a portable payload, install/uninstall, state isolation, inspection, diagnostics, a safe tool smoke, and session resume. It is supported on Ubuntu x64, macOS arm64, and Windows x64.

## In progress (preview): v0.2 — Managed access

Implemented: the `piship/v1alpha2` schema with runtime references and migration; separate identity, credential, secret-store, and inference contracts; OIDC Authorization Code + PKCE login; the `http-broker` credential protocol with platform secret stores and a crash-safe refresh lifecycle; an OpenAI-compatible gateway binding with an intersected model catalog; model governance on the pinned Pi runtime; layered configuration with `config explain`; managed network and TLS rules; and branded `login`, `logout`, `doctor`, and `models`. PiShip integrates with an identity provider or gateway; it does not become one.

Status: verified with deterministic local fixtures on the pinned Pi public API. Still pending before it can be supported: a live OIDC login, live gateway inference, a real authenticated personal model request, real platform secret-store results, and three-target installed E2E for the managed surface.

## Later: v0.3 — Governance

Add policy, project and resource trust, MCP governance, diagnostics, and audit integration. Governance claims must match actual enforcement.

## Later: v0.4 — Production lifecycle

Add verified release wrappers, update and rollback flows, SBOM, provenance, signing, and migration support around the existing payload. A future release pipeline may use Changesets, GitHub Releases, npm Trusted Publishing via OIDC, and npm provenance after ownership and release policy are settled.
