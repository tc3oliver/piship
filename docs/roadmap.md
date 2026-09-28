# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. The current v0.1 implementation is the portable personal foundation; managed access, governance/security, and production lifecycle follow in later milestones. The personal alpha example builds a portable payload and launches an upstream Pi session after user-writable installation. These milestones describe direction, without dates.

## Now: v0.1 — Distribution core

The personal distribution core includes a portable payload, install/uninstall, state isolation, inspection, diagnostics, a safe tool smoke, and session resume. Cross-platform installed-surface CI remains the release gate. No managed access is included yet.

## Later: v0.2 — Managed access

Add identity and credential boundaries and managed inference configuration. PiShip should integrate with an identity provider or gateway, not become one.

## Later: v0.3 — Governance

Add policy, project and resource trust, MCP governance, diagnostics, and audit integration. Governance claims must match actual enforcement.

## Later: v0.4 — Production lifecycle

Add verified release wrappers, update and rollback flows, SBOM, provenance, signing, and migration support around the existing payload. A future release pipeline may use Changesets, GitHub Releases, npm Trusted Publishing via OIDC, and npm provenance after ownership and release policy are settled.
