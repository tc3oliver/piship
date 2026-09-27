# Roadmap

PiShip is in early development. The personal alpha example now validates, locks, builds, and launches an upstream Pi session from this checkout. These milestones describe direction, without dates.

## Now: v0.1 — Distribution core

The first runnable personal slice is present: manifest, exact Pi pin, content-hashed lock, isolated state/resources, branded command, and cross-platform launch smoke. Next work includes a portable installation/build artifact, richer diagnostics and inspection, and compatibility coverage beyond initialization. No managed access is included yet.

## Later: v0.2 — Managed access

Add identity and credential boundaries and managed inference configuration. PiShip should integrate with an identity provider or gateway, not become one.

## Later: v0.3 — Governance

Add policy, project and resource trust, MCP governance, diagnostics, and audit integration. Governance claims must match actual enforcement.

## Later: v0.4 — Production lifecycle

Add install, update and rollback flows, SBOM, provenance, signing, and migration support. A future release pipeline may use Changesets, GitHub Releases, npm Trusted Publishing via OIDC, and npm provenance after ownership and release policy are settled.
