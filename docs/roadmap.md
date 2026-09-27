# Roadmap

PiShip is in early development. Today it has the package boundaries, alpha schema marker, pinned Pi compatibility check, and help/version CLI described in the [README](../README.md). These milestones describe direction, without dates.

## Next: v0.1 — Distribution core

Make a personal distribution run: `piship.yaml → exact Pi pin → isolated state → controlled resources → branded command`. This includes manifest validation, lockfile generation, a managed resource loader, a build path, inspection, and compatibility checks. The branded command must launch upstream Pi.

## Later: v0.2 — Managed access

Add identity and credential boundaries and managed inference configuration. PiShip should integrate with an identity provider or gateway, not become one.

## Later: v0.3 — Governance

Add policy, project and resource trust, MCP governance, diagnostics, and audit integration. Governance claims must match actual enforcement.

## Later: v0.4 — Production lifecycle

Add install, update and rollback flows, SBOM, provenance, signing, and migration support. A future release pipeline may use Changesets, GitHub Releases, npm Trusted Publishing via OIDC, and npm provenance after ownership and release policy are settled.
