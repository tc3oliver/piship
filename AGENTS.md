# Repository instructions

PiShip is an open-source framework for personal or managed Pi-based coding-agent distributions. Pi owns the agent runtime; PiShip owns distribution concerns.

## Invariants

1. Keep Pi upstream. Do not vendor, fork, or patch Pi here.
2. Only `packages/pi` may import or depend directly on `@earendil-works/pi-*`; use public exports and exact production versions.
3. Never import Pi private or internal paths. Every compatibility workaround needs a regression test.
4. Keep the CLI thin. Put distribution logic in the appropriate package.
5. Never put secrets in `piship.yaml` or `piship.lock`.
6. Put generic runtime improvements upstream in Pi and agent-specific behavior in its distribution repository.
7. Add a package only for a real boundary. Do not silently weaken trust, security, or isolation semantics.

Before architecture changes, read `docs/architecture.md` and, if present locally, `docs/spec/product-v1.0.md`. The latter is a maintainer-local product specification excluded from Git; public contributors can use the architecture and manifest docs as the public contract.

Scope test: does the change help describe, build, govern, distribute, secure, diagnose, reproduce, or maintain a Pi-based coding-agent distribution?

Run `npm run check` before completion. For Pi-related changes, also run `npm run test:compatibility`.
