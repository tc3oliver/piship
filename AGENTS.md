# Repository instructions

PiShip is an open-source framework for personal or managed Pi-based coding-agent distributions. Pi owns the agent runtime; PiShip owns distribution concerns.

## Invariants

1. Keep Pi upstream. Do not vendor, fork, or patch Pi here.
2. Only `packages/pi` may import or depend directly on `@earendil-works/pi-*`; use public exports and exact pinned versions.
3. Never import Pi private or internal paths. Every compatibility workaround needs a regression test.
4. Keep the CLI thin. Put distribution logic in the appropriate package.
5. Never put secrets in `piship.yaml` or `piship.lock`.
6. Put generic runtime improvements upstream in Pi and agent-specific behavior in its distribution repository.
7. Add a package only for a real boundary. Do not silently weaken trust, security, or isolation semantics.

Before architecture changes, use the public repository contract: this file, `docs/architecture.md`, `docs/manifest.md`, `docs/compatibility.md`, and `docs/security.md`. A maintainer-local product specification may exist, but it is not required for public contributions.

Scope test: does the change help describe, build, govern, distribute, secure, diagnose, reproduce, or maintain a Pi-based coding-agent distribution?

Run `npm run check` before completion. For Pi-related changes, also run `npm run test:compatibility`.

For pull requests, follow the title and evidence guidance in `CONTRIBUTING.md`.

## CI evidence tiers

Keep pull request feedback fast. Do not put full release qualification on the normal pull request path.

- A pull request validates whether a change is safe to merge. Pull requests run the fast merge gate, one `CI` job per target plus CodeQL: cross-platform build and unit checks, Pi compatibility, the live platform secret store on Linux, macOS, and Windows, and security and static analysis. Every check runs on every pull request; do not path-scope a check, because a required check that never reports blocks the merge.
- Full Portable E2E validates the cross-platform integration surface, and Reference E2E the enterprise reference stack (Keycloak, the credential broker, LiteLLM) on Ubuntu. Both run nightly, manually, and inside Release qualification; neither is a normal pull request merge gate.
- Release qualification proves that a specific commit and its artifacts are ready to ship. The `Release qualification` workflow is dispatched manually on the exact candidate HEAD before a release: it runs `CI`, CodeQL, Portable E2E (excluding live Chrome startup), and Reference E2E in parallel, then the `Release candidate` build, attestation, and verification once all four pass. It is not triggered by every pull request or every `main` merge.
- Live Chrome startup remains required in nightly and standalone manual Portable E2E. Release qualification excludes that one browser startup test and the Chrome preflight; it retains the developer profile’s package registration, permissions, lifecycle, and release checks. A green qualification run does not establish live browser availability.
- Moving an expensive check out of the pull request path never permits deleting its coverage. Preserve the evidence at the appropriate tier.
- Do not add a normal pull-request-required job expected to take more than about five minutes without explicit maintainer approval.
- Do not respond to an ordinary pull request regression by expanding the pull request qualification surface. Use targeted tests locally and within the fast gate, and leave full qualification to its designated tier.
