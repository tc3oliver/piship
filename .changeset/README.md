# Changesets

All `@piship/*` packages are `private: true`, versioned `0.7.0`, and not published to npm. There is no publish policy yet, and publishing needs the maintainer's explicit approval ([release checklist](../docs/release/owner-workflow.md#release-checklist)).

## Decision while packages are unpublished

- [`CHANGELOG.md`](../CHANGELOG.md) is the authoritative record of changes, organized by project milestone. Every user-visible change adds an entry under its `Unreleased` section.
- The changesets in this directory (`first-distribution.md`, `managed-access.md`, and `governance.md`) are kept as they were written for v0.1, v0.2, and v0.3. No changesets were written for v0.4 or v0.5, and none are back-filled: their changes are recorded in `CHANGELOG.md`.
- A changeset is optional until a publish policy exists. When you add one, use the levels below.
- Do not run `npx changeset version` or `npx changeset publish`. Versioning would bump every package from the accumulated changesets and write per-package changelogs, which is a release decision.
- `config.json` uses `"access": "restricted"`, the changesets default. It has no effect on private packages; whether packages are published publicly is decided together with the publish policy.

## Levels

- Internal-only refactor: no changeset
- Bug fix: patch
- New user-facing capability: minor
- Breaking public API or schema change: major
