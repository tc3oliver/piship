# Contributing

PiShip is in early development. Documentation, tests for existing behavior, and the first distribution core are useful contributions. The [roadmap](docs/roadmap.md) shows what is next.

## Set up

Use Node.js 22.19.0 or newer and npm. From the repository root:

```bash
npm ci
npm run check
```

`npm run check` covers formatting, lint, types, package boundaries, tests, and build. For CLI changes, run `npm run test:e2e`. For Pi integration changes, run `npm run test:compatibility`.

## Choose the right place

| Change | Start in |
| --- | --- |
| Manifest marker and validation | `packages/schema` |
| Distribution types and orchestration | `packages/core` |
| Public Pi API integration | `packages/pi` |
| Command presentation | `packages/cli` |
| A particular agent's branding or private integration | Its distribution repository |

Generic runtime behavior should be considered upstream in Pi first. Read [AGENTS.md](AGENTS.md) and the [architecture guide](docs/architecture.md) before changing package boundaries or Pi integration. Small documentation and test changes do not require reading the full architecture first.

The only current CLI behavior is help and version output. Other commands return an unavailable error. The manifest examples are fixtures, not runnable distributions.

## Pi compatibility

Keep Pi dependencies exact-pinned and confined to `packages/pi`. Use public exports only. Update the pin, [compatibility metadata](compatibility/pi.json), lockfile, and affected tests together. Every temporary workaround needs a regression test. Follow the [upgrade policy](docs/compatibility.md).

## Changesets and pull requests

Packages are at `0.0.0` and are not published. Internal refactors need no changeset. Add a patch changeset for a bug fix, minor for a new user-facing capability, or major for a breaking public API or schema change. The `piship/v1alpha1` schema is experimental.

In a pull request, explain what changed, why, and how you checked it. Include Pi compatibility details only when the change touches Pi integration. Update docs when behavior changes. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
