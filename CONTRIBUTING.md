# Contributing

PiShip is in early development. Documentation, tests for existing behavior, and the first distribution core are useful contributions. The [roadmap](docs/roadmap.md) shows what is next.

## Set up

Use Node.js 22.19.0 or newer and npm. From the repository root:

```bash
npm ci
npm run check
```

`npm run check` covers formatting, lint, types, package boundaries, tests, and build. For CLI changes, run `npm run test:e2e`. For Pi integration changes, run `npm run test:compatibility`.

CI evidence is routed to four tiers ([AGENTS.md](AGENTS.md#ci-evidence-tiers)); moving a check between tiers changes when it runs, never what it covers.

- **Pull requests: fast merge gate.** CI on Ubuntu, macOS, and Windows (formatting, lint, types, and boundaries once on Ubuntu; build and unit tests on every target), Pi compatibility on all three targets, CodeQL, and the real macOS Keychain and Windows Credential Manager tests when `packages/credentials` or `packages/contracts` change. Superseded runs are cancelled. The critical path should stay around three to five minutes.
- **`main`: normal integration.** The same cross-platform CI, compatibility, and path-scoped checks run after a merge. A `main` push does not start release qualification.
- **Nightly and manual: full Portable E2E.** The three-target installed E2E (install, managed and personal lifecycles, governance, update, rollback, uninstall) runs every night and through `workflow_dispatch`. It is no longer a pull request gate; a nightly failure becomes a follow-up rather than blocking ordinary pull requests.
- **Release candidate: explicit release qualification.** The `Release candidate` workflow runs only through `workflow_dispatch`, on the exact `main` HEAD being released: two independent builds per target, reproducibility, provenance attestation and verification, tamper rejection, supply-chain gates, and installer verification on Linux, macOS, and Windows. It does not run for ordinary pull requests or `main` pushes. A release still requires this workflow, Portable E2E, and CodeQL green on the candidate HEAD.

Windows jobs disable Defender real-time scanning on the ephemeral runner and keep temp output and the npm cache on the runner's work drive, which is much faster than C: for npm installs.

## Choose the right place

| Change | Start in |
| --- | --- |
| Manifest schema, runtime references, and migration | `packages/schema` |
| Shared contracts, policy decisions, audit events, errors, redaction, and network policy | `packages/contracts` |
| Policy engine, trust, project discovery, and capability state | `packages/policy` |
| Audit log, sinks, and local metrics | `packages/audit` |
| OS sandbox adapters and contained processes | `packages/sandbox` |
| Governed MCP client and transports | `packages/mcp` |
| OIDC and identity providers | `packages/identity` |
| Credential providers, secret stores, and lifecycle | `packages/credentials` |
| Inference binding and model catalog | `packages/inference` |
| Lock, payload, install, access orchestration, and configuration | `packages/core` |
| Public Pi API integration and branded commands | `packages/pi` |
| Command presentation | `packages/cli` |
| A particular agent's branding or private integration | Its distribution repository |

Generic runtime behavior should be considered upstream in Pi first. `identity`, `credentials`, and `inference` may import only `contracts`, never each other; `policy`, `audit`, `sandbox`, and `mcp` are governance leaves composed by `core` and `pi`; `npm run check:boundaries` enforces these rules. Read [AGENTS.md](AGENTS.md) and the [architecture guide](docs/architecture.md) before changing package boundaries or Pi integration. Small documentation and test changes do not require reading the full architecture first.

The CLI supports `init [--managed]`, `dev`, `validate`, `migrate [--write]`, `lock`, `build`, `test [--model-request]`, `config explain`, `inspect`, `doctor`, `install`, `uninstall`, and explicit `purge`. v1alpha2 branded commands add `login`, `logout`, `doctor`, `models`, `version`, `config explain|set|unset`, `--model`, `--smoke`, and `--smoke-model`; v1alpha3 adds `policy explain` and `capabilities`. See the [personal](examples/personal/README.md) and [demo company](examples/demo-company/README.md) examples. Managed tests use the deterministic fixtures in `examples/demo-company/fixtures/`; they are not evidence of a live integration, so describe them that way in PRs.

## Pi compatibility

Keep Pi dependencies exact-pinned and confined to `packages/pi`. Use public exports only. Update the pin, [compatibility metadata](compatibility/pi.json), lockfile, and affected tests together. Every temporary workaround needs a regression test. Follow the [upgrade policy](docs/compatibility.md).

## Changesets and pull requests

Packages are at `0.1.0` and are not published. Internal refactors need no changeset. Add a patch changeset for a bug fix, minor for a new user-facing capability, or major for a breaking public API or schema change. The `piship/v1alpha1`, `piship/v1alpha2`, and `piship/v1alpha3` schemas are experimental.

Use a descriptive PR title: `type(scope): concise summary`, or `type: concise summary` when a scope adds nothing. Common types are `feat`, `fix`, `perf`, `docs`, `test`, `refactor`, `ci`, and `chore`. Name the part changed, such as `schema`, `core`, `pi`, or `cli`; do not force a scope onto every PR. For example, `fix(pi): keep the compatibility check on public exports` or `docs: explain the alpha manifest status`.

In the PR body, explain the problem, the change, and how you verified it. Give actual commands and results; for a performance claim, include the baseline, candidate, and measurement setup. A small docs fix needs only a short explanation and its relevant check. Include Pi version and compatibility impact when changing Pi integration, a manifest/schema, or a public API. Update docs when behavior changes. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
