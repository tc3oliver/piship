# Contributing

PiShip is in early development. Documentation, tests for existing behavior, and the first distribution core are useful contributions. The [status page](docs/status.md) shows what current `main` supports, and the [roadmap](docs/roadmap.md) shows what is next.

## Set up

Use Node.js 22.19.0 or newer and npm. From the repository root:

```bash
npm ci
npm run check
```

`npm run check` covers formatting, lint, types, package boundaries, tests, and build. For CLI changes, run `npm run test:e2e`. For Pi integration changes, run `npm run test:compatibility`.

CI evidence is routed to three tiers ([AGENTS.md](AGENTS.md#ci-evidence-tiers)); moving a check between tiers changes when it runs, never what it covers.

- **Pull requests and `main` pushes: fast merge gate.** CI on Ubuntu, macOS, and Windows (formatting, lint, types, and boundaries once on Ubuntu; build, unit tests, and Pi compatibility on every target; the real macOS Keychain and Windows Credential Manager tests on those two targets) and CodeQL. Every pull request runs all of it, so the required checks always report. Superseded runs are cancelled. The critical path should stay around three to five minutes. After a merge, the same gate runs again on the `main` push; a `main` push starts neither the full Portable E2E nor release qualification.
- **Nightly and manual: full Portable E2E.** The three-target installed E2E (install, managed and personal lifecycles, governance, update, rollback, uninstall) runs every night, through `workflow_dispatch`, and inside Release qualification. It is no longer a pull request gate; a scheduled failure opens or updates a tracking issue, a follow-up rather than a block on ordinary pull requests.
- **Nightly and manual early warning: Pi latest canary.** Outside the three tiers, `Pi latest canary` installs the newest published Pi over the pin in the runner's throwaway checkout and runs the compatibility suite on all three targets. It is read-only (it never changes the pin, commits, or publishes); a scheduled failure opens or updates a tracking issue ahead of the next Pi upgrade.
- **Release: one-click qualification.** The `Release qualification` workflow runs only through `workflow_dispatch`, on the exact `main` HEAD being released. It runs `CI`, CodeQL, and the full Portable E2E in parallel, then, once all three pass, the `Release candidate` workflow for the managed demo and the personal example: two independent builds per target, reproducibility, provenance attestation and verification, tamper rejection, supply-chain gates, and installer verification on Linux, macOS, and Windows, plus the installed personal release's offline `--smoke` and `doctor`. It does not run for ordinary pull requests or `main` pushes. A release requires one green Release qualification run on the candidate HEAD; `Release candidate` can still be dispatched alone for a faster artifact check, but that is not release evidence on its own.

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

The CLI supports `init [--managed]`, `dev`, `validate`, `migrate [--write]`, `lock`, `build`, `test [--model-request]`, `config explain`, `inspect`, `doctor`, `install`, `uninstall`, and explicit `purge`, plus the release commands `release`, `verify-release`, `reproducibility`, `diff`, `keygen`, `sign-channel`, `update`, `rollback`, and `migrate-check`. `init` writes `piship/v1alpha4`. v1alpha2 branded commands add `login`, `logout`, `doctor`, `models`, `version`, `config explain|set|unset`, `--model`, `--smoke`, and `--smoke-model`; v1alpha3 adds `policy explain` and `capabilities`; v1alpha4 adds `update` and `rollback`. See the [personal](examples/personal/README.md) and [demo company](examples/demo-company/README.md) examples. Managed tests use the deterministic fixtures in `examples/demo-company/fixtures/`; they are not evidence of a live integration, so describe them that way in PRs.

## Pi compatibility

Keep Pi dependencies exact-pinned and confined to `packages/pi`. Use public exports only. Update the pin, [compatibility metadata](compatibility/pi.json), lockfile, and affected tests together. Every temporary workaround needs a regression test. Follow the [upgrade policy](docs/compatibility.md).

## Changesets and pull requests

Packages are at `0.1.0`, private, and not published. Record every user-visible change under `Unreleased` in [CHANGELOG.md](CHANGELOG.md), and mark a behavior change as such. Changesets are optional until a publish policy exists; if you add one, use patch for a bug fix, minor for a new user-facing capability, or major for a breaking public API or schema change, and never run `changeset version`. The `piship/v1alpha1` through `piship/v1alpha4` schemas are experimental; both examples use `piship/v1alpha4`. The [changesets README](.changeset/README.md) records this decision.

Use a descriptive PR title: `type(scope): concise summary`, or `type: concise summary` when a scope adds nothing. Common types are `feat`, `fix`, `perf`, `docs`, `test`, `refactor`, `ci`, and `chore`. Name the part changed, such as `schema`, `core`, `pi`, or `cli`; do not force a scope onto every PR. For example, `fix(pi): keep the compatibility check on public exports` or `docs: explain the alpha manifest status`.

In the PR body, explain the problem, the change, and how you verified it. Give actual commands and results; for a performance claim, include the baseline, candidate, and measurement setup. A small docs fix needs only a short explanation and its relevant check. Include Pi version and compatibility impact when changing Pi integration, a manifest/schema, or a public API. Update docs when behavior changes. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
