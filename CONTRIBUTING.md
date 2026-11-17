# Contributing

PiShip is pre-release (latest release v0.13.0). Documentation, tests for existing behavior, and the first distribution core are useful contributions. The [status page](docs/status.md) shows what current `main` supports, and the [roadmap](docs/roadmap.md) shows what is next.

## Set up

Use Node.js 22.19.0 or newer and npm 11 or later (`npm install -g npm@11`): the tests that lock Pi packages skip with an older npm, and CI runs them on npm 11. On Linux the sandbox tests need bubblewrap with unprivileged user namespaces; see the [prerequisites](docs/troubleshooting.md#prerequisites). From the repository root:

```bash
npm ci
npm run check
```

`npm run check` covers formatting, lint, types, package boundaries, build, the footprint budgets, and the unit tests; it takes about four minutes on a recent laptop, nearly all of it the unit tests. With an older Node.js, `npm ci` stops with `EBADENGINE` (`engine-strict` is on). For CLI changes, run `npm run test:e2e`; for Pi integration changes, `npm run test:compatibility`. Both run the built packages (`packages/*/dist`, which `npm run check` and `npm run build` write), so run `npm run build` again after every source change before either.

Run one test file with the config of its tier:

```bash
npx vitest run packages/schema/src/access.test.ts                                     # a unit test
npm run build && npx vitest run --config vitest.e2e.config.ts tests/e2e/cli.test.ts  # an E2E test
```

An E2E file run alone still builds the shared release fixtures first, about a minute. `npm test` is the unit tier only and leaves out `tests/e2e`, `tests/compatibility`, and the enterprise reference tests.

CI evidence is routed to three tiers ([AGENTS.md](AGENTS.md#ci-evidence-tiers)); moving a check between tiers changes when it runs, never what it covers.

- **Pull requests and `main` pushes: fast merge gate.** CI on Ubuntu, macOS, and Windows (formatting, lint, types, and boundaries once on Ubuntu; build, unit tests, and Pi compatibility on every target; the live platform secret-store test on every target: macOS Keychain, Windows Credential Manager, and the Linux Secret Service under GNOME Keyring) and CodeQL. Every pull request runs all of it, so the required checks always report. Superseded runs are cancelled. The critical path should stay around three to five minutes. After a merge, the same gate runs again on the `main` push; a `main` push starts neither the full Portable E2E nor release qualification.
- **Nightly and manual: full Portable E2E.** The three-target installed E2E (install, managed and personal lifecycles, governance, update, rollback, uninstall) runs every night, through `workflow_dispatch`, and inside Release qualification. It is no longer a pull request gate; a scheduled failure opens or updates a tracking issue, a follow-up rather than a block on ordinary pull requests. `Reference E2E` runs on the same schedule and triggers on Ubuntu: the AcmeCode reference distribution against the [enterprise reference stack](examples/enterprise-reference/README.md) (Keycloak, the credential broker, LiteLLM, and the reference container sandbox), with the Linux Secret Service; locally it is `npm run test:reference` and needs Docker.
- **Nightly and manual early warning: Pi latest canary.** Outside the three tiers, `Pi latest canary` installs the newest published Pi over the pin in the runner's throwaway checkout and runs the compatibility suite on all three targets. It is read-only (it never changes the pin, commits, or publishes); a scheduled failure opens or updates a tracking issue ahead of the next Pi upgrade.
- **Release: one-click qualification.** The `Release qualification` workflow runs only through `workflow_dispatch`, on the exact `main` HEAD being released. It runs `CI`, CodeQL, Portable E2E (excluding live Chrome startup), and Reference E2E in parallel, then, once all four pass, the `Release candidate` workflow for the managed demo, personal example, and developer example: two independent builds per target, reproducibility, provenance attestation and verification, tamper rejection, supply-chain gates, and installer verification on Linux, macOS, and Windows, plus the installed personal and developer releases' offline `--smoke` and `doctor`. It does not run for ordinary pull requests or `main` pushes. A release requires one green Release qualification run on the candidate HEAD; `Release candidate` can still be dispatched alone for a faster artifact check, but that is not release evidence on its own.

Live Chrome startup remains required in nightly and standalone manual Portable E2E. Release qualification excludes that one browser startup test and the Chrome preflight; it retains the developer profile’s package registration, permissions, lifecycle, and release checks. A green qualification run does not establish live browser availability.

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
| The supported surface for writing identity, credential, sandbox, and audit adapters | `packages/adapter-sdk` |
| Conformance kits that test an adapter through the SDK only | `packages/adapter-conformance` |
| A particular agent's branding or private integration | Its distribution repository |

Generic runtime behavior should be considered upstream in Pi first. `identity`, `credentials`, and `inference` may import only `contracts`, never each other; `policy`, `audit`, `sandbox`, and `mcp` are governance leaves: `core` composes `policy` and `audit`, and `pi` composes all four; `npm run check:boundaries` enforces these rules. Read [AGENTS.md](AGENTS.md) and the [architecture guide](docs/architecture.md) before changing package boundaries or Pi integration. Small documentation and test changes do not require reading the full architecture first.

Run `node packages/cli/dist/bin.js --help` after a build for the CLI commands, and see [manifest](docs/manifest.md) for which manifest version adds what. See the [personal](examples/personal/README.md), [developer](examples/developer/README.md), and [demo company](examples/demo-company/README.md) examples. Managed tests use the deterministic fixtures in `examples/demo-company/fixtures/`; they are not evidence of a live integration, so describe them that way in PRs.

## Pi compatibility

Keep Pi dependencies exact-pinned and confined to `packages/pi`. Use public exports only. Update the pin, the sibling pins (the root `package.json` `overrides`, from `PI_SIBLING_PINS` in `@piship/pi`), [compatibility metadata](compatibility/pi.json), lockfile, and affected tests together. Every temporary workaround needs a regression test. Follow the [compatibility contract](docs/compatibility.md#compatibility-contract) and the [support policy](docs/support-policy.md).

## Dependency updates

Each example's `piship.lock` records the versions of PiShip's runtime dependencies, so any dependency bump, a Dependabot pull request included, leaves them stale and `npm run check:budgets` and the example tests fail. After `npm ci && npm run build` on the branch, run `npm run relock:examples` and commit the changed locks. `undici` is also a security override in the root `package.json`, which must equal `packages/contracts`' version (`tests/compatibility/pi.test.ts`); Dependabot does not edit overrides, so it proposes undici in a pull request of its own, where the override is bumped by hand.

## Changesets and pull requests

Packages are at `0.13.0`, private, and not published. Record every user-visible change in the newest section of [CHANGELOG.md](CHANGELOG.md) (`Unreleased`), and mark a behavior change as such. Changesets are optional until a publish policy exists; if you add one, use patch for a bug fix, minor for a new user-facing capability, or major for a breaking public API or schema change, and never run `changeset version`. `piship/v1` and `piship-lock/v1` are stable: an additive, backward-compatible change keeps them, and a breaking change needs a new major schema ([support policy](docs/support-policy.md)). The `piship/v1alpha1` through `piship/v1alpha6` schemas are experimental and stay accepted for the migration window; every example uses `piship/v1`. Every user-visible restriction needs its row in the [UX contract](docs/ux-contract.md). The [changesets README](.changeset/README.md) records this decision.

Use a descriptive PR title: `type(scope): concise summary`, or `type: concise summary` when a scope adds nothing. Common types are `feat`, `fix`, `perf`, `docs`, `test`, `refactor`, `ci`, and `chore`. Name the part changed, such as `schema`, `core`, `pi`, or `cli`; do not force a scope onto every PR. For example, `fix(pi): keep the compatibility check on public exports` or `docs: explain the alpha manifest status`.

In the PR body, explain the problem, the change, and how you verified it. Give actual commands and results; for a performance claim, include the baseline, candidate, and measurement setup. A small docs fix needs only a short explanation and its relevant check. Include Pi version and compatibility impact when changing Pi integration, a manifest/schema, or a public API. Update docs when behavior changes. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
