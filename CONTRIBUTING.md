# Contributing

PiShip is in early development. Documentation, tests for existing behavior, and the first distribution core are useful contributions. The [roadmap](docs/roadmap.md) shows what is next.

## Set up

Use Node.js 22.19.0 or newer and npm. From the repository root:

```bash
npm ci
npm run check
```

`npm run check` covers formatting, lint, types, package boundaries, tests, and build. For CLI changes, run `npm run test:e2e`. For Pi integration changes, run `npm run test:compatibility`.

Every PR runs CI and, when package, installer, launcher, payload, resource, state, compatibility metadata, test, or relevant workflow inputs change, Pi compatibility on Ubuntu, macOS, and Windows. Formatting, lint, types, and boundaries run once on Ubuntu. Portable E2E, the installed-lifecycle test, runs on Ubuntu and macOS for PRs and also on Windows, its slowest target, for pushes to `main` and `workflow_dispatch` runs; for a PR that changes the installer, launcher, paths, or shell behavior, run it with `workflow_dispatch` on the PR branch before merging. Windows jobs disable Defender real-time scanning on the ephemeral runner to speed up npm installs. The real macOS Keychain and Windows Credential Manager tests run only when `packages/credentials` or `packages/contracts` change. Documentation-only PRs skip Pi compatibility and portable E2E. Superseded PR runs are cancelled. Pi compatibility does not repeat portable E2E. Release qualification requires both three-target workflows and CodeQL green on the candidate HEAD.

## Choose the right place

| Change | Start in |
| --- | --- |
| Manifest schema, runtime references, and migration | `packages/schema` |
| Shared contracts, errors, redaction, and network policy | `packages/contracts` |
| OIDC and identity providers | `packages/identity` |
| Credential providers, secret stores, and lifecycle | `packages/credentials` |
| Inference binding and model catalog | `packages/inference` |
| Lock, payload, install, access orchestration, and configuration | `packages/core` |
| Public Pi API integration and branded commands | `packages/pi` |
| Command presentation | `packages/cli` |
| A particular agent's branding or private integration | Its distribution repository |

Generic runtime behavior should be considered upstream in Pi first. `identity`, `credentials`, and `inference` may import only `contracts`, never each other; `npm run check:boundaries` enforces this. Read [AGENTS.md](AGENTS.md) and the [architecture guide](docs/architecture.md) before changing package boundaries or Pi integration. Small documentation and test changes do not require reading the full architecture first.

The CLI supports `init [--managed]`, `dev`, `validate`, `migrate [--write]`, `lock`, `build`, `test [--model-request]`, `config explain`, `inspect`, `doctor`, `install`, `uninstall`, and explicit `purge`. v1alpha2 branded commands add `login`, `logout`, `doctor`, `models`, `version`, `config explain|set|unset`, `--model`, `--smoke`, and `--smoke-model`. See the [personal](examples/personal/README.md) and [demo company](examples/demo-company/README.md) examples. Managed tests use the deterministic fixtures in `examples/demo-company/fixtures/`; they are not evidence of a live integration, so describe them that way in PRs.

## Pi compatibility

Keep Pi dependencies exact-pinned and confined to `packages/pi`. Use public exports only. Update the pin, [compatibility metadata](compatibility/pi.json), lockfile, and affected tests together. Every temporary workaround needs a regression test. Follow the [upgrade policy](docs/compatibility.md).

## Changesets and pull requests

Packages are at `0.1.0` and are not published. Internal refactors need no changeset. Add a patch changeset for a bug fix, minor for a new user-facing capability, or major for a breaking public API or schema change. The `piship/v1alpha1` and `piship/v1alpha2` schemas are experimental.

Use a descriptive PR title: `type(scope): concise summary`, or `type: concise summary` when a scope adds nothing. Common types are `feat`, `fix`, `perf`, `docs`, `test`, `refactor`, `ci`, and `chore`. Name the part changed, such as `schema`, `core`, `pi`, or `cli`; do not force a scope onto every PR. For example, `fix(pi): keep the compatibility check on public exports` or `docs: explain the alpha manifest status`.

In the PR body, explain the problem, the change, and how you verified it. Give actual commands and results; for a performance claim, include the baseline, candidate, and measurement setup. A small docs fix needs only a short explanation and its relevant check. Include Pi version and compatibility impact when changing Pi integration, a manifest/schema, or a public API. Update docs when behavior changes. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
