# PiShip

**Ship Pi as your company's coding agent — without forking Pi.**

Pi stays upstream. Your company owns the distribution. PiShip turns the pinned, unmodified Pi into a branded coding agent that signs in with your identity provider, talks only to your LLM gateway, runs under your policy and sandbox, and ships through your release process. Individuals use the same framework in personal mode to pin Pi, isolate its state, and reproduce their setup on another machine.

## Why PiShip?

- **No Pi fork.** Pi stays upstream and pinned; PiShip owns distribution and governance through Pi's public SDK only.
- **Bring your own identity.** Users sign in with your existing OIDC / SSO provider (Authorization Code + PKCE).
- **Bring your own gateway.** Inference goes only to your company LLM gateway, so provider keys never reach developer machines.
- **Short-lived credentials.** Your credential broker issues scoped runtime credentials; PiShip stores, renews, and revokes them.
- **Enforced governance.** Models, tools, MCP servers, resources, and project trust are decided by policy before anything runs.
- **Bring your own sandbox.** Native bubblewrap or Seatbelt, your internal sandbox, E2B-compatible services such as CubeSandbox, or Kubernetes Agent Sandbox, behind [one contract](docs/sandbox.md) that fails closed.
- **A tested sandbox boundary.** The native sandbox is proven by a live probe at every launch, and boundary and escape regression tests (denied reads, writes outside the allowlist, network, environment, git hooks, process-tree cleanup, macOS launchd escapes) run in CI.
- **Audit and diagnostics.** Metadata-first audit of policy decisions, plus `doctor`, `policy explain`, and `capabilities` for the effective runtime state.
- **Controlled releases.** Pinned Pi, reproducible per-target artifacts, SBOM and notices, signed update channels, and rollback.

An excerpt of the [demo company manifest](examples/demo-company/piship.yaml):

```yaml
app:
  id: acmecode
  name: AcmeCode
  command: acmecode
runtime:
  pi: "0.87.1"
deployment:
  mode: managed
identity:
  mode: oidc
credential:
  provider: http-broker
inference:
  provider: openai-compatible
  baseUrl: ${ACMECODE_LLM_GATEWAY_URL}
models:
  default: acme/coder
  allowed: [acme/coder, acme/general, acme/review]
```

Try it against the deterministic local fixtures (a loopback OIDC provider, credential broker, and gateway that auto-approve sign-in; test infrastructure, not a live integration). From the repository root with Node.js 22.19.0 or newer:

```bash
npm ci && npm run build
node examples/demo-company/fixtures/local-services.mjs   # keeps running; prints ACMECODE_* export lines
```

In a second terminal, paste the printed lines, then:

```bash
npm exec -- piship build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode login
~/.local/bin/acmecode
```

The demo requires an OS sandbox (bubblewrap on Linux, Seatbelt on macOS) and a system secret store (Secret Service on Linux, Keychain, or Credential Manager). Windows has no native sandbox adapter, so there the demo stops with `SANDBOX_UNAVAILABLE` unless a copy sets `sandbox.required: false` or uses a remote [sandbox backend](docs/sandbox.md); use `acmecode.cmd` on Windows. The [demo README](examples/demo-company/README.md) has the full walkthrough and the file secret-store fallback.

**Powered by Pi, governed by you.**

**Current state:** PiShip is pre-release. Nothing is published to npm or as a GitHub Release, and release archives carry no macOS or Windows code signature. The portable personal distribution core is supported on the pinned Pi; managed access, governance, and the release lifecycle are implemented as candidates or previews, verified with deterministic local fixtures rather than live company services. The [status page](docs/status.md) is the single source of truth for what current `main` supports, the evidence behind each claim, and how milestones v0.1 to v0.5 map to the `piship/v1alpha1` to `v1alpha4` schemas.

## Portable personal preview

The personal example (`piship/v1alpha4`, `identity.mode: none`, Pi-native auth, a user-managed MCP server, and signed update channels) builds a versioned, checkout-independent payload with pinned Pi 0.87.1, declared resources and a custom theme, isolated state, install/uninstall ownership, and a branded launcher. The targets are Ubuntu x64, macOS arm64, and Windows x64 with Node 22.19.0; see [status](docs/status.md) for the current installed E2E evidence. Node.js 22.19.0 or newer is a separately installed prerequisite. The payload is currently a development artifact, not a signed release or npm publication.

```bash
npm ci
npm run build
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship test examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi --version
~/.local/bin/mypi --smoke
node dist/mypi/piship.mjs inspect mypi
node dist/mypi/piship.mjs doctor mypi
node dist/mypi/piship.mjs uninstall mypi
```

On Windows use the installed `mypi.cmd` in the configured bin directory. Set `PISHIP_INSTALL_HOME` and `PISHIP_BIN_HOME` to change install paths and `PISHIP_STATE_HOME` to change the state root. `uninstall` preserves sessions and credentials. `node dist/mypi/piship.mjs purge mypi --yes` removes only that distribution's PiShip state after uninstall, including the platform secret-store entries its metadata references (best effort). `--smoke` tests Pi startup, a safe read tool, declared resources, and session resume without a model call. The plain branded command opens Pi's interactive TUI.

The installer and launcher never fetch Node, Pi, or packages. `piship build` runs `npm ci --omit=dev` from exact locked inputs and may access a package registry. Add the selected bin directory to your `PATH` yourself.

## Managed access preview

`piship/v1alpha2` adds `deployment.mode: managed`. A managed distribution signs users in with OIDC Authorization Code + PKCE, obtains a scoped runtime credential from an organization broker, and sends inference only to a declared OpenAI-compatible gateway. Only allowed models are visible or callable, ambient provider keys are removed from the runtime environment, and branded `login`, `logout`, `doctor`, `models`, and `config explain` commands are included. Endpoints are runtime references, so the lock never holds secrets or machine-specific values. The managed surface is a compatibility **candidate**: it has no live identity provider or live gateway evidence ([status](docs/status.md)). Try it with the [demo company example](examples/demo-company/README.md) and its local fixtures.

## Governance

`piship/v1alpha3` adds governance to both deployment modes. A distribution declares resources by trust class (company, certified with a reviewed tree digest, or user), a policy with enforced rules and relaxable defaults, project trust by git origin, MCP servers with tool allowlists, an OS sandbox, and audit sinks. PiShip decides each resource load, tool call, governed file access, shell command, and MCP call before it happens, runs `bash`, `!` commands, and MCP stdio servers inside bubblewrap (Linux) or Seatbelt (macOS) when the sandbox is required, or runs commands in a custom, E2B-compatible, or Kubernetes Agent Sandbox backend ([sandbox backends](docs/sandbox.md), a preview), and fails closed when a required sandbox or audit sink is unavailable. Windows has no native sandbox adapter. The Pi process and in-process extensions are not contained; see [security](docs/security.md#governance) for exactly what is enforced. Branded `policy explain`, `capabilities`, and governance sections in `doctor` show the effective state. `piship migrate` moves v1alpha1 and v1alpha2 manifests to v1alpha3 with behavior-preserving defaults, and on to v1alpha4.

## Release and update preview

`piship/v1alpha4` adds signed update channels and release policy. `piship release` wraps the unchanged payload in one deterministic archive per target (Linux x64, macOS arm64, Windows x64) with release metadata, an SPDX SBOM, third-party notices, a vulnerability scan result, and checksums, and stops on stale locks, unapproved package sources, unreviewed install scripts, or blocking advisories. `piship verify-release` checks an artifact as a consumer; `piship sign-channel` publishes it to a stable, candidate, or dev channel signed with a key whose public half is pinned in the manifest. Users run the branded `update` and `rollback`: updates are verified, staged, and activated atomically, a known-good release is retained, sessions and settings are kept, and credentials are never snapshotted or restored. CI build provenance uses GitHub artifact attestations. See [release](docs/release.md) for the commands, trust model, and limits.

## Scope

Pi owns the agent loop, tools, sessions, TUI, and model/runtime behavior. PiShip owns the distribution layer: manifest/configuration, pinned runtime, resources, reproducible payload, identity/credential/inference integration, policy/trust and governance, and lifecycle/release. Start with the [status page](docs/status.md), then read the [architecture](docs/architecture.md), [manifest](docs/manifest.md), [release](docs/release.md), [compatibility](docs/compatibility.md), [security](docs/security.md), [identity](docs/identity.md), [credentials](docs/credentials.md), [inference](docs/inference.md), [sandbox backends](docs/sandbox.md), [enterprise integration contract](docs/enterprise-integration.md), [roadmap](docs/roadmap.md), [architecture decisions](docs/decisions.md), and [portable payload decision](docs/portable-artifact.md) for the precise contract.

The [personal example](examples/personal/README.md) contains the full walkthrough. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). Security reports follow [SECURITY.md](SECURITY.md). PiShip is licensed under [MIT](LICENSE).
