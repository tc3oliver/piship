# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. This page describes direction, without dates. What current `main` supports, and the evidence for it, is on the [status page](status.md); this page does not repeat it.

## History

Seven preview milestones are implemented; none has been published to npm or as a GitHub Release, and v0.7 has no Release qualification recorded. v0.1 delivered the portable personal distribution core (`piship/v1alpha1`). v0.2 added managed access and layered configuration: OIDC sign-in, broker-issued runtime credentials, an explicit OpenAI-compatible gateway, and model governance (`piship/v1alpha2`). v0.3 added governance: a layered policy engine, resource, provider, and project trust, capabilities, governed MCP, an OS sandbox for tool subprocesses on Linux and macOS, and metadata-first audit (`piship/v1alpha3`). v0.4 added the production lifecycle: per-target release archives with an SBOM, notices, and a vulnerability gate, signed update channels, verified update, and rollback (`piship/v1alpha4`). v0.5 closed gaps across governance, access, supply chain, and the personal profile, and introduced the three CI evidence tiers, without a new schema. v0.6 consolidated the project, and v0.7 connected it to company infrastructure; both are described below. The [changelog](../CHANGELOG.md) has the details of each milestone.

## v0.6 — Project Consolidation (implemented)

v0.6 makes the documentation match `main`, fixes known contract problems, and splits oversized internal modules. It adds no major feature and keeps `piship/v1alpha4` and `piship-lock/v1alpha4`. Behavior changes are marked as such in the changelog, refactors change no behavior, and the pull request gate stays within the [CI evidence tiers](../AGENTS.md#ci-evidence-tiers). The milestone is implemented and frozen; the [status page](status.md#recorded-evidence) records the freeze commit and which qualification runs exist for it.

1. **Documentation status and drift.** A single [status page](status.md) with a capability matrix and its evidence; README, roadmap, compatibility, release, and architecture link to it instead of each stating status; stale CI and schema claims are corrected; the manifest guide lists its differences from the product specification.
   - An [enterprise integration contract](enterprise-integration.md) documents the IdP, broker, and gateway endpoints a company provides, with a LiteLLM starting point.
2. **Release guide and changelog.** The release guide is split into owner workflow, artifact contract, and update lifecycle pages; the changelog gets one section per milestone; the changesets decision is recorded.
3. **Contract fixes.** In managed mode, user policy rules may only narrow distribution defaults. Recursive symlink checks for project resources, fail-closed `tool_call` handling, one shared redaction implementation, and MCP runtime credentials bound to their origin. `network.publicFallback` is enforced and reported accurately, `updates.source` is validated consistently at runtime, `Retry-After` handling is shared, `keygen` refuses to write into a git worktree, and credential lifecycle fixes cover purge, timeouts, adapter claims, and lock expiry.
4. **Error and capability contracts.** Error codes without a runtime path are removed or justified, with a test that every code has a producer; one shared function decides model compatibility for both launch and the `capabilities` report.
5. **Observability and audit retention.** Every local metrics recorder is wired to its runtime call site, and `logs/audit.jsonl` is rotated by size with fixed defaults.
6. **Module split and boundaries.** Large files in `core`, `pi`, and `schema` are split into modules with no behavior change, Pi-independent branded commands move out of `packages/pi`, and the boundary check discovers packages automatically and reads the Pi version from one source.
7. **Compatibility and examples.** A `governance` surface is added to `compatibility/pi.json` and to the weaker-of-surfaces rule in `release.json`; a read-only latest-Pi canary; the examples and README quickstart are checked against the current CLI; the Release candidate workflow also qualifies the personal example.

## v0.7 — Enterprise Integration and Qualification (implemented; Release qualification not recorded)

v0.7 connects PiShip to the identity, credential, gateway, sandbox, and audit infrastructure a company already runs, and qualifies managed deployments on real components and on clean machines. It starts from the frozen v0.6 baseline and keeps `piship/v1alpha4` and `piship-lock/v1alpha4` unless the work shows that a manifest field is necessary; a schema change would ship once, as `piship/v1alpha5`. PiShip does not become an identity provider, gateway, credential broker, sandbox service, or audit platform, and Pi remains the agent runtime. Publication and a Windows sandbox adapter are not planned for v0.7. Direction, not dates:

1. **Contract hardening.** State bound to the signed-in principal so that switching users leaves nothing of the previous user; credential error and retry rules; audit delivery that never silently discards a required control; network and diagnostics coverage for proxies, custom certificate authorities, and private endpoints.
2. **Adapter platform.** A thin SDK and public conformance kits for identity, credential, sandbox, and audit adapters.
3. **Sandbox contracts.** A declared and verified workspace consistency contract for remote sandboxes, and a PiShip-managed credential source for them.
4. **Reference deployment.** A neutral, runnable reference stack of open-source components, exercised on Ubuntu by the Reference E2E, which runs nightly, on demand, and inside Release qualification.
5. **Qualification.** Live Linux secret store coverage, and clean-machine managed and personal flows on all three targets.

Everything on this list is implemented on `main`. What evidence backs each item, and that no Release qualification is recorded for a v0.7 commit, is on the [status page](status.md#recorded-evidence); nothing here is claimed beyond it.

## Next

Out of scope for v0.6 and, unless listed above, for v0.7; candidates for later:

- A `piship/v1alpha5` schema: a `data` section for retention and purge policy, `app.configDir` and branding, a `policy.userRules` field, `resources.packages`, and a `tests` section.
- A unified lock format: a `sha256-` prefixed, canonical manifest digest, and capabilities that record the contract actually selected.
- A `registry/` directory and additional certification metadata.
- The remaining git control-file hardening listed in [security](security.md#limits).
- Verification against live identity providers, gateways, and platform secret stores; macOS and Windows code signing; a Windows sandbox adapter.
- Runtime hooks for actions that have none yet: `network.connect`, `web.request`, `browser.execute`, `agent.invoke`, and `memory.*`.
- Publish automation (for example GitHub Releases or npm Trusted Publishing with provenance), only after package ownership and release policy are settled and with the maintainer's explicit approval ([release checklist](release/owner-workflow.md#release-checklist)); more targets once each has installed lifecycle evidence.

## Remote execution backends

v0.3 contained tool subprocesses with the host OS sandbox (bubblewrap on Linux, Seatbelt on macOS). Pluggable [sandbox backends](sandbox.md) now let a company run commands on its own infrastructure instead: a custom adapter, an E2B-compatible service such as E2B or CubeSandbox, or Kubernetes Agent Sandbox, as a preview without live evidence. Still considered, not scheduled: synchronizing the local workspace into a remote sandbox (today the template or image provides it), running file tools remotely, and mapping `sandbox.filesystem` path rules into a remote sandbox. v0.7 adds a declared and verified workspace consistency contract and a sandbox credential: `credential: stored` for an API key or bearer token a person stores with `sandbox login`, bound to the user and the endpoint origins, and a custom adapter's own in-memory `sandboxCredential` for short-lived and workload credentials ([sandbox credentials](sandbox.md#credentials)). Still considered, not scheduled: a short-lived or workload credential source for the built-in e2b-compatible and Kubernetes backends (such as an in-cluster service account token).