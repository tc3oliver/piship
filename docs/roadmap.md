# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. This page describes direction, without dates. What current `main` supports, and the evidence for it, is on the [status page](status.md); this page does not repeat it.

## History

Five preview milestones are complete; none has been published to npm or as a GitHub Release. v0.1 delivered the portable personal distribution core (`piship/v1alpha1`). v0.2 added managed access and layered configuration: OIDC sign-in, broker-issued runtime credentials, an explicit OpenAI-compatible gateway, and model governance (`piship/v1alpha2`). v0.3 added governance: a layered policy engine, resource, provider, and project trust, capabilities, governed MCP, an OS sandbox for tool subprocesses on Linux and macOS, and metadata-first audit (`piship/v1alpha3`). v0.4 added the production lifecycle: per-target release archives with an SBOM, notices, and a vulnerability gate, signed update channels, verified update, and rollback (`piship/v1alpha4`). v0.5 closed gaps across governance, access, supply chain, and the personal profile, and introduced the three CI evidence tiers, without a new schema. The [changelog](../CHANGELOG.md) has the details of each milestone.

## v0.6 — Project Consolidation (in progress)

v0.6 makes the documentation match `main`, fixes known contract problems, and splits oversized internal modules. It adds no major feature and keeps `piship/v1alpha4` and `piship-lock/v1alpha4`. Behavior changes are marked as such in the changelog, refactors change no behavior, and the pull request gate stays within the [CI evidence tiers](../AGENTS.md#ci-evidence-tiers).

1. **Documentation status and drift.** A single [status page](status.md) with a capability matrix and its evidence; README, roadmap, compatibility, release, and architecture link to it instead of each stating status; stale CI and schema claims are corrected; the manifest guide lists its differences from the product specification.
2. **Release guide and changelog.** The release guide is split into owner workflow, artifact contract, and update lifecycle pages; the changelog gets one section per milestone; the changesets decision is recorded.
3. **Contract fixes.** In managed mode, user policy rules may only narrow distribution defaults. Recursive symlink checks for project resources, fail-closed `tool_call` handling, one shared redaction implementation, and MCP runtime credentials bound to their origin. `network.publicFallback` is enforced and reported accurately, `updates.source` is validated consistently at runtime, `Retry-After` handling is shared, `keygen` refuses to write into a git worktree, and credential lifecycle fixes cover purge, timeouts, adapter claims, and lock expiry.
4. **Error and capability contracts.** Error codes without a runtime path are removed or justified, with a test that every code has a producer; one shared function decides model compatibility for both launch and the `capabilities` report.
5. **Observability and audit retention.** Every local metrics recorder is wired to its runtime call site, and `logs/audit.jsonl` is rotated by size with fixed defaults.
6. **Module split and boundaries.** Large files in `core`, `pi`, and `schema` are split into modules with no behavior change, Pi-independent branded commands move out of `packages/pi`, and the boundary check discovers packages automatically and reads the Pi version from one source.
7. **Compatibility and examples.** A `governance` surface is added to `compatibility/pi.json` and to the weaker-of-surfaces rule in `release.json`; a read-only latest-Pi canary; the examples and README quickstart are checked against the current CLI; the Release candidate workflow also qualifies the personal example.

## Next

Out of scope for v0.6, and candidates for v0.7 or later:

- A `piship/v1alpha5` schema: a `data` section for retention and purge policy, `app.configDir` and branding, a `policy.userRules` field, `resources.packages`, and a `tests` section.
- A unified lock format: a `sha256-` prefixed, canonical manifest digest, and capabilities that record the contract actually selected.
- A `registry/` directory and additional certification metadata.
- The remaining git control-file hardening listed in [security](security.md#limits).
- Verification against live identity providers, gateways, and platform secret stores; macOS and Windows code signing; a Windows sandbox adapter.
- Runtime hooks for actions that have none yet: `network.connect`, `web.request`, `browser.execute`, `agent.invoke`, and `memory.*`.
- Publish automation (for example GitHub Releases or npm Trusted Publishing with provenance), only after package ownership and release policy are settled and with the maintainer's explicit approval ([release checklist](release/owner-workflow.md#release-checklist)); more targets once each has installed lifecycle evidence.

## Considered: remote execution backends

v0.3 contains tool subprocesses with the host OS sandbox (bubblewrap on Linux, Seatbelt on macOS) so that commands run on the developer's machine against the local workspace. A company that wants commands to run on its own infrastructure instead could later add an optional remote execution backend, for example a KVM microVM service such as CubeSandbox. That needs workspace synchronization and a server deployment, so it is not scheduled.
