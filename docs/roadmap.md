# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. This page describes direction, without dates. It does not restate history or evidence: what each milestone delivered is in the [changelog](../CHANGELOG.md), and what current `main` supports, with the evidence behind it, is on the [status page](status.md).

## Current baseline

v0.8.1 is the production-validation baseline: tag `v0.8.1` at commit `d069104`, published as a [GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.8.1) with six attested archives, Pi 1.0.0, and the schemas `piship/v1alpha5` and `piship-lock/v1alpha5`. A production consumer pins it and installs its qualified artifact directly instead of tracking `main`. Its qualification, platforms, and open issues are in the [baseline section](status.md#v081-production-validation-baseline) of the status page. It replaced v0.8.0 (the same schemas and Pi), which stays documented as the [previous baseline](status.md#v080-previous-production-validation-baseline). It adds an administrator-allowed user auto mode, an administrator-allowed plain-HTTP update channel, and clean handling of a secret store that cannot be reached, with the fixes from their review (the [changelog](../CHANGELOG.md) lists them). Changes on `main` since v0.8.1 are under `Unreleased` in the changelog.

## v0.8.0 — pre-production trust & validation hardening (implemented)

v0.8.0 is the final planned architecture-hardening milestone before PiShip is tested against a real company identity provider, credential broker, LLM gateway, proxy and enterprise CA, endpoint controls, and update path. It is published as a [GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.8.0) from tag `v0.8.0` after [Release qualification](https://github.com/tc3oliver/piship/actions/runs/37108519783) passed on its exact commit, and it was the production-validation baseline until v0.8.1, replacing v0.7.1. It freezes the contracts that are expensive to change once real installations exist:

- **Update trust.** Manifest `piship/v1alpha5` and `piship-lock/v1alpha5`, with a bootstrap trust root that separates a root role from a channel role, each with a threshold. Older manifests stay inspectable and migratable.
- **Installation trust state.** The current update root is installation state, monotonic and written atomically, advanced by a root refresh before any channel is verified. A release lock or a rollback cannot lower it.
- **Signatures, rotation, and revocation.** Multi-signature channel metadata that keeps the v0.7 top-level signature, planned root-key rotation, and emergency channel-key revocation.
- **Signer hardening.** Encrypted Ed25519 PEM signing keys, behind an internal signer boundary that leaves room for a later KMS or HSM adapter.
- **Setup.** Explicit `piship init --personal` and `--managed`, with the personal and the managed path equally covered by the agent-assisted setup.
- **Production validation.** The [protocol](production-validation.md) and its de-identified evidence form.

This is the work that closed signed channel hardening ([#181](https://github.com/tc3oliver/piship/issues/181)); the gaps that remain are in the [trust root gaps](release/trust-root.md#gaps-and-follow-ups). The project still operates no update channel of its own. Not part of v0.8.0: a `data` lifecycle section, `resources.packages`, a public external-signer protocol, vendor KMS or HSM integrations, full TUF compatibility, a registry, a Windows sandbox, remote workspace synchronization, new enforcement hooks, code signing, and npm publication. No further manifest, lock, or update-trust redesign is planned before production evidence exists; that evidence decides what changes next.

## Production validation

The first production consumer validates the managed path of a real company distribution on a pinned baseline: v0.8.1, which replaced v0.8.0. The steps to run, and the only facts a report may carry, are in the [production validation protocol](production-validation.md). That evidence is collected downstream, with the owner's approval, and summarized on the status page without identifiers ([distribution qualification](status.md#distribution-qualification)).

So far the project has manual real-provider evidence for the reference stack only ([Live provider runs](status.md#after-v071-on-main)). Validation against a real company identity provider and company gateway in production does not exist yet; it is what this stage is for. Fixes that production validation needs go to `main` and reach the consumer in a later qualified release, never by tracking `main`.

## Before broad rollout

These must be resolved before PiShip is rolled out broadly, beyond production validation:

- **The `brace-expansion` exception ([#129](https://github.com/tc3oliver/piship/issues/129)).** The reviewed vulnerability exception for the version Pi pins (5.0.9 in both 0.87.1 and 1.0.0) expires on 2026-12-31, after which the release vulnerability gate fails again. It goes when upstream Pi ships a fixed version.
- **Upstream Pi gaps ([#64](https://github.com/tc3oliver/piship/issues/64), [#139](https://github.com/tc3oliver/piship/issues/139)).** A user's `!` command output still goes through Pi's own temp file, and Pi still adds its `/bug` hint to a PiShip identity or credential failure in the TUI. Pi 1.0 also keeps its "π" terminal title, its `pi --session-dir` exit hint, and the built-in `/share` command, which uploads the session file as a GitHub gist through the user's `gh` CLI ([security](security.md#limits)). Each needs a public Pi API or a Pi change; PiShip does not patch Pi.

## Later

Candidates, not scheduled:

- A schema revision after `piship/v1alpha5`, driven by production evidence: a `data` section for retention and purge policy, `app.configDir` and branding, a `policy.userRules` field, `resources.packages` (Pi packages come from npm, git, and local sources, so a local-only schema would be incomplete), and a `tests` section.
- Lock capabilities that record the contract actually selected, if the provider evidence the governance lock already carries proves not to be enough. The `sha256-` prefixed, canonical manifest digest is part of `piship-lock/v1alpha5` in v0.8.0.
- A `registry/` directory and additional certification metadata.
- The remaining git control-file hardening listed in [security](security.md#limits).
- macOS and Windows code signing, and a Windows sandbox adapter.
- Runtime hooks for actions that have none yet: `network.connect`, `web.request`, `browser.execute`, `agent.invoke`, and `memory.*`.
- Remote execution: synchronizing the local workspace into a remote [sandbox backend](sandbox.md) (today the template or image provides it), running file tools remotely, mapping `sandbox.filesystem` path rules into a remote sandbox, and a short-lived or workload credential source for the built-in e2b-compatible and Kubernetes backends (such as an in-cluster service account token).
- Publish automation (for example GitHub Releases or npm Trusted Publishing with provenance), only after package ownership and release policy are settled and with the maintainer's explicit approval ([maintainer release checklist](maintainers/release-checklist.md)); more targets once each has installed lifecycle evidence.
