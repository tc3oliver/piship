# Roadmap

PiShip is a company-first open-source distribution and governance framework around upstream Pi. This page describes direction, without dates. It does not restate history or evidence: what each milestone delivered is in the [changelog](../CHANGELOG.md), and what current `main` supports, with the evidence behind it, is on the [status page](status.md).

## Current baseline

v0.7.1 is the production-validation baseline: tag `v0.7.1` at commit `bd4bc09`, published as a [GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.7.1) with six attested archives, Pi 0.87.1, and the schemas `piship/v1alpha4` and `piship-lock/v1alpha4`. A production consumer pins it and installs its qualified artifact directly instead of tracking `main`. Its qualification, platforms, and open issues are in the [baseline section](status.md#v071-production-validation-baseline) of the status page; changes on `main` since then are under `Unreleased` in the [changelog](../CHANGELOG.md).

## Production validation

The first production consumer validates the managed path of a real company distribution on v0.7.1. That evidence is collected downstream, with the owner's approval, and summarized on the status page without identifiers ([distribution qualification](status.md#distribution-qualification)).

So far the project has manual real-provider evidence for the reference stack only ([Live provider runs](status.md#after-v071-on-main)). Validation against a real company identity provider and company gateway in production does not exist yet; it is what this stage is for. Fixes that production validation needs go to `main` and reach the consumer in a later qualified release, never by tracking `main`.

## Before broad rollout

These must be resolved before PiShip is rolled out broadly, beyond production validation:

- **Signed channel hardening ([#181](https://github.com/tc3oliver/piship/issues/181)).** Time-bounded key validity, revocation before activation, multiple signatures per channel, and signer hardening. A broad rollout that relies on a signed update channel needs these; see the [trust root gaps](release/trust-root.md#gaps-and-follow-ups).
- **The `brace-expansion` exception ([#129](https://github.com/tc3oliver/piship/issues/129)).** The reviewed vulnerability exception for the version Pi 0.87.1 pins expires on 2026-12-31, after which the release vulnerability gate fails again. It goes when upstream Pi ships a fixed version.
- **Pi upgrade review ([#176](https://github.com/tc3oliver/piship/issues/176)).** Any Pi upgrade first classifies the new `AssistantMessage.thinkingLevel` field, and any other new field, in the redaction map, and runs the governance review for newer Pi's built-in MCP, codemode, and tool search.
- **Upstream Pi gaps ([#64](https://github.com/tc3oliver/piship/issues/64), [#139](https://github.com/tc3oliver/piship/issues/139)).** A user's `!` command output still goes through Pi's own temp file, and Pi still adds its `/bug` hint to a PiShip identity or credential failure in the TUI. Each needs a public Pi API or a Pi change; PiShip does not patch Pi.

## Later

Candidates, not scheduled:

- A `piship/v1alpha5` schema: a `data` section for retention and purge policy, `app.configDir` and branding, a `policy.userRules` field, `resources.packages`, and a `tests` section.
- A unified lock format: a `sha256-` prefixed, canonical manifest digest, and capabilities that record the contract actually selected.
- A `registry/` directory and additional certification metadata.
- The remaining git control-file hardening listed in [security](security.md#limits).
- macOS and Windows code signing, and a Windows sandbox adapter.
- Runtime hooks for actions that have none yet: `network.connect`, `web.request`, `browser.execute`, `agent.invoke`, and `memory.*`.
- Remote execution: synchronizing the local workspace into a remote [sandbox backend](sandbox.md) (today the template or image provides it), running file tools remotely, mapping `sandbox.filesystem` path rules into a remote sandbox, and a short-lived or workload credential source for the built-in e2b-compatible and Kubernetes backends (such as an in-cluster service account token).
- Publish automation (for example GitHub Releases or npm Trusted Publishing with provenance), only after package ownership and release policy are settled and with the maintainer's explicit approval ([maintainer release checklist](maintainers/release-checklist.md)); more targets once each has installed lifecycle evidence.
