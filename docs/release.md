# Releases, updates, and rollback

The production lifecycle for `piship/v1alpha4` distributions consists of a verifiable release archive per target, signed update channels, verified update with atomic activation, rollback to a retained known-good release, and an explicit migration check for local data. It wraps the [portable payload](portable-artifact.md) unchanged. Its current status and evidence are on the [status page](status.md); nothing is published to npm or through a signed channel.

The guide has three parts:

- [Owner workflow](release/owner-workflow.md): the owner's flow and commands, building a release and its gates, supported platforms, reviewing a change with `piship diff`, signing a channel, and the release checklist.
- [Artifact contract](release/artifact-contract.md): the archive layout, `verify-release`, reproducibility, the SBOM, notices, and vulnerability scan, build provenance, and the artifact limitations.
- [Update lifecycle](release/update-lifecycle.md): the channel trust model, `update` and `rollback`, the migration check and local data, the install layout and atomic activation, the failure policy, and the update limitations.

## Where each former section moved

This page used to hold the whole guide. Each former section, and its anchor on this page, now lives here:

| Former section | Former anchor | New location |
| --- | --- | --- |
| Introduction, owner flow, and commands | (top of page) | [Owner workflow](release/owner-workflow.md) |
| <a id="building-a-release"></a>Building a release | `#building-a-release` | [Owner workflow: Building a release](release/owner-workflow.md#building-a-release) |
| <a id="artifact-layout"></a>Artifact layout | `#artifact-layout` | [Artifact contract: Artifact layout](release/artifact-contract.md#artifact-layout) |
| <a id="verifying-a-release"></a>Verifying a release | `#verifying-a-release` | [Artifact contract: Verifying a release](release/artifact-contract.md#verifying-a-release) |
| <a id="reproducibility"></a>Reproducibility | `#reproducibility` | [Artifact contract: Reproducibility](release/artifact-contract.md#reproducibility) |
| <a id="reviewing-a-change"></a>Reviewing a change | `#reviewing-a-change` | [Owner workflow: Reviewing a change](release/owner-workflow.md#reviewing-a-change) |
| <a id="sbom-notices-and-vulnerabilities"></a>SBOM, notices, and vulnerabilities | `#sbom-notices-and-vulnerabilities` | [Artifact contract: SBOM, notices, and vulnerabilities](release/artifact-contract.md#sbom-notices-and-vulnerabilities) |
| <a id="build-provenance"></a>Build provenance | `#build-provenance` | [Artifact contract: Build provenance](release/artifact-contract.md#build-provenance) |
| <a id="channels-and-signed-metadata"></a>Channels and signed metadata | `#channels-and-signed-metadata` | [Update lifecycle: Channels and signed metadata](release/update-lifecycle.md#channels-and-signed-metadata); the `keygen`, `sign-channel`, and key rotation steps are in [Owner workflow: Signing a channel](release/owner-workflow.md#signing-a-channel) |
| <a id="updating-and-rolling-back"></a>Updating and rolling back | `#updating-and-rolling-back` | [Update lifecycle: Updating and rolling back](release/update-lifecycle.md#updating-and-rolling-back) |
| <a id="migration-check-and-local-data"></a>Migration check and local data | `#migration-check-and-local-data` | [Update lifecycle: Migration check and local data](release/update-lifecycle.md#migration-check-and-local-data) |
| <a id="install-layout-and-atomic-activation"></a>Install layout and atomic activation | `#install-layout-and-atomic-activation` | [Update lifecycle: Install layout and atomic activation](release/update-lifecycle.md#install-layout-and-atomic-activation) |
| <a id="failure-policy"></a>Failure policy | `#failure-policy` | [Update lifecycle: Failure policy](release/update-lifecycle.md#failure-policy) |
| <a id="supported-platforms"></a>Supported platforms | `#supported-platforms` | [Owner workflow: Supported platforms](release/owner-workflow.md#supported-platforms) |
| <a id="known-limitations"></a>Known limitations | `#known-limitations` | Split by topic: [Artifact contract: Known limitations](release/artifact-contract.md#known-limitations) and [Update lifecycle: Known limitations](release/update-lifecycle.md#known-limitations) |
| <a id="release-checklist"></a>Release checklist | `#release-checklist` | [Owner workflow: Release checklist](release/owner-workflow.md#release-checklist) |
