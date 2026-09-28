# Project status

This page is the single source of truth for what current `main` supports and what evidence backs each claim. Other documents describe how things work and link here for status. When this page and another document disagree, this page wins; please report the mismatch.

Nothing is published. There is no npm release, GitHub Release, or signed channel operated by the project; release archives exist only as CI workflow artifacts. Every milestone below is a preview milestone.

## Status terms

| Status | Meaning |
| --- | --- |
| **supported** | The surface is marked `supported` in [`compatibility/pi.json`](../compatibility/pi.json): installed E2E has passed on every advertised target (Ubuntu x64, macOS arm64, Windows x64 with Node 22.19.0) as defined in [compatibility](compatibility.md). |
| **candidate** | The surface is marked `candidate` in `compatibility/pi.json`: public-API, unit, and local-fixture checks pass, while live-service evidence or complete current-head target evidence is still missing. |
| **preview** | Implemented and tested, but not a surface of its own in `compatibility/pi.json`, or only proven with deterministic local fixtures. Expect changes. |

## Capability matrix

The evidence column names the [CI tier](#ci-evidence-tiers) that produces the evidence, the example it exercises, and the platforms it runs on.

| Area | Mode | Status | Evidence |
| --- | --- | --- | --- |
| Distribution core: portable payload, install, uninstall, isolated state, inspect, doctor, `--smoke`, session resume | Personal | **supported** (Pi surface `personal`) | Fast gate: build, unit, and Pi compatibility on Ubuntu, macOS, and Windows. Portable E2E: [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts) and [`cli`](../tests/e2e/cli.test.ts) on all three targets with [`examples/personal`](../examples/personal/README.md). See [current evidence](#recorded-evidence) for the gap on the current `main` commit. |
| Distribution core | Managed | **candidate** (Pi surface `managed`) | Fast gate as above. Portable E2E: [`managed`](../tests/e2e/managed.test.ts) with [`examples/demo-company`](../examples/demo-company/README.md) against local fixtures, on all three targets. |
| Managed access: OIDC + PKCE login, `http-broker` credentials, platform secret store, OpenAI-compatible gateway, model governance, layered configuration | Managed | **candidate** (Pi surface `managed`) | Deterministic loopback fixtures only (OIDC provider, broker, gateway). No live identity provider or gateway. The Secret store workflow runs the opt-in live Keychain and Credential Manager test on macOS and Windows when credential or contract code changes; Linux Secret Service has no live coverage. |
| Access modes `local-secret`, `none`, and a local OpenAI-compatible model | Personal | **preview** | Portable E2E: [`personal-local-model`](../tests/e2e/personal-local-model.test.ts) with [`examples/personal/local-model`](../examples/personal/local-model/piship.yaml) against a fixture server. No real authenticated model request is claimed. |
| Governance: policy, resource/provider/project trust, capabilities and Plan/Build, governed MCP, OS sandbox, audit | Managed and personal | **preview** (not yet a separate Pi surface) | Fast gate: the live sandbox probe and boundary tests run in the unit suite with a required sandbox on Ubuntu (bubblewrap) and macOS (Seatbelt). Portable E2E: [`governance`](../tests/e2e/governance.test.ts) on all three targets; on Windows only with the sandbox optional, because Windows has no sandbox adapter and a required sandbox fails closed. |
| Lifecycle: `piship release`, `verify-release`, signed channels, `update`, `rollback`, migration check | Managed | **candidate** (Pi surface `lifecycle`) | Portable E2E: `lifecycle-install`, `lifecycle-integrity`, `lifecycle-update`, and `lifecycle-rollback` with the demo on all three targets (Windows with the sandbox optional). Release candidate: two builds per target, reproducibility, `verify-release` on a fresh runner, tamper rejection, attestation, and install with the shipped script, for the demo only. |
| Lifecycle | Personal | **candidate** (Pi surface `lifecycle`) | Portable E2E: [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts) covers signed update and rollback of the personal example. The personal example has never gone through the Release candidate workflow. |

Not claimed anywhere: a live OIDC login, live gateway inference, a real authenticated model request, a Windows sandbox, macOS notarization or code signing, Windows Authenticode signing, targets other than the three above, or an npm publication.

## Pi compatibility

[`compatibility/pi.json`](../compatibility/pi.json) is the machine-readable record, and `@piship/core` carries a copy that the compatibility suite keeps equal. For the pinned Pi 0.87.1 it currently lists three surfaces:

| Surface | Status | What it covers |
| --- | --- | --- |
| `personal` | supported | The portable personal distribution core |
| `managed` | candidate | Managed access and configuration |
| `lifecycle` | candidate | Release, signed channels, update, and rollback |

Governance is not a separate surface yet. `release.json` records the weaker of the distribution's surface and the `lifecycle` surface, so every release built today records `candidate`. See [compatibility](compatibility.md) for the Pi public API PiShip uses and the upgrade policy.

## CI evidence tiers

[AGENTS.md](../AGENTS.md#ci-evidence-tiers) defines three tiers. A result is evidence only for the tier and commit it ran on.

| Tier | Workflows | When it runs | What it proves |
| --- | --- | --- | --- |
| Fast merge gate | `CI` (build and unit tests on Ubuntu, macOS, and Windows; format, lint, types, and boundaries on Ubuntu), `Pi compatibility` (three targets, path-scoped), `Secret store` (macOS and Windows, path-scoped), `CodeQL` | Every pull request and every `main` push | A change is safe to merge |
| Full Portable E2E | `Portable E2E` (`npm run test:e2e` on three targets; Ubuntu also runs the repeated-build qualification) | Nightly and `workflow_dispatch`; not a pull request gate | The cross-platform installed integration surface |
| Release candidate | `Release candidate` (demo company only) | `workflow_dispatch` only, on the exact candidate commit | A specific artifact is ready to ship |

## Recorded evidence

The latest recorded runs relevant to current `main` (`03c33cf`, v0.5):

| Tier | Commit | Result |
| --- | --- | --- |
| Fast merge gate | `03c33cf` on `main` | [CI](https://github.com/tc3oliver/piship/actions/runs/36426544851), [Pi compatibility](https://github.com/tc3oliver/piship/actions/runs/36426544785), [Secret store](https://github.com/tc3oliver/piship/actions/runs/36426544791), and [CodeQL](https://github.com/tc3oliver/piship/actions/runs/36426544770) passed |
| Portable E2E | `03c33cf` | No run recorded yet |
| Portable E2E | Last head of the v0.5 pull request | [Run](https://github.com/tc3oliver/piship/actions/runs/36422526632): Ubuntu and Windows passed, macOS failed |
| Portable E2E | Earlier v0.5 pull request head (personal examples relocked) | [Run](https://github.com/tc3oliver/piship/actions/runs/36416137244): passed on all three targets |
| Release candidate | `03c33cf` | No run recorded yet |
| Release candidate | Last head of the v0.5 pull request | [Run](https://github.com/tc3oliver/piship/actions/runs/36422526731): passed on all three targets |
| Governance sandbox on macOS | v0.3 pull request | [CI run](https://github.com/tc3oliver/piship/actions/runs/36389270268) with the Seatbelt live probe and launchd boundary test; [Portable E2E](https://github.com/tc3oliver/piship/actions/runs/36389270287) passed on all three targets |
| Personal surface first qualified | v0.1 pull request | [Pi compatibility run](https://github.com/tc3oliver/piship/actions/runs/36345041538) with build and installed E2E on all three targets, for the `piship/v1alpha1` personal example of that time |

Consequence: the `personal` surface stays `supported` in `compatibility/pi.json`, but the current `piship/v1alpha4` personal example has no green three-target Portable E2E on the exact `main` commit. A manual Portable E2E and Release candidate run on `main` is the next qualification step. Until then, treat current-head claims conservatively.

## Version map

Product milestones and schema versions are separate. A milestone is a unit of project work; a schema version changes only when the manifest or lock format changes.

| Milestone | Theme | Manifest schema | Lock schema |
| --- | --- | --- | --- |
| v0.1 | Portable personal distribution core | `piship/v1alpha1` | `piship-lock/v1alpha1` |
| v0.2 | Managed access and configuration | `piship/v1alpha2` | `piship-lock/v1alpha2` |
| v0.3 | Governance and security baseline | `piship/v1alpha3` | `piship-lock/v1alpha3` |
| v0.4 | Production release lifecycle | `piship/v1alpha4` | `piship-lock/v1alpha4` |
| v0.5 | Gap closure across governance, access, supply chain, and the personal profile | `piship/v1alpha4` (unchanged) | `piship-lock/v1alpha4` (unchanged) |
| v0.6 (in progress) | Project consolidation | `piship/v1alpha4` (unchanged) | `piship-lock/v1alpha4` (unchanged) |

All four manifest schemas are still accepted and all are experimental; only v1alpha4 can build a release. Both examples use `piship/v1alpha4`. The schema details live in [manifest](manifest.md); the history lives in the [changelog](../CHANGELOG.md); what comes next is in the [roadmap](roadmap.md).
