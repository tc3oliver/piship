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
| Distribution core | Managed | **candidate** (Pi surface `managed`) | Fast gate as above. Portable E2E: [`managed`](../tests/e2e/managed.test.ts) with [`examples/demo-company`](../examples/demo-company/README.md) against local fixtures, on all three targets; it also checks that one launch writes the metadata-only local metrics (`logs/metrics.json`). |
| Managed access: OIDC + PKCE login, `http-broker` credentials, platform secret store, OpenAI-compatible gateway, model governance, layered configuration | Managed | **candidate** (Pi surface `managed`) | Fast gate: the live platform secret-store test on all three targets (macOS Keychain, Windows Credential Manager, Linux Secret Service under GNOME Keyring). Portable E2E: [`managed`](../tests/e2e/managed.test.ts), [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts), [`user-switching`](../tests/e2e/user-switching.test.ts), [`lifecycle-secret-store`](../tests/e2e/lifecycle-secret-store.test.ts), and [`headless`](../tests/e2e/headless.test.ts) on all three targets against deterministic loopback fixtures (OIDC provider, broker, gateway), with the managed scenarios' secrets in the live platform store (`headless` uses the file store). The clean-machine flow's model request is authenticated by the fixture gateway, which is not a model. Reference E2E, Ubuntu only: the [AcmeCode reference distribution](../examples/enterprise-reference/README.md) signs in on a real Keycloak, exchanges the identity at the reference broker, keeps the credential in the Linux Secret Service, and sends model requests through a real LiteLLM gateway to a deterministic mock upstream, as one clean-machine flow and across a user switch. No production identity provider or gateway, and no model provider behind the gateway. |
| Access modes `local-secret`, `none`, and a local OpenAI-compatible model | Personal | **preview** | Portable E2E on all three targets: [`personal-access-modes`](../tests/e2e/personal-access-modes.test.ts), [`personal-local-model`](../tests/e2e/personal-local-model.test.ts) with [`examples/personal/local-model`](../examples/personal/local-model/piship.yaml), and [`personal-clean-machine`](../tests/e2e/personal-clean-machine.test.ts), which takes MyPi (key delegated to Pi) and MyPi Local (key in its own secret store) from install to uninstall and sends a model request with that key to a stand-in model server on loopback. No request to a real model provider is claimed. |
| Governance: policy, resource/provider/project trust, capabilities and Plan/Build, governed MCP, OS sandbox, audit | Managed and personal | **candidate** (Pi surface `governance`) | Fast gate: the live sandbox probe and boundary tests run in the unit suite with a required sandbox on Ubuntu (bubblewrap) and macOS (Seatbelt). Portable E2E: [`governance`](../tests/e2e/governance.test.ts) on all three targets; on Windows only with the sandbox optional, because Windows has no sandbox adapter and a required sandbox fails closed. [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts) also runs the commands the fixture gateway asks for through the required native sandbox on Linux and macOS and checks that each escape is refused; on Windows it runs none. |
| Sandbox backends: `custom` adapters, `e2b-compatible` (E2B, CubeSandbox), `kubernetes-agent-sandbox` ([sandbox backends](sandbox.md)) | Managed and personal | **preview** | Per backend in [sandbox backends](#sandbox-backends) below. |
| Lifecycle: `piship release`, `verify-release`, signed channels, `update`, `rollback`, migration check | Managed | **candidate** (Pi surface `lifecycle`) | Portable E2E: `lifecycle-install`, `lifecycle-integrity`, `lifecycle-update`, and `lifecycle-rollback` with the demo on all three targets (Windows with the sandbox optional). Release candidate: two builds per target, reproducibility, `verify-release` on a fresh runner, tamper rejection, attestation, and install with the shipped script. |
| Lifecycle | Personal | **candidate** (Pi surface `lifecycle`) | Portable E2E: [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts) covers signed update and rollback of the personal example. Release candidate: the same two builds, reproducibility, verification, attestation, and install as the demo, plus the installed release's offline `--smoke` and `doctor`; recorded on `21de31a` and on the [freeze SHA](#recorded-evidence) `ab3e7f2` ([run](https://github.com/tc3oliver/piship/actions/runs/36553329711)). |

The endpoints a company must provide for managed access, and how PiShip calls them, are in the [enterprise integration contract](enterprise-integration.md).

Not claimed anywhere: sign-in at a production identity provider, inference through a production gateway, a model request that reaches a real model provider (the manual `Live provider` workflow routes the reference LiteLLM to one, and no run of it is recorded), a Windows OS sandbox, a live E2B, CubeSandbox, or Kubernetes sandbox, an `InferenceProvider` adapter for a gateway that is not OpenAI-compatible, macOS notarization or code signing, Windows Authenticode signing, targets other than the three above, or an npm publication.

## Sandbox backends

Each sandbox backend has its own maturity; a distribution's containment is only as strong as the backend it selects. What each backend enforces and reports is in [sandbox backends](sandbox.md).

| Backend | Status | Evidence |
| --- | --- | --- |
| `native` on Linux (bubblewrap) | **candidate** (part of the Pi surface `governance`) | Fast gate: the live probe and the boundary and escape tests with a required sandbox on Ubuntu. Portable E2E: `governance` and `managed-clean-machine` with a required sandbox. Reference E2E: AcmeCode's commands run in the required sandbox. |
| `native` on macOS (Seatbelt) | **candidate** (part of the Pi surface `governance`) | Fast gate: the live probe and the boundary and escape tests, including the launchd, `open`, and `osascript` escapes, with a required sandbox on macOS arm64. Portable E2E: `governance` and `managed-clean-machine` with a required sandbox. |
| `native` on Windows | **unavailable** | There is no Windows sandbox adapter. A distribution that requires the sandbox fails closed with `SANDBOX_UNAVAILABLE` (Portable E2E `governance`); with the sandbox optional, the Windows E2E runs no command in a sandbox. |
| `custom` | **preview** | Unit tests of the adapter lifecycle and capability checks with fake adapters, and the [sandbox conformance kit](adapter-sdk.md#sandbox-conformance-kit) against reference backends. Reference E2E, Ubuntu only: the [reference container sandbox](../examples/enterprise-reference/sandbox/README.md) and its single-file adapter pass every kit behavior against real containers, and a governed session verifies its `shared` workspace with a stored sandbox credential. PiShip ships no company adapter. |
| `e2b-compatible` (E2B, CubeSandbox) | **preview** | Unit tests against a mock E2B control plane and envd; the conformance kit against a fake E2B service fails two behaviors where the kit is stricter than PiShip ([kit self-tests](adapter-sdk.md#kit-self-tests)). No live E2B or CubeSandbox. |
| `kubernetes-agent-sandbox` | **preview** | Unit tests against a mock API server and router; Portable E2E [`sandbox-credential`](../tests/e2e/sandbox-credential.test.ts) runs `bash` in the mock with a stored sandbox credential. No live cluster. |

The backends are recorded here and not in `compatibility/pi.json`: their maturity does not change which Pi surface a release records.

## Pi compatibility

[`compatibility/pi.json`](../compatibility/pi.json) is the machine-readable record, and `@piship/core` carries a copy that the compatibility suite keeps equal. For the pinned Pi 0.87.1 it currently lists four surfaces:

| Surface | Status | What it covers |
| --- | --- | --- |
| `personal` | supported | The portable personal distribution core |
| `managed` | candidate | Managed access and configuration |
| `governance` | candidate | Policy and trust, capabilities, governed MCP, the OS sandbox, and audit (`piship/v1alpha3` and later) |
| `lifecycle` | candidate | Release, signed channels, update, and rollback |

`release.json` records the weakest of the distribution's deployment surface, the `governance` surface when the distribution declares governance (every `piship/v1alpha3` or later manifest does), and the `lifecycle` surface, so every release built today records `candidate`. See [compatibility](compatibility.md) for the Pi public API PiShip uses and the upgrade policy.

## CI evidence tiers

[AGENTS.md](../AGENTS.md#ci-evidence-tiers) defines three tiers. A result is evidence only for the tier and commit it ran on.

| Tier | Workflows | When it runs | What it proves |
| --- | --- | --- | --- |
| Fast merge gate | `CI` (build, unit tests, and Pi compatibility on Ubuntu, macOS, and Windows; the live platform secret store on Ubuntu (GNOME Keyring), macOS, and Windows; format, lint, types, and boundaries on Ubuntu), `CodeQL` | Every pull request and every `main` push | A change is safe to merge |
| Full Portable E2E | `Portable E2E` (`npm run test:e2e` on three targets; Ubuntu also runs the repeated-build qualification), `Reference E2E` (`npm run test:reference` and the broker contract tests against the enterprise reference stack on Ubuntu, with the Linux Secret Service) | Nightly, `workflow_dispatch`, and inside `Release qualification`; not a pull request gate | The cross-platform installed integration surface, and the managed distribution against live identity, broker, and gateway services |
| Release qualification | `Release qualification`: `CI`, `CodeQL`, `Portable E2E`, and `Reference E2E` in parallel, then `Release candidate` (demo company and personal example) | `workflow_dispatch` only, on the exact candidate commit | A specific commit and its artifacts are ready to ship |

Outside these tiers, `Pi latest canary` runs the compatibility suite nightly against the newest published Pi. It is early warning for the next Pi upgrade, not evidence for the pinned version. Scheduled failures of the canary, of Portable E2E, and of Reference E2E open or update a tracking issue.

## Recorded evidence

A result is evidence only for the commit and tier it ran on. A run that has not happened is listed as not recorded; it is never inferred from another commit.

### v0.6 freeze

`ab3e7f2` on `main` is the v0.6 freeze SHA: the last commit before any v0.7 pull request merges. v0.7 work branches from it.

| Tier | Commit | Result |
| --- | --- | --- |
| Fast merge gate | `ab3e7f2` (freeze) | [CI](https://github.com/tc3oliver/piship/actions/runs/36519003434) and [CodeQL](https://github.com/tc3oliver/piship/actions/runs/36519003468) passed |
| Portable E2E | `ab3e7f2` (freeze) | Passed on Ubuntu, macOS, and Windows inside the [Release qualification run](https://github.com/tc3oliver/piship/actions/runs/36553329711) below |
| Release qualification | `ab3e7f2` (freeze) | [Run](https://github.com/tc3oliver/piship/actions/runs/36553329711), dispatched manually on the exact commit: `CI`, `CodeQL`, `Portable E2E`, and `Release candidate` (demo company and personal example: two builds per target, reproducibility, verification, attestation, and install) passed on all three targets |
| Fast merge gate | `4830b07`, the commit before the freeze | [CI](https://github.com/tc3oliver/piship/actions/runs/36518291601): the Windows job failed in `packages/audit/src/log.test.ts`, an audit log rotation test whose assertion depended on how two concurrent writers interleave; the macOS and Ubuntu jobs and [CodeQL](https://github.com/tc3oliver/piship/actions/runs/36518291609) passed |
| Release qualification | `21de31a`, three commits before the freeze | [Run](https://github.com/tc3oliver/piship/actions/runs/36516126990): `CI`, `CodeQL`, `Portable E2E`, and `Release candidate` (demo company and personal example) passed on all three targets. It is not evidence for `ab3e7f2`: the commits after it change an E2E fixture and the E2E hook timeout (#36), ignore rules (#37), and `SECURITY.md` (#38) |

Consequence: the `personal` surface stays `supported` in `compatibility/pi.json`, and the Release qualification on `21de31a` covered the `piship/v1alpha4` personal example on all three targets. The freeze SHA `ab3e7f2` now has its own green Release qualification, so the v0.6 baseline is implemented, frozen, and qualified at its exact commit. Still, a v0.7 result is evidence only for the v0.7 commit it ran on and does not stand in for the v0.6 baseline.

### v0.7

No Portable E2E, Reference E2E, or Release qualification run is recorded on a v0.7 commit of `main` yet. The runs on pull request heads are linked from those pull requests and are evidence only for those heads.

### Earlier milestones

| Tier | Commit | Result |
| --- | --- | --- |
| Fast merge gate | v0.5 `03c33cf` on `main` | [CI](https://github.com/tc3oliver/piship/actions/runs/36426544851), [Pi compatibility](https://github.com/tc3oliver/piship/actions/runs/36426544785), [Secret store](https://github.com/tc3oliver/piship/actions/runs/36426544791), and [CodeQL](https://github.com/tc3oliver/piship/actions/runs/36426544770) passed |
| Portable E2E | v0.5 `03c33cf` | No run recorded |
| Portable E2E | Last head of the v0.5 pull request | [Run](https://github.com/tc3oliver/piship/actions/runs/36422526632): Ubuntu and Windows passed, macOS failed |
| Portable E2E | Earlier v0.5 pull request head (personal examples relocked) | [Run](https://github.com/tc3oliver/piship/actions/runs/36416137244): passed on all three targets |
| Release candidate | v0.5 `03c33cf` | No run recorded |
| Release candidate | Last head of the v0.5 pull request | [Run](https://github.com/tc3oliver/piship/actions/runs/36422526731): passed on all three targets |
| Governance sandbox on macOS | v0.3 pull request | [CI run](https://github.com/tc3oliver/piship/actions/runs/36389270268) with the Seatbelt live probe and launchd boundary test; [Portable E2E](https://github.com/tc3oliver/piship/actions/runs/36389270287) passed on all three targets |
| Personal surface first qualified | v0.1 pull request | [Pi compatibility run](https://github.com/tc3oliver/piship/actions/runs/36345041538) with build and installed E2E on all three targets, for the `piship/v1alpha1` personal example of that time |

## Version map

Product milestones and schema versions are separate. A milestone is a unit of project work; a schema version changes only when the manifest or lock format changes.

| Milestone | Theme | Manifest schema | Lock schema |
| --- | --- | --- | --- |
| v0.1 | Portable personal distribution core | `piship/v1alpha1` | `piship-lock/v1alpha1` |
| v0.2 | Managed access and configuration | `piship/v1alpha2` | `piship-lock/v1alpha2` |
| v0.3 | Governance and security baseline | `piship/v1alpha3` | `piship-lock/v1alpha3` |
| v0.4 | Production release lifecycle | `piship/v1alpha4` | `piship-lock/v1alpha4` |
| v0.5 | Gap closure across governance, access, supply chain, and the personal profile | `piship/v1alpha4` (unchanged) | `piship-lock/v1alpha4` (unchanged) |
| v0.6 (implemented, frozen and qualified at `ab3e7f2`) | Project consolidation | `piship/v1alpha4` (unchanged) | `piship-lock/v1alpha4` (unchanged) |
| v0.7 (in progress) | Enterprise integration and qualification | `piship/v1alpha4` (unchanged so far) | `piship-lock/v1alpha4` (unchanged so far) |

All four manifest schemas are still accepted and all are experimental; only v1alpha4 can build a release. Both examples use `piship/v1alpha4`. The schema details live in [manifest](manifest.md); the history lives in the [changelog](../CHANGELOG.md); what comes next is in the [roadmap](roadmap.md).
