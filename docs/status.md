# Project status

This page is the single source of truth for what current `main` supports and what evidence backs each claim. Other documents describe how things work and link here for status. When this page and another document disagree, this page wins; please report the mismatch.

Nothing is published. There is no npm release, GitHub Release, or signed channel operated by the project; release archives exist only as CI workflow artifacts. Every milestone below is a preview milestone.

## Status terms

| Status | Meaning |
| --- | --- |
| **supported** | The surface is marked `supported` in [`compatibility/pi.json`](../compatibility/pi.json): installed E2E has passed on every advertised target (Ubuntu x64, macOS arm64, Windows x64 with Node 22.19.0) as defined in [compatibility](compatibility.md). |
| **candidate** | The surface is marked `candidate` in `compatibility/pi.json`: public-API, unit, and local-fixture checks pass, while live-service evidence or complete current-head target evidence is still missing. |
| **preview** | Implemented and tested, but not a surface of its own in `compatibility/pi.json`, or only proven with deterministic local fixtures. Expect changes. |
| **unavailable** | Nothing exists to run, or nothing was available to run it on. A backend with no adapter on a platform is unavailable there (native Windows: a required sandbox fails closed with `SANDBOX_UNAVAILABLE`), and a live qualification that had no service, account, or cluster to run against is unavailable. It is a statement about the evidence, never a pass. |

## Capability matrix

The evidence column names the [CI tier](#ci-evidence-tiers) that produces the evidence, the example it exercises, and the platforms it runs on. The runs behind the current evidence are listed under [v0.7 candidate](#v07-candidate).

| Area | Mode | Status | Evidence |
| --- | --- | --- | --- |
| Distribution core: portable payload, install, uninstall, isolated state, inspect, doctor, `--smoke`, session resume | Personal | **supported** (Pi surface `personal`) | Fast gate: build, unit, and Pi compatibility on Ubuntu, macOS, and Windows. Portable E2E: [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts) and [`cli`](../tests/e2e/cli.test.ts) on all three targets with [`examples/personal`](../examples/personal/README.md); [`personal-clean-machine-mypi`](../tests/e2e/personal-clean-machine-mypi.test.ts) also takes MyPi from install to uninstall, with a model request, session resume, update, and rollback. |
| Distribution core | Managed | **candidate** (Pi surface `managed`) | Fast gate as above. Portable E2E: [`managed`](../tests/e2e/managed.test.ts) with [`examples/demo-company`](../examples/demo-company/README.md) against local fixtures, on all three targets; it also checks that one launch writes the metadata-only local metrics (`logs/metrics.json`). |
| Managed access: OIDC + PKCE login, `http-broker` credentials, platform secret store, OpenAI-compatible gateway, model governance, layered configuration | Managed | **candidate** (Pi surface `managed`) | Fast gate: the live platform secret-store test on all three targets (macOS Keychain, Windows Credential Manager, Linux Secret Service under GNOME Keyring). Portable E2E: [`managed`](../tests/e2e/managed.test.ts), [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts) (one continuous flow: install, launch, login, credential acquire, model discovery, an authenticated model request, session resume, doctor, sandboxed commands, update, rollback, logout, uninstall and purge), user switching ([`file`](../tests/e2e/user-switching-file.test.ts) and [`system`](../tests/e2e/user-switching-system.test.ts) store), the secret-store lifecycle ([`file`](../tests/e2e/lifecycle-secret-store-file.test.ts) and [`system`](../tests/e2e/lifecycle-secret-store-system.test.ts) store), [`headless`](../tests/e2e/headless.test.ts), enterprise networking through the real launcher ([`network`](../tests/e2e/network.test.ts)), and the security suite ([`security-controls`](../tests/e2e/security-controls.test.ts), [`security-sweep`](../tests/e2e/security-sweep.test.ts), [`security-lifecycle`](../tests/e2e/security-lifecycle.test.ts), [`security-findings-session`](../tests/e2e/security-findings-session.test.ts), [`security-sandbox`](../tests/e2e/security-sandbox.test.ts), [`lifecycle-credentials`](../tests/e2e/lifecycle-credentials.test.ts)), all on all three targets against deterministic loopback fixtures (OIDC provider, broker, gateway). The secrets of `managed-clean-machine` and of the `system` variants are in the live platform store, while `managed`, `headless`, and the `file` variants use the file store. The clean-machine flow's model request is authenticated by the fixture gateway, which is not a model. Reference E2E, Ubuntu only: the [AcmeCode reference distribution](../examples/enterprise-reference/README.md) signs in on a real Keycloak, exchanges the identity at the reference broker, keeps the credential in the Linux Secret Service, and sends model requests through a real LiteLLM gateway to a deterministic mock upstream, as one flow from install to uninstall (including commands in the required sandbox, update, rollback, and logout) and across a user switch. No production identity provider or gateway, and no model provider behind the gateway. |
| Access modes `local-secret`, `none`, and a local OpenAI-compatible model | Personal | **preview** | Portable E2E on all three targets: [`personal-access-modes`](../tests/e2e/personal-access-modes.test.ts), [`personal-local-model`](../tests/e2e/personal-local-model.test.ts) with [`examples/personal/local-model`](../examples/personal/local-model/piship.yaml), and the personal clean-machine flows ([`personal-clean-machine-mypi`](../tests/e2e/personal-clean-machine-mypi.test.ts), [`personal-clean-machine-local`](../tests/e2e/personal-clean-machine-local.test.ts)), which take MyPi (key delegated to Pi) and MyPi Local (key in its own secret store) from install to uninstall, send a model request with that key to a stand-in model server on loopback, and update and roll back through a signed loopback channel. No request to a real model provider is claimed. |
| Governance: policy, resource/provider/project trust, capabilities and Plan/Build, governed MCP, OS sandbox, audit | Managed and personal | **candidate** (Pi surface `governance`) | Fast gate: the live sandbox probe and boundary tests run in the unit suite with a required sandbox on Ubuntu (bubblewrap) and macOS (Seatbelt); a missing sandbox fails the job instead of skipping the tests. Portable E2E: [`governance`](../tests/e2e/governance.test.ts) on all three targets; on Windows only with the sandbox optional, because Windows has no sandbox adapter and a required sandbox fails closed. [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts) also runs the commands the fixture gateway asks for through the required native sandbox on Linux and macOS and checks that each escape is refused; on Windows it runs none. Reference E2E: the same commands in the required sandbox on Ubuntu. Per backend in [sandbox backends](#sandbox-backends). |
| Sandbox backends: `custom` adapters, `e2b-compatible` (E2B, CubeSandbox), `kubernetes-agent-sandbox` ([sandbox backends](sandbox.md)) | Managed and personal | **preview** | Per backend in [sandbox backends](#sandbox-backends) below. |
| Lifecycle: `piship release`, `verify-release`, signed channels, `update`, `rollback`, migration check | Managed | **candidate** (Pi surface `lifecycle`) | Portable E2E: `lifecycle-install`, `lifecycle-integrity`, `lifecycle-update`, and `lifecycle-rollback` with the demo on all three targets (Windows with the sandbox optional). Release candidate: two builds per target, reproducibility, `verify-release` on a fresh runner, tamper rejection, attestation, and install with the shipped script; recorded on `21de31a`, on the [freeze SHA](#v06-freeze) `ab3e7f2` ([run](https://github.com/tc3oliver/piship/actions/runs/36553329711)), and on the [v0.7 candidate](#v07-candidate) `ee8b4a9` ([run](https://github.com/tc3oliver/piship/actions/runs/36764947340)). |
| Lifecycle | Personal | **candidate** (Pi surface `lifecycle`) | Portable E2E: [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts) covers signed update and rollback of the personal example. Release candidate: the same two builds, reproducibility, verification, attestation, and install as the demo, plus the installed release's offline `--smoke` and `doctor`; recorded on `21de31a`, on the [freeze SHA](#v06-freeze) `ab3e7f2` ([run](https://github.com/tc3oliver/piship/actions/runs/36553329711)), and on the [v0.7 candidate](#v07-candidate) `ee8b4a9` ([run](https://github.com/tc3oliver/piship/actions/runs/36764947340)). |

The endpoints a company must provide for managed access, and how PiShip calls them, are in the [enterprise integration contract](enterprise-integration.md).

Not claimed anywhere: sign-in at a production identity provider, inference through a production gateway, a model request that reaches a real model provider (the manual `Live provider` workflow routes the reference LiteLLM to one, and no run of it is recorded), a Windows OS sandbox, a live E2B, CubeSandbox, or Kubernetes sandbox, an `InferenceProvider` adapter for a gateway that is not OpenAI-compatible (out of scope for v0.7), the managed path of the named production consumer (open, see [distribution qualification](#distribution-qualification)), macOS notarization or code signing, Windows Authenticode signing, targets other than the three above, or an npm publication.

## Sandbox backends

Each sandbox backend has its own maturity; a distribution's containment is only as strong as the backend it selects. What each backend enforces and reports is in [sandbox backends](sandbox.md). The statuses use the terms above, which are defined by `compatibility/pi.json`: a native backend is `candidate` because the `governance` surface it belongs to is, and no row is promoted beyond what that record says.

Every run named below used Node 22.19.0 and the pinned Pi 0.87.1. The [v0.7 candidate](#v07-candidate) section lists the runs.

| Backend | Status | Environment and versions | Evidence and results |
| --- | --- | --- | --- |
| `native` on Linux (bubblewrap) | **candidate** (part of the Pi surface `governance`) | `ubuntu-latest`: Ubuntu 24.04 image, bubblewrap 0.9.0. The workflows set `kernel.apparmor_restrict_unprivileged_userns=0`, because Ubuntu restricts, by default, the unprivileged user namespaces bubblewrap needs. | Fast gate, with the sandbox required: the live probe and the boundary and escape tests ([`boundary.test.ts`](../packages/sandbox/src/boundary.test.ts): 18 of 19 tests run, the 19th is the macOS launchd test), the workspace and backend-contract tests, and the sandbox conformance kit against the native backend all passed. Portable E2E: [`governance`](../tests/e2e/governance.test.ts) and [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts) with a required sandbox (four commands run: one writes inside the workspace, and reading the user's SSH key, writing outside the workspace, and connecting to a loopback listener are each refused), and the installed E2E files on both Ubuntu shards. Reference E2E: AcmeCode's commands run in the required sandbox and each escape is refused ([`distribution-flow`](../examples/enterprise-reference/tests/distribution-flow.test.ts)). Bubblewrap cannot guard a protected git file that does not exist yet, so git control is reported `not-verified` in every regular repository; `doctor` names the files and the sandbox still runs ([protected git paths](sandbox.md#protected-git-paths)). |
| `native` on macOS (Seatbelt) | **candidate** (part of the Pi surface `governance`) | `macos-latest`: macOS 26 arm64 image, Seatbelt through `/usr/bin/sandbox-exec`. | Fast gate, with the sandbox required: all 19 boundary and escape tests passed, including the launchd test, which first confirms that an unsandboxed launchd job runs and then sees six attempts (`launchctl`, a copied `launchctl`, `open`, a copied `open`, `osascript`, and `osascript` from Node) refused with no escape marker created; the workspace and backend-contract tests and the conformance kit against the native backend passed as on Linux. Portable E2E: `governance` and `managed-clean-machine` with a required sandbox (the same four commands), and the installed E2E files on all three macOS shards. Not run on Reference E2E, which is Ubuntu only. |
| `native` on Windows | **unavailable** | `windows-latest`: the `windows-2025-vs2026` image. | There is no Windows sandbox adapter. A distribution that requires the sandbox fails closed with `SANDBOX_UNAVAILABLE` (Portable E2E `governance` asserts it on Windows). With the sandbox optional, the Windows E2E runs no command in a sandbox: `managed-clean-machine` says so in its output and skips the step, and `doctor` reports containment `not-required` and isolation `none`. The native sandbox tests skip on Windows. Governed children there run in a kill-on-close Job Object that ends descendants with their leader; it isolates nothing. |
| `custom` | **preview** | The [reference container sandbox](../examples/enterprise-reference/sandbox/README.md) and its single-file adapter on `ubuntu-latest`: Ubuntu 24.04 image, Docker 28.0.4. | Unit tests of the adapter lifecycle and capability checks with fake adapters, and the [sandbox conformance kit](adapter-sdk.md#sandbox-conformance-kit) against reference backends. Reference E2E, Ubuntu only: [`sandbox`](../examples/enterprise-reference/tests/sandbox.test.ts) passed 16 tests: the service and adapter pass every kit behavior against real containers with none skipped, and a governed session with a stored sandbox credential verifies the `shared` workspace in both directions. An adapter that declares a network probe has its network denial verified (unit tests with fakes); otherwise it is attested. The reference adapter declares no network probe in v0.7, so its network denial is attested, never verified. PiShip ships no company adapter. |
| `e2b-compatible` (E2B, CubeSandbox) | **preview** (live qualification **unavailable**) | Fixtures only; no E2B service and no CubeSandbox. See [external backends](#external-backends). | [`remote.test.ts`](../packages/sandbox/src/remote.test.ts) (52 tests, Fast gate on all three targets) runs the backend against a mock E2B control plane and envd that enforces the sandbox user (`user`, or `root` as CubeSandbox needs), checks that the API key appears only as `X-API-Key` on control requests, and checks every request for leaked credentials. The conformance kit against a fake E2B service fails two behaviors where the kit is stricter than PiShip ([kit self-tests](adapter-sdk.md#kit-self-tests)). The backend declares no network probe, so network denial is attested by the service, never verified. |
| `kubernetes-agent-sandbox` | **preview** (live qualification **unavailable**) | Fixtures only; no cluster. See [external backends](#external-backends). | It does not claim network denial, so a required `deny` sandbox fails closed. [`remote.test.ts`](../packages/sandbox/src/remote.test.ts) runs it against a mock API server and router (claim lifecycle, renewal across clock jumps, expired and removed claims). Portable E2E [`sandbox-credential`](../tests/e2e/sandbox-credential.test.ts) and [`security-sandbox`](../tests/e2e/security-sandbox.test.ts) on all three targets launch a governed session whose `bash` runs in that mock with a stored sandbox credential, through a change of user, a rejected credential, and an outage in which the command never runs on the host instead. The conformance kit is not run against it: there is no fake of its runtime API that runs commands. |

The backends are recorded here and not in `compatibility/pi.json`: their maturity does not change which Pi surface a release records.

### External backends

Live qualification of E2B, CubeSandbox, and Kubernetes Agent Sandbox needs a service the project does not operate, and never gates a release. It was checked, read-only, on the maintainer's machine that prepared the v0.7 evidence, on 2026-09-30 (UTC):

- `command -v kubectl kind minikube k3d orb docker` found `kubectl` (client v1.33.9), `orb`, and `docker`; `kind`, `minikube`, and `k3d` are not installed.
- `kubectl config get-contexts` lists no context, no current context is set, and `KUBECONFIG` is unset. There is no cluster to reach, so `kubectl get crd` was not run: there was nothing to run it against. No cluster was started and no context was changed; OrbStack's Kubernetes was neither started nor queried.
- No E2B account or API key and no CubeSandbox deployment was provided for this qualification.

| Backend | Live qualification | What it needs |
| --- | --- | --- |
| E2B-compatible (E2B) | **unavailable** | An E2B account and API key, or a self-hosted service that implements the E2B API |
| CubeSandbox | **unavailable** | A CubeSandbox deployment and its API URL (commands run as `user: root`) |
| Kubernetes Agent Sandbox | **unavailable** | A cluster with the Agent Sandbox custom resources (`SandboxClaim`, `SandboxWarmPool`) and its sandbox router |

All three stay `preview` on the fixture-level evidence in the table above, and none of it is live evidence. E2B and CubeSandbox network denial is backend-attested: neither backend declares a network probe, so the service's word stands and PiShip reports it as attested. Kubernetes Agent Sandbox claims no network denial at all.

## Distribution qualification

What each kind of distribution has been shown to do. The runs are listed under [v0.7 candidate](#v07-candidate).

| Distribution | Role | Evidence | Status |
| --- | --- | --- | --- |
| AcmeCode reference distribution ([`examples/enterprise-reference`](../examples/enterprise-reference/README.md)) | A neutral managed distribution that depends on no company's infrastructure | Reference E2E, Ubuntu: [`distribution-flow`](../examples/enterprise-reference/tests/distribution-flow.test.ts) (14 tests) takes one user from install to uninstall against a live Keycloak 26.7.4, the reference credential broker, and LiteLLM v1.103.0 (PostgreSQL 17.11 and a deterministic mock upstream behind it): install, sign-in, credential, models, a model request and session resume, doctor, commands in the required sandbox, update, rollback, logout, and uninstall and purge. [`user-switching`](../examples/enterprise-reference/tests/user-switching.test.ts) signs a second user in over the first without a logout: the second gets none of the first's credential, entitlement, or model selection. The demo distribution ([`examples/demo-company`](../examples/demo-company/README.md)) runs the same flow against local fixtures on all three targets. | Recorded for the v0.7 candidate |
| MyPi and MyPi Local ([`examples/personal`](../examples/personal/README.md)) | Personal regression: no enterprise identity, a local or direct model | Portable E2E on all three targets: [`personal-clean-machine-mypi`](../tests/e2e/personal-clean-machine-mypi.test.ts), [`personal-clean-machine-local`](../tests/e2e/personal-clean-machine-local.test.ts), [`personal-lifecycle`](../tests/e2e/personal-lifecycle.test.ts), [`personal-access-modes`](../tests/e2e/personal-access-modes.test.ts), and [`personal-local-model`](../tests/e2e/personal-local-model.test.ts). | Recorded for the v0.7 candidate |
| The named production consumer | The managed path of a real company distribution | Not available in this repository. It is collected downstream with the owner's approval and summarized here without identifiers. | **open** |

## Known limits and non-claims

Limits of v0.7 as shipped, each checked against the code or document it cites. None of them is claimed as handled.

- Shell output is stopped at 64 MiB, but Pi still writes the complete output to its own `pi-bash-*.log` file in the OS temp directory: PiShip does not remove it after the session, and a full temp filesystem while Pi writes it is not contained. Closing both needs a change in Pi upstream (#64, partly fixed; [security](security.md#tools-shell-and-plan-mode)).
- The Reference E2E tests bind fixed host ports, so two runs on one machine collide; CI gives each test group a runner of its own, so this affects local runs only (#79, deferred).
- `--smoke-model` classifies a failed request by the gateway's status, but a request that is aborted, interrupted, or ends without a status is still `GATEWAY_PROTOCOL_ERROR`, because a new error code would change the contract (#85).
- On Windows, a governed child that writes the launcher's startup-failure marker to stderr has that output dropped and its exit reported as a startup failure (a low-severity review finding on #104, left for after the release).
- On Windows, the Job Object helper is compiled from C# for every governed child, which adds startup time to each one (a low-severity review finding on #104, left for after the release).
- On Windows, the request that carries a child's file, arguments, working directory, and approved environment travels base64-encoded in one environment variable of the launcher, so it is bound by Windows' 32,767-character limit for a variable (a low-severity review finding on #104, left for after the release).
- The native sandbox probe connects to 1.1.1.1:443 and to a host loopback listener in `deny` mode as negative probes: each must fail, and the probe never requires an address to be reachable. The positive control is in the boundary tests, where a sandbox with the network allowed does reach the loopback listener ([network denial](sandbox.md#network-denial)).
- E2B and CubeSandbox network denial is backend-attested, never verified; Kubernetes Agent Sandbox claims none, and a required `deny` sandbox on it fails closed.
- The reference container sandbox declares no network probe in v0.7, so its network denial is attested.
- Bubblewrap cannot guard a protected git file that does not exist yet, so git control is `not-verified` under it in every regular repository ([sandbox](sandbox.md#protected-git-paths)); Seatbelt can guard a missing file.
- No run of the `Live provider` workflow is recorded: it is manual, uses a paid provider key held in the `live-provider` environment, and is never part of Release qualification (#77).
- PiShip refuses state, install, and bin homes that are equal or nested in one another, so an install home that contains the bin home is rejected with `CONFIG_INVALID`.
- A system clock set forward cannot be told from a suspend and counts as elapsed time: the sandbox workspace check and a Kubernetes claim come due or expire early ([sandbox](sandbox.md#the-workspace-check)).

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
| Full Portable E2E | `Portable E2E` (`npm run test:e2e` on three targets, each split into shards on runners of their own that together run every E2E file; Ubuntu also runs the repeated-build qualification), `Reference E2E` (`npm run test:reference` and the broker contract tests against the enterprise reference stack on Ubuntu, with the Linux Secret Service) | Nightly, `workflow_dispatch`, and inside `Release qualification`; not a pull request gate | The cross-platform installed integration surface, and the managed distribution against live identity, broker, and gateway services |
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

### v0.7 candidate

The last v0.7 code change is pull request #118, head `44d11e2`. Its squash commit on `main`, `3110556`, has the same tree as `44d11e2` (`e1b374e`). CI, CodeQL, and Portable E2E ran on `44d11e2` or on the merge ref built from it, before the squash, and cover that tree. Reference E2E ran on `3e935a5`; see its row. None of them ran on `3110556` itself. Pull request #119 then changed documentation only; its squash commit `ee8b4a9` is the v0.7 candidate, and its [Release qualification](https://github.com/tc3oliver/piship/actions/runs/36764947340) ran on that exact commit. The rows before it are the pull request evidence, kept for their own commits.

| Tier | Commit | Result |
| --- | --- | --- |
| Fast merge gate | `a185470`, the pull request's merge ref (`44d11e2` merged into `main` at `6fc3345`; tree `e1b374e`, the tree of `44d11e2`) | [CI](https://github.com/tc3oliver/piship/actions/runs/36761274903): `check` passed on Ubuntu, macOS, and Windows. Unit tests: Ubuntu 2803 passed and 8 skipped, macOS 2805 and 6, Windows 2596 and 198 (platform-gated tests skip). Pi compatibility: 31 tests on each. The live platform secret store passed on each. With the sandbox required on Ubuntu and macOS, the live probe and the boundary tests ran, per [sandbox backends](#sandbox-backends). [CodeQL](https://github.com/tc3oliver/piship/actions/runs/36761274788) passed on the same ref. |
| Portable E2E | `44d11e2`, the branch head | [Run](https://github.com/tc3oliver/piship/actions/runs/36761275728), dispatched on the branch head: passed on all nine shards (Ubuntu 2, macOS 3, Windows 4). Together the shards ran all 27 E2E files once on each target, and every file passed on every target: Ubuntu 71 tests passed and 1 skipped, macOS 71 and 1, Windows 70 and 2 (tests gated to another platform skip; the one skipped in `governance` on Ubuntu and macOS is the Windows-only refusal). `managed-clean-machine` ran its whole flow on each target in the live platform store; its sandboxed commands ran under bubblewrap on Ubuntu and under Seatbelt on macOS, and on Windows it ran none (`unavailable`). |
| Reference E2E | `3e935a5` | [Run](https://github.com/tc3oliver/piship/actions/runs/36759044911) on Ubuntu 24.04 with Docker 28.0.4, bubblewrap 0.9.0, and the Linux Secret Service: passed, the `stack` job and all four test groups (78 tests passed, 1 skipped: the `Live provider` test skips itself without its provider variables). The groups ran the AcmeCode flow, user switching, sign-in security cases against Keycloak, gateway evidence, usage continuity, budgets, rate limits, and the reference sandbox. `44d11e2` differs from `3e935a5` only in two test files that Reference E2E does not run (`packages/pi/src/launch/session-file.test.ts` and `tests/e2e/personal-lifecycle.test.ts`), so the run is cited for `44d11e2` on that ground and is otherwise evidence for `3e935a5`. |
| Live qualification of E2B, CubeSandbox, and Kubernetes Agent Sandbox | none | **unavailable**: no service, account, or cluster was available ([external backends](#external-backends)). |
| Live provider | none | Not recorded. |
| Named production consumer's managed path | none | **open**: collected downstream, see [distribution qualification](#distribution-qualification). |
| Release qualification | `ee8b4a9` (candidate) | [Run](https://github.com/tc3oliver/piship/actions/runs/36764947340), dispatched manually on the exact commit: `CI` (`check` on Ubuntu, macOS, and Windows), `CodeQL`, `Portable E2E` (all nine shards: Ubuntu 2, macOS 3, Windows 4), `Reference E2E` (the `stack` job and all four test groups), and `Release candidate` passed. The Release candidate built the demo company (`acmecode`) and the personal example (`mypi`) twice per target, and each distribution passed reproducibility, attestation, verification on a fresh runner with tamper rejection, and install on all three targets; the installed `mypi` also passed the offline `--smoke` and `doctor`. The Windows `acmecode` candidate is the patched variant, with the sandbox optional and its lock generated in CI ([artifact contract](release/artifact-contract.md)). It does not tag, sign a channel, or publish. |

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
| v0.7 (implemented and qualified at `ee8b4a9`) | Enterprise integration and qualification | `piship/v1alpha4` (unchanged) | `piship-lock/v1alpha4` (unchanged) |

All four manifest schemas are still accepted and all are experimental; only v1alpha4 can build a release. Both examples use `piship/v1alpha4`. The schema details live in [manifest](manifest.md); the history lives in the [changelog](../CHANGELOG.md); what comes next is in the [roadmap](roadmap.md).
