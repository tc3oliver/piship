# PiShip

<p align="center">
  <strong>Turn upstream Pi into your company's coding agent — without forking Pi.</strong>
</p>

<p align="center">
  Bring your identity, LLM gateway, policy, sandbox, resources, and release process.<br>
  Pi stays upstream. You own the distribution.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-pre--release-orange" alt="Status: pre-release">
  <img src="https://img.shields.io/badge/Pi-0.87.1-blue" alt="Pi 0.87.1">
  <img src="https://img.shields.io/badge/Node-%3E%3D22.19.0-339933?logo=node.js&logoColor=white" alt="Node >=22.19.0">
  <img src="https://img.shields.io/github/license/tc3oliver/piship" alt="License">
</p>

<p align="center">
  <img src="docs/assets/piship-demo.gif" alt="Animation: upstream Pi is wrapped by PiShip, connected to company identity, credential broker, LLM gateway and sandbox, and becomes your company coding agent" width="720">
</p>

<p align="center">
  <a href="#why-piship">Why PiShip?</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#bring-your-own-sandbox">Sandbox</a> ·
  <a href="#project-status">Status</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## Pi, shipped your way

PiShip is an open-source **distribution and governance layer for Pi**.

It does not replace Pi and it does not fork Pi. Pi continues to own the agent loop, tools, sessions, TUI, and model runtime.

PiShip owns everything around it that turns an upstream coding agent into something an organization can actually distribute:

<p align="center">
  <img src="docs/assets/diagram-overview.svg" alt="Upstream Pi plus PiShip plus your distribution manifest becomes your coding agent: AcmeCode, CompanyCode, TeamPi, MyPi" width="800">
</p>

Your company keeps its existing infrastructure.

PiShip plugs it into Pi.

**Bring your own identity. Bring your own gateway. Bring your own sandbox.**

---

## Why PiShip?

| Problem | PiShip |
| --- | --- |
| You want to customize Pi without maintaining a fork | Pi stays upstream and pinned; PiShip owns the distribution layer |
| Developers should not carry upstream provider keys | Sign in through company OIDC and receive a scoped runtime credential for your gateway |
| Different users should not get arbitrary models and tools | Declare models, resources, MCP servers, capabilities, and policy in one distribution |
| Agent commands need containment | Use bubblewrap, Seatbelt, your own sandbox, E2B-compatible infrastructure, CubeSandbox, or Kubernetes Agent Sandbox |
| Company policy must survive project and user configuration | Managed policy is layered and downstream configuration can only narrow what the company allows |
| You need to know what is actually enforced | `doctor`, `policy explain`, `config explain`, and `capabilities` show effective runtime state |
| Shipping an internal agent should be reproducible | PiShip pins Pi and dependencies and builds versioned distribution artifacts |
| Updates need a trust boundary | Signed channels, verified update, rollback, SBOM, notices, checksums, and vulnerability gates |

PiShip is not an identity provider, LLM gateway, or sandbox service.

It is the layer that connects those systems to a Pi-based coding agent under one reproducible distribution contract.

---

## How it works

<p align="center">
  <img src="docs/assets/diagram-flow.svg" alt="Developer logs in through company OIDC; the PiShip distribution around upstream Pi sends a scoped runtime credential to the company LLM gateway and approved commands to the sandbox backend" width="840">
</p>

A typical managed flow is:

<p align="center">
  <img src="docs/assets/diagram-login-flow.svg" alt="OIDC login, company identity, credential broker, short-lived gateway credential, Pi runtime, company LLM gateway" width="1000">
</p>

The identity token goes to the credential broker. The gateway receives the scoped runtime credential. Upstream provider credentials do not need to be distributed to developer machines.

See the [enterprise integration contract](docs/enterprise-integration.md) for the exact wire protocols.

---

## What you control

A PiShip distribution can define the parts of Pi that should be consistent across an organization.

| Area | Examples |
| --- | --- |
| **Identity** | OIDC Authorization Code + PKCE |
| **LLM access** | OpenAI-compatible company gateway |
| **Credentials** | Broker-issued short-lived runtime credentials |
| **Models** | Default model, allowlist, capability metadata |
| **Resources** | Instructions, skills, extensions, prompts, themes |
| **Policy** | Tools, filesystem, shell, MCP, resources, providers |
| **Project trust** | Different behavior for company, external, and unknown repositories |
| **MCP** | Declared servers, tool allowlists, expected server identity |
| **Sandbox** | Native, custom, E2B-compatible, CubeSandbox, Kubernetes Agent Sandbox |
| **Audit** | Metadata-first policy and runtime events |
| **Release** | Reproducible artifacts, SBOM, notices, vulnerability gates |
| **Updates** | Signed channels, verification, atomic activation, rollback |

The distribution is declarative.

An excerpt of the demo company manifest:

```yaml
schema: piship/v1alpha4

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
  allowed:
    - acme/coder
    - acme/general
    - acme/review

sandbox:
  required: true
  network:
    mode: deny
```

The manifest contains configuration, not company secrets. Runtime endpoints are resolved at launch and credentials are stored separately.

See the complete [demo company manifest](examples/demo-company/piship.yaml).

---

## Quickstart

PiShip is currently built from source.

Requirements:

**Node.js 22.19.0 or newer.**

Clone the repository and build it:

```bash
npm ci
npm run build
```

### Try a company distribution

The repository includes **AcmeCode**, a deterministic local demo of a managed company distribution.

It provides local fixtures for:

```text
OIDC provider
credential broker
LLM gateway
```

Start them:

```bash
node examples/demo-company/fixtures/local-services.mjs
```

The fixture prints the required `ACMECODE_*` environment variables.

In another terminal, export those values and build the distribution:

```bash
npm exec -- piship build examples/demo-company/piship.yaml

node dist/acmecode/piship.mjs install dist/acmecode

~/.local/bin/acmecode login
~/.local/bin/acmecode
```

You now have a branded Pi distribution with managed identity, model access, governance, sandbox policy, resources, MCP, diagnostics, and release configuration.

Useful commands:

```bash
acmecode doctor
acmecode models
acmecode capabilities

acmecode config explain

acmecode policy explain shell.execute "git status"
acmecode policy explain filesystem.read ~/.ssh/id_ed25519
```

The local services are deterministic test fixtures, not evidence of a live company integration.

See the full [company demo walkthrough](examples/demo-company/README.md).

---

## Governance that fails closed

PiShip does not treat configuration as documentation.

The runtime checks it.

A managed distribution can control resource loading, tools, filesystem access, shell commands, MCP servers and tools, project trust, model selection, and supported capabilities before the corresponding action occurs.

When a required enforcement mechanism cannot be activated, PiShip does not silently downgrade to unrestricted execution.

For example:

<p align="center">
  <img src="docs/assets/diagram-fail-closed.svg" alt="sandbox.required: true plus sandbox unavailable results in SANDBOX_UNAVAILABLE, not running the command without a sandbox" width="760">
</p>

Effective state is inspectable:

```bash
acmecode doctor
acmecode capabilities
acmecode config explain
acmecode policy explain shell.execute "npm test"
```

See [governance and security](docs/security.md#governance).

---

## Bring your own sandbox

PiShip owns the **policy decision**.

The sandbox backend owns **execution isolation**.

<p align="center">
  <img src="docs/assets/diagram-sandbox.svg" alt="PiShip policy flows through the sandbox contract to native backends (bubblewrap on Linux, Seatbelt on macOS) or remote company backends (custom adapter, E2B-compatible, CubeSandbox, Kubernetes Agent Sandbox; preview)" width="800">
</p>

Native sandboxing is live-probed at launch.

PiShip's boundary tests cover denied reads, writes outside the allowlist, network isolation, environment filtering, git control files, process-tree cleanup, and macOS launchd escape cases.

Remote sandbox backends use the same contract but are currently a **preview** and have not yet been qualified against live E2B, CubeSandbox, Kubernetes Agent Sandbox, or company infrastructure.

Read the full [sandbox contract](docs/sandbox.md).

---

## Your infrastructure stays yours

PiShip is designed around existing company infrastructure rather than replacing it.

| Your organization provides | PiShip provides |
| --- | --- |
| OIDC / SSO | Authorization Code + PKCE client integration |
| Identity and group policy | Identity lifecycle and broker exchange |
| Credential service | Credential storage, refresh, revoke lifecycle |
| LLM gateway | Model governance and Pi runtime binding |
| Enterprise CA / proxy | TLS and network policy integration |
| Sandbox infrastructure | Sandbox backend contract |
| Internal resources | Distribution packaging and trust classification |
| Release policy | Reproducible release and signed update machinery |

A LiteLLM-based gateway is one possible starting point; PiShip only requires the documented integration contracts.

Read [enterprise integration](docs/enterprise-integration.md).

---

## Company-first, not company-only

PiShip can also build personal Pi distributions.

Personal mode does not require:

```text
Company IdP
Credential broker
Company gateway
Audit service
Private network
```

You can still use the same distribution machinery to pin Pi, isolate its state, package your own instructions, skills, extensions, prompts and themes, declare MCP servers, and create reproducible releases.

The included **MyPi** example keeps its state separate from `~/.pi` and can use Pi-native authentication or a local OpenAI-compatible endpoint.

```bash
npm exec -- piship build examples/personal/piship.yaml

node dist/mypi/piship.mjs install dist/mypi

~/.local/bin/mypi
```

See the [personal distribution example](examples/personal/README.md).

---

## Pi stays upstream

PiShip deliberately has a narrow ownership boundary.

| Upstream Pi owns | PiShip owns |
| --- | --- |
| Agent loop | Distribution manifest |
| Model runtime | Pi version pinning |
| Built-in tools | Identity integration |
| Sessions | Credential lifecycle |
| TUI | LLM gateway binding |
| Core coding behavior | Model governance |
| Provider implementations | Resources and trust |
|  | Policy |
|  | MCP governance |
|  | Sandbox integration |
|  | Audit |
|  | Build and install |
|  | Release, update, rollback |

This is the core design rule:

> **Own the distribution, not the agent.**

It keeps PiShip focused and lets Pi evolve upstream without turning every company customization into a permanent fork.

---

## Release and update

PiShip can turn a locked distribution into one artifact per target with:

```text
Pinned runtime
Exact dependency inputs
Release metadata
SPDX SBOM
Third-party notices
Vulnerability scan result
Checksums
```

A release can then be published through signed `stable`, `candidate`, or `dev` channels.

Installed distributions support verified update and rollback while preserving user sessions and settings. Credentials are not snapshotted into rollback state.

```bash
piship release piship.yaml

piship verify-release <artifact>

piship sign-channel <channel-dir> <artifact> \
  --channel stable \
  --key <private-key> \
  --key-id <key-id>
```

Users update through the branded command:

```bash
acmecode update --check
acmecode update
acmecode rollback
```

See the [release documentation](docs/release.md).

---

## Project status

**PiShip is pre-release.**

Nothing is currently published to npm or as an official GitHub Release.

The portable personal distribution core is the most mature surface. Managed access, governance, and release lifecycle are currently compatibility candidates. Sandbox maturity is reported per backend: the native Linux (bubblewrap) and macOS (Seatbelt) sandboxes are candidates, native Windows is unavailable, and the `custom`, `e2b-compatible`, and `kubernetes-agent-sandbox` backends are preview functionality ([per-backend table](docs/status.md#sandbox-backends)).

Many integration paths are tested with deterministic local fixtures. The project does **not** currently claim live qualification against a real company IdP, LLM gateway, model provider, E2B deployment, CubeSandbox deployment, or Kubernetes Agent Sandbox cluster. The [enterprise reference stack](examples/enterprise-reference/README.md) (Keycloak, a reference credential broker, LiteLLM in front of a mock model, and a reference container sandbox) runs the managed flow against real services of those kinds on Ubuntu in the nightly and manual Reference E2E; it stands in for a company's services and is not one.

The [project status page](docs/status.md) is the source of truth for current support and the evidence behind each claim.

---

## Platform support

Current targets are:

| Platform | Distribution | Native sandbox |
| --- | --- | --- |
| Linux x64 | Yes | bubblewrap |
| macOS arm64 | Yes | Seatbelt |
| Windows x64 | Yes | Not currently available |

A Windows distribution that requires a sandbox therefore fails closed unless it uses a remote sandbox backend.

Node.js 22.19.0 or newer is required.

See [compatibility](docs/compatibility.md).

---

## Documentation

| Topic | Document |
| --- | --- |
| What works today | [Project status](docs/status.md) |
| System design | [Architecture](docs/architecture.md) |
| Distribution configuration | [Manifest](docs/manifest.md) |
| Company infrastructure integration | [Enterprise integration](docs/enterprise-integration.md) |
| Identity | [Identity](docs/identity.md) |
| Credentials | [Credentials](docs/credentials.md) |
| LLM gateway and models | [Inference](docs/inference.md) |
| Policy and security boundaries | [Security](docs/security.md) |
| Sandbox backends | [Sandbox](docs/sandbox.md) |
| Writing and testing adapters | [Adapter SDK](docs/adapter-sdk.md) |
| Release, update, rollback | [Release](docs/release.md) |
| Pi compatibility | [Compatibility](docs/compatibility.md) |
| Future direction | [Roadmap](docs/roadmap.md) |
| Architecture decisions | [Decisions](docs/decisions.md) |

---

## Development

Run the full local gate:

```bash
npm run check
npm run test:compatibility
```

The repository uses separate CI evidence tiers for merge safety, installed cross-platform qualification, and release-candidate qualification.

See [project status](docs/status.md) for the current evidence.

---

## Security

PiShip's security model and known limits are documented explicitly in [docs/security.md](docs/security.md).

Security reports should follow [SECURITY.md](SECURITY.md).

---

## Contributing

Contributions are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT
