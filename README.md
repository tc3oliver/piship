# PiShip

<p align="center">
  English · <a href="README.zh-TW.md">繁體中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-pre--release-orange" alt="Status: pre-release">
  <img src="https://img.shields.io/badge/Pi-1.0.0-blue" alt="Pi 1.0.0">
  <img src="https://img.shields.io/badge/Node-%3E%3D22.19.0-339933?logo=node.js&logoColor=white" alt="Node >=22.19.0">
  <img src="https://img.shields.io/github/license/tc3oliver/piship" alt="License">
</p>

PiShip builds your own branded coding agent on top of upstream [Pi](https://github.com/earendil-works/pi), without forking or patching it. You describe the distribution in one `piship.yaml`: which Pi version, how users sign in, which LLM gateway and models they get, what policy and sandbox apply, which instructions, skills, and extensions ship with it, and how it is released and updated. PiShip turns that into an installable command such as `acmecode`.

Pi keeps the agent loop, tools, sessions, TUI, and model runtime. PiShip handles everything around it that a company needs before it can hand the agent to its developers.

<p align="center">
  <img src="docs/assets/piship-demo.gif" alt="Animation: upstream Pi is wrapped by PiShip, connected to company identity, credential broker, LLM gateway and sandbox, and becomes your company coding agent" width="720">
</p>

## What it covers

| Area | What PiShip does |
| --- | --- |
| Identity | OIDC sign-in (Authorization Code + PKCE) |
| Credentials | Exchanges the identity at your credential broker for a short-lived gateway credential, keeps it in the OS secret store, renews and revokes it. Developers never hold upstream provider keys |
| Models | Talks to an OpenAI-compatible company gateway; default model, allowlist, and per-model metadata |
| Resources | Ships instructions, skills, extensions, prompts, and themes with the distribution, each with a trust class |
| Policy | Decides tool calls, file access, shell commands, MCP servers and tools, and resource loading before they happen; project trust changes what is allowed per repository |
| Sandbox | Runs agent commands in bubblewrap (Linux), Seatbelt (macOS), or a remote backend: your own adapter, an E2B-compatible service such as CubeSandbox, or Kubernetes Agent Sandbox |
| Audit | Metadata-only policy and runtime events to a local file or your collector |
| Release | One reproducible artifact per platform, with SPDX SBOM, third-party notices, vulnerability gate, and checksums |
| Updates | Signed channels, verified update with atomic activation, and rollback that keeps sessions |

PiShip is not an identity provider, gateway, or sandbox service. It connects the ones you already run. The wire protocols they must speak are in the [enterprise integration contract](docs/enterprise-integration.md); a LiteLLM gateway works.

<p align="center">
  <img src="docs/assets/diagram-login-flow.svg" alt="OIDC login, company identity, credential broker, short-lived gateway credential, Pi runtime, company LLM gateway" width="1000">
</p>

## A managed manifest

This is a complete manifest; `piship validate` accepts it as is.

```yaml
schema: piship/v1alpha4

app:
  id: acmecode
  name: AcmeCode
  command: acmecode
  version: 1.0.0

runtime:
  pi: "1.0.0"

deployment:
  mode: managed

# Endpoints are resolved from the environment at launch.
variables:
  - ACMECODE_OIDC_ISSUER
  - ACMECODE_OIDC_CLIENT_ID
  - ACMECODE_CREDENTIAL_BROKER_URL
  - ACMECODE_LLM_GATEWAY_URL

identity:
  mode: oidc
  oidc:
    issuer: ${ACMECODE_OIDC_ISSUER}
    clientId: ${ACMECODE_OIDC_CLIENT_ID}
    flow: authorization_code_pkce
    redirectUri: http://127.0.0.1:8765/callback

credential:
  provider: http-broker
  broker:
    endpoint: ${ACMECODE_CREDENTIAL_BROKER_URL}

inference:
  provider: openai-compatible
  baseUrl: ${ACMECODE_LLM_GATEWAY_URL}

models:
  default: acme/coder
  allowed:
    - acme/coder
    - acme/general
  catalog:
    acme/coder:
      name: Acme Coder
      contextWindow: 128000
      maxOutputTokens: 8192
      tools: true
    acme/general:
      name: Acme General
      contextWindow: 128000
      maxOutputTokens: 8192

network:
  publicFallback: deny

sandbox:
  required: true
  network:
    mode: deny

updates:
  channel: stable
  channels: [stable]
  rollback: true
```

The manifest holds no secrets; the schema rejects secret-looking fields. Policy, resources, MCP servers, audit, and release gates are optional and have defaults. Every field is in the [manifest reference](docs/manifest.md), and the [demo company manifest](examples/demo-company/piship.yaml) uses most of them.

## Quickstart

PiShip is built from source and needs Node.js 22.19.0 or newer. The managed demo also needs an OS sandbox (Seatbelt on macOS, bubblewrap with unprivileged user namespaces on Linux) and a platform secret store. [Troubleshooting](docs/troubleshooting.md) lists the prerequisites and every error code.

```bash
git clone https://github.com/tc3oliver/piship.git
cd piship
npm ci
npm run build
```

The CLI is `node packages/cli/dist/bin.js`. It is not on npm, so `npx` and `npm exec` would look it up on the public registry instead.

### Run the company demo

AcmeCode is a managed distribution that runs against local stand-ins for an OIDC provider, a credential broker, and a gateway:

```bash
node examples/demo-company/fixtures/local-services.mjs
```

It prints the `ACMECODE_*` variables to export. In another terminal, with those set:

```bash
node packages/cli/dist/bin.js build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode login
~/.local/bin/acmecode
```

Then look at what is actually in force:

```bash
acmecode doctor
acmecode models
acmecode capabilities
acmecode config explain
acmecode policy explain shell.execute "git status"
acmecode policy explain filesystem.read ~/.ssh/id_ed25519
```

To remove it, sign out first (`logout` revokes the credential at the broker; purge does not, so it refuses while you are signed in):

```bash
acmecode logout
node dist/acmecode/piship.mjs uninstall acmecode --purge --yes
```

The fixtures are deterministic test services, not a real company integration. Full walkthrough: [company demo](examples/demo-company/README.md).

### Start your own

Keep your distribution in its own repository and run the CLI by path ([details](docs/enterprise-integration.md#running-the-cli-from-your-own-repository)):

```bash
node ~/src/piship/packages/cli/dist/bin.js init ./my-agent              # personal: Pi's own providers and sign-in
node ~/src/piship/packages/cli/dist/bin.js init ./my-agent --managed    # managed: OIDC, broker, gateway

# edit my-agent/piship.yaml and my-agent/resources/AGENTS.md, then:
node ~/src/piship/packages/cli/dist/bin.js validate ./my-agent/piship.yaml
node ~/src/piship/packages/cli/dist/bin.js lock ./my-agent/piship.yaml
node ~/src/piship/packages/cli/dist/bin.js build ./my-agent/piship.yaml
node dist/my-agent/piship.mjs install dist/my-agent
```

Commit `piship.yaml`, `piship.lock`, and `resources/`. To ship releases and updates to other people, follow the [release guide](docs/release.md).

### Personal use

The same machinery works without a company: no IdP, broker, or gateway. The MyPi example pins Pi, keeps its state away from `~/.pi`, and uses Pi's own sign-in or a local OpenAI-compatible server.

```bash
node packages/cli/dist/bin.js build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi
```

See the [personal example](examples/personal/README.md).

## How enforcement works

Policy is checked at runtime, not just written down. When something the manifest requires cannot be switched on, the launch stops instead of running with less: a required sandbox that is not available ends in `SANDBOX_UNAVAILABLE`, and the command never runs on the host. `doctor`, `capabilities`, `config explain`, and `policy explain` show the effective state. Company policy is layered, and project or user configuration can only narrow it.

PiShip makes the policy decision; the sandbox backend does the isolation. The native sandboxes are probed at every launch, and their tests cover denied reads, writes outside the allowlist, network denial, environment filtering, protected git files, process cleanup, and macOS launchd escapes. In a remote sandbox only shell commands run remotely; Pi's file tools still work on the local checkout, so the backend has to mount or sync the workspace for both to see the same files ([sandbox](docs/sandbox.md#workspace)).

Details and known limits: [security](docs/security.md) and [sandbox](docs/sandbox.md).

## Releases and updates

`piship release` turns a locked distribution into one artifact per target with the pinned runtime, exact dependencies, SBOM, notices, the vulnerability scan result, and checksums. You publish it to signed `stable`, `candidate`, or `dev` channels; users run `acmecode update` and `acmecode rollback`. Rollback keeps sessions and settings and never snapshots credentials.

```bash
piship release piship.yaml
piship verify-release <artifact>
piship sign-channel <channel-dir> <artifact> --channel stable --key <private-key> --key-id <key-id>
```

See [release](docs/release.md).

## Status

PiShip is pre-release and not published to npm.

- **v0.7.1** is the [production-validation baseline](docs/status.md#v071-production-validation-baseline): tag `v0.7.1` (commit `bd4bc09`) on Pi 0.87.1, with six attested example archives on its [GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.7.1). A production consumer pins it instead of tracking `main`.
- **`main`** pins Pi 1.0.0. Changes since v0.7.1 are in the [changelog](CHANGELOG.md).
- The personal distribution core is supported. Managed access, governance, and the release lifecycle are candidates. The native Linux and macOS sandboxes are candidates, Windows has no native sandbox, and the remote backends are a preview ([per backend](docs/status.md#sandbox-backends)).
- Managed flows are tested against local fixtures on all three platforms, and on Ubuntu against a reference stack of Keycloak, a reference broker, LiteLLM, and a container sandbox. One manual run sent a real model request through that stack ([run](https://github.com/tc3oliver/piship/actions/runs/36877709332)).
- Not yet shown: a production company IdP or gateway, and live E2B, CubeSandbox, or Kubernetes Agent Sandbox deployments.
- The project runs no signed update channel; keys and channels belong to each distribution owner.

The [status page](docs/status.md) is the source of truth, with the evidence for each claim.

| Platform | Distribution | Native sandbox |
| --- | --- | --- |
| Linux x64 | Yes | bubblewrap |
| macOS arm64 | Yes | Seatbelt |
| Windows x64 | Yes | None; use a remote backend or leave the sandbox optional |

## Documentation

| Topic | Document |
| --- | --- |
| What works today | [Status](docs/status.md) |
| Design | [Architecture](docs/architecture.md), [Decisions](docs/decisions.md) |
| Manifest fields | [Manifest](docs/manifest.md) |
| Connecting company services | [Enterprise integration](docs/enterprise-integration.md) |
| Identity, credentials, models | [Identity](docs/identity.md), [Credentials](docs/credentials.md), [Inference](docs/inference.md) |
| Policy and limits | [Security](docs/security.md) |
| Sandbox backends | [Sandbox](docs/sandbox.md), [Adapter SDK](docs/adapter-sdk.md) |
| Release, update, rollback | [Release](docs/release.md) |
| Pi versions | [Compatibility](docs/compatibility.md) |
| Errors and prerequisites | [Troubleshooting](docs/troubleshooting.md) |
| Direction | [Roadmap](docs/roadmap.md) |

## Development

```bash
npm run check
npm run test:compatibility
```

CI has separate tiers for merging, installed cross-platform runs, and release qualification; see [status](docs/status.md#ci-evidence-tiers).

Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). License: MIT.
