# PiShip

**Ship Pi as your company's coding agent, without forking Pi.** PiShip is an open-source, company-first distribution and governance framework around upstream Pi. It provides generic building blocks for branded, managed distributions; personal use is supported by the same architecture.

**Current implementation:** v0.1 delivers the portable personal distribution core. v0.2 managed access and configuration is in preview: OIDC sign-in, broker-issued runtime credentials in the platform secret store, an explicit OpenAI-compatible gateway, model governance on the pinned Pi runtime, and layered configuration. It is verified with deterministic local fixtures only. Governance and security policy, then production lifecycle, are later milestones. There is no sandbox, policy engine, audit, signing, or update channel.

## Portable personal preview

The `piship/v1alpha1` personal flow builds a versioned, checkout-independent payload with pinned Pi 0.87.1, declared resources and a custom theme, isolated state, install/uninstall ownership, and a branded launcher. Installed E2E passes on Ubuntu x64, macOS arm64, and Windows x64 with Node 22.19.0. Node.js 22.19.0 or newer is a separately installed prerequisite. The payload is currently a development artifact, not a signed release or npm publication.

```bash
npm ci
npm run build
npm exec -- piship validate examples/personal/piship.yaml
npm exec -- piship lock examples/personal/piship.yaml
npm exec -- piship test examples/personal/piship.yaml
npm exec -- piship build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi --version
~/.local/bin/mypi --smoke
node dist/mypi/piship.mjs inspect mypi
node dist/mypi/piship.mjs doctor mypi
node dist/mypi/piship.mjs uninstall mypi
```

On Windows use the installed `mypi.cmd` in the configured bin directory. Set `PISHIP_INSTALL_HOME` and `PISHIP_BIN_HOME` to change install paths and `PISHIP_STATE_HOME` to change the state root. `uninstall` preserves sessions and credentials. `node dist/mypi/piship.mjs purge mypi --yes` removes only that distribution's PiShip state after uninstall. `--smoke` tests Pi startup, a safe read tool, declared resources, and session resume without a model call. The plain branded command opens Pi's interactive TUI.

The installer and launcher never fetch Node, Pi, or packages. `piship build` runs `npm ci --omit=dev` from exact locked inputs and may access a package registry. Add the selected bin directory to your `PATH` yourself.

## Managed access preview

`piship/v1alpha2` adds `deployment.mode: managed`. A managed distribution signs users in with OIDC Authorization Code + PKCE, obtains a scoped runtime credential from an organization broker, and sends inference only to a declared OpenAI-compatible gateway. Only allowed models are visible or callable, ambient provider keys are removed from the runtime environment, and branded `login`, `logout`, `doctor`, `models`, and `config explain` commands are included. Endpoints are runtime references, so the lock never holds secrets or machine-specific values. The managed surface is a compatibility **candidate**: no live identity provider, live gateway, or three-target managed result has been recorded yet. Try it with the [demo company example](examples/demo-company/README.md) and its local fixtures. `piship migrate` moves v1alpha1 personal manifests to v1alpha2.

## Scope

Pi owns the agent loop, tools, sessions, TUI, and model/runtime behavior. PiShip owns the distribution layer: manifest/configuration, pinned runtime, resources, reproducible payload, identity/credential/inference integration, and progressively policy/trust and lifecycle/release. Read the [architecture](docs/architecture.md), [manifest](docs/manifest.md), [compatibility](docs/compatibility.md), [security](docs/security.md), [identity](docs/identity.md), [credentials](docs/credentials.md), [inference](docs/inference.md), [roadmap](docs/roadmap.md), and [portable payload decision](docs/portable-artifact.md) for the precise contract.

The [personal example](examples/personal/README.md) contains the full walkthrough. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). Security reports follow [SECURITY.md](SECURITY.md). PiShip is licensed under [MIT](LICENSE).
