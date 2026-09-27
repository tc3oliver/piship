# PiShip

**Ship your own coding agent on Pi without forking Pi.** PiShip builds branded personal distributions around upstream Pi's public runtime.

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

The installer never fetches Node or Pi. `piship build` runs `npm ci --omit=dev` using the committed npm lock and may need package-registry access. Add the selected bin directory to your `PATH` yourself.

## Scope

Pi owns the agent loop, tools, sessions, and TUI. PiShip owns distribution manifests, resource selection, lock and payload assembly, installation, state isolation, and compatibility gates. Managed identity, credentials, policy, sandboxing, signing, updates, and production release channels are later work. Read the [architecture](docs/architecture.md), [manifest](docs/manifest.md), [compatibility](docs/compatibility.md), [security](docs/security.md), and [roadmap](docs/roadmap.md), and [portable payload decision](docs/portable-artifact.md) guides for the precise contract.

The [personal example](examples/personal/README.md) contains the full walkthrough. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). Security reports follow [SECURITY.md](SECURITY.md). PiShip is licensed under [MIT](LICENSE).
