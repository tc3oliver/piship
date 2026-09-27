# Pi compatibility

`@piship/pi` pins `@earendil-works/pi-coding-agent` to exactly `0.87.1` through its public package entrypoint. Node.js 22.19.0 or newer is required. No other PiShip package may directly depend on or import Pi. The committed npm lock fixes transitive package versions; the distribution lock records their npm integrity values.

`compatibility/pi.json` reports the portable installed surface. `candidate` means local public-API and artifact checks pass while the complete target matrix remains pending. `supported` requires a branded install, real Pi startup, declared TypeScript extension, safe tool path, session resume, inspection, diagnostics, and uninstall on each advertised OS/CPU target. An authenticated model request is outside v0.1.

The local macOS arm64 acceptance test exercises this surface. CI runs the same E2E and compatibility tests on Ubuntu, macOS, and Windows. Hosted runner CPU architectures must be checked before advertising a target. The previous checkout-local Pi 0.87.1 result does not establish portable-install support by itself.

PiShip uses the public SDK entrypoint: `createAgentSessionRuntime`, `createAgentSession`, `DefaultResourceLoader`, `ModelRuntime`, `SessionManager`, `SettingsManager`, `InteractiveMode`, and `createReadTool`. There are no Pi private imports or source patches. A future Pi upgrade must update the exact pin, npm lock, matrix, and compatibility tests together, then pass the installed E2E gate. Temporary shims need a regression test and an owner.
