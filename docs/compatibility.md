# Pi compatibility

`@piship/pi` pins `@earendil-works/pi-coding-agent` to exactly `0.87.1` through its public package entrypoint. Node.js 22.19.0 or newer is required. No other PiShip package may directly depend on or import Pi. The committed npm lock fixes transitive package versions; the distribution lock records their npm integrity values.

`compatibility/pi.json` reports the portable installed surface. `candidate` means local public-API and artifact checks pass while the complete target matrix remains pending. `supported` requires a branded install, real Pi startup, declared TypeScript extension, safe tool path, session resume, inspection, diagnostics, and uninstall on each advertised OS/CPU target. An authenticated model request is outside v0.1.

Pi 0.87.1 is **supported for the portable personal surface** on Ubuntu x64, macOS arm64, and Windows x64 with Node 22.19.0. The [three-target compatibility run](https://github.com/tc3oliver/piship/actions/runs/36345041538) passed build, installed E2E, and public-API compatibility on each target. A local macOS arm64 PTY run also opened the real interactive TUI. This status does not claim a live authenticated model request, managed features, or other CPU architectures. PR-only CI remains a merge gate.

PiShip uses the public SDK entrypoint: `createAgentSessionRuntime`, `createAgentSession`, `DefaultResourceLoader`, `ModelRuntime`, `SessionManager`, `SettingsManager`, `InteractiveMode`, and `createReadTool`. There are no Pi private imports or source patches. A future Pi upgrade must update the exact pin, npm lock, matrix, and compatibility tests together, then pass the installed E2E gate. Temporary shims need a regression test and an owner.
