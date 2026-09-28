# Pi compatibility

`@piship/pi` pins `@earendil-works/pi-coding-agent` to exactly `0.87.1` through its public package entrypoint. Node.js 22.19.0 or newer is required. No other PiShip package may directly depend on or import Pi. The committed npm lock fixes transitive package versions; the distribution lock records their npm integrity values.

`compatibility/pi.json` reports status per surface. `candidate` means local public-API and artifact checks pass while the complete target matrix or live evidence remains pending. `supported` requires a branded install, real Pi startup, declared TypeScript extension, safe tool path, session resume, inspection, diagnostics, and uninstall on each advertised OS/CPU target.

## Personal surface: supported

Pi 0.87.1 is **supported for the portable personal surface** on Ubuntu x64, macOS arm64, and Windows x64 with Node 22.19.0. The [three-target compatibility run](https://github.com/tc3oliver/piship/actions/runs/36345041538) passed build, installed E2E, and public-API compatibility on each target. A local macOS arm64 PTY run also opened the real interactive TUI. This status does not claim a live authenticated model request or other CPU architectures. PR-only CI remains a merge gate.

## Managed surface: candidate

Managed access (`piship/v1alpha2`) is a **candidate** on Pi 0.87.1. It is verified on the pinned public API with deterministic local fixtures: a loopback OIDC provider, `http-broker`, and OpenAI-compatible gateway that auto-approve sign-in. Tests cover login, credential acquisition, refresh, gateway rejection and renewal, model governance, streamed text, a tool-call round trip, cancellation, session resume, `config explain`, `doctor`, logout, and the personal `local-secret` and `none` modes. These fixtures prove PiShip's contracts, not an integration with a real identity provider or gateway.

Still pending:

- A live OIDC login against a real identity provider.
- Live inference through a real gateway, and a real authenticated personal model request.
- Three-target installed E2E results for the managed surface.
- Real platform secret-store results. Unit tests use a command-runner double; an opt-in live Keychain and Credential Manager test is wired into CI with no recorded result; Linux Secret Service has no live coverage.

## Public API used

PiShip uses the public SDK entrypoint: `createAgentSessionRuntime`, `createAgentSession`, `DefaultResourceLoader`, `ModelRuntime`, `SessionManager`, `SettingsManager`, `InteractiveMode`, `createReadTool`, `VERSION`, and the `AgentSessionServices`, `CreateAgentSessionRuntimeFactory`, and `InlineExtension` types.

The managed runtime calls `ModelRuntime.create` with an in-memory credential store and no models file, then `ModelRuntime.registerProvider` for the declared gateway. Governance replaces these public methods on the `ModelRuntime` instance PiShip creates: `getModel`, `getModels`, `getAvailable`, `getAvailableSnapshot`, `checkAuth`, `getAuth`, `stream`, `streamSimple`, `complete`, `completeSimple`, `login`, and `setRuntimeApiKey`. An inline `piship-governance` extension listens to `message_end`, to detect credential rejections, and to `model_select`, to update the enterprise context. The compatibility test fails if any of these methods disappears, so an upgrade cannot silently bypass governance.

There are no Pi private imports or source patches. A future Pi upgrade must update the exact pin, npm lock, matrix, and compatibility tests together, then pass the installed E2E gate. Temporary shims need a regression test and an owner.
