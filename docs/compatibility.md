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

## Managed governance surface: in preview

Governance (`piship/v1alpha3`) is implemented on Pi 0.87.1 as a preview; it is not yet a separate surface in `compatibility/pi.json`. The end-to-end governance test drives a real Pi session with scripted tool calls from the local fixture gateway and checks Plan mode, MCP policy (a denied tool is never offered or sent), project trust and symlinked instruction imports, certified integrity, user and project rule precedence in `policy explain`, sandboxed Build-mode commands, a required audit sink that fails the launch, and metadata-only audit content.

| Target | Status |
| --- | --- |
| Linux | Tested locally and in [PR CI](https://github.com/tc3oliver/piship/actions/runs/36389270268) on Ubuntu with real bubblewrap: the live probe enforces filesystem read deny, write allowlist, network deny, and the environment filter, and the governance E2E passes |
| macOS | Tested in [PR CI](https://github.com/tc3oliver/piship/actions/runs/36389270268) on macOS 26 arm64 with Seatbelt: the live probe and the boundary tests, including refused launchd, `open`, and `osascript` escapes |
| Windows | No sandbox adapter. A distribution with `sandbox.required: true` fails closed with `SANDBOX_UNAVAILABLE`, which the governance E2E checks; with the sandbox optional, the governance E2E passes in [PR CI](https://github.com/tc3oliver/piship/actions/runs/36389270287) |

The fixtures prove PiShip's governance contracts, not a production deployment. The [portable E2E run](https://github.com/tc3oliver/piship/actions/runs/36389270287) passed on Ubuntu, macOS, and Windows. Still pending: live company services.

## Production lifecycle surface: in preview

The v0.4 lifecycle (`piship/v1alpha4`) is implemented on Pi 0.87.1 as a preview and is recorded as the `lifecycle` surface with status `candidate` in `compatibility/pi.json`, pending recorded three-target release-candidate and lifecycle E2E runs. `@piship/core` carries a copy of the matrix, and the compatibility suite checks that the two are equal: `piship release` refuses a Pi version that is not in it, records the version's status for the distribution's surface (`supported` for personal, `candidate` for managed) in `release.json`, and `update` refuses a release that records its Pi version as unsupported. A Pi upgrade must therefore update `compatibility/pi.json` and that copy together.

Releases are built only for `linux-x64`, `darwin-arm64`, and `win32-x64`. The lifecycle E2E installs a release of the managed demo from its archive with the shipped install script, checks that the release payload matches `piship build` output, signs in against the local fixtures, keeps a session across an update through a signed loopback channel, rejects a tampered archive, altered metadata, and replayed metadata, rolls back and resumes the session, refuses credentials revoked server-side until the user signs in again, confirms no credential remains in state or install directories and that `~/.pi` is untouched, and uninstalls while keeping state. On Windows it runs the demo with the sandbox optional. The release-candidate workflow adds per-target reproducibility, fresh-job verification, and attestation checks. Recorded results for these runs are pending; see [release](release.md#supported-platforms).

## Public API used

PiShip uses the public SDK entrypoint: `createAgentSessionRuntime`, `createAgentSession`, `DefaultResourceLoader`, `ModelRuntime`, `SessionManager`, `SettingsManager`, `InteractiveMode`, `createReadTool`, `createReadToolDefinition`, `createWriteToolDefinition`, `createEditToolDefinition`, `createBashToolDefinition`, `createLocalBashOperations`, `VERSION`, and the `AgentSessionServices`, `CreateAgentSessionRuntimeFactory`, and `InlineExtension` types.

The managed runtime calls `ModelRuntime.create` with an in-memory credential store and no models file, then `ModelRuntime.registerProvider` for the declared gateway. Governance replaces these public methods on the `ModelRuntime` instance PiShip creates: `getModel`, `getModels`, `getAvailable`, `getAvailableSnapshot`, `checkAuth`, `getAuth`, `stream`, `streamSimple`, `complete`, `completeSimple`, `login`, and `setRuntimeApiKey`. An inline `piship-governance` extension listens to `message_end`, to detect credential rejections, and to `model_select`, to update the enterprise context. The compatibility test fails if any of these methods disappears, so an upgrade cannot silently bypass governance.

Governance additionally depends on these public exports and extension hooks: `createAgentSession` options `noTools: "builtin"` and `customTools`; `createReadToolDefinition`, `createWriteToolDefinition`, `createEditToolDefinition`, and `createBashToolDefinition` with their `operations` overrides; `createLocalBashOperations`; the `tool_call`, `user_bash`, `before_agent_start`, `before_provider_request`, and `session_start` events; `registerTool` and `registerCommand`; and the extension context's `hasUI` and `ui` dialogs. Governed tools replace Pi's built-in tools of the same names. The compatibility suite asserts each of these seams individually, so a rename or behavior change fails it first: each tool definition routes file and command access through its `operations` override and nothing else; `createLocalBashOperations` runs a command and reports its exit code; the resource loader loads only the explicit paths when ambient discovery is off; each extension event and registration is delivered in a headless session against the loopback fixture gateway; a `tool_call` block prevents the tool from running; `user_bash` operations are used for `!` commands; a provider registered with an in-memory credential store is listed and then narrowed by PiShip's model governance; and a persisted session resumes through `createAgentSessionRuntime`. The extension context's UI dialogs are checked for presence only, since the suite has no interactive UI.

There are no Pi private imports or source patches. A future Pi upgrade must update the exact pin, npm lock, matrix, and compatibility tests together, then pass the installed E2E gate. Temporary shims need a regression test and an owner.
