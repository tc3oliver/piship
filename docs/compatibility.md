# Pi compatibility

## Exact pin

`packages/pi/package.json` pins `@earendil-works/pi-coding-agent` to exactly `0.87.1`. Its public package entrypoint requires Node `>=22.19.0`. No other package may directly depend on or import `@earendil-works/pi-*`. A manifest requesting another Pi version fails; PiShip does not install arbitrary runtime versions. The npm lockfile fixes transitive dependency resolution.

## Status contract

`compatibility/pi.json` maps a Pi version to:

- `candidate`: public API, metadata, and compatibility foundation checks pass, but the complete distribution runtime gate has not passed.
- `supported`: a real branded distribution launches and all required compatibility and end-to-end gates pass across Ubuntu, macOS, and Windows CI.
- `unsupported`: known incompatible or not accepted.

The local personal example now validates, locks, builds, and initializes a real Pi SDK session through its branded launcher. `0.87.1` remains a **candidate** until the cross-platform CI gates for this change pass. The `--smoke` gate initializes Pi and loads resources without an LLM call; it does not prove live provider access or every interactive TUI path.

## Public API and upgrade policy

Use only exported package entrypoints. Never import `node_modules/.../src/*`, private or internal subpaths, GitHub source URLs, or Pi implementation files. The adapter uses `createAgentSessionRuntime`, `createAgentSession`, `DefaultResourceLoader`, `ModelRuntime`, `SessionManager`, `SettingsManager`, and `InteractiveMode` from the public root entrypoint. The boundary scanner and compatibility tests guard against deep imports.

1. Record an upstream release and affected APIs in a compatibility change.
2. Test through public exports before changing the exact pin.
3. Update the pin, matrix, npm lockfile, and regression tests together.
4. Launch a branded distribution and pass compatibility and end-to-end gates across Ubuntu, macOS, and Windows before declaring `supported`.

The scheduled latest-version canary is deferred. It must only signal and must never change the pinned runtime dependency, commit, merge, or publish.

Each temporary shim requires an owner, reason, removal condition, upstream issue or PR when appropriate, and a regression test. Prefer an upstream fix.
