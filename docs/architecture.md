# Architecture

PiShip assembles a personal coding-agent distribution from a strict manifest, a committed npm lock, and upstream Pi public packages. Pi owns the agent loop, TUI, sessions, tools, and extension execution. PiShip owns the manifest, dependency closure, resource selection, payload, installer, state locations, and diagnostics. Distribution repositories own their brand and declared resources. Pi source is neither forked nor patched.

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Manifest, lock, payload, installation | PiShip |
| Brand and selected resources | Distribution repository |

`@piship/schema` validates `piship/v1alpha1`. `@piship/core` locks and assembles artifacts, verifies their files, and manages install ownership. `@piship/pi` is the only direct Pi dependency and uses public SDK exports. `@piship/cli` presents commands.

## Canonical payload

`piship build` creates `dist/<id>` from the committed npm lock via `npm ci --omit=dev`. This directory contains `node_modules` (including Pi and PiShip), `bin/`, declared `resources/`, `piship.yaml`, `package-lock.json`, and `metadata/` with the distribution lock and SHA-256 inventory. The launcher resolves only packages inside this directory. A machine must have Node.js 22.19.0 or newer installed separately. Build-time npm access may be needed; installation and launch never install packages. The payload includes upstream package notices. It is the same unit future release verification and updates must consume.

The payload includes `piship.mjs`, so installation and diagnostics need no source checkout. `node <payload>/piship.mjs install <payload>` copies this payload into `~/.local/share/piship/apps/<id>/<version>` and writes a command shim in `~/.local/bin` by default. Set `PISHIP_INSTALL_HOME` and `PISHIP_BIN_HOME` to choose other user-writable locations. Add the bin directory to `PATH` yourself; PiShip does not edit shell profiles. The receipt in `<install-home>/receipts/<id>.json` records owned paths. Name, command, existing install, and pre-existing state collisions fail. `--use-existing-state` explicitly adopts state during install. `uninstall` removes the receipt, shim, and payload; `purge <id> --yes` separately deletes the selected state after uninstall.

State defaults to `~/.piship/<id>` or `PISHIP_STATE_HOME/<id>`. The state path depends on the distribution ID, so relocation or reinstallation can resume the same session. State is never copied into the payload.

| State path | Scope and sensitivity | Retention and clearing |
| --- | --- | --- |
| `agent/` | Pi config, model metadata, and local auth file; sensitive | Kept by uninstall; selected distribution purge deletes it |
| `sessions/user/` | Interactive Pi sessions; may contain private project content | Kept by uninstall; purge deletes it |
| `sessions/acceptance/` | Labeled keyless smoke session | Kept by uninstall; purge deletes it |
| `cache/` | Reserved per-distribution cache | Kept by uninstall; purge deletes it |
| `logs/` | Reserved per-distribution diagnostics; may be sensitive | Kept by uninstall; purge deletes it |
| `data/` | Reserved runtime-generated data | Kept by uninstall; purge deletes it |

These paths have no automatic migration in v0.1; reinstalling the same distribution ID reuses them. Pi's resource loader disables ambient extension, skill, prompt, theme, and context discovery and receives only declared packaged paths. The working directory remains the user's project; its `.pi` resources are not distribution resources.

See [manifest](manifest.md), [compatibility](compatibility.md), and [security](security.md).
