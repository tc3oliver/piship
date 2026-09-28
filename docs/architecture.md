# Architecture

PiShip is an open-source, company-first distribution and governance framework for branded Pi-based coding agents. Pi owns the agent loop, TUI, sessions, tools, model/runtime behavior, and extension execution. PiShip owns the distribution layer: manifest/configuration, pinned runtime, resources, reproducible payload, and progressively identity/credential/inference integration, policy/trust, and lifecycle/release. Distribution repositories own their brand and declared resources. Pi source is neither forked nor patched.

The current v0.1 implementation is the portable personal foundation. Managed access, governance/security, and production lifecycle arrive in later milestones; none is claimed for this payload.

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Manifest, lock, payload, installation | PiShip |
| Brand and selected resources | Distribution repository |

`@piship/schema` validates `piship/v1alpha1`. `@piship/core` locks and assembles artifacts, verifies their files, and manages install ownership. `@piship/pi` is the only direct Pi dependency and uses public SDK exports. `@piship/cli` presents commands.

## Canonical payload

`piship build` creates `dist/<id>` from package-owned build inputs prepared with `@piship/core`, using `npm ci --omit=dev` and exact locked dependencies. It does not infer the PiShip source repository from its module path. The payload contains `node_modules` (including Pi and PiShip), `bin/`, declared `resources/`, the exact source `piship.yaml` and `piship.lock`, `package-lock.json`, and `metadata/target.json` and `metadata/inventory.json`. The inventory covers the canonical lock and all payload files. The launcher checks the recorded target and integrity before entering Pi and resolves only packages inside this directory. A machine must have Node.js 22.19.0 or newer installed separately. Build-time registry access may be needed; installation and launch do not fetch Node, Pi, or packages. The payload includes upstream package notices. It is the same unit future release verification and updates must consume.

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
