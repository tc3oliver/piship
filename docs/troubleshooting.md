# Troubleshooting

This page lists what PiShip needs on a machine and what each PiShip error code means. A failing command prints `CODE: message`, and often an action; `doctor` (`<command> doctor`, or `node packages/cli/dist/bin.js doctor <artifact|id>`) reports the same areas without starting a session. In the tables, `<command>` is the distribution's branded command, such as `acmecode` or `mypi`.

## Prerequisites

| Need | When | Details |
| --- | --- | --- |
| Node.js 22.19.0 or newer, and npm | Always, to build from source | The `engines` field in `package.json`. An installed release carries its own payload but still runs on the user's Node.js |
| Linux: bubblewrap (`bwrap`) with unprivileged user namespaces | `sandbox.required: true` with the default `native` provider, as in the managed demo | On Ubuntu 24.04, and other systems where `kernel.apparmor_restrict_unprivileged_userns` is `1`, AppArmor blocks unprivileged user namespaces. Allow them with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (as CI does), or with an AppArmor profile for `bwrap`. Otherwise the launch fails with `SANDBOX_UNAVAILABLE` |
| macOS: Seatbelt | The same | Built in (`/usr/bin/sandbox-exec`); nothing to install |
| Windows | The same | There is no native sandbox on Windows: a required `native` sandbox fails with `SANDBOX_UNAVAILABLE`. Use a remote backend ([sandbox](sandbox.md)) or `sandbox.required: false` |
| A secret store | `storage.provider: system` (the managed demo, `login`) | macOS Keychain (`/usr/bin/security`), Linux Secret Service (`secret-tool` from libsecret, with an unlocked keyring such as GNOME Keyring), or Windows Credential Manager. Without one, `login` fails with `SECRET_STORE_UNAVAILABLE`; PiShip never falls back to a file on its own. `storage: {provider: file}` keeps owner-only plaintext files instead (a managed manifest must also set `acknowledgePlaintext: true`) ([credentials](credentials.md#secret-stores)) |

Releases are built for `linux-x64`, `darwin-arm64`, and `win32-x64`. Pi's interactive mode can download `fd` and `rg` on its first start ([security](security.md#secrets)).

## Error codes

Every code PiShip reports is defined in `packages/contracts/src/errors.ts`. A retryable error says so and may give `Retry after: <n> s`.

| Code | Meaning | What to do |
| --- | --- | --- |
| `CONFIG_INVALID` | The manifest, a preference, a state file, or the install layout is invalid: a field value, a path, overlapping state, install, and bin homes, a refused setting | Fix what the message names. `node packages/cli/dist/bin.js validate <manifest>` checks a manifest. For overlapping homes, point `PISHIP_STATE_HOME`, `PISHIP_INSTALL_HOME`, and `PISHIP_BIN_HOME` at separate directories |
| `CONFIG_UNAVAILABLE` | Something the launch needs cannot be read: an unset `${NAME}` runtime variable, an unreadable CA bundle, a required MCP server's configuration, or a damaged or over-64 MiB most recent session. For `login`: the registered redirect port (such as 8765) is in use | Set the runtime variables `validate` lists. For a session, start `<command>` again to continue, or run `<command> --new-session`. For a busy login port, finish or cancel the other `login`, or stop the process the error names |
| `IDENTITY_REQUIRED` | No one is signed in, sign-in was cancelled or timed out, or the signed-in user changed in another session | Run `<command> login` and complete sign-in in the browser, then start `<command>` again. Over SSH, forward the redirect port first ([remote shells](identity.md#remote-shells)). A timeout that names a provider error, or a browser that showed one, means the client registration needs checking |
| `IDENTITY_INVALID` | The identity session or provider is not acceptable: another principal, a misconfigured issuer, or a workload identity adapter that failed, returned no expiry, or tried to open a browser | Run `<command> login` again, or contact your administrator. Administrators: check the configured issuer and client registration; for a workload identity, check its token source and the adapter ([identity](identity.md#workload-identity-headless-runs)) |
| `IDENTITY_EXPIRED` | The identity session expired and cannot be refreshed | Run `<command> login`. If it keeps happening, check the system clock; for a workload identity, check that its token source is current |
| `CREDENTIAL_REQUIRED` | No runtime credential or local secret is stored | Run `<command> login` |
| `CREDENTIAL_ACQUIRE_FAILED` | The credential provider could not issue a usable credential, or another process is still signing in or refreshing | Try again when the other session finishes. Make the state directory writable. Administrators: check the broker and that it matches `inference.baseUrl` |
| `CREDENTIAL_DENIED` | The credential broker denied this user or distribution | Ask your administrator for access |
| `CREDENTIAL_EXPIRED` | The runtime credential expired and could not be renewed, or the broker issued one already expired | Run `<command> login`. For a credential the broker issued already expired, `detail` holds `expiresAt`, `localTime`, and, when the broker sent a `Date` header, `brokerTime` and `clockSkewSeconds`: check this computer's clock first (signing in again cannot help while it is wrong), then ask an administrator to check the broker's clock and credential lifetime |
| `CREDENTIAL_REVOKED` | The gateway rejected the runtime credential or the stored key | PiShip re-acquires once. If it persists, run `<command> login` again; for a local secret, check the key first |
| `SECRET_STORE_UNAVAILABLE` | The secret store is missing, locked, or failed to read or delete a secret | Unlock or repair the secret store, then run the same command again. See [prerequisites](#prerequisites) for what each platform needs |
| `GATEWAY_UNREACHABLE` | A request to the identity provider, credential broker, gateway, or a workload identity adapter failed or timed out, or the gateway's model provider refused it. Retryable | Check the network connection, then try again. Administrators: check the gateway's provider configuration |
| `GATEWAY_RATE_LIMITED` | The gateway or another service answered 429. Retryable | Wait for the time shown, then try again |
| `GATEWAY_PROTOCOL_ERROR` | The gateway answered with an unexpected status or a model list that is not valid | Administrators: check that `inference.baseUrl` points at an OpenAI-compatible gateway and that it is healthy |
| `MODEL_DENIED` | The model is not allowed by the distribution or a policy rule, or no default model is configured | Choose one of the allowed models the action lists (`<command> models`) |
| `MODEL_UNAVAILABLE` | No allowed model is currently available, or the gateway does not serve the selected one | Choose one of the models the action lists, or try again later |
| `MODEL_INCOMPATIBLE` | The selected model does not meet the requirements of an enabled capability, or its metadata is unknown; no other model is substituted | Select a model that meets the requirements (`<command> capabilities` shows them), or ask the distribution owner to adjust them ([inference](inference.md)) |
| `NETWORK_DENIED` | The network policy refused a host: plain HTTP to a non-loopback host, or an undeclared host under `network.privateOnly` | Use HTTPS. Distribution owners: declare the host through a managed endpoint or `network.allowHosts` |
| `TLS_POLICY_VIOLATION` | `NODE_TLS_REJECT_UNAUTHORIZED=0` would disable TLS verification | Unset `NODE_TLS_REJECT_UNAUTHORIZED` and declare the enterprise CA bundle in `network.tls.additionalCA` |
| `POLICY_DENIED` | The distribution's policy refused a command or setting: an enforced key, a preference that widens an allowlist, a channel outside `updates.channels`, or `login`/`logout` in a distribution that delegates authentication to Pi | Use a value the distribution allows. In a Pi-native distribution, use Pi's `/login` and `/logout` inside the session |
| `MCP_DENIED` | Policy denies a required MCP server | Ask the distribution owner; a required server that is denied stops the launch ([manifest](manifest.md#mcp)) |
| `MCP_UNHEALTHY` | An MCP server cannot start or failed its checks, for example a wrong `serverInfo.name` or a `credential: runtime` server on another origin than `inference.baseUrl` | Check the server's command or URL and the `doctor` MCP section. A required server stops the launch; an optional one is marked failed |
| `SANDBOX_UNAVAILABLE` | The distribution requires a sandbox that cannot be used: the OS sandbox is missing or blocked, a backend's configuration or runtime variables are wrong, or the backend cannot enforce the declared network mode. PiShip never falls back to running unsandboxed | See [prerequisites](#prerequisites). Fix the sandbox backend configuration or its runtime variables ([sandbox](sandbox.md)) |
| `AUDIT_UNAVAILABLE` | A required audit sink is failing; governed actions fail closed until it recovers | Restore the audit sink or contact the distribution administrator, and report any unrecorded activity |
| `LOCK_INVALID` | `piship.lock` is missing or stale, or an installed payload's manifest or npm lock no longer matches its lock | Run `node packages/cli/dist/bin.js lock <manifest>` and rebuild. For an installed distribution, restore the release with `piship repair <id> <release archive>` ([repairing an installed release](#repairing-an-installed-release)) |
| `INTEGRITY_FAILED` | A payload, release archive, or update does not match its inventory, checksums, or signed channel entry. For an installed payload, the message names each offending path as unexpected (not in the inventory), modified, or missing | Do not install or run it. For an installed distribution, restore the release with `piship repair <id> <release archive>` ([repairing an installed release](#repairing-an-installed-release)); otherwise obtain the artifact again from the trusted source. Report a bad update source to the distribution owner |
| `UPDATE_FAILED` | An update cannot proceed: no update source or trusted key, a downgrade, an install without release tracking, a migration that needs review, or local data no release can read | Follow the message: pass `--from`, add `updates.trust.keys`, reinstall, review the migration check and rerun `update --accept-review`, or move the damaged file the message names aside and run `update` again ([update lifecycle](release/update-lifecycle.md#migration-check-and-local-data)) |
| `ROLLBACK_FAILED` | There is no retained release, it is newer than the active one, it failed verification, or it cannot read the current state | Use `update` instead where the message says so. For a damaged state file the message names, move it aside and run `rollback` again. A retained release that failed verification is not activated: restore it with `piship repair <id> <release archive of that version>` and roll back again |

## Repairing an installed release

An installed release is verified against its inventory every time it starts, so any change to its payload directory stops the branded command, its `update`, `rollback`, and `doctor`, and `piship doctor`, with `INTEGRITY_FAILED`. Nothing is exempt from that check, including operating-system metadata such as `.DS_Store`, `._*`, `Thumbs.db`, and `desktop.ini`: an exemption would let any file of those names ride along unchecked. The message names the payload and the offending paths, up to five per kind and a count of the rest (the error detail carries up to 50):

```text
INTEGRITY_FAILED: Installed payload integrity mismatch in <install-home>/apps/acmecode/1.1.0; unexpected (not in the inventory): .DS_Store
Action: Do not run it. Restore it from a trusted release of the same version with: piship repair acmecode <release archive> (repair does not run this payload). …
```

`update` and `rollback` run through the active release, so they cannot fix it themselves. `piship repair` runs in PiShip instead and never runs or trusts the damaged payload:

```bash
piship repair acmecode ./acmecode-1.1.0-darwin-arm64.tar.gz   # or a release directory or payload
```

The source must be the same release that is installed: it is verified like an install (`verify-release` for this target for an archive or release directory, or the payload inventory and lock for a payload directory), and must have a version this installation records (the active or the retained release), the same command, and, when the receipt recorded them at install or update, the same lock digest and archive digest. A copy from another build of that version, or of another version, is refused with nothing changed. A release that verifies is reported intact and left alone; a release a running session still uses is refused until the session exits. Otherwise the damaged payload is replaced by the verified copy in two renames inside `apps/<id>`; the receipt, state, and credentials are untouched. An interruption between the renames leaves the release missing, which the launcher refuses, and running the same `repair` again restores it. Afterwards `update` and `rollback` work again. `piship` here is the PiShip CLI; a user without one can use the copy inside the extracted release they downloaded, `node <release-dir>/payload/piship.mjs repair <id> <release-dir>`, when that release was built with a PiShip that has `repair` (later than 0.7.0). Never run the `piship.mjs` of the damaged payload.

Removing an unexpected file from the payload by hand also restores it, when the message lists only unexpected files. A modified or missing file needs `repair`.
