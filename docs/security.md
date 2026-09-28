# Security architecture

Upstream Pi runs the agent. PiShip validates distribution inputs, locks declared resources and package identities, and verifies packaged file hashes before entering Pi. A distribution's extensions are executable code with the user's process privileges. This is resource and state isolation, not an OS sandbox.

## Payload and state

The installer owns only its receipt, installed payload, and command shim. Existing install, command, and state collisions fail by default. `uninstall` preserves `~/.piship/<id>`; `purge <id> --yes` removes that one distribution's state after uninstall. The payload is separate from mutable config, sessions, cache, logs, credential metadata, and other runtime data. There is no shared runtime cache.

Pi receives a dedicated agent directory, user and acceptance session directories, in-memory settings, and a loader with ambient extension, skill, prompt, theme, and context discovery disabled. Only declared resources are packaged. Packaging rejects symlinks in resource roots, nested files, and adapter paths. Project files remain accessible to Pi tools and trusted extensions; PiShip does not enforce project trust or tool policy.

The SHA-256 inventory detects accidental or unauthorized file changes only while the inventory itself is trusted. PiShip does not sign artifacts, attest their origin, or provide a security boundary against a malicious local user who can rewrite both files and inventory.

## Secrets

- `piship.yaml` and `piship.lock` never hold secrets. The schema rejects secret fields, client secrets, and runtime variables whose names look like secrets. It cannot detect every secret embedded in an otherwise allowed string, so never commit one.
- Identity tokens and runtime credentials are wrapped in `SecretValue`, which prints, serializes, and inspects as `[REDACTED]`. Only an explicit `reveal()` returns the value, and revealed values are scrubbed from later diagnostics. `PiShipError` messages, actions, and details, launcher and CLI error output, `config explain`, and `doctor` pass through the same redaction, which also removes common token shapes.
- State files hold only non-secret metadata and secret-store references ([architecture](architecture.md#state)).
- Secrets go to the platform store first: macOS Keychain, Linux Secret Service, or Windows Credential Manager. Secrets reach these tools on standard input, never as command arguments. `storage.provider: system` never silently falls back to a file: an unavailable store fails with `SECRET_STORE_UNAVAILABLE`.
- The file store is an explicit opt-in: owner-only (0700 directory, 0600 files) atomic writes under `<state>/secrets/`. Values are base64url-encoded, not encrypted. A managed manifest must set `acknowledgePlaintext: true` to use it, and `login`, `doctor`, and `config explain` report it as a plaintext fallback.

Unit tests exercise the platform stores through a command-runner double, not against real keychains. An opt-in live test for macOS Keychain and Windows Credential Manager is wired into CI with no result recorded yet; Linux Secret Service has no live coverage.

## Managed runtime isolation

In managed mode the branded command removes ambient credential variables from its own environment before Pi starts, so Pi, its tools, and child processes do not inherit them. This covers names containing `API_KEY`, `ACCESS_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, or `AUTH`, and common provider prefixes such as `OPENAI_`, `ANTHROPIC_`, `AWS_`, `AZURE_`, `GOOGLE_CLOUD_`, `GITHUB_TOKEN`, and `PI_`. Declared runtime variables, `SSH_AUTH_SOCK`, and `GPG_AGENT_INFO` are kept. Proxy variables are also removed when `network.proxy.inheritEnvironment` is false. `--smoke` reports the removed names, never values.

The managed Pi `ModelRuntime` uses an in-memory credential store and no `models.json` or `auth.json`, so personal Pi auth under `~/.pi` or the distribution's `agent/` is not read. PiShip registers one provider, named after the app ID, for the declared gateway. Only allowed models are listed, selectable, authorized, or callable; built-in, environment, file-based, and extension-registered providers receive no credentials; Pi's provider `login` and `setRuntimeApiKey` are refused. A resumed session on a model that is no longer allowed is switched to the resolved model with a visible notice.

Model governance is not containment. Extensions run in-process with the user's privileges: they can read files, spawn processes, and make their own network requests. PiShip does not isolate them from the credential while a request is in flight.

## Network and TLS

PiShip-managed requests (OIDC, broker, gateway probes) use a managed fetch:

- TLS verification is always on. A launch with `NODE_TLS_REJECT_UNAUTHORIZED=0` fails with `TLS_POLICY_VIOLATION`, and the manifest cannot disable verification.
- Plain HTTP is accepted only for loopback hosts, intended for local fixtures. Endpoint URLs may not embed credentials, query strings, or fragments.
- `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` are honored when inherited. `network.tls.additionalCA` bundles are added to, never replace, the default roots.
- With `network.privateOnly`, only the declared issuer, broker, and gateway hosts and `network.allowHosts` may be contacted; anything else fails with `NETWORK_DENIED`. OIDC endpoints that discovery returns on other hosts must be listed in `allowHosts`.
- Redirects are not followed.

The proxy, CA, and `privateOnly` policy is also applied to the Pi process's default HTTP dispatcher, so Pi's provider requests and extensions' in-process `fetch` calls to undeclared hosts fail too. It does not cover raw sockets, other HTTP clients, Pi tools such as `bash`, or child processes; it is not an egress firewall.

## Logout and revocation

`logout` revokes the runtime credential at the broker's revoke endpoint when one is declared, revokes identity refresh and access tokens at the provider's revocation endpoint when discovery advertises one, then deletes local secrets, including any orphaned or pending generations, and metadata. Revocation failures are reported as warnings, and local clearing still happens. Sessions and preferences are kept. `purge` removes PiShip-owned state files but cannot revoke credentials; run `logout` first. Credentials that PiShip does not manage, such as Pi-native provider auth, may need manual revocation.

## Not covered

PiShip does not provide an OS or process sandbox, a policy engine for tools, projects, or MCP, audit logging, artifact signing or provenance, or an update channel. Credential safety across a rollback to an older payload is future work. Report vulnerabilities through [SECURITY.md](../SECURITY.md).
