# Security architecture

Upstream Pi runs the agent. PiShip validates distribution inputs, locks declared resources and package identities, and verifies packaged file hashes before entering Pi. A distribution's extensions are executable code with the user's process privileges. For `piship/v1alpha3` distributions PiShip also governs what loads and what tools may do, and can run tool subprocesses and MCP stdio servers inside an OS sandbox (see [Governance](#governance)). The Pi process itself is never sandboxed.

## Payload and state

The installer owns only its receipt, installed payload, and command shim. Existing install, command, and state collisions fail by default. `uninstall` preserves `~/.piship/<id>`; `purge <id> --yes` removes that one distribution's state after uninstall. The payload is separate from mutable config, sessions, cache, logs, credential metadata, and other runtime data. There is no shared runtime cache.

Pi receives a dedicated agent directory, user and acceptance session directories, in-memory settings, and a loader with ambient extension, skill, prompt, theme, and context discovery disabled. Only declared resources are packaged. Packaging rejects symlinks in resource roots, nested files, and adapter paths. For v1alpha1 and v1alpha2 distributions, project files remain accessible to Pi tools and trusted extensions, and PiShip does not enforce project trust or tool policy.

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

PiShip-managed requests (OIDC, broker, gateway probes, Streamable HTTP MCP servers, and HTTP audit sinks) use a managed fetch:

- TLS verification is always on. A launch with `NODE_TLS_REJECT_UNAUTHORIZED=0` fails with `TLS_POLICY_VIOLATION`, and the manifest cannot disable verification.
- Plain HTTP is accepted only for loopback hosts, intended for local fixtures. Endpoint URLs may not embed credentials, query strings, or fragments.
- `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` are honored when inherited. `network.tls.additionalCA` bundles are added to, never replace, the default roots.
- With `network.privateOnly`, only the declared issuer, broker, and gateway hosts and `network.allowHosts` may be contacted; anything else fails with `NETWORK_DENIED`. OIDC endpoints that discovery returns on other hosts must be listed in `allowHosts`.
- Redirects are not followed.

The proxy, CA, and `privateOnly` policy is also applied to the Pi process's default HTTP dispatcher, so Pi's provider requests and extensions' in-process `fetch` calls to undeclared hosts fail too. It does not cover raw sockets, other HTTP clients, or child processes; it is not an egress firewall. Child processes are covered only by the OS sandbox's `deny` or `allow` network mode.

## Governance

A `piship/v1alpha3` launch opens a governance session before Pi starts (see [architecture](architecture.md#governed-launch-flow)). Every mandatory control that cannot be established fails the launch; nothing silently falls back to an ungoverned run. Every decision names its enforcement plane:

| Plane | Meaning | Actions |
| --- | --- | --- |
| `control-plane` | PiShip decides before the action runs, inside the Pi process | Model use, resource and extension loading, MCP server start and tool calls, tool calls; file access through the governed `read`, `write`, and `edit` tools and shell command gating when no sandbox is enforced |
| `sandbox` | An OS sandbox proven by a live probe also contains the action | `filesystem.*` and `shell.execute` when the sandbox is enforced; `network.connect` when it is enforced in `deny` mode |
| `audit-only` | Observed at best; never reported as prevented | `network.connect` without an enforced deny sandbox, `web.request`, `browser.execute` |

`policy explain` prints the plane for any action and resource. This release has no runtime hook for `network.connect`, `web.request`, `browser.execute`, `agent.invoke`, or `memory.*`. A non-builtin capability provider whose capability is effective is also decided as `provider.load` (the provider ID) and `extension.load` (`<class>:<path>`) before its extension loads; a denial skips the provider, records `provider.denied`, and makes the capability not effective.

### Policy precedence

For each request the policy engine takes the first matching rule of each layer and applies the strictest effect (`deny` over `ask` over `allow`):

1. Distribution Enforced (`policy.enforced`).
2. Team and project rules (`policy.adapter` and the project's `.piship/policy.json`): narrowing only; their `allow` rules are ignored and reported.
3. Distribution Defaults (`policy.defaults`), or
4. a matching User rule from `<state>/config/policy.json`, which takes the default's place.

When nothing matches, `policy.default` applies. A user may relax a default but never an enforced rule, and no team or project file can widen anything. `ask` needs an approval channel: before Pi starts, a y/N prompt on an interactive terminal; during a session, Pi's confirmation dialog. Headless runs (`--smoke`, piped input, no UI) have no channel, so `ask` resolves to deny. Denials name the policy, rule, and reason.

### Tools, shell, and Plan mode

Governed sessions start Pi without its built-in tools and supply governed `read`, `write`, `edit`, and `bash` tools built from Pi's public tool definitions, so Pi's rendering and diff behavior stay upstream. Every tool call is decided as `tool.execute` in Pi's `tool_call` hook.

- `read`, `write`, and `edit` run in the Pi process. Each file access is decided on both the path as given and its symlink-resolved target, and the stricter decision wins. The file is then opened at the decided target without following a final symlink, and reads and writes go through that open file only. On Linux the path of the opened file is decided again when it differs; elsewhere the opened file must be the same file (device and inode) as the decided target, or the access fails (`piship.path-changed`), so a symlink or directory swapped in after the decision is not followed. A write that creates a file may leave it empty at the swapped location before this check refuses it. When the sandbox is enforced, its profile is also applied to these in-process tools: read-denied paths are refused and writes must land in a write-allowed path.
- Whatever the policy and sandbox level, these tools never read or write the distribution state directory (`piship.state`), and never write the project's git files that decide its origin: `.git`, `.git/config`, and the `config` and `commondir` of the git directory a `.git` file points to (`piship.project.git-config`). Shell commands are not covered by this built-in rule; an enforced sandbox limits them to its write allowlist.
- `bash` commands and user `!` commands are decided as `shell.execute`, then run inside the OS sandbox when it is enforced. Without an enforced sandbox they run as Pi would run them, and the decision covers only the command text. A command-text rule is pattern matching, not containment: without a sandbox a permitted command can still read or write any file the user can. An `allow` or `ask` rule such as `git *` is a prefix hint: it does not match a command containing a shell metacharacter (`;`, `&`, `|`, `$`, `` ` ``, `<`, `>`, `(`, `)`, a line break, or cmd.exe's `^` and `%`) unless the rule's pattern spells out that character, so `git status; rm -rf ~` or `git $(id)` falls through to the next rule or `policy.default`. A bare `**` pattern means every command. `deny` rules match regardless.
- Plan mode (the builtin `workflow` capability) blocks the `write`, `edit`, and `bash` tools, all file writes, and user `!` commands until the user switches with `/build`. Reads, MCP tools, and `ask_user` stay available. Plan mode is a control-plane restriction on PiShip's governed tools; it does not restrict extension code.
- The selected model is decided as `model.use` before the session starts; models the policy denies, or that need approval not yet given, are not offered for switching.

### Project trust

PiShip classifies the working project as company, external, or unknown from its git origin remote or path and decides each project item by its trust dimension ([manifest](manifest.md#policy)). Pi's own project discovery stays disabled; only admitted items are handed to Pi's loader. Every candidate is symlink-resolved: a target outside the project root is evaluated as unknown origin, and executable items (skills, agents, hooks, extensions, MCP, providers) that leave the root are denied. Instruction `@path` imports must resolve inside the root and are followed at most five levels. A dangling link is reported as denied. This release never loads project agents, hooks (`.pi/settings.json`), or capability providers. Project `.mcp.json` servers are used only in personal `explicit` MCP mode with `mcp.project: allow`, never receive the runtime credential, and cannot replace a declared server.

The origin remote is read from the project's own git configuration, which anyone who can write the checkout controls. A `remote` matcher alone is a claim, not proof: a clone of any repository can declare a company remote. Managed distributions should combine `remote` with `path` in one matcher (both must match), so only checkouts under a managed location count as company projects. The governed file tools refuse to rewrite these git files; an enforced sandbox's write allowlist limits shell commands.

### Certified resources and providers

A certified resource's tree digest is checked against its reviewed `integrity` at lock time and recomputed from the installed payload at launch; a mismatch fails the launch with `INTEGRITY_FAILED`. A certified resource reviewed for another Pi version or platform is not loaded. Certified and non-builtin provider trees with npm install-time scripts or a `binding.gyp` (an implicit `node-gyp rebuild`) are rejected at lock time. Non-builtin capability providers load only when their trust class is allowed and their files match the lock. `user` resources and providers are denied by default in managed mode. Certification is a digest match against reviewed evidence, not a signature.

### MCP

MCP servers are declared in the manifest and started by PiShip, not by an extension.

- Each server start is authorized as `mcp.server.start` before anything is spawned or contacted. A denied or failing server is reported; a `required` one fails the launch.
- `initialize` must negotiate a supported protocol version (`2025-06-18`, `2025-03-26`, or `2024-11-05`), and `expectedServerName` must match when declared.
- A tool is offered to the model only when the manifest's `tools` lists admit it and the policy does not always deny `<server>:<tool>`. A denied tool is never offered, and a call to it never reaches the server.
- Every call is authorized again when it happens (manifest lists, then policy with approval for `ask`); an authorization error is a denial. Results are redacted and capped at 256 KiB.
- stdio servers run in the project root with only their allowlisted and fixed environment variables; credential-looking names are stripped. When the sandbox is enforced they run inside it, with the same filesystem, network, and environment profile as tool subprocesses.
- Streamable HTTP servers use the managed fetch, do not follow redirects, and receive the runtime credential as a bearer only with `credential: runtime`.

### Audit

Audit is metadata first. Events (`piship-audit/v1`) record the event type, time, identity subject (never a token), session, distribution, and, where relevant, the resource, decision, policy, rule, and enforcement plane. File access is recorded as a path class (`workspace`, `tmp`, `home`, or `other`), shell commands by tool and byte length, and MCP calls by `<server>:<tool>`, outcome, and duration. Prompt, response, command, and source content are recorded only for classes the distribution opts in to under `audit.capture`, and are redacted. The file sink writes `<state>/logs/audit.jsonl` (0600 in a 0700 directory); HTTP sinks POST `piship-audit-batch/v1` batches through the managed fetch. Local counters for denials, startup failures, sandbox level, and MCP health are kept in `<state>/logs/metrics.json`.

| Sink | Condition | Result |
| --- | --- | --- |
| Required | Cannot be opened (file) or reached (empty-batch probe, HTTP) at launch | Launch fails with `AUDIT_UNAVAILABLE` |
| Required | Delivery fails | Events stay buffered and are retried; governed actions continue |
| Required | Buffer full while delivery keeps failing | New events are dropped and counted; governed actions fail closed with `AUDIT_UNAVAILABLE` until the buffer drains |
| Optional | Cannot be opened, delivery fails, or buffer full | Sink is degraded; affected batches or events are dropped and counted; governed actions continue |
| Any | Close deadline passes | In-flight delivery is aborted; optional batches count as dropped, required ones stay pending |

`doctor` reports each sink's state and delivered, pending, and dropped counts. Login and logout events are recorded best effort, so signing out still works while a company sink is down.

### OS sandbox

The OS sandbox is activated only when `sandbox.required: true`. PiShip then selects the platform adapter and runs a live probe inside it: a child must fail to write outside the write allowlist, fail to read denied paths, see only allowed environment variables, and, in `deny` mode, fail to reach an external address and a host loopback listener. Only planes the probe proved are reported as enforced. If the adapter is missing or the probe fails, the launch fails with `SANDBOX_UNAVAILABLE`; there is no unsandboxed fallback. The distribution state directory is always read-denied; the installed payload stays readable; `tmp` is a private per-session directory.

| Platform | Adapter | Status |
| --- | --- | --- |
| Linux | bubblewrap (`bwrap`): read-only host root, private `/tmp`, bind-mounted write paths, denied paths replaced by empty mounts, all namespaces unshared (network shared only in `allow` mode), capabilities dropped, environment cleared to the allowlist. Session-bus and container-daemon sockets are hidden in every mode | Verified with the live probe. Needs bubblewrap and unprivileged user namespaces |
| macOS | Seatbelt through `/usr/bin/sandbox-exec` with a generated profile: writes denied outside the allowlist, denied paths unreadable and unwritable, `(deny network*)` in `deny` mode, and launches that launchd would start outside the sandbox denied (`lsopen`, Apple events, the LaunchServices and Apple event services, and `/bin/launchctl`), so `open` and `osascript` cannot start an unsandboxed process | Implemented; verification depends on the CI sandbox probe |
| Windows | None | No adapter: a required sandbox fails closed with `SANDBOX_UNAVAILABLE` |

### Limits

- The Pi process and in-process extensions are not contained. Company, certified, and user extension code runs with the user's privileges, can read files, spawn processes, and use the network directly, and can bypass Pi's `tool_call` hook and PiShip's governed tools. Trust classes and certification decide what loads; they do not sandbox it.
- The sandbox network contract is `deny` or `allow` only. There are no hostname allowlists at the OS boundary. In `allow` mode, host loopback services and abstract Unix sockets are reachable.
- Filesystem denies are path based. An existing hard link to a denied file in a readable location stays readable.
- There is no seccomp or system-call filtering.
- Machine administrators, and anyone who can modify the installed payload, state, or inventory, can defeat these controls. Governance does not protect against them or against a malicious extension a distribution chose to load.

## Logout and revocation

`logout` revokes the runtime credential at the broker's revoke endpoint when one is declared, revokes identity refresh and access tokens at the provider's revocation endpoint when discovery advertises one, then deletes local secrets, including any orphaned or pending generations, and metadata. Revocation failures are reported as warnings, and local clearing still happens. Sessions and preferences are kept. `purge` removes PiShip-owned state files but cannot revoke credentials; run `logout` first. Credentials that PiShip does not manage, such as Pi-native provider auth, may need manual revocation.

## Not covered

PiShip does not contain the Pi process or in-process extensions, enforce hostname-level egress for child processes, filter system calls, sign artifacts or attest provenance, or provide an update channel. v1alpha1 and v1alpha2 distributions have no tool policy, OS sandbox, MCP governance, or audit log. Credential safety across a rollback to an older payload is future work. Report vulnerabilities through [SECURITY.md](../SECURITY.md).
