# Sandbox backends

**PiShip owns policy and governance. The sandbox backend owns execution isolation.**

A distribution chooses where contained commands run: the built-in OS sandbox, a company's own sandbox, an E2B-compatible service, or Kubernetes Agent Sandbox. All of them sit behind one contract in `@piship/sandbox`. Whichever backend is used, PiShip decides every action before it runs, filters what the backend receives, keeps credentials, audit, and policy on its side, and owns the timeout and cancellation of every command.

```text
PiShip Sandbox Contract
├─ native
│  ├─ Linux bubblewrap
│  └─ macOS Seatbelt
├─ custom adapter
│  └─ company internal sandbox
├─ e2b-compatible
│  ├─ E2B
│  └─ CubeSandbox
└─ kubernetes-agent-sandbox
```

| Provider | Runs commands | Guarantees reported | Workspace | Contains MCP stdio servers | Verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `native` (default) | Local processes inside bubblewrap (Linux) or Seatbelt (macOS) | `filesystem-read-deny`, `filesystem-write-allowlist`, `network-deny` (deny mode), `environment-filter`, `git-control-protection` | `shared` (this host's files) | Yes | Live probe | Linux and macOS: candidate, with the boundary and escape tests below. Windows: unavailable, there is no adapter |
| `custom` | Wherever the company adapter runs them | What the adapter declares, checked against the policy | What the adapter declares, verified before the first command | Only a local adapter that wraps processes | Live probe for a local wrapping adapter; otherwise backend-attested | Preview. Contract and lifecycle tested with fake adapters. PiShip ships no company adapter; the [reference container sandbox](../examples/enterprise-reference/sandbox/README.md) is a working example with a `shared` workspace, tested against real containers |
| `e2b-compatible` | In a remote sandbox created through the E2B API | `host-filesystem-isolation`, `network-deny` (deny mode), `environment-filter` | `snapshot` | No | Backend-attested | Preview. Tested against a mock E2B server; no live E2B or CubeSandbox evidence |
| `kubernetes-agent-sandbox` | In a sandbox pod claimed from a warm pool | `host-filesystem-isolation`, `environment-filter` | `snapshot` | No | Backend-attested | Preview. Deny mode fails closed until the adapter can verify the warm pool's network policy; no live cluster evidence |

The Status column is a summary. Maturity is recorded per backend on the [status page](status.md#sandbox-backends), which is authoritative, and it does not change which Pi surface a release records.

A report never claims more than the backend enforces. The `filesystem-read-deny` and `filesystem-write-allowlist` planes mean that `sandbox.filesystem.read.deny` and `sandbox.filesystem.write.allow` are enforced on the commands. `host-filesystem-isolation` means something narrower and different: commands run on another machine or VM and cannot reach this host's files at all. It is not PiShip's path policy. Inside the remote sandbox, what a command may read or write is up to the template or image, and the path rules still govern PiShip's local file tools. The E2B and Kubernetes backends therefore report `host-filesystem-isolation` and never the `filesystem-*` planes, and `doctor` says that the path rules are not enforced inside the remote sandbox. A remote backend whose sandbox mounts or syncs the developer's workspace reaches this host's files through it, so it cannot claim `host-filesystem-isolation`; it claims `workspace-confinement` and `git-control-protection` instead ([Workspace](#workspace)).

## Configuration

Only `sandbox.required: true` activates a sandbox, and a non-native provider is accepted only when the sandbox is required. A backend that cannot be used fails the launch with `SANDBOX_UNAVAILABLE`; there is no fallback to another backend or to running uncontained. The `filesystem`, `network`, and `environment` fields ([manifest](manifest.md#sandbox)) apply to every provider. A declared `filesystem.read.deny`, `filesystem.write.allow`, or `environment.allow` replaces its default list instead of extending it, so restate the defaults you want to keep. A `policy.enforced` `filesystem.read` deny refuses Pi's file tools only: a command (`cat .env` in `bash`, or a user's `!` command) reads files through the sandbox, so list the directory in `filesystem.read.deny` too. `piship validate` warns about an enforced read deny that no `filesystem.read.deny` directory covers; a pattern such as `**/.env` has no directory to list, so the warning stays.

```yaml
sandbox:
  required: true
  provider: native          # the default
```

```yaml
variables: [SANDBOX_ENDPOINT]
sandbox:
  required: true
  provider: e2b-compatible
  endpoint: ${SANDBOX_ENDPOINT}   # E2B API URL, or a CubeSandbox API URL
  template: piship-workspace      # default: base
  workdir: /home/user/repo        # default: /home/user (a remote workspace: /home/<user>/workspace)
  credential: stored              # default: none; see Credentials below
```

CubeSandbox implements the same API but runs commands as `root`, so a CubeSandbox distribution sets the user explicitly. PiShip never detects the vendor:

```yaml
variables: [CUBE_API_URL]
sandbox:
  required: true
  provider: e2b-compatible
  endpoint: ${CUBE_API_URL}       # the CubeSandbox API URL
  template: piship-workspace
  user: root                      # CubeSandbox; E2B keeps the default, user
  workspace: remote               # the project goes into /root/workspace, which PiShip creates empty
```

Under a private-only network policy (every managed launch), list the API host in `network.allowHosts`, for example `allowHosts: [api.cube.corp]`; the per-sandbox envd hosts under its domain need no entry ([Credentials](#credentials) describes which names are accepted).

Without `workspace: remote`, the template or image must already hold the code, so set `workdir` to the directory that holds it (for example `/root/repo`). With `workspace: remote` leave `workdir` unset, or point it at a directory the template leaves empty: the seed refuses a project directory that already holds files.

```yaml
variables: [KUBE_API_URL, SANDBOX_ROUTER_URL]
sandbox:
  required: true
  provider: kubernetes-agent-sandbox
  endpoint: ${KUBE_API_URL}          # Kubernetes API, or an authenticating proxy to it
  router: ${SANDBOX_ROUTER_URL}      # the sandbox router
  namespace: agents                  # default: default
  template: python-sandbox-pool      # SandboxWarmPool to claim from
  network:
    mode: allow                      # required: this backend cannot enforce deny
```

```yaml
sandbox:
  required: true
  provider: custom
  adapter: ./sandbox/acme-sandbox.mjs   # packaged and locked like other adapters
  endpoint: https://sandbox.acme.example # optional, passed to the adapter
```

| Field | Providers | Meaning |
| --- | --- | --- |
| `provider` | all | `native` (default), `custom`, `e2b-compatible`, or `kubernetes-agent-sandbox` |
| `adapter` | `custom` | Module path (`./...`, `.mjs` or `.js`) whose default export is a factory returning a backend |
| `endpoint` | remote and `custom` | Control endpoint URL or `${NAME}` [runtime reference](manifest.md#runtime-references). HTTPS, or HTTP to loopback or to a private or internal host, unless `httpTransport: https` or `credential: runtime` |
| `router` | `kubernetes-agent-sandbox` | Sandbox router URL or `${NAME}` reference |
| `httpTransport` | remote and `custom` with an `endpoint` | piship/v1alpha6: `https` forces HTTPS-only; `http-allowed` (the default) also accepts plain HTTP to a private or internal host for `endpoint` and `router` (and an e2b-compatible backend's command host `<port>-<id>.<domain>` on port 80 under the endpoint's domain, matched by name; an IP-literal endpoint cannot reach it over plain HTTP). Always https with `credential: runtime`; otherwise commands, output, files, and a `stored` credential then travel unencrypted ([security](security.md#plain-http-to-internal-endpoints)) |
| `namespace` | `kubernetes-agent-sandbox` | Namespace of the SandboxClaims |
| `template` | `e2b-compatible`, `kubernetes-agent-sandbox` | E2B template ID, or the SandboxWarmPool name |
| `workdir` | `e2b-compatible`, `kubernetes-agent-sandbox` | Absolute remote directory that maps to the workspace. Default for `e2b-compatible`: `/home/user`; with `workspace: remote` and `e2b-compatible`, `/home/<user>/workspace` (`/root/workspace` for `root`), created empty. Default for `kubernetes-agent-sandbox`: the runtime's working directory in the pod |
| `user` | `e2b-compatible` | The sandbox user commands run as (envd's `Authorization: Basic <user>:`). Default `user`, as E2B expects; CubeSandbox is expected to need `root` (not verified against a live CubeSandbox). Without `workspace: remote` the default `workdir` stays `/home/user`, so set `workdir` together with `user` (for example `/root/repo`); with it, the default follows the user |
| `lifetimeSeconds` | `e2b-compatible`, `kubernetes-agent-sandbox` | piship/v1alpha6: how long the sandbox lives, 1 to 86400 seconds (default 3600). It is renewed while the session uses it (four times per lifetime for a remote workspace, even when idle), so this is the idle time after which an abandoned sandbox disappears |
| `workspace` | `e2b-compatible` and `custom` | piship/v1alpha6: `remote` makes the sandbox hold the only live copy of the project; the host working tree changes only through `<command> sandbox pull` ([Remote workspace](#remote-workspace)). Omitted keeps today's behavior. `native` and `kubernetes-agent-sandbox` fail `validate` |
| `credential` | remote and `custom` | `none` (default), `runtime` (the inference runtime credential, only on its origin), or `stored` (the sandbox credential stored with `sandbox login`, bound to the user and the endpoint origins; needs `endpoint`); see [Credentials](#credentials) |

Fields that do not apply to the chosen provider are rejected. There is no field for an API key: secrets are never written in `piship.yaml`, and runtime references cannot name secret-looking variables. A release whose manifest uses `credential: stored` can be installed by `update` only from a release that already knows the value: adopt it one release after the PiShip upgrade.

### Credentials

`sandbox.credential` says what, if anything, PiShip sends to the sandbox service. The manifest names only the source; there is no field for a secret.

| Value | What is sent | To where |
| --- | --- | --- |
| `none` (default) | Nothing | — |
| `runtime` | The **inference** runtime credential the company broker issues for the LLM gateway | Only when every URL it would reach (the endpoint, and for Kubernetes the router) is on the inference gateway's origin, the rule [MCP servers](security.md#mcp) follow; otherwise activation fails closed |
| `stored` | The sandbox credential a person stored with `<command> sandbox login`: an API key (e2b-compatible, `X-API-Key`) or a bearer token (Kubernetes, `Authorization: Bearer`; a custom adapter receives it as is) | Only to the origins (scheme, host, port) of the endpoint, and for Kubernetes the router, it was stored for, and only for the user who stored it |

A custom adapter can also bring its own credential: see [adapter credentials](#adapter-credentials).

**Storing it.** `<command> sandbox login` resolves the endpoint (and router) from the runtime variables, reads the secret, and stores it; it does not contact the service, so the next launch proves it. The secret is read only from a prompt on stderr that does not echo, or from the first line of standard input when it is piped, so it never reaches argv, the environment, shell history, the model context, or Pi session files. There is no `--secret` flag, no environment variable, no file, and no command inside a session. Provision it from a secret manager, never with `echo <key> |` (that puts it in shell history):

```sh
secret-tool lookup service acme-sandbox | acme sandbox login     # Linux
security find-generic-password -s acme-sandbox -w | acme sandbox login   # macOS
acme sandbox login                                               # prompts
```

The value must be 8 to 4096 visible ASCII characters: no space, CR, LF, NUL, or other control character. With identity configured, `sandbox login` needs a signed-in user, and the credential is bound to that principal; without identity it is bound to nobody. It is kept in the distribution's configured secret store (`access.credential.storage`, else the platform store). A distribution whose inference credential is `pi-native` or `none` cannot configure a store, so its sandbox credential uses the platform store only and fails with `SECRET_STORE_UNAVAILABLE` where there is none; there is no plaintext fallback for it. `sandbox login` again replaces it; `sandbox logout` deletes it. The user is checked again, holding the locks, when the secret is stored: a user who signed out or was replaced while `sandbox login` waited for the secret stores nothing (`IDENTITY_REQUIRED`), and `logout` deletes the sandbox credential after the identity, so one stored just before it is deleted too.

**Using it.** Before the secret is read at launch (and by `doctor`, which creates a sandbox the same way), PiShip checks the stored metadata:

- It must belong to the launch's principal. One bound to another user, or stored without identity once an identity is configured, is deleted (every generation, each deletion confirmed) and the launch fails with `SANDBOX_UNAVAILABLE` ("belonged to another user"); a deletion that cannot be confirmed fails with `SECRET_STORE_UNAVAILABLE` and leaves a discarded marker that nobody can use. Only the signed-in user's launch deletes: a session of a user who has since signed out, or been replaced by another user, fails with `IDENTITY_REQUIRED` and deletes nothing, so it cannot remove the new user's credential.
- Every URL the backend would send it to must be one of the origins it was stored for. The endpoint usually comes from a runtime variable, which whoever launches the process controls; pointing that variable at another host fails the launch closed and sends nothing.
- A credential the service rejected is refused, and the user is asked to run `sandbox login` again.

The e2b-compatible backend sends it to the control endpoint only, never to envd (which uses the per-sandbox access token); the Kubernetes backend sends it to the API and the router. When one of those origins answers 401, the stored credential is marked rejected and the request is not repeated. A 403 is an authorization denial, not a rejection: the credential was accepted and a policy refused the request (for example Kubernetes RBAC denying the namespace, claim creation, or router execution). It leaves the credential as it is, and the command or activation fails with an error that names HTTP 403 and carries the service's answer with any credential redacted; replacing the credential would not fix it. A running session re-reads the metadata before every request: when another user signs in, or the credential is replaced or deleted, the session stops using it without deleting anything; the same user's new credential is used from the next request.

**Clearing it.** `login` as another principal deletes it, confirming the deletion, before the new identity is stored; a failed deletion fails the login. `logout`, `sandbox logout`, and `purge` delete it. An update or rollback to a release that cannot read it (every release before it) deletes it first; run `sandbox login` again after rolling forward. It is never copied into a rollback snapshot. See [security](security.md#user-switching).

**Checking it.** The Sandbox group of `doctor` shows `sandbox credential <state> (<source>, <kind>) in <store>`, where the state is `absent`, `valid`, `rejected`, `principal-mismatch`, or `origin-mismatch`, and two binding lines: whether it is bound to the current principal, and whether its recorded origin matches the configured endpoint. A rejected credential is a warning that asks for `sandbox login`; an absent one, another user's, or one stored for another endpoint fails a required sandbox. Without a signed-in user, the principal binding is shown as not checked. Doctor reads the non-secret metadata only: it never shows the secret, its reference or ID, or the recorded origins, and it deletes nothing (the next launch does).

A stored key is typed by a person and is often a shared organization key. For managed distributions, prefer credentials the company issues per user: `runtime` behind the gateway, or an adapter credential.

#### Adapter credentials

A custom adapter module may export `sandboxCredential`, a standard `CredentialProvider` (`acquire`, optional `refresh` and `revoke`), next to its factory. PiShip then acquires it at launch with the signed-in identity, holds it in memory for that process only (never in the secret store, state, snapshots, or migration), renews it before it expires and once after a rejection, repeats the one request that created nothing with the renewed credential, and revokes it, best effort, when the session ends. The identity it passes must stay the launch's principal. The factory receives it as `credential`, with `credentialOrigins` (the declared endpoint's origin) and `credentialRejected`. Exporting `sandboxCredential` while the manifest also declares `sandbox.credential` fails closed: a backend gets one credential. A failure to provide it is `SANDBOX_UNAVAILABLE` (component `sandbox`) that keeps the adapter error's `retryable` and `retryAfterMs`, so an outage or rate limit of its token source asks to try again later; its message and `detail` keep only the adapter's error code (`adapterCode`) and the bounded `reason`, `status`, and `outcome` of the credential failure contract, never the adapter's own text. Short-lived and workload credentials (such as an in-cluster service account token) come this way; the built-in backends take only `stored`.

Without a credential PiShip can send, use `credential: none` with an endpoint that needs no client credential, such as `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy.

PiShip calls remote backends through its managed fetch, so the proxy, CA, and `network.privateOnly` settings apply. With `privateOnly` (every managed launch), the endpoint's host must be declared in `network.allowHosts`. E2B's data plane uses one host per sandbox (`49983-<id>.<domain>`), whose name exists only once the sandbox does, so the e2b-compatible backend's own requests also accept exactly that form: `49983-` and a sandbox ID as the first label, then the declared endpoint's host without a leading `api.` (an endpoint of `https://api.cube.corp` admits `49983-<id>.cube.corp`; `api.` stays when only one label would remain, so `https://api.internal` admits `49983-<id>.api.internal`, never `49983-<id>.internal`), on the endpoint's scheme and either the default port or the endpoint's own. A `domain` the service returns that differs from that, a nested or lookalike name, another port label, and an IP-literal endpoint are refused. The allowance holds for the sandbox backend only: agent tools, extensions, and every other request still need the host in `allowHosts`.

#### The E2B API an e2b-compatible service must answer

PiShip has been tested only against a mock E2B server. An operator of another E2B-compatible service, such as CubeSandbox, can check it against the calls the backend makes (`packages/sandbox/src/remote/e2b.ts`).

Control plane, at `sandbox.endpoint`. Only these requests carry the stored credential, as `X-API-Key`:

| Request | Body sent | What PiShip reads |
| --- | --- | --- |
| `GET health` | — | Any 2xx means available |
| `POST sandboxes` | `templateID` (`sandbox.template`, default `base`, or a snapshot ID), `timeout` (`lifetimeSeconds`), `metadata`, `allow_internet_access` (false in deny mode) | `sandboxID` (letters, digits, `-`), optional `domain` (else the endpoint's host without a leading `api.`), optional `envdAccessToken` |
| `POST sandboxes/<id>/timeout` | `timeout` | 2xx renews; 404 or 410 means the sandbox expired |
| `POST sandboxes/<id>/snapshots` | `memory: false` | `snapshotID`. 404, 405, or 501 means snapshots are unsupported (remote workspace cache only) |
| `DELETE templates/<snapshot id>` | — | 2xx or 404 |
| `DELETE sandboxes/<id>` | — | Best effort at session end |

envd (data plane), at `<scheme>://49983-<sandboxID>.<domain>`, the endpoint's scheme on its default port. Every request carries `E2b-Sandbox-Id: <sandboxID>`, `E2b-Sandbox-Port: 49983`, `Connect-Protocol-Version: 1`, and `X-Access-Token: <envdAccessToken>` when the service returned one; the control-plane key is never sent here. Command and file requests also carry `Authorization: Basic <base64 of "<sandbox.user>:">`.

| Request | Protocol | Use |
| --- | --- | --- |
| `POST process.Process/Start` | Connect server stream (`application/connect+json`); runs `/bin/bash -l -c <command>` with `envs`, `cwd`, and a `tag` | stdout and stderr (base64) and the exit code |
| `POST process.Process/SendSignal` | Connect unary JSON, `{process: {tag}, signal: "SIGNAL_SIGKILL"}` | Cancelling a command |
| `GET /files?path=<absolute>&username=<user>` | Raw bytes | Reading a file; 404 means it does not exist |
| `POST /files?path=<absolute>&username=<user>` | `multipart/form-data`, one part named `file` | Writing a file, creating its parent directories |
| `POST filesystem.Filesystem/Stat` | Connect unary JSON, `{path}` | `entry.type` (`FILE_TYPE_FILE`, `FILE_TYPE_DIRECTORY`); 404 means it does not exist |

The file calls serve a remote workspace (`workspace: remote`).

## Lifecycle

```text
activate:  available() ──▶ capabilities() checked against the policy
           ──▶ prepare(profile) ──▶ verify (live probe, or outside check)
           ──▶ report: enforced | unavailable | not-required
command:   PiShip decides shell.execute ──▶ approved env + workspace path
           ──▶ instance.exec(request, {signal, onStdout, onStderr})
           ──▶ PiShip times out / cancels / reports the exit
session end: instance.dispose()
```

1. **Availability.** The backend reports whether it can be used now (the mechanism is installed, the endpoint answers its health check). A failure or an exception is unavailable.
2. **Capabilities.** The backend declares its isolation kind (`local` or `remote`), the guarantees it enforces, the network modes it can enforce, whether it can contain local processes, and, for a remote backend, how it sees the workspace. A required sandbox needs `environment-filter`, plus `network-deny` when `sandbox.network.mode` is `deny`, plus filesystem guarantees that depend on where commands run:

   | Isolation | Workspace | Required filesystem guarantees | Refused |
   | --- | --- | --- | --- |
   | `local` | `shared` by construction | `filesystem-read-deny`, `filesystem-write-allowlist` (`git-control-protection` is live-probed and reported, not yet required) | — |
   | `remote` | `snapshot` (the default) | `host-filesystem-isolation` | — |
   | `remote` | `shared` or `synchronized` | `workspace-confinement`, `git-control-protection` | a `host-filesystem-isolation` claim |

   The `filesystem-*` planes are not accepted in place of the remote guarantees, a local backend's `host-filesystem-isolation` and `workspace-confinement` are ignored, and a local backend's workspace declaration is ignored. A missing guarantee, a malformed declaration (including a malformed `workspace`), or a remote backend that claims `host-filesystem-isolation` with a shared or synchronized workspace fails closed before anything is created.
3. **Create or prepare.** The backend receives the resolved profile (paths, network mode, environment allowlist) and creates its sandbox: nothing for native, a sandbox for E2B, a SandboxClaim for Kubernetes.
4. **Verify.** A backend whose instance can wrap local processes is live-probed exactly like the native sandbox, including `git-control-protection`: a child must fail to write a protected file, to create a file in a protected directory, and to rename the directory that holds a protected file. Until that check has passed on Linux and macOS CI it is reported, not required: a local backend that fails it still activates, without the plane and with a warning. Any other backend is checked from outside: a command must run and report back, a marker variable PiShip set in its own source environment must not arrive (this confirms PiShip's filtering end to end; the backend's own environment plane is attested), and in `deny` mode the backend's [network probe](#network-denial), when it declares one, must be unreachable from inside. The report says which: `verification: live-probe` or `backend-attested`, and in `deny` mode `networkDenial` says whether network denial is `verified` or `attested`.
5. **Exec.** See below. For a remote backend with a shared or synchronized workspace, the first command that reaches the sandbox is preceded by the [workspace check](#workspace).
6. **Dispose.** Called once when the session ends, or right away when verification fails. A remote sandbox is deleted; E2B sandboxes also expire on their own after the renewed lifetime. The session's temporary directory is removed with it, and on normal process exit ([Temporary files](#what-piship-controls)).

`doctor` shows the backend, level, guarantees, and verification, the network mode with how its denial is known (`deny (verified)`, or `deny (attested by the backend, not verified: <reason>)`), and the isolation the containment report names: `local` for an enforced backend that runs commands on this host, `remote` for one that runs them on another machine, and `none` when nothing is enforced. Its Workspace group shows the effective consistency, the declared mode, the verification state, whether the workspace is a complete coding-agent workspace, and how the git control files are protected ([Workspace](#workspace)). The path policy counts as enforced by the backend only when it reports both `filesystem-read-deny` and `filesystem-write-allowlist`. Otherwise `doctor` adds that `sandbox.filesystem` path rules are not enforced inside the sandbox, or, when the backend reports only one of the two planes, that they are only partly enforced. The `--smoke` summary adds the provider, and local metrics record the level, the backend, and in `deny` mode `networkDenial` (`verified` or `attested`). `policy explain` and file-tool denials count filesystem actions as sandbox-enforced only with both path planes; otherwise they are `control-plane`, decided by PiShip for its local file tools.

## What PiShip controls

- **Policy and approvals.** Every `bash` and `!` command is decided as `shell.execute` before any backend sees it. File tools (`read`, `write`, `edit`) always run in the Pi process under PiShip's governed file access.
- **Environment.** A backend receives one command, its working directory, and the environment PiShip approved: the `sandbox.environment.allow` list, with credential-looking names always removed. A remote backend additionally never receives host-bound variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`); its own environment provides them. Nothing else is sent when a sandbox is created: no environment, no files, and no credential other than the declared control-plane credential.
- **Filesystem.** Without `workspace: remote`, PiShip does not upload or sync the workspace (with it, see [Remote workspace](#remote-workspace)). A remote backend runs commands in `workdir` plus the command's path relative to the workspace, and refuses a working directory outside the workspace. The template, image, or volume must provide the code. Local file tools and remote commands therefore see different copies unless the backend mounts or syncs the workspace, which it declares and PiShip verifies ([Workspace](#workspace)). The remote sandbox does not apply `sandbox.filesystem` path rules; they keep governing the local file tools.
- **Credentials.** A backend receives a credential only as `sandbox.credential` declares it (`runtime` or `stored`) or from its own adapter module, and only for the origins that credential may reach ([Credentials](#credentials)). It is read per request, never placed in a command's environment, and scrubbed from any error that echoes it. E2B's per-sandbox envd access token is used only for that sandbox's data plane and never leaves the process.
- **Timeout and cancellation.** PiShip starts the timer and listens to the user's cancel. On either, it aborts the signal it passed to the backend, stops forwarding output, and reports `timeout` or `aborted` whatever the backend returns afterwards. A backend that does not settle within five seconds is retired: its instance is disposed, and later commands in that session fail with `SANDBOX_UNAVAILABLE`. Native commands get SIGTERM, then SIGKILL of the whole process group after one second; disposing a native instance stops a command still running the same way and returns once it is gone (for two seconds at most), so nothing runs in the session temp directory the activation removes next. E2B commands get `SendSignal(SIGKILL)` for the command's tagged process, which works even before its pid is known; background processes it started in the sandbox are removed when the sandbox is. The Kubernetes runtime API cannot stop a running command, so a cancelled command retires its claim: the next command gets a fresh sandbox, and the retired claim is deleted once no other command still running in it needs it. A cancellation belongs to its own command: parallel commands that share the claim keep running in it, and the claim stays renewed until the last of them ends; a command cancelled while it waits for a claim to become ready stops waiting, and the claim is still created for the commands that wait with it (only disposing the session cancels its creation). If that DELETE fails, the claim's `shutdownTime` still removes it (see below); a failed cleanup is not logged and never exposes the command, environment, or credential.
- **Windows child processes.** Windows has no native sandbox adapter, but a child PiShip spawns itself (an MCP stdio server, for one) runs inside a kill-on-close Job Object, which bounds its process lifetime and isolates nothing. Three limits of that start-up path are known and not fixed in v0.7: a child that writes the startup-failure marker to its own stderr has that output dropped and its exit reported as a startup failure; the C# helper is compiled once per machine and kept, but a child started where it cannot be (no compiler, or a failed check) waits for a compile at each start, which adds latency; and the request carrying the child's command and approved environment travels in one environment variable, so one larger than Windows allows in a variable (documented as 32,767 characters; not measured here) cannot start the child ([security](security.md#limits)).
- **Temporary files.** An active sandbox gets a private session directory, `piship-sandbox-*` (0700) under the OS temp directory, and its `tmp` subdirectory is the `TMPDIR` of contained commands, so tool output can land there. Beside `tmp` the directory holds an owner marker that contained commands cannot reach, because they can write only in `tmp`. The directory is removed when the session ends and on normal process exit. SIGKILL, a machine reset, or power loss run neither, so the next sandbox activation, and the next launch of a distribution, remove it with everything in it once its process no longer exists; a running session's directory is never removed, and a directory that only shares the name, or has no marker, is never touched ([temporary directories](architecture.md#temporary-directories)). A sandbox that is not active makes no session directory. Removal moves the directory aside and checks it is the same real directory before it removes it, so a command that outlived the session cannot turn the removal into a deletion elsewhere. The live probe's scratch directory inside the session's `tmp` goes with it; the ones it makes outside the write allowlist (`.piship-probe-*`) are reclaimed by the next probe.

When a command in an enforced local sandbox fails on a denied path or host, PiShip appends one line after its output naming that path or host and the manifest key that decides it (`sandbox.filesystem.read.deny`, `sandbox.filesystem.write.allow`, `sandbox.network.mode`), or saying it is a [protected git path](#protected-git-paths). It reads the error the command printed: the path the error names, a relative one (`.git/config`, `../out`) resolved against the command's directory, and a refused lookup or connection (`ENOTFOUND`, Seatbelt's `connect EPERM`, `Network is unreachable`). A hidden or protected path counts wherever the line names it, and bubblewrap's `Device or resource busy` for a protected file it bound read-only is read as a denial too. A path the sandbox allows gets no line, so an ordinary permission error is not blamed on the sandbox.

MCP stdio servers need a local process with pipes. A backend that cannot contain local processes refuses them with `SANDBOX_UNAVAILABLE`, so such servers do not start; use Streamable HTTP servers with remote backends.

### Package caches, Go modules, and git over SSH

Recipes for three things that fail inside an enforced local sandbox. They follow from the code; the SSH one was not run end to end.

- **Package caches are per session.** `npm_config_cache`, `PIP_CACHE_DIR`, `GOCACHE`, and `CARGO_HOME` point into the session's temp directory, so every session starts with empty caches and the first install downloads again. This keeps `npm install`, `pip install`, and `cargo build` working without a writable `~/.npm` or `~/.cargo`. `CARGO_HOME` being redirected also means the command does not read `~/.cargo/config.toml` (mirrors, source replacement). A profile that makes `~/.cargo` writable keeps it.
- **Go modules.** `GOMODCACHE` is deliberately not redirected: Go makes its module cache read-only, which would stop the session temp directory from being removed. A `go build` with dependencies therefore needs `~/go/pkg/mod` in `sandbox.filesystem.write.allow`. The trade-off is that the module cache is then shared with your normal Go use and persists across sessions.
- **Git over SSH** does not work by default, for separate reasons: `~/.ssh` is in the default `sandbox.filesystem.read.deny`, `SSH_AUTH_SOCK` is not in the default `sandbox.environment.allow`, `deny` network mode blocks Unix sockets on macOS (see [egress coverage](#egress-coverage)), and on Linux bubblewrap mounts a private `/tmp` and hides `/run/user/<uid>`, where an agent socket usually lives. What works today: HTTPS remotes (with a token or credential helper whose files the sandbox may read), or running `git push` outside the sandbox. To use SSH inside it, set `sandbox.network.mode: allow`, add `SSH_AUTH_SOCK` to `sandbox.environment.allow`, and on Linux put the socket's directory in `sandbox.filesystem.write.allow` (a `/tmp` path there also turns the private `/tmp` off); to use a key file instead of an agent, remove `~/.ssh` from `sandbox.filesystem.read.deny`. Each of these widens what a contained command can reach: an agent socket lets it authenticate as you with every key the agent holds, a readable `~/.ssh` exposes the keys, and `allow` removes the network denial for everything else. None of this combination was tested.

## The contract

```ts
interface SandboxBackend {
  readonly id: string;                 // e.g. "linux-bubblewrap", "acme-sandbox"
  readonly provider: "native" | "custom" | "e2b-compatible" | "kubernetes-agent-sandbox";
  available(options?: { signal?: AbortSignal }): Promise<{ available: true } | { available: false; reason: string }>;
  capabilities(): {
    isolation: "local" | "remote";
    // filesystem-*: enforces the profile's readDeny and writeAllow paths.
    // host-filesystem-isolation (remote, snapshot only): cannot reach this host's files.
    // workspace-confinement (remote, shared or synchronized): reaches this host's
    //   files only through the workspace.
    // git-control-protection: profile.writeProtect cannot be changed from inside,
    //   also not through a sync engine.
    planes: ("filesystem-read-deny" | "filesystem-write-allowlist" | "network-deny"
      | "environment-filter" | "git-control-protection" | "host-filesystem-isolation"
      | "workspace-confinement")[];
    network: ("deny" | "allow")[];
    localProcesses: boolean;
    // Local only, optional: the isolator keeps a protected file that does not exist
    //   yet (.git/commondir, .git/config.worktree) from being created, as Seatbelt
    //   does and bubblewrap cannot. Omitted or false: git control is reported
    //   not-verified while such a file is missing where the sandbox may write.
    guardsMissingFiles?: boolean;
    // Remote only; omitted means snapshot. Ignored for local backends (shared).
    workspace?: {
      mode: "snapshot" | "synchronized" | "shared";
      propagationMs?: number;   // synchronized only: 1..60000, default 10000
      sentinelDir?: string;     // shared or synchronized only: workspace-relative
    };
    // Remote only, optional: a TCP endpoint the backend or its operator controls,
    //   reachable from an allow-mode sandbox of this backend. See Network denial.
    networkProbe?: { host: string; port: number };
  };
  prepare(request: { profile: SandboxProfile; signal?: AbortSignal }): Promise<SandboxInstance>;
}

interface SandboxInstance {
  exec(
    request: { command: string; cwd: string; workspacePath: string | undefined; env: Record<string, string> },
    io: { signal: AbortSignal; onStdout(chunk: Buffer): void; onStderr(chunk: Buffer): void },
  ): Promise<{ exitCode: number | null; signal?: NodeJS.Signals | null }>;
  wrap?(command: { file: string; args: string[]; cwd: string; env: Record<string, string> }): WrappedCommand;
  dispose(options?: { signal?: AbortSignal }): Promise<void>;
  // Optional: an opaque, non-secret id of the environment the last command ran in.
  epoch?(): string | undefined;
}
```

A backend never decides policy, never reads PiShip's state, and must pass `env` through as given. `exec` must stop when `io.signal` aborts. `wrap` is only for local backends: spawning the returned command on this host must run it contained. `epoch` changes when the backend moves the session to a new environment (the Kubernetes backend returns the claim name, which changes when an expired claim is replaced); a change makes PiShip check a shared or synchronized workspace again before the next command.

## Network denial

A local backend's network denial is live-probed: a child inside the sandbox must fail to reach a listener PiShip runs on this host's loopback, which the same host reaches without the sandbox, and an external address. The report says `networkDenial: { evidence: "verified" }`. Both attempts (the loopback listener and `1.1.1.1:443`) are negative probes: each must fail in `deny` mode, and the probe never requires any address to be reachable. The positive control is the boundary test "reaches a host loopback listener in network allow mode" (`packages/sandbox/src/boundary.test.ts`), where a sandbox with the network allowed does reach that listener.

A remote backend cannot be probed that way: its loopback is its own, and PiShip knows no address that every remote sandbox with the network allowed can reach. A connection that fails in a denied sandbox proves nothing unless the same connection succeeds with the network allowed, so PiShip never picks a public address of its own. Instead a remote backend may declare `networkProbe`, a TCP endpoint (`host`, `port`) that the backend or its operator controls and guarantees is reachable from a sandbox of this backend with the network allowed: the operator's own endpoint on the execution network, for example. It must not be a secret; it is sent to the sandbox in the check command and never appears in a report, notice, or metric. The host is a hostname or an IP address (letters, digits, `.`, `-`, and `:` only, no brackets or port) and the port 1 to 65535; anything else fails activation closed before a sandbox is created.

In `deny` mode:

| What happens | Result |
| --- | --- |
| The backend declares no network probe | Attested: `the backend declares no network probe to check it with`. No connection is tried and no second sandbox is created |
| The session's sandbox connects to the probe | Fails closed with `SANDBOX_UNAVAILABLE`: `a connection to the backend's network probe succeeded although the network is denied` |
| The connection check cannot run in the sandbox (it needs `bash` and `timeout`, or `nc`) | Attested, with a warning |
| The connection is blocked, and the backend does not list `allow` in `network` | Attested, with a warning; no second sandbox is created |
| The connection is blocked, and a temporary allow-mode sandbox of the same backend cannot be prepared, fails its check, or cannot reach the probe either | Attested, with a warning. The allow-mode sandbox is disposed before the session runs anything |
| The connection is blocked, and the same probe is reachable from the temporary allow-mode sandbox | **Verified** |

Attested network denial follows the rule for every plane of a backend PiShip cannot live-probe: the backend declares `network-deny`, the plane is reported, a required `deny` sandbox activates, and `verification` stays `backend-attested`. Only a reachable probe in the denied sandbox is a failure. When a backend declared a probe that did not prove denial, the result is lower than it declared: the containment warnings and `doctor` say `network denial is attested by the backend, not verified: <reason>`, and a session shows one notice. The temporary allow-mode sandbox is prepared with an empty workspace and temp directory that PiShip creates for it and removes afterwards on every path, no protected paths, and no environment variables: it never sees the user's project or environment. Verified means that one controlled target is reachable with the network allowed and blocked with it denied; it is not a proof for every destination. It is evidence against a misconfigured sandbox as reported through the backend's own command channel, not against a backend that misreports what its commands printed. PiShip does not check the cloud metadata address separately: a VM-based service such as E2B serves its own metadata at `169.254.169.254` inside every sandbox whatever its network, so a connection there proves no egress, and a blocked one proves nothing.

## Egress coverage

PiShip does not keep a per-host egress allowlist for shell subprocesses. A command-text or `fetch`-only list would not contain a child process, so it is not offered as isolation. Ordinary network policy belongs to the organization's endpoint firewall, secure web gateway or proxy, DLP and EDR. PiShip keeps identity, TLS, proxy and CA integration, the private-only policy for its own requests, and the sandbox's network denial. `doctor` reports each row below under `Network` (lines starting `egress:`), as `PiShip` when PiShip enforces it, and otherwise as not enforced.

| Process | What PiShip restricts | What only IT can restrict |
| --- | --- | --- |
| Pi runtime (provider and gateway requests) | `network.privateOnly`: declared hosts only, public fallback denied; the proxy and CA settings apply to Pi's default HTTP dispatcher | Every other destination, and TLS inspection |
| In-process extensions | Nothing: they run in the Pi process and are not contained | All of their egress |
| Shell and child processes | With an enforced sandbox in `deny` network mode: all network, live-probed (local) or attested (remote). Otherwise only the proxy and CA variables a child receives | Per-host destinations, always |
| Git and package managers | Run as shell children, or in the Pi process when Pi itself runs them: covered by the row for that process, not separately | Hosts such as the registry or remote |
| MCP stdio servers | The same sandbox network denial when a sandbox is active; the environment they receive | Per-host destinations |

`sandbox.network.egress: it` is how a managed distribution says that IT owns egress for shell and MCP stdio: the required sandbox keeps its filesystem and environment containment and the network default becomes `allow`. It is the same as `network.mode: allow`, with clearer wording, and it verifies nothing: `doctor` shows `egress delegated to IT: declared by the distribution (sandbox.network.egress: it), not verified by PiShip`, never a passed check, and a machine off the corporate network is not detected. Commands then receive the approved proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) when `network.proxy.inheritEnvironment` is on, but a trust bundle only as `NODE_EXTRA_CA_CERTS`. Checked by reading what `approvedNetworkEnvironment` returns (with `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` set in the launching environment, both were dropped); pip, curl, git, cargo and go were not run. From their documented behavior they read `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or the system store, so behind a TLS-inspecting proxy they would need the CA in the system store (inferred, not tested).

In `allow` mode, which `egress: it` selects by default and plain `network.mode: allow` already is, the sandbox adds no separate block for the host's loopback, link-local and cloud-metadata addresses (169.254.169.254), or Unix sockets: Seatbelt omits its `(deny network*)` rule and bubblewrap shares the host network. IT's egress controls do not see this local traffic. On macOS a Unix socket outside Docker's may be reachable, for example an ssh-agent socket under `/private/tmp/com.apple.launchd.*/Listeners`; this is possible from how the rules are built and has not been tested.

In `deny` mode, Seatbelt refuses every socket connection, Unix sockets included. Bubblewrap's network namespace does not cover filesystem (pathname) Unix sockets, so it hides the ones that could carry data off the machine: Docker's and Podman's sockets and the user's `/run/user/<uid>` (in every mode), and, with the network denied, the host's name resolvers (`/run/systemd/resolve`, the system D-Bus socket that also reaches systemd-resolved, nscd, and Avahi), since a name lookup is a DNS query that leaves the host. Any other filesystem socket on a Linux host stays reachable in `deny` mode.

`doctor` treats a control it cannot see as not enforced and says so (on Windows it adds that there is no native sandbox adapter). Shell and MCP stdio egress is a note, never a warning: a sandbox that allows the network is a deliberate choice, and a required sandbox that cannot be enforced already fails containment in the Sandbox group. An attested denial is shown as attested by the backend, not verified. The IT-owned controls are listed as externally attested at most. PiShip reads no firewall, proxy, DLP or EDR state. Windows has no native sandbox adapter, so shell children there have no PiShip network denial. Behavior off the corporate network is not detected. Negative tests of denied destinations through real endpoint or proxy infrastructure (shell, Node and MCP, not only `fetch`) have not been run; only the loopback and `1.1.1.1:443` sandbox probes above are tested. A required sandbox that cannot be enforced still stops the launch; nothing falls back to unrestricted execution.

## Workspace

Without `workspace: remote`, Pi's file tools (`read`, `write`, `edit`) work on this host's files and only shell commands reach the sandbox; with it, see [Remote workspace](#remote-workspace). A backend is a complete coding-agent workspace only when its commands see the files those tools edit. It declares how in `capabilities().workspace`:

| Mode | Meaning | Examples | Complete coding-agent workspace |
| --- | --- | --- | --- |
| `shared` | The sandbox and the file tools touch the same files | a bind mount, a shared volume, a company workspace service | Yes, once verified |
| `synchronized` | Different stores that a backend-owned engine keeps in step both ways within `propagationMs` | a two-way sync agent | Yes, once verified |
| `snapshot` (default) | Anything else: the sandbox sees a copy at best | a template, an image, a `git clone`, a one-time upload | Never |

A local backend is `shared` by construction and needs no check. The built-in `e2b-compatible` and `kubernetes-agent-sandbox` backends declare `snapshot`: PiShip does not know what their template or warm pool mounts. A company that mounts the developer's workspace into its sandbox uses a custom adapter and declares `shared`. PiShip does not implement a sync engine.

### Remote workspace

Short version: the sandbox holds the project while the agent works, and you bring the result back with one command.

#### Quick start

1. **Declare it.** The sandbox must be required, and the manifest must be `piship/v1` (or `piship/v1alpha6`):

   ```yaml
   variables: [SANDBOX_ENDPOINT]
   sandbox:
     required: true
     provider: e2b-compatible      # E2B, or CubeSandbox (add user: root)
     endpoint: ${SANDBOX_ENDPOINT}
     template: my-project-template
     workspace: remote
     credential: stored
   ```

   `SANDBOX_ENDPOINT` is read from the environment of the process that starts the command (`export SANDBOX_ENDPOINT=https://...` in a POSIX shell, `$env:SANDBOX_ENDPOINT = "https://..."` in PowerShell, or `setx SANDBOX_ENDPOINT https://...` to keep it for new Windows terminals). An IDE or desktop launcher does not read your shell profile; a plain `https` URL in `endpoint:` needs no variable. A managed distribution also lists the endpoint's host in `network.allowHosts`; the per-sandbox envd hosts (`49983-<id>.<domain>`) need no entry.

   Store the sandbox key once. It is read from a prompt or from standard input, never from a flag:

   ```sh
   acme sandbox login
   ```

2. **Build the template.** The sandbox template needs `git`, `tar` and `gzip` (your machine needs only `git`: PiShip packs and compresses the upload itself, so Windows needs no `tar` or `gzip`), and whatever your project builds and tests with (Node, Python, a compiler). Leave the project directory empty: PiShip uploads the project into `/home/<user>/workspace` itself. Dependencies go one of two ways:
   - Install them in the template, in a directory outside the project (a global npm prefix, a virtualenv or cache under the home directory). This works with the default network setting.
   - Install them at run time. That needs `sandbox.network.mode: allow`. With the default `deny`, `npm install` and `pip install` fail inside the sandbox.

   Ignored files are not uploaded, so `node_modules` and `.env` from your machine never reach the sandbox. A distribution can install them for you: `sandbox.remote.setup: npm ci` runs once in the sandbox right after the upload (see [Setup](#setup)). With `setup`, the second start is fast: the sandbox is saved after the setup succeeds and the next session starts from it, without running setup again (see [Setup cache](#setup-cache)).

3. **Check it.** `doctor` creates a sandbox and tells you what a session would otherwise find out the hard way:

   ```sh
   acme doctor
   ```

   Look at the Sandbox group: the file API, `tar`, `gzip`, `git`, an empty project directory, the network mode, and whether an earlier patch is waiting. Each failing row says what to change.

4. **Work.** Start a session in a git repository (remote workspace needs git). The first file tool or command uploads the project. Edit in the session as usual. When it ends, PiShip prints a line like this one:

   ```text
   3 files changed in the sandbox; run acme sandbox pull to bring them to this machine
   ```

   Then look at the changes, apply them, and commit:

   ```sh
   acme sandbox pull            # shows a summary and asks y/N
   acme sandbox pull --diff     # also prints the full diff
   git diff                     # the changes are in your working tree, not staged
   git add -A                   # new files from the sandbox are untracked until added
   git commit -m "..."
   ```

   `sandbox pull` never commits and never stages (unless it needs a 3-way merge, see below). It works with uncommitted changes of your own.

   To keep your checkout untouched, use `acme sandbox pull --branch` (or `--branch <name>`): the changes are applied and committed on a new branch in a new worktree next to your project, and the command prints the path and the next commands (`git -C <path> log -1`, `git merge <branch>`, or `git worktree remove <path>`). Your files, index, and branch stay as they are.

5. **When something goes wrong.**
   - *The sandbox expired or the session crashed.* Everything up to the end of the last agent turn is already saved on this machine. Run `acme sandbox pull`, then start a new session. A new session starts from your files on disk, so pull first.
   - *An earlier patch is still waiting.* A new session says so when it starts. Run `acme sandbox pull` first. If several sessions left patches, each `sandbox pull` takes the next one; run it again until it says nothing is waiting.
   - *The patch does not fit your files.* Pull tries a plain apply first and falls back to a 3-way merge. A 3-way merge stages the patch's files and can leave conflict markers: resolve them and `git add` the files. If git cannot apply the patch at all, nothing changes and the patch stays stored: commit or stash your edits to those files and run pull again.
   - *You do not want the changes.* `acme sandbox pull --discard` drops the next waiting patch.

The rest of this section explains how it works and what it does not do.

`sandbox.workspace: remote` (piship/v1alpha6, `e2b-compatible` and `custom` providers) changes who holds the files. The sandbox holds the only live copy of the project. The harness (Pi and PiShip's governance, credentials, and audit) stays on this host. `read`, `write`, and `edit` are decided by the same policy as without it, then performed in the sandbox through the backend's file API; the host working tree is not touched during the session. The work comes back as a patch that you review and apply with `<command> sandbox pull`. The backend must expose `files` (read, write, stat); activation fails closed when the backend is local or its instance has no `files`. The shared and synchronized workspace check does not apply, and `doctor` shows `Workspace: remote (the sandbox holds the only live copy of the project; the host working tree changes only when you pull the result).` The Sandbox group of `doctor` also checks the file API, `tar`, `gzip`, `git`, an empty project directory, and the network mode in the sandbox it opens, and lists any patch still waiting on this machine.

The flow:

1. **Activation** uploads nothing.
2. **Seed**, lazily before the first file tool or command that reaches the sandbox (a Plan-mode session that never touches the sandbox uploads nothing). PiShip lists `git ls-files -co --exclude-standard -z` at the project root; a project that is not a git work tree fails closed, because remote workspace needs git. Each file is decided as `filesystem.read` without prompting: `allow` uploads it, `deny` and `ask` skip it (counted and audited, never prompted). Symlinks, files outside the workspace, and anything under `.git/` are skipped. A file over the per-file cap (50 MiB) stays on this host and the session continues with one notice; a project over the total cap (200 MiB) fails with a message that says to add the large directories to `.gitignore`. Both caps can be changed with `sandbox.remote.seed` (`maxTotalMiB`, `maxFileMiB`, positive integers up to 4096 and 1024), and `sandbox.remote.pull` (`protectedFiles: skip | refuse`, `confirm: optional | required`; defaults `skip` and `optional`) is recorded in each checkpoint for `sandbox pull`. A seed that fails for a reason a retry cannot cure (the cap, a missing tool, a non-empty directory) is remembered and fails the same way at once; a seed that died halfway is cleaned and redone on the next call. The files go as gzip-compressed tar parts of about 32 MiB of file data each (a larger file is a part of its own), read, uploaded, and extracted one after another, so memory use is about one part and not the whole project (no new dependency; mode 0644 or 0755, taken from git's index for a tracked file and otherwise from the host executable bit, which is never set on Windows). The size caps count uncompressed file sizes. A progress line after each part shows the parts and MiB done (`3/7 parts, 96 of 210 MiB`). A seed that fails in a later part is cleaned and redone from the start on the next call. A git baseline commit is made in the sandbox after the last part. The template needs `tar`, `gzip` and `git`; a missing one fails with an error naming it. With an e2b-compatible backend and no `sandbox.workdir`, the project goes into `/home/<user>/workspace` (`/root/workspace` for `root`), which PiShip creates, so the baseline never holds the home directory's dotfiles; the seed refuses a project directory that already holds other files.
3. **File tools** keep `gatePath`, policy, approvals, and audit. After the decision the operation goes to the sandbox instead of the host. Host-only guards (the no-follow open and the hard-link check) are not applied to sandbox paths. A path outside the workspace is refused: the remote workspace holds only the project.
4. **Checkpoint** after every agent turn in which a remote write or command ran, and always at session end: PiShip runs `git add -A && git diff --cached --binary --no-color --no-ext-diff --no-textconv --no-renames <baseline>` in the sandbox (no rename detection, so a rename is a delete and an add, and no diff driver or textconv program of the sandbox's runs) and stores the result, atomically with mode 0600, at `<state>/sandbox-workspace/<projectKey>/latest.patch`, with `latest.json` (session, project root, baseline `HEAD`, time, file count, and the protected paths `sandbox pull` refuses) beside it. `projectKey` is the first 16 hex digits of the SHA-256 of the project root's real path. The patch is capped at 64 MiB; over it, that checkpoint fails with a warning and the earlier one is kept. A failed checkpoint never fails the turn and warns once, and another session's unapplied patch is never replaced: while one waits, this session's changes are saved under `<state>/sandbox-workspace-parked/<session>/` and the session end says so. Run `<command> sandbox pull` once for each waiting patch; each run takes the next one. A new session also says at its start that earlier changes are waiting, and it starts from your host files, not from them. When the patch is not empty the session ends with `N files changed in the sandbox; run <command> sandbox pull to bring them to this machine`.

`<command> sandbox pull` reads the latest checkpoint of the project at the git top-level of the current directory and:

- validates the patch ([rules](#patch-rules)). A malformed patch, a symlink, a gitlink, or a rename is refused whole: nothing is applied;
- skips files under protected paths (`.git`, hooks, git config, and the others in [Protected git paths](#protected-git-paths)), lists them, and applies the rest. A distribution can set `sandbox.remote.pull.protectedFiles: refuse` to refuse the whole patch instead;
- lists one line per file (the full path with control and bidi characters shown as `?`, created, deleted or changed, a mode change, and `+added -removed`; at most 50 lines, then `and N more; use --diff`) and one summary line: how many files apply cleanly to your working tree, or that the patch needs a 3-way merge. The full diff is printed only with `--diff` (terminal control characters are replaced by `?`);
- asks one `y/N` question, skipped by `--yes`. Without a terminal it refuses unless `--yes` is given. A distribution can set `sandbox.remote.pull.confirm: required`, which refuses `--yes`, so the terminal prompt is the only way;
- with `--branch [<name>]`, does the apply in a new git worktree instead (see below). `--branch` and `--discard` cannot be combined, and `sandbox pull --help` lists the options;
- applies the patch with plain `git apply` first: it changes the working tree only, stages nothing, and works with uncommitted changes of your own. Only if the patch did not fit from the start does it use `git apply --3way`, which stages the files it touches and can write conflict markers. It never commits, and `git apply` runs no hook. On success the patch moves to `applied/` next to it; if it cannot be applied, nothing changes and the patch stays stored, so you can fix the tree and run it again. Before writing, pull refuses a path whose file or parent is a directory, a file, or a symlink where the patch needs something else; if a write still fails halfway, the files the patch names are put back from a copy taken just before, and the message says whether the tree was untouched or restored.

When the 3-way merge conflicts, git has already written conflict markers and applied and staged the patch's other files. The patch stays stored, and pull refuses to apply it again (that would only conflict again): resolve the markers, `git add` those files, then run `sandbox pull --discard`. When your branch has moved since the session started, one line says so and the patch is applied to the current tree. A successful pull leaves a marker naming the sandbox commit the patch was taken from; the live session moves its baseline there at its next checkpoint (only to a commit it recorded itself), so a later pull holds just the changes made after this one. `--discard` leaves no marker.

`sandbox pull --branch [<name>]` leaves your checkout, index, and branch untouched. It creates the branch (default `sandbox/<first 8 characters of the session id>`; a name that exists, that `git check-ref-format --branch` rejects or expands to another name (`@{-1}`, `@{u}`), that contains `@{`, starts with `-`, or is longer than 200 bytes is refused, and cleanup only ever removes the branch and worktree this command created) and a worktree at `<project parent>/<project name>-sandbox-<name>` (the path is printed; anything already at that path, a dangling symlink included, is refused), starting from the commit the session was seeded at (`baseHead`) when this repository still has it, otherwise from your current HEAD, and says which. The patch goes through the same validation, protected-file handling, symlink check, listing, `--diff`, `--yes`, `confirm: required`, archiving, and marker as a normal pull, with the checks run against the new worktree. It is applied there with plain `git apply`, then `--3way`, and the result is committed as `sandbox: changes from session <id>` with your git identity, staging exactly the patch's files (forced, so an ignore rule cannot leave one out; the message says so if one is still missing), without running any repository hook or fsmonitor in any of its git commands and without overriding your signing settings. Your own clean and smudge filters still run, as in a normal pull. If the commit fails (no identity configured, a signing failure), the changes stay staged in the worktree and the message says so. The session was seeded from your working tree, so when you had uncommitted edits then, the patch may not fit a clean checkout of `baseHead`: the worktree and branch are removed again, the patch stays stored, and the message tells you to run `sandbox pull` without `--branch` (which applies onto your working tree; switch to a new branch first to keep it apart). Committing your edits does not help, since `--branch` still starts from `baseHead`. Declining the prompt removes the new branch and worktree too. Keep the result with `git merge <branch>`, or throw it away with `git worktree remove <path> && git branch -D <branch>`.

A session that finds an earlier session's patch still waiting saves its own patch beside it (parked), so nothing is overwritten. Running `sandbox pull` again picks up the next one and says how many are left.

`sandbox pull --discard` drops the next waiting patch. With no stored patch it says so; with a patch recorded for a different project root it refuses and names both.

#### Host edits during a session

Fix a file in your IDE and say "look again": the agent sees it. At the start of each agent turn (after the seed), PiShip lists the project's git-listed files, compares size and modification time with what it saw at the seed or the last turn, and hashes only the files that differ. For each file you changed, added, or deleted:

- If the agent did not change that path in the sandbox, the new content is uploaded (under the seed's rules: only files whose read policy allows without asking, no symlinks or paths leaving the project, within the per-file cap) and folded into the baseline, so it never shows up in the patch. A deletion is applied the same way. You get one line, `Sent N files you changed on this machine to the sandbox`, and the model gets one line naming them.
- If the agent changed it too, the sandbox copy is kept and you get, once per file per session: `<path> changed on this machine and in the sandbox; the sandbox copy is kept. <command> sandbox pull will merge or flag it.`
- A file whose host content already equals the sandbox's current content is in sync, so the files a mid-session `sandbox pull` wrote to your tree are not sent back and are not reported as conflicts.

A refresh that fails is a single warning and never fails the turn; the next turn tries again. `sandbox.remote.refresh: off` turns it off (default `auto`). Edits made while the agent is working are picked up at the next turn. Files the seed left out stay out until you approve a read of them.

#### Setup

`sandbox.remote.setup` is one shell command, such as `npm ci` or `uv sync`, that PiShip runs once in the sandbox project directory right after the seed succeeds, with the sandbox's own network policy and environment. It is the distribution author's command (the manifest is trusted), and it runs without a prompt. `sandbox.remote.setupTimeoutSeconds` bounds it (default 900, at most 7200). The session shows `Running setup in the sandbox: <command>`.

PiShip runs setup after the baseline commit and then folds anything it changed in files git tracks or would list (a rewritten lockfile) into the baseline, with one notice. The patch therefore holds only the agent's work. Ignored output such as `node_modules` never enters it.

Setup can take minutes, so the session says `Still running setup in the sandbox (N min): <command>` every minute. Esc or Ctrl-C during any tool call that is waiting for the upload or the setup cancels it: nothing is cached, and the next tool call runs it again. The workspace counts as seeded only after setup and the snapshot step are done, so a checkpoint or a refresh taken meanwhile does nothing and setup's partial output never appears in `sandbox pull`. Text from the sandbox shown in notices has its control characters replaced with `?`.

A failing setup does not fail the session. PiShip warns with the command, the exit code (or the timeout), and the last ten lines of output, and the agent's prompt says setup failed so it can run the command again. With `sandbox.network.mode: deny` an install fails: allow the network, or put the dependencies in the template. `doctor` shows the command and warns when the network is denied; it never runs it.

#### Setup cache

With `sandbox.remote.setup` on an `e2b-compatible` backend, PiShip saves the sandbox after the setup command succeeds and starts later sessions from that snapshot, so the install does not run again. Nothing to turn on: the default is `sandbox.remote.cache: snapshot` there. A `custom` adapter is cached only when the manifest says `cache: snapshot` and the adapter's instance offers `snapshot()` (see [Custom adapters](#custom-adapters)); `cache: off` turns it off everywhere.

What is cached: the sandbox's filesystem as it is right after the upload, setup, and the baseline fold, and before the agent's first command or file write reaches the sandbox. Only files PiShip uploaded and the setup command's output are in it, so a session that went wrong can never poison a snapshot. The snapshot holds no memory state (`memory: false`) and no name; PiShip keeps the id the backend returned in `<state>/sandbox-workspace/<project key>/cache.json` (mode 0600), with the key it is valid for and the time it was saved. It never looks a snapshot up by name, metadata or a listing.

On a start from a snapshot, the project directory already holds the files and the ignored setup output (`node_modules`) of the session that saved it. PiShip does not run setup. It extracts the current upload over that tree, removes the files that are in the sandbox but are neither uploaded nor ignored (a file you deleted, or one the policy now withholds), and also every file the saving session uploaded that this session does not, whatever `.gitignore` says now (PiShip keeps that list of paths in the snapshot's `.git`, written before any agent acted; a list that is missing or malformed resets the project directory and runs setup again), and makes a fresh baseline commit exactly as a first seed does, so patches, refresh and `sandbox pull` work as before. Setup output must therefore be git-ignored (`node_modules`, `.venv`, `target`): a setup output that git would list is removed on a start from the snapshot.

The key is a SHA-256 over: the control endpoint's origin, the template, the sandbox user, the project directory in the sandbox, the network mode, the setup command (not its timeout), a digest of the policy rules that name a filesystem action or a wildcard, from every layer (so a policy change rebuilds, and a change to an unrelated rule does not), the signed-in identity (the OS user name without one, so people never share a snapshot), and the path and content hash of each key file. Key files are `sandbox.remote.cacheKeyFiles` (workspace-relative paths, at most 32), or by default whichever of these exist at the project root: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`, `uv.lock`, `poetry.lock`, `requirements.txt`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`. They are read like the seed reads files (regular files inside the project, no symlinks, up to 16 MiB) and only hashed on this machine: a key file the policy would not upload is hashed, never sent. A key file that cannot be read that way turns the cache off for the session, with one notice.

Invalidation: a different key (a changed lockfile, setup command, template, endpoint, directory, user or network mode) starts from the base template, runs setup, saves a new snapshot and deletes the old one. A snapshot older than 7 days is not used and is replaced the same way. A snapshot the backend no longer has gives one notice (`The cached sandbox setup was no longer available; setting up again.`) and a start from the base template. A snapshot that cannot be applied (`The cached sandbox setup could not be applied; setting up again.`) is deleted, the project directory is cleaned, setup runs again, and that session saves nothing.

Failure never fails a session. A save still running after a moment says `Saving the sandbox setup so the next session can start from it (Esc skips this).`; Esc or Ctrl-C then skips it (`Skipped saving the sandbox setup; the next session sets up again.`): no `cache.json` entry is written, a snapshot the service still finishes is deleted when its id arrives, and the session goes on with the set-up sandbox. If saving fails, one warning says so and the next session tries again. A backend that answers 404, 405 or 501 to the snapshot call has no snapshots: PiShip records that for 24 hours and stays silent. A subagent child never uses the cache, and `doctor` starts from the template, so its checks stay meaningful. `doctor` shows one row, `remote setup cache`, from `cache.json` alone: off, no snapshot yet, the snapshot's time, or that the backend has no snapshots.

To reset it, delete `cache.json` in the project's directory under `<state>/sandbox-workspace/` (its name is a hash of the project path; `sandbox-workspace/<key>/latest.patch` is beside it). The next session sets up again and saves a new snapshot; the old one expires on the backend or is deleted the next time one is saved. Snapshots can be left behind when a delete fails (the backend is down, or two sessions saved at once and one delete was lost); `doctor`'s `remote setup cache` row shows the current snapshot id, so an administrator can find and remove an older one in the backend. A snapshot is never started for the network-denial contrast sandbox, which must see none of your files.

Because setup does not run on a start from the snapshot, it must only install dependencies, not build the project's own sources: a build of files you edit would be stale. Run builds in the session, or in a command the agent runs.

#### Patch rules

The patch comes from a sandbox that may be compromised, so it is untrusted input. Git's own parser decides which paths the patch touches: PiShip runs `git apply --numstat -z` and `git apply --summary` on it (nothing is applied) and checks every path git reports. A line scan covers what git's report omits: the patch must be well formed, so a hunk ends exactly where its `@@` counts say and no plain `---`/`+++` diff can follow it, every header line must be one git writes, and every mode, including the one on the `index` line, must be exactly `100644` or `100755`. It refuses the whole patch when any entry:

- has an absolute path, a drive-letter path, a `..` or empty segment, a backslash, or a NUL or other control character;
- touches `.git` in any segment, in any case (also `.git.` and `GIT~1`), or a protected path. The checkpoint's `latest.json` lists the project's protected git files and directories, workspace-relative and written by the host (hooks, config, `info`, `modules`, `worktrees`, and the others in [Protected git paths](#protected-git-paths)); a checkpoint without the list refuses `.git` only. A segment ending in a dot or a space is refused (Windows drops them, so `.claude.` would land in `.claude`), and so is a patch that would skip more than 200 protected files. Any other path segment ending in `~N` is refused, because on Windows it can be the 8.3 short name of another file. By default such files alone do not refuse the patch: they are skipped and listed, and the rest is applied if it passes every other rule. With `sandbox.remote.pull.protectedFiles: refuse`, any such file refuses the whole patch;
- has a mode other than `100644` or `100755` on either side (so no symlink `120000` or gitlink `160000`);
- uses `/dev/null` as a name without the matching `new file mode` or `deleted file mode` header (git would delete the other name and create a file named `dev/null`);
- names a path that is, or sits under, a symbolic link on this machine, checked at pull time (a sandbox patch never writes through or over a symlink);
- has a rename or copy header (the checkpoint is made with `--no-renames`, so an honest patch has none), or a `---` name that differs from its `+++` name (git deletes the first and writes the second, while its report shows one);
- is not a git diff at all, or is larger than 64 MiB.

#### Limits

- No live sync. The host working tree, and so your IDE, shows the sandbox's changes only after `sandbox pull`. In the other direction, edits you make on this machine reach the sandbox at the start of the agent's next turn, not while it works ([Host edits](#host-edits-during-a-session)); with `sandbox.remote.refresh: off` the agent keeps the copy uploaded at the start.
- Pi's own reads that are not tool calls read the host: `AGENTS.md` and other instruction files, and `@file` mentions in your prompt. The agent sees their current host content, which can differ from the sandbox copy.
- A subagent works in its own sandbox, and its changes are not returned: only the main session's changes are saved for `sandbox pull`. When a subagent wrote a file or ran a command, the last message it returns ends with `Note: this subagent's file changes were not kept (remote workspace). Apply them from its report.` so the parent knows.
- `kubernetes-agent-sandbox` and `native` are not supported.
- A file the seed left out because it was over `sandbox.remote.seed.maxFileMiB` is sent after all if you shrink it, at the start of a later turn. A file whose name is longer than 100 bytes is uploaded like any other.
- A file the policy denies to read, or asks about, is not uploaded; the session says how many were left out. If the agent later creates a file at such a path with `write`, it shows up as a new file in the patch, and pulling it can conflict with your original. A withheld file the agent reads after you approve the read is uploaded then, and is a change only if the agent edits it.
- Changes to files outside git's view (ignored files) do not come back, and dependencies installed in the sandbox are lost with it.
- On Windows, the tar uses `/` separators, and an untracked file gets mode 0644. The upload holds the bytes on disk, CRLF included. When git converts line endings on this machine (`core.autocrlf=true`, the Git for Windows default), the sandbox's repository gets `core.autocrlf=input`, so it stores LF as yours does: a tool in the sandbox that rewrites a file with LF line endings changes only the lines it changed, and `sandbox pull` writes them back with your CRLF. No `.gitattributes` change is needed. The end-to-end tests of remote workspace run on Windows with a custom adapter over a local directory and Git for Windows' `sh`; no live E2B or CubeSandbox service is part of them.

### Protected git paths

Git runs some of the project's files outside any sandbox, with the user's next command, so `profile.writeProtect` names the git paths a sandbox must not change. They come from the project's `.git`, the git directory a `.git` file points to, and the shared directory of a linked worktree:

- Files: the `.git` entry itself (a pointer file in a linked worktree or submodule), and `config`, `config.worktree`, and `commondir` of each git directory, with the shared `config`. `commondir` and `config.worktree` normally do not exist; git follows them when they appear. Also the files those configs include (`include.path` and `includeIf.*.path`, every one whatever its condition, from the including file's directory or `~/`, followed as deep as git follows them, and listed whether or not they exist yet), since a setting there acts like one in the config itself. The config git reads besides the repository is read the same way, from the process environment PiShip has: the system config (`GIT_CONFIG_SYSTEM` alone when it is set, else `/etc/gitconfig` and the places other git installations keep it, since the path is fixed when git is built: `/opt/homebrew/etc/gitconfig`, `/usr/local/etc/gitconfig`, `/home/linuxbrew/.linuxbrew/etc/gitconfig` (not on macOS, where Homebrew never uses that prefix and `/home` is an autofs mount whose every lookup costs tens of milliseconds), and the `usr/etc/gitconfig` of the Command Line Tools and of Xcode; PiShip cannot tell which git runs, so it reads all of them, and a file the running git does not read only adds a protected path; a git built with another prefix reads a file PiShip does not know, so `GIT_CONFIG_SYSTEM` has to name it; none when `GIT_CONFIG_NOSYSTEM` is true), the global config (`GIT_CONFIG_GLOBAL` alone when it is set, else `~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`, or `~/.config/git/config` without it), and the `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, and `GIT_CONFIG_VALUE_<n>` settings and the `GIT_CONFIG_PARAMETERS` ones that `git -c` exports (`core.hooksPath`, and `include.path` with an absolute or `~/` path, since git refuses a relative one there; both formats git writes, `'key=value'` and `'key'='value'`, are read, and a value that is not in either is reported below as not readable). These are the only sources besides the repository, and they are the user's or the machine's, not the project's. `profile.writeProtect` lists a file among them, or one only they include, wherever it lies: a distribution that lets commands write `~` would otherwise let one plant a hooks path in `~/.gitconfig`. A path outside every writable path is read-only already, so the list matters where the sandbox may write the directory that holds one. PiShip's own file tools refuse only the files inside the project (a project that holds the home directory, an include into the working tree), so the edit tool can still change the user's `~/.gitconfig`.
- Trees, as a whole and also while they do not exist yet: `hooks` and `info`; `modules`, the git directories of submodules (each has its own `config`, `hooks`, and `info`, and `git status` enters them); `worktrees`, the administrative directories of linked worktrees (each has its own `commondir`, `gitdir`, and `config.worktree`); and the directory `core.hooksPath` names in the repository's config and in every source above, and what they include, unless it lies in the working tree outside `.git` (husky's `.husky/_`, a team `.githooks`): a sandbox may write that one, and PiShip's own file tools still refuse it. That last one is read from those and from no other file: every value counts, a relative one is taken from the project root whichever file sets it (a global `.githooks` lands in every working tree) and `~/` from the home directory, and one that holds the whole project root is left out, since it would make the project read-only.

The native adapters keep all of these read-only inside the writable paths, and PiShip's own file tools refuse to write those in the project. So a shell command in a native sandbox cannot add or update a submodule, commit or fetch inside one, or add a linked worktree (`git submodule update --init`, `git worktree add`); run those outside the sandbox. A tool that regenerates a hooks directory named by `core.hooksPath` in the working tree (husky's `.husky/_`) works: that directory and the scripts it calls (`.husky/pre-commit`) are ordinary project files, so a sandboxed command can change what the next `git commit` runs outside the sandbox, as it can already change `package.json` scripts; the protected trees above (`.git/hooks`, `modules`, `worktrees`) and the git config files stay read-only. For that reason git control is `not-verified` whenever such a `core.hooksPath` is configured, even if the directory does not exist yet. It is also `not-verified` for a local backend while a protected file does not exist yet where the sandbox may write, and the isolator cannot guard a file that is not there. Bubblewrap guards a directory that does not exist yet by mounting an empty read-only one over it, which leaves an empty directory (`.git/modules`, `.git/worktrees`) on the host; it cannot guard a missing file, because a mount point for one would be an empty file left in the user's repository, and PiShip does not create placeholder files there (ownership and races with the user's own git commands). So under bubblewrap every regular repository is `not-verified`: `.git/commondir` and `.git/config.worktree`, which git follows if they appear, normally do not exist, and neither does an include nobody has created or a global config in a writable `~`. A sandboxed command could create one and redirect the next git command outside the sandbox. The report is only a downgrade: the sandbox is not failed, nothing is created, and the sandbox warning names the files (`git control is not verified: linux-bubblewrap cannot guard a protected file that does not exist yet (.git/config.worktree, .git/commondir)`). Seatbelt denies the path itself, so the file can be neither created nor renamed into place, and a missing file stays protected and verified there when the directory above it cannot be swapped: the workspace root or another writable root itself (an include `.gitconfig.local` in the project root), or a directory that holds an existing protected path, which is pinned (`.git`, for `commondir` and `config.worktree`). A missing file in any other directory counts (an include under a directory of the working tree, `~/.config/git/config` while `~/.config/git` does not exist), because the rule covers the path and not the directory above it: a command can build that directory elsewhere, with the file in it, and rename it into place. The warning then says `denies the path ... but not the directory above it, which can be swapped`. Which isolators can guard a missing file is the adapter's `guardsMissingFiles` (`capabilities().guardsMissingFiles` for a backend, false when omitted). An include that exists is protected like the others (in the project, so PiShip's file tools cannot edit it either). A remote backend has to keep the same paths read-only, and the check below tries them.

Protection follows a symbolic link to the file or directory it points to, and nothing a backend offers can hold the link itself in place: a bind mount or a Seatbelt rule on a link acts on its target, and the check below can only try writes through it. So when a protected path is reached through a link (an include that is a link, a `core.hooksPath` directory or `.git/hooks` linked to a shared directory, a dotfile manager's `~/.gitconfig`, a linked directory above any of them) and the directory that holds the link is one the sandbox may write, a command could replace the link with a file or a link of its own before the next scan, and git would follow it. Git control is then reported `not-verified` for every backend, and the sandbox warning names the links (`git control is not verified: a protected git path is reached through a symbolic link ...`). A link in a directory the sandbox cannot write cannot be replaced from inside and is not reported. The links are looked up each time the profile is built, and are not part of the cached scan.

Protecting a path that exists also pins every directory between the workspace root and it, as mount points on Linux and denied for rename and removal on macOS, so the path cannot be moved aside and replaced. Two more things then fail in a native sandbox: `mv`, `rm -rf`, or a `git checkout` that deletes a directory holding a protected path, which fails with EBUSY or EPERM (an included `config/local.cfg` pins `config/`), and a package install whose `prepare` script rewrites a protected hooks directory (husky's `.husky/_`), since that directory is read-only; run those outside the sandbox. A protected path that does not exist pins nothing, since there is nothing to move aside and git control is reported `not-verified` for it in the working tree anyway.

What to expect. Under bubblewrap, `not-verified` is the expected, permanent, and truthful report in essentially every regular Linux repository: `.git/commondir` and `.git/config.worktree` do not exist, and bubblewrap cannot guard a file that is not there. It does not mean something is wrong, and it will not go away until an isolator can guard a missing file; `doctor` and the sandbox warning name the files. Under Seatbelt it is the exception (a missing include in a directory that can be swapped, a hooks directory in the working tree, a link). A policy that lets the sandbox write the home directory or a configuration directory has a cost for what the agent runs in it: the user's global git config is protected there, so `git config --global` and `gh auth setup-git` inside the sandbox fail (the file is bound read-only on Linux, where replacing it fails with `EBUSY`, and denied on macOS), and the directories above a protected global file (`~/.config`, `~/.config/git`) are pinned and cannot be renamed or removed from inside. Run those commands outside the sandbox; the agent's own edit tool still changes the file.

What the scan follows is bounded, because every path it finds becomes a protected path (a bind mount, or a line in the check command) and one config file under 1 MiB can list about fifty thousand. It follows at most 64 include entries, 64 `core.hooksPath` values, and 64 environment settings (`GIT_CONFIG_COUNT` and `GIT_CONFIG_PARAMETERS` counted together), each counted over every config, and does not read a config file over 1 MiB. A `GIT_CONFIG_PARAMETERS` that is not in the format git writes is not guessed at: git control is `not-verified` for it too. Past a limit it protects what it followed, reports git control `not-verified` for every backend, and puts the reason in the sandbox warnings (`git control is not verified: the git config lists more than 64 ...`). The result is kept between file accesses under a key made of the repository's config paths and the environment inputs (the home directory, `XDG_CONFIG_HOME`, and the `GIT_CONFIG_*` variables); an entry stays valid while every file the scan tried, an include that did not exist included, has the same modification time, change time, size, and inode, and for ten seconds at most. A change to any of those files, one that adds or removes an include too, shows at the next access, also when the writer put the modification time back (only the kernel sets the change time); one that keeps all four, which takes a file system whose clock is too coarse to tell two writes apart, shows within ten seconds.

### The workspace check

A declared `shared` or `synchronized` workspace is checked lazily, just before the first command that reaches the sandbox, and not at activation: a session that stays in Plan mode, where no command reaches the sandbox, writes nothing into the project, and `doctor` never runs the check (it shows the workspace as `pending`). The agent's command is sent only after the check. One check is one command in the sandbox, run at the workspace root with the approved environment, bounded by the window plus 30 seconds, and not charged to the command's timeout:

1. **Location.** PiShip uses a directory it owns: `<workspace>/.git/piship-workspace/` when `.git` is a real directory (git ignores unknown entries there, so nothing appears in `git status`), or `<workspace>/<sentinelDir>/piship-workspace/` when the backend declares `sentinelDir`. A `sentinelDir` in the working tree (not under `.git`) is used only when the project's origin is `company`. Without a usable location (no `.git`, a `.git` file of a linked worktree, a `.git` symbolic link, a working-tree `sentinelDir` in an external or unknown project) the workspace is `unverifiable` and counts as `snapshot`. Every host-side component must be a plain directory, never a symbolic link, and must resolve inside the workspace; directories are created with mode 0700, files with 0600 and no-follow, exclusively. Each run uses a fresh random directory, removes it afterwards (and at process exit), and first removes nonce directories an earlier run left behind for more than a day. Nothing here is ever deleted recursively: the sandbox can write in this location, and a recursive delete would follow a link it swapped in for a component and remove host files. A run creates only `h2s`, `s2h`, and `s2h.tmp`; cleanup checks every component of the path again before each step, unlinks those names when they are regular files, and removes the directory only if that leaves it empty. The stale sweep skips a directory that holds any other name, so whatever else the sandbox adds to a nonce directory, which is clutter it controls and not a safety issue, stays in `.git/piship-workspace` until someone removes it.
2. **Host to sandbox.** The host writes a random token; the sandbox polls for it every 200 ms up to the window (10 s for `shared`, `propagationMs` for `synchronized`).
3. **Sandbox to host.** The sandbox writes a second random token (to a temporary name, then renamed); the host reads it right after the command returns and polls up to the window.
4. **Git control files.** In the same command, the sandbox tries, without changing anything that exists, to open each existing protected file (the profile's `writeProtect`: `.git/config`, a `.git` pointer file, and the like) for append with zero bytes, to create each protected file that does not exist yet without clobbering (`.git/commondir` and `.git/config.worktree` normally do not exist, and git follows them when they appear), and to create `<protected dir>/.piship-probe-<nonce>` in each protected directory (`.git/hooks`, `.git/info`, `.git/modules`, `.git/worktrees`, and a `core.hooksPath` directory, creating the directory first when it is missing). Every attempt must fail. The host, which recorded before the command what existed, then removes any probe file, any protected directory the probe created if it is empty, and any protected file the probe created if it is still an empty regular file, each reached only through plain directories. Renames are not tried remotely (a successful rename is destructive). The same command looks for a way to rename instead: for each protected path and each directory above it, up to the workspace root, that exists in the sandbox, it checks whether it is a mount point (its device differs from its parent's, read with GNU `stat -c` or BSD `stat -f`, or it is listed in Linux's `/proc/self/mountinfo`, which also covers a bind mount of the same filesystem) and whether its parent directory is writable (`test -w`). A path that is not a mount point and sits in a writable directory could be moved aside and replaced (`mv .git/hooks .git/h; mkdir .git/hooks`, or renaming `.git` itself, whose parent is the workspace root), so git control is reported `not-verified`; the commands still run. When nothing could be moved the report says `attested-renames`: writes were probed and renames ruled out by the mount and permission structure, not tried. The answer errs toward `not-verified`: without `stat` and a mount table, or where `test -w` calls a read-only directory writable (BusyBox's `test` reads the mode bits, whoever runs it, so a read-only mount looks writable), a protected path still counts as movable.

Every path in the command is workspace-relative, written `./<path>`, and given to `mkdir` after `--`, so a path such as `-h` (a `core.hooksPath` of that name) is an operand and never a flag. The command prints only fixed tokens, never file contents or paths, and the report never carries a token, a path, or an origin.

| Result | Effective mode | Verification | Outcome |
| --- | --- | --- | --- |
| Declared `shared`, both directions seen at once | `shared` | `verified` | Commands run |
| Declared `shared`, a direction delayed within 10 s | `synchronized` | `verified` | Warning; commands run |
| Declared `synchronized`, both within `propagationMs` | `synchronized` | `verified` | Commands run |
| A direction missing | `snapshot`, naming the direction that failed | `failed` | Warning; commands run |
| No location | `snapshot` | `unverifiable` | Warning; commands run |
| A protected file or directory was writable, a missing protected file could be created, or the check did not run or exited non-zero | — | `failed` | `SANDBOX_UNAVAILABLE`: the instance is retired, the pending command was never sent, and no later command runs in that session |
| The check timed out and the backend stopped it | `snapshot` | `failed` ("the workspace check timed out") | `SANDBOX_UNAVAILABLE`, retryable: the pending command was never sent, the instance is kept, and the next command checks again. A timeout proves nothing either way, so it neither retires the sandbox nor points at git control. A backend that does not stop the timed-out check within the settle time is retired, as for any command it does not stop |

The effective mode is never stronger than the declaration. A lower mode is a warning, not a failure: the commands still run on what the sandbox sees. Only the git-control failure closes, because the hooks the sandbox could write run outside any sandbox with the user's next git command. A protected path the sandbox could rename lowers nothing and closes nothing: `doctor` shows the git control files as not verified. The check refutes a claim; it cannot prove a mount. An immediate result also fits a very fast sync, so the report says "both directions immediate", never "is a mount". The session shows one notice when the mode is lower than declared and records the result in the local metrics, which `doctor` shows while its own check is pending.

A result counts until the first of: 30 minutes pass, the instance reports a new `epoch()`, or the instance is retired. The 30 minutes are measured on whichever of the monotonic clock and the wall clock advanced more since the check: the monotonic clock stops while the machine sleeps, so a check made before a suspend does not outlive it, and setting the system clock back does not extend it. Setting the clock forward cannot be told apart from a suspend and counts as elapsed time, so the next command checks again early. The propagation wait is a wait and uses the monotonic clock alone: a clock set forward does not cut it short. `verifiedAt` is the wall-clock time of the check. The next command then checks again first. A backend reports a replaced environment only after running something in it, so on an instance with `epoch()` PiShip runs a no-op (`true`) before each command once the workspace is verified: a replacement happens on the no-op and is verified before the command runs. A command during which the environment is still replaced fails with an error instead of reporting its result.

`ContainmentReport.workspace` carries the state at activation (`pending` for `shared` and `synchronized`), `ActiveSandbox.workspace()` the live one, and `onWorkspaceReport` delivers each new result. The containment line (`doctor`, `policy explain`) adds one sentence for a remote backend:

| Case | Sentence |
| --- | --- |
| Snapshot | `Workspace: snapshot. Remote commands see a copy, not the files the agent edits; this is not a complete coding-agent workspace.` |
| Pending | `Workspace: shared declared, verified before the first sandboxed command.` |
| Verified shared | `Workspace: shared (verified <time>, both directions immediate).` |
| Verified synchronized | `Workspace: synchronized (verified <time>, within <n> ms).`, with `declared shared; ` before `verified` when it was lowered |
| Lowered | `Workspace: snapshot (declared shared; the sandbox did not see host changes). Not a complete coding-agent workspace.` |
| Unverifiable | `Workspace: snapshot (declared shared; no PiShip-owned location to verify it: <reason>).` |

For adapter authors:

- Declare `shared` or `synchronized` only if commands see the files at `workdir` (the project root) that PiShip's file tools edit, and claim `workspace-confinement` only if nothing else of this host is reachable. Claim `git-control-protection` only if the protected paths are read-only from inside the sandbox, also through your sync engine; mount them read-only or exclude them from write-back, and make the directories above them (`.git`) mount points too, as the native adapters do, so that none can be renamed away and replaced. Otherwise the check reports the git control files as `not-verified`.
- A sync engine that excludes `.git` (common) makes the default location fail, which is reported as `snapshot`. Declare a `sentinelDir` both sides can write, preferably under `.git`; one in the working tree is used only in company-origin projects.
- The sandbox user must be able to read and write a directory the host user created with mode 0700 (and files with 0600). A container running as root does; one that maps a different unprivileged user does not, and the workspace is reported as `snapshot`.
- The check needs a POSIX `sh`, `cat`, `mkdir`, `mv`, `printf`, and `sleep` in the sandbox. `stat` (GNU or BSD) and, on Linux, `/proc/self/mountinfo` are how it sees mount points; without them the git control files count as `not-verified`.
- A sandbox whose environment can change under a session (a replaced pod or VM) implements `epoch()`.

### Custom adapters

A custom adapter is a module in the distribution, declared as `sandbox.adapter`, locked with a SHA-256 digest, and loaded from the verified payload. Its default export is a factory:

```js
// sandbox/acme-sandbox.mjs
export default ({ distributionId, fetch, endpoint, credential, credentialRejected }) => ({
  id: "acme-sandbox",
  available: async () => ({ available: true }),
  capabilities: () => ({
    isolation: "remote",
    // Add "filesystem-read-deny" and "filesystem-write-allowlist" only if the
    // service really applies profile.readDeny and profile.writeAllow.
    planes: ["host-filesystem-isolation", "network-deny", "environment-filter"],
    network: ["deny", "allow"],
    localProcesses: false,
  }),
  prepare: async ({ profile }) => {
    const session = await createAcmeSession(fetch, endpoint, credential, profile.network);
    return {
      exec: (request, io) => session.run(request, io),
      dispose: () => session.close(),
    };
  },
});
```

The factory receives the distribution ID, PiShip's managed fetch, the resolved endpoint, and, under the rules above, `credential` (a function that returns the credential for one request), `credentialOrigins` (where it may be sent), and `credentialRejected` (to call when those origins reject the credential, which means authentication failed: HTTP 401 for the built-in backends, never a 403 authorization denial; it resolves true when a renewed credential is ready for one retry of a request that created nothing). PiShip fixes the provider to `custom`, rejects ids that belong to built-in backends, checks the shape of every returned object, and fails closed if the module is missing or throws. It bounds the adapter's code as the built-in remote backends bound their requests: loading the module and running the factory have 60 s, `available()` 60 s, `prepare()` 180 s, and `dispose()` 30 s, each with a signal that aborts at the deadline (`request.signal` for `prepare`, an optional `{ signal }` argument for the others). A backend that runs past one fails activation closed with a retryable `SANDBOX_UNAVAILABLE` naming the backend and the call; a `dispose()` that does is no longer waited for, so quit never hangs, and PiShip says so on stderr ([deadlines](adapter-sdk.md#deadlines)). The adapter runs in the Pi process with the user's privileges, like other company adapters, so it is reviewed and shipped by the distribution owner.

For the [setup cache](#setup-cache) an instance may also return `snapshot({ signal })`, which saves the sandbox and resolves `{ id }` (an id of letters, digits, `_ . : -`, at most 128 characters; anything else is refused), and the backend may offer `deleteSnapshot(id, { signal })`. PiShip then passes the id back as `template` in the request to `prepare()`; an adapter that cannot find it rejects with an error whose `code` is `SNAPSHOT_GONE`, and PiShip prepares again without `template`. A `snapshot()` that rejects with `code: "SNAPSHOT_UNSUPPORTED"` is remembered for 24 hours. Caching is on for a custom adapter only with `sandbox.remote.cache: snapshot`.

### e2b-compatible

The backend speaks the E2B sandbox API: `GET /health`, `POST /sandboxes` (template, lifetime, `allow_internet_access` from the network mode, no environment), `POST /sandboxes/{id}/timeout` before each command, and `DELETE /sandboxes/{id}` on dispose, and, for the [setup cache](#setup-cache), `POST /sandboxes/{id}/snapshots` (body `{"memory": false}`; a snapshot id is later passed as `templateID` to create) and `DELETE /templates/{id}`, with the declared credential (`runtime` or `stored`) sent as `X-API-Key` to the control endpoint only. Commands run through envd's `process.Process/Start` (Connect streaming over JSON) as `/bin/bash -l -c <command>` at `https://49983-<id>.<domain>`, where the domain comes from the create response or the endpoint host, with `Authorization: Basic <user>:` naming the sandbox user (`sandbox.user`, default `user`). Output streams as it arrives.

The backend declares no [network probe](#network-denial): PiShip has no endpoint it knows an E2B sandbox with Internet access can reach, and the manifest has no field to name one. In `deny` mode the sandbox is created with `allow_internet_access: false` and network denial is reported attested by the service; no second sandbox is created.

CubeSandbox and other services that implement the E2B API use the same backend: point `endpoint` at their API URL and set the user they run commands as (`user: root` for CubeSandbox). Nothing in PiShip depends on or detects a specific vendor.

### kubernetes-agent-sandbox

A thin client for [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox): it creates a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) with `spec.warmPoolRef`, waits for its `Ready` condition, runs each command through the router's `POST /execute` with the `X-Sandbox-ID`, `X-Sandbox-Namespace`, and `X-Sandbox-Port` headers, and deletes the claim when the session ends. Because the runtime splits the command without a shell, PiShip sends `env NAME=value ... /bin/sh -c '<command>'`. Output arrives when the command ends.

A command's request lasts as long as the command: no PiShip deadline applies to it, and undici's 300-second header and body timeouts, which every other managed request keeps, are off for it. Only PiShip's command timeout (the `bash` tool's `timeout`) or the user's cancel ends it, and a command without a timeout runs until it ends, as it would locally. A proxy, ingress, or the router itself may still give up on a long request first. When the connection to the router fails after a command was sent, or the router or a gateway in front of it answers 5xx, the command may have run in part or in full, or still be running. PiShip never sends it again and never reports it as retryable: the command fails with `SANDBOX_UNAVAILABLE` (`retryable: false`), saying that its outcome is unknown and that its effects should be checked before it is run again. Its claim is retired as a cancelled command's is: deleted, with whatever still runs in its pod, once no other command uses it, and the next command gets a fresh claim. Give any proxy or ingress in front of the router a read timeout at least as long as the longest command the agent runs, or such commands fail this way.

Every claim is created with a bounded lifecycle as a safety net, using Agent Sandbox's `spec.lifecycle`: `shutdownTime` one lifetime (`lifetimeSeconds`, default one hour) after creation (rounded up to the second) and `shutdownPolicy: Delete`. The cluster removes the claim at that time even if PiShip's DELETE never arrives, for example because the API was down when a command was cancelled. A session in use is not cut short: before a command, PiShip extends `shutdownTime` by a merge patch when less than half the lifetime is left, and while a command runs it extends it every quarter of the lifetime. Before every command PiShip also checks that the claim still exists. A claim past its `shutdownTime`, or one the cluster already removed, is replaced before the command runs and is never revived; a router 404 retires the claim without replaying a command whose result might be ambiguous, as does a command whose outcome is unknown (above), and so does a claim the cluster removes while a command runs, as soon as a renewal finds it gone: that command's outcome stands, and the next command gets a fresh claim. A session idle for longer than one lifetime therefore continues in a fresh sandbox pod, and anything the earlier commands left inside the old pod is gone. No claim is created after the session is disposed. A renewal that fails otherwise fails the command, rather than run it in a sandbox about to be removed. A retired claim is renewed only while a command that started before its retirement still runs in it, and a disposed or removed claim never, so each is gone at most one lifetime after its last command or renewal. `shutdownTime` is an absolute time the cluster compares with its own clock. PiShip takes the wall clock and the monotonic clock when it creates a claim, and counts the time since on whichever advanced more: the monotonic clock stops while the machine sleeps, and the wall clock can be set back, so neither may shorten the count. That count decides when the claim is due for renewal, when it counts as expired (it is then replaced, and a renewal, including a keepalive that fires late after a suspend, never revives it), and the `shutdownTime` a renewal sends: the creation time plus the count plus the lifetime. A clock set back therefore never moves `shutdownTime` earlier, and PiShip never sends a `shutdownTime` earlier than the one the cluster last accepted. A clock set forward cannot be told apart from a suspend and counts as elapsed time: renewal comes earlier, a jump past `shutdownTime` replaces the claim, and a renewal can lengthen the claim by at most the jump. How long PiShip waits for a claim to become ready (120 seconds, not configurable) is a wait and uses the monotonic clock alone. The lifetime the cluster enforces is still only as accurate as the agreement between this machine's clock at claim creation and the cluster's: the two must roughly agree (for example, both synchronized with NTP). The cluster owns images, scheduling, and isolation. The adapter cannot verify the pool's NetworkPolicy or construct an equivalent allow-mode pool, so it refuses a required `network: deny` sandbox rather than treating one unreachable public host as proof. A declared credential (`runtime` or `stored`) is sent as `Authorization: Bearer` to the API and the router; otherwise use `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy ([Credentials](#credentials)).

## Tests

- Native: the live boundary and escape tests in `packages/sandbox/src/boundary.test.ts` (writes, reads, network, environment, git control files, submodule and linked-worktree git directories, a `core.hooksPath` directory in the working tree, process-tree kill on timeout and cancel, the macOS launchd escape test) run unchanged through the backend contract. The live probe's `git-control-protection` must be reported there on Linux and macOS before local backends are required to provide it. `native.test.ts` checks that `dispose()` returns only once a command that ignores SIGTERM has been killed, and that the session temp directory the activation removes next is not recreated by such a command.
- Workspace: `workspace.test.ts` runs the check against fake backends in `packages/sandbox/src/testing/workspace-fakes.ts` whose commands run in a real shell: a shared workspace (the workspace itself), a synchronized one (a separate directory and a timer-driven copier, with either direction switchable off), and a snapshot. It covers malformed declarations, the plane matrix, each row of the result table and its report sentence, a writable git control file or directory and a missing protected file the sandbox can create (fails closed before the agent's command, nothing changed, probe files, created files, and created directories removed), the rename check (a path that could be moved aside, a git directory above the protected paths, mount points found by device and in a mount table), a hooks directory in the working tree, a failing or timed-out check, a cancelled check that does not count, every location case including a planted symbolic link, the company-only working-tree location, the stale sweep, removal at process exit and a link swapped in for the location during a check (nothing is deleted through it, and never recursively), the validity window with an injected clock and an epoch change, one check for concurrent first commands, and that no token or path reaches a report. A local backend that ignores `writeProtect` is reported without `git-control-protection` and with a warning.
- Contract: `backends.test.ts` covers the custom adapter lifecycle order, fail-closed availability, preparation, and verification, capability mismatch for every guarantee and isolation kind (path planes never stand in for host isolation or the reverse), the environment a backend receives, and PiShip-owned timeout, cancellation, retirement, and dispose. A local adapter that wraps nothing is rejected by the live probe.
- Remote: `remote.test.ts` checks that the E2B and Kubernetes backends never report `filesystem-*` planes and declare a `snapshot` workspace, including the exact `doctor` line, that no workspace check reaches either service, and that the Kubernetes `epoch()` changes when an expired claim is replaced. It runs the e2b-compatible backend against a mock E2B control plane and envd that enforces the Basic user (`user` by default, `root` when configured), and the Kubernetes backend against a mock API server and router, covering the claim lifecycle safety net, failed cleanup, renewal (including wall-clock jumps), expired claims, a claim removed early before or during a command or unknown to the router, a command whose router connection drops or whose router answers 5xx (non-retryable, never resent, its claim deleted), and idempotent dispose. `packages/contracts/src/network-long-running.test.ts` holds a request with fake timers past undici's 300-second header timeout: a normal managed request fails with `UND_ERR_HEADERS_TIMEOUT`, and a long-running one, the kind a Kubernetes command sends, waits for its answer and still ends with its signal. Every request on the wire is checked for leaked credentials and host environment. A mock E2B control plane that requires an API key checks that the key appears only as `X-API-Key` on control requests, that a rejected create is reported and never repeated, that a rejected renewal is repeated once only when the credential was renewed, and that a 401 body echoing the key never reaches an error.
- Reference sandbox: `examples/enterprise-reference/tests/sandbox.test.ts` runs the [reference container sandbox](../examples/enterprise-reference/sandbox/README.md) service and its custom adapter against real Docker containers: the sandbox conformance kit passes every behavior with none skipped, and a governed session built from the committed manifest and lock, with the stored sandbox credential, finds the workspace `shared` (both directions immediate, git control attested). It also holds the service to its own boundary: a key mounts only projects owned by the host user it is bound to, a command's environment is on no process list and in no file, and cancelling a command leaves no process behind, even one that dropped the ID the service marks a command's processes with. The adapter declares no network probe, so its network denial is attested by the service (`networkDenial: {evidence: "attested"}`) and no second container is created. It runs with the reference tests (`npm run test:reference`), not in the pull request gate.
- Credentials: `packages/core/src/sandbox-credential.test.ts` and `branded-sandbox.test.ts` cover `sandbox login` (no-echo prompt, first stdin line, no argv or environment path, validation), persistence, the origin rule (no secret read for another origin), principal binding across user switches with injected crashes and failing deletes, `logout`, `sandbox logout`, `purge`, update and rollback to a release without the state key, audit events, and a scan of the state directory. `packages/pi/src/governance/sandbox-credential.test.ts` checks what each backend sends and to where, the fail-closed endpoint change, rejection, and a custom adapter's in-memory `sandboxCredential`. `tests/e2e/sandbox-credential.test.ts` runs `sandbox login` over stdin, a launch whose bash runs in a mock Kubernetes Agent Sandbox that requires the token, the endpoint change, and `logout`.
