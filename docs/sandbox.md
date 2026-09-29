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
| `native` (default) | Local processes inside bubblewrap (Linux) or Seatbelt (macOS) | `filesystem-read-deny`, `filesystem-write-allowlist`, `network-deny` (deny mode), `environment-filter`, `git-control-protection` | `shared` (this host's files) | Yes | Live probe | Candidate, with the boundary and escape tests below |
| `custom` | Wherever the company adapter runs them | What the adapter declares, checked against the policy | What the adapter declares, verified before the first command | Only a local adapter that wraps processes | Live probe for a local wrapping adapter; otherwise backend-attested | Contract and lifecycle tested with fake adapters; no company adapter is shipped |
| `e2b-compatible` | In a remote sandbox created through the E2B API | `host-filesystem-isolation`, `network-deny` (deny mode), `environment-filter` | `snapshot` | No | Backend-attested | Tested against a mock E2B server; no live E2B or CubeSandbox evidence |
| `kubernetes-agent-sandbox` | In a sandbox pod claimed from a warm pool | `host-filesystem-isolation`, `network-deny` (deny mode), `environment-filter` | `snapshot` | No | Backend-attested | Tested against a mock API server and router; no live cluster evidence |

A report never claims more than the backend enforces. The `filesystem-read-deny` and `filesystem-write-allowlist` planes mean that `sandbox.filesystem.read.deny` and `sandbox.filesystem.write.allow` are enforced on the commands. `host-filesystem-isolation` means something narrower and different: commands run on another machine or VM and cannot reach this host's files at all. It is not PiShip's path policy. Inside the remote sandbox, what a command may read or write is up to the template or image, and the path rules still govern PiShip's local file tools. The E2B and Kubernetes backends therefore report `host-filesystem-isolation` and never the `filesystem-*` planes, and `doctor` says that the path rules are not enforced inside the remote sandbox. A remote backend whose sandbox mounts or syncs the developer's workspace reaches this host's files through it, so it cannot claim `host-filesystem-isolation`; it claims `workspace-confinement` and `git-control-protection` instead ([Workspace](#workspace)).

## Configuration

Only `sandbox.required: true` activates a sandbox, and a non-native provider is accepted only when the sandbox is required. A backend that cannot be used fails the launch with `SANDBOX_UNAVAILABLE`; there is no fallback to another backend or to running uncontained. The `filesystem`, `network`, and `environment` fields ([manifest](manifest.md#sandbox)) apply to every provider.

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
  workdir: /home/user/repo        # default: /home/user
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
  workdir: /root/repo
  user: root                      # CubeSandbox; E2B keeps the default, user
```

```yaml
variables: [KUBE_API_URL, SANDBOX_ROUTER_URL]
sandbox:
  required: true
  provider: kubernetes-agent-sandbox
  endpoint: ${KUBE_API_URL}          # Kubernetes API, or an authenticating proxy to it
  router: ${SANDBOX_ROUTER_URL}      # the sandbox router
  namespace: agents                  # default: default
  template: python-sandbox-pool      # SandboxWarmPool to claim from
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
| `endpoint` | remote and `custom` | Control endpoint URL or `${NAME}` [runtime reference](manifest.md#runtime-references). HTTPS, or HTTP to loopback only |
| `router` | `kubernetes-agent-sandbox` | Sandbox router URL or `${NAME}` reference |
| `namespace` | `kubernetes-agent-sandbox` | Namespace of the SandboxClaims |
| `template` | `e2b-compatible`, `kubernetes-agent-sandbox` | E2B template ID, or the SandboxWarmPool name |
| `workdir` | `e2b-compatible`, `kubernetes-agent-sandbox` | Absolute remote directory that maps to the workspace |
| `user` | `e2b-compatible` | The sandbox user commands run as (envd's `Authorization: Basic <user>:`). Default `user`, as E2B expects; CubeSandbox needs `root`. The default `workdir` stays `/home/user`, so set `workdir` together with `user` (for example `/root/repo`) |
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

The e2b-compatible backend sends it to the control endpoint only, never to envd (which uses the per-sandbox access token); the Kubernetes backend sends it to the API and the router. When one of those origins answers 401 or 403, the stored credential is marked rejected and the request is not repeated. A running session re-reads the metadata before every request: when another user signs in, or the credential is replaced or deleted, the session stops using it without deleting anything; the same user's new credential is used from the next request.

**Clearing it.** `login` as another principal deletes it, confirming the deletion, before the new identity is stored; a failed deletion fails the login. `logout`, `sandbox logout`, and `purge` delete it. An update or rollback to a release that cannot read it (every release before it) deletes it first; run `sandbox login` again after rolling forward. It is never copied into a rollback snapshot. See [security](security.md#user-switching).

**Checking it.** The Sandbox group of `doctor` shows `sandbox credential <state> (<source>, <kind>) in <store>`, where the state is `absent`, `valid`, `rejected`, `principal-mismatch`, or `origin-mismatch`, and two binding lines: whether it is bound to the current principal, and whether its recorded origin matches the configured endpoint. A rejected credential is a warning that asks for `sandbox login`; an absent one, another user's, or one stored for another endpoint fails a required sandbox. Without a signed-in user, the principal binding is shown as not checked. Doctor reads the non-secret metadata only: it never shows the secret, its reference or ID, or the recorded origins, and it deletes nothing (the next launch does).

A stored key is typed by a person and is often a shared organization key. For managed distributions, prefer credentials the company issues per user: `runtime` behind the gateway, or an adapter credential.

#### Adapter credentials

A custom adapter module may export `sandboxCredential`, a standard `CredentialProvider` (`acquire`, optional `refresh` and `revoke`), next to its factory. PiShip then acquires it at launch with the signed-in identity, holds it in memory for that process only (never in the secret store, state, snapshots, or migration), renews it before it expires and once after a rejection, repeats the one request that created nothing with the renewed credential, and revokes it, best effort, when the session ends. The identity it passes must stay the launch's principal. The factory receives it as `credential`, with `credentialOrigins` (the declared endpoint's origin) and `credentialRejected`. Exporting `sandboxCredential` while the manifest also declares `sandbox.credential` fails closed: a backend gets one credential. Short-lived and workload credentials (such as an in-cluster service account token) come this way; the built-in backends take only `stored`.

Without a credential PiShip can send, use `credential: none` with an endpoint that needs no client credential, such as `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy.

PiShip calls remote backends through its managed fetch, so the proxy, CA, and `network.privateOnly` settings apply. With `privateOnly`, every host must be listed in `network.allowHosts`; E2B's data plane uses one host per sandbox (`49983-<id>.<domain>`), so an e2b-compatible backend works with `privateOnly` only when that host is known and allowed.

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
4. **Verify.** A backend whose instance can wrap local processes is live-probed exactly like the native sandbox, including `git-control-protection`: a child must fail to write a protected file, to create a file in a protected directory, and to rename the directory that holds a protected file. Until that check has passed on Linux and macOS CI it is reported, not required: a local backend that fails it still activates, without the plane and with a warning. Any other backend is checked from outside: a command must run and report back, a marker variable PiShip set in its own source environment must not arrive (this confirms PiShip's filtering end to end; the backend's own environment plane is attested), and in `deny` mode an outbound connection from inside must fail. The network check needs `bash` and `timeout`, or `nc`, in the sandbox; if it cannot run, a `deny` policy fails closed. The report says which: `verification: live-probe` or `backend-attested`.
5. **Exec.** See below. For a remote backend with a shared or synchronized workspace, the first command that reaches the sandbox is preceded by the [workspace check](#workspace).
6. **Dispose.** Called once when the session ends, or right away when verification fails. A remote sandbox is deleted; E2B sandboxes also expire on their own after the renewed lifetime.

`doctor` shows the backend, level, guarantees, and verification, and the isolation the containment report names: `local` for an enforced backend that runs commands on this host, `remote` for one that runs them on another machine, and `none` when nothing is enforced. Its Workspace group shows the effective consistency, the declared mode, the verification state, whether the workspace is a complete coding-agent workspace, and how the git control files are protected ([Workspace](#workspace)). The path policy counts as enforced by the backend only when it reports both `filesystem-read-deny` and `filesystem-write-allowlist`. Otherwise `doctor` adds that `sandbox.filesystem` path rules are not enforced inside the sandbox, or, when the backend reports only one of the two planes, that they are only partly enforced. The `--smoke` summary adds the provider, and local metrics record the level and backend. `policy explain` and file-tool denials count filesystem actions as sandbox-enforced only with both path planes; otherwise they are `control-plane`, decided by PiShip for its local file tools.

## What PiShip controls

- **Policy and approvals.** Every `bash` and `!` command is decided as `shell.execute` before any backend sees it. File tools (`read`, `write`, `edit`) always run in the Pi process under PiShip's governed file access.
- **Environment.** A backend receives one command, its working directory, and the environment PiShip approved: the `sandbox.environment.allow` list, with credential-looking names always removed. A remote backend additionally never receives host-bound variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`); its own environment provides them. Nothing else is sent when a sandbox is created: no environment, no files, and no credential other than the declared control-plane credential.
- **Filesystem.** PiShip does not upload or sync the workspace. A remote backend runs commands in `workdir` plus the command's path relative to the workspace, and refuses a working directory outside the workspace. The template, image, or volume must provide the code. Local file tools and remote commands therefore see different copies unless the backend mounts or syncs the workspace, which it declares and PiShip verifies ([Workspace](#workspace)). The remote sandbox does not apply `sandbox.filesystem` path rules; they keep governing the local file tools.
- **Credentials.** A backend receives a credential only as `sandbox.credential` declares it (`runtime` or `stored`) or from its own adapter module, and only for the origins that credential may reach ([Credentials](#credentials)). It is read per request, never placed in a command's environment, and scrubbed from any error that echoes it. E2B's per-sandbox envd access token is used only for that sandbox's data plane and never leaves the process.
- **Timeout and cancellation.** PiShip starts the timer and listens to the user's cancel. On either, it aborts the signal it passed to the backend, stops forwarding output, and reports `timeout` or `aborted` whatever the backend returns afterwards. A backend that does not settle within five seconds is retired: its instance is disposed, and later commands in that session fail with `SANDBOX_UNAVAILABLE`. Native commands get SIGTERM, then SIGKILL of the whole process group after one second; disposing a native instance stops a command still running the same way and returns once it is gone (for two seconds at most), so nothing runs in the session temp directory the activation removes next. E2B commands get `SendSignal(SIGKILL)` for the command's tagged process, which works even before its pid is known; background processes it started in the sandbox are removed when the sandbox is. The Kubernetes runtime API cannot stop a running command, so a cancelled command retires its claim: the next command gets a fresh sandbox, and the retired claim is deleted once no other command still running in it needs it. If that DELETE fails, the claim's `shutdownTime` still removes it (see below); a failed cleanup is not logged and never exposes the command, environment, or credential.
- **Audit and diagnostics.** Decisions are recorded by PiShip as before; failure details from backends are redacted.

MCP stdio servers need a local process with pipes. A backend that cannot contain local processes refuses them with `SANDBOX_UNAVAILABLE`, so such servers do not start; use Streamable HTTP servers with remote backends.

## The contract

```ts
interface SandboxBackend {
  readonly id: string;                 // e.g. "linux-bubblewrap", "acme-sandbox"
  readonly provider: "native" | "custom" | "e2b-compatible" | "kubernetes-agent-sandbox";
  available(): Promise<{ available: true } | { available: false; reason: string }>;
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
    // Remote only; omitted means snapshot. Ignored for local backends (shared).
    workspace?: {
      mode: "snapshot" | "synchronized" | "shared";
      propagationMs?: number;   // synchronized only: 1..60000, default 10000
      sentinelDir?: string;     // shared or synchronized only: workspace-relative
    };
  };
  prepare(request: { profile: SandboxProfile; signal?: AbortSignal }): Promise<SandboxInstance>;
}

interface SandboxInstance {
  exec(
    request: { command: string; cwd: string; workspacePath: string | undefined; env: Record<string, string> },
    io: { signal: AbortSignal; onStdout(chunk: Buffer): void; onStderr(chunk: Buffer): void },
  ): Promise<{ exitCode: number | null; signal?: NodeJS.Signals | null }>;
  wrap?(command: { file: string; args: string[]; cwd: string; env: Record<string, string> }): WrappedCommand;
  dispose(): Promise<void>;
  // Optional: an opaque, non-secret id of the environment the last command ran in.
  epoch?(): string | undefined;
}
```

A backend never decides policy, never reads PiShip's state, and must pass `env` through as given. `exec` must stop when `io.signal` aborts. `wrap` is only for local backends: spawning the returned command on this host must run it contained. `epoch` changes when the backend moves the session to a new environment (the Kubernetes backend returns the claim name, which changes when an expired claim is replaced); a change makes PiShip check a shared or synchronized workspace again before the next command.

## Workspace

Pi's file tools (`read`, `write`, `edit`) always work on this host's files; only shell commands reach the sandbox. A backend is a complete coding-agent workspace only when its commands see the files those tools edit. It declares how in `capabilities().workspace`:

| Mode | Meaning | Examples | Complete coding-agent workspace |
| --- | --- | --- | --- |
| `shared` | The sandbox and the file tools touch the same files | a bind mount, a shared volume, a company workspace service | Yes, once verified |
| `synchronized` | Different stores that a backend-owned engine keeps in step both ways within `propagationMs` | a two-way sync agent | Yes, once verified |
| `snapshot` (default) | Anything else: the sandbox sees a copy at best | a template, an image, a `git clone`, a one-time upload | Never |

A local backend is `shared` by construction and needs no check. The built-in `e2b-compatible` and `kubernetes-agent-sandbox` backends declare `snapshot`: PiShip does not know what their template or warm pool mounts. A company that mounts the developer's workspace into its sandbox uses a custom adapter and declares `shared`. PiShip does not implement a sync engine.

### Protected git paths

Git runs some of the project's files outside any sandbox, with the user's next command, so `profile.writeProtect` names the git paths a sandbox must not change. They come from the project's `.git`, the git directory a `.git` file points to, and the shared directory of a linked worktree:

- Files: the `.git` entry itself (a pointer file in a linked worktree or submodule), and `config`, `config.worktree`, and `commondir` of each git directory, with the shared `config`. `commondir` and `config.worktree` normally do not exist; git follows them when they appear.
- Trees, as a whole and also while they do not exist yet: `hooks` and `info`; `modules`, the git directories of submodules (each has its own `config`, `hooks`, and `info`, and `git status` enters them); `worktrees`, the administrative directories of linked worktrees (each has its own `commondir`, `gitdir`, and `config.worktree`); and the directory `core.hooksPath` names in those config files. That last one is read when the session starts: every value counts, a relative one is taken from the project root and `~/` from the home directory, and one that holds the whole project root is left out, since it would make the project read-only.

The native adapters keep all of these read-only inside the writable workspace, and PiShip's own file tools refuse to write them. So a shell command in a native sandbox cannot add or update a submodule, commit or fetch inside one, or add a linked worktree (`git submodule update --init`, `git worktree add`), and a tool that regenerates a hooks directory named by `core.hooksPath` (husky's `.husky/_`) fails while it does; run those outside the sandbox. A hooks directory in the working tree is protected but not vouched for: the scripts it calls (`.husky/pre-commit`) are ordinary project files the sandbox can write, so git control is reported `not-verified`. Bubblewrap guards a directory that does not exist yet by mounting an empty read-only one over it, which leaves an empty directory (`.git/modules`, `.git/worktrees`) on the host; it cannot guard a missing file. A remote backend has to keep the same paths read-only, and the check below tries them.

### The workspace check

A declared `shared` or `synchronized` workspace is checked lazily, just before the first command that reaches the sandbox, and not at activation: a session that stays in Plan mode, where no command reaches the sandbox, writes nothing into the project, and `doctor` never runs the check (it shows the workspace as `pending`). The agent's command is sent only after the check. One check is one command in the sandbox, run at the workspace root with the approved environment, bounded by the window plus 30 seconds, and not charged to the command's timeout:

1. **Location.** PiShip uses a directory it owns: `<workspace>/.git/piship-workspace/` when `.git` is a real directory (git ignores unknown entries there, so nothing appears in `git status`), or `<workspace>/<sentinelDir>/piship-workspace/` when the backend declares `sentinelDir`. A `sentinelDir` in the working tree (not under `.git`) is used only when the project's origin is `company`. Without a usable location (no `.git`, a `.git` file of a linked worktree, a `.git` symbolic link, a working-tree `sentinelDir` in an external or unknown project) the workspace is `unverifiable` and counts as `snapshot`. Every host-side component must be a plain directory, never a symbolic link, and must resolve inside the workspace; directories are created with mode 0700, files with 0600 and no-follow, exclusively. Each run uses a fresh random directory, removes it afterwards (and at process exit), and first removes nonce directories an earlier run left behind for more than a day. Nothing here is ever deleted recursively: the sandbox can write in this location, and a recursive delete would follow a link it swapped in for a component and remove host files. A run creates only `h2s`, `s2h`, and `s2h.tmp`; cleanup checks every component of the path again before each step, unlinks those names when they are regular files, and removes the directory only if that leaves it empty. The stale sweep skips a directory that holds any other name, so a directory the sandbox filled with other files stays until someone removes it.
2. **Host to sandbox.** The host writes a random token; the sandbox polls for it every 200 ms up to the window (10 s for `shared`, `propagationMs` for `synchronized`).
3. **Sandbox to host.** The sandbox writes a second random token (to a temporary name, then renamed); the host reads it right after the command returns and polls up to the window.
4. **Git control files.** In the same command, the sandbox tries, without changing anything that exists, to open each existing protected file (the profile's `writeProtect`: `.git/config`, a `.git` pointer file, and the like) for append with zero bytes, to create each protected file that does not exist yet without clobbering (`.git/commondir` and `.git/config.worktree` normally do not exist, and git follows them when they appear), and to create `<protected dir>/.piship-probe-<nonce>` in each protected directory (`.git/hooks`, `.git/info`, `.git/modules`, `.git/worktrees`, and a `core.hooksPath` directory, creating the directory first when it is missing). Every attempt must fail. The host, which recorded before the command what existed, then removes any probe file, any protected directory the probe created if it is empty, and any protected file the probe created if it is still an empty regular file, each reached only through plain directories. Renames are not tried remotely (a successful rename is destructive). The same command looks for a way to rename instead: for each protected path and each directory above it, up to the workspace root, that exists in the sandbox, it checks whether it is a mount point (its device differs from its parent's, read with GNU `stat -c` or BSD `stat -f`, or it is listed in Linux's `/proc/self/mountinfo`, which also covers a bind mount of the same filesystem) and whether its parent directory is writable (`test -w`). A path that is not a mount point and sits in a writable directory could be moved aside and replaced (`mv .git/hooks .git/h; mkdir .git/hooks`, or renaming `.git` itself, whose parent is the workspace root), so git control is reported `not-verified`; the commands still run. When nothing could be moved the report says `attested-renames`: writes were probed and renames ruled out by the mount and permission structure, not tried. The answer errs toward `not-verified`: without `stat` and a mount table, or where `test -w` calls a read-only directory writable (BusyBox as root), a protected path still counts as movable.

The command prints only fixed tokens, never file contents or paths, and the report never carries a token, a path, or an origin.

| Result | Effective mode | Verification | Outcome |
| --- | --- | --- | --- |
| Declared `shared`, both directions seen at once | `shared` | `verified` | Commands run |
| Declared `shared`, a direction delayed within 10 s | `synchronized` | `verified` | Warning; commands run |
| Declared `synchronized`, both within `propagationMs` | `synchronized` | `verified` | Commands run |
| A direction missing | `snapshot`, naming the direction that failed | `failed` | Warning; commands run |
| No location | `snapshot` | `unverifiable` | Warning; commands run |
| A protected file or directory was writable, a missing protected file could be created, or the check did not run, exited non-zero, or timed out | — | `failed` | `SANDBOX_UNAVAILABLE`: the instance is retired, the pending command was never sent, and no later command runs in that session |

The effective mode is never stronger than the declaration. A lower mode is a warning, not a failure: the commands still run on what the sandbox sees. Only the git-control failure closes, because the hooks the sandbox could write run outside any sandbox with the user's next git command. A protected path the sandbox could rename lowers nothing and closes nothing: `doctor` shows the git control files as not verified. The check refutes a claim; it cannot prove a mount. An immediate result also fits a very fast sync, so the report says "both directions immediate", never "is a mount". The session shows one notice when the mode is lower than declared and records the result in the local metrics, which `doctor` shows while its own check is pending.

A result counts until the first of: 30 minutes pass, the instance reports a new `epoch()`, or the instance is retired. The next command then checks again first. A command that happened to run in a replaced environment before that is not checked afterwards.

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

The factory receives the distribution ID, PiShip's managed fetch, the resolved endpoint, and, under the rules above, `credential` (a function that returns the credential for one request), `credentialOrigins` (where it may be sent), and `credentialRejected` (to call on a 401 or 403 from those origins; it resolves true when a renewed credential is ready for one retry of a request that created nothing). PiShip fixes the provider to `custom`, rejects ids that belong to built-in backends, checks the shape of every returned object, and fails closed if the module is missing or throws. The adapter runs in the Pi process with the user's privileges, like other company adapters, so it is reviewed and shipped by the distribution owner.

### e2b-compatible

The backend speaks the E2B sandbox API: `GET /health`, `POST /sandboxes` (template, lifetime, `allow_internet_access` from the network mode, no environment), `POST /sandboxes/{id}/timeout` before each command, and `DELETE /sandboxes/{id}` on dispose, with the declared credential (`runtime` or `stored`) sent as `X-API-Key` to the control endpoint only. Commands run through envd's `process.Process/Start` (Connect streaming over JSON) as `/bin/bash -l -c <command>` at `https://49983-<id>.<domain>`, where the domain comes from the create response or the endpoint host, with `Authorization: Basic <user>:` naming the sandbox user (`sandbox.user`, default `user`). Output streams as it arrives.

CubeSandbox and other services that implement the E2B API use the same backend: point `endpoint` at their API URL and set the user they run commands as (`user: root` for CubeSandbox). Nothing in PiShip depends on or detects a specific vendor.

### kubernetes-agent-sandbox

A thin client for [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox): it creates a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) with `spec.warmPoolRef`, waits for its `Ready` condition, runs each command through the router's `POST /execute` with the `X-Sandbox-ID`, `X-Sandbox-Namespace`, and `X-Sandbox-Port` headers, and deletes the claim when the session ends. Because the runtime splits the command without a shell, PiShip sends `env NAME=value ... /bin/sh -c '<command>'`. Output arrives when the command ends.

Every claim is created with a bounded lifecycle as a safety net, using Agent Sandbox's `spec.lifecycle`: `shutdownTime` one hour after creation (rounded up to the second) and `shutdownPolicy: Delete`. The cluster removes the claim at that time even if PiShip's DELETE never arrives, for example because the API was down when a command was cancelled. A session in use is not cut short: before a command, PiShip extends `shutdownTime` by a merge patch when less than half the lifetime is left, and while a command runs it extends it every quarter of the lifetime. A claim past its `shutdownTime`, or one the cluster already removed, is replaced before the command runs and is never revived; a claim that disappears while a command runs is not reused. A session idle for longer than one lifetime therefore continues in a fresh sandbox pod, and anything the earlier commands left inside the old pod is gone. No claim is created after the session is disposed. A renewal that fails otherwise fails the command, rather than run it in a sandbox about to be removed. Retired and disposed claims are never renewed, so they are gone at most one lifetime after their last renewal. The cluster owns images, scheduling, and isolation; network denial is the template's NetworkPolicy, which PiShip checks with the outbound connection test. A declared credential (`runtime` or `stored`) is sent as `Authorization: Bearer` to the API and the router; otherwise use `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy ([Credentials](#credentials)).

## Tests

- Native: the live boundary and escape tests in `packages/sandbox/src/boundary.test.ts` (writes, reads, network, environment, git control files, process-tree kill on timeout and cancel, the macOS launchd escape test) run unchanged through the backend contract. The live probe's `git-control-protection` must be reported there on Linux and macOS before local backends are required to provide it. `native.test.ts` checks that `dispose()` returns only once a command that ignores SIGTERM has been killed, and that the session temp directory the activation removes next is not recreated by such a command.
- Workspace: `workspace.test.ts` runs the check against fake backends in `packages/sandbox/src/testing/workspace-fakes.ts` whose commands run in a real shell: a shared workspace (the workspace itself), a synchronized one (a separate directory and a timer-driven copier, with either direction switchable off), and a snapshot. It covers malformed declarations, the plane matrix, each row of the result table and its report sentence, a writable git control file or directory (fails closed before the agent's command, nothing changed, probe files and created directories removed), a failing or timed-out check, a cancelled check that does not count, every location case including a planted symbolic link, the company-only working-tree location, the stale sweep, removal at process exit, the validity window with an injected clock and an epoch change, one check for concurrent first commands, and that no token or path reaches a report. A local backend that ignores `writeProtect` is reported without `git-control-protection` and with a warning.
- Contract: `backends.test.ts` covers the custom adapter lifecycle order, fail-closed availability, preparation, and verification, capability mismatch for every guarantee and isolation kind (path planes never stand in for host isolation or the reverse), the environment a backend receives, and PiShip-owned timeout, cancellation, retirement, and dispose. A local adapter that wraps nothing is rejected by the live probe.
- Remote: `remote.test.ts` checks that the E2B and Kubernetes backends never report `filesystem-*` planes and declare a `snapshot` workspace, including the exact `doctor` line, that no workspace check reaches either service, and that the Kubernetes `epoch()` changes when an expired claim is replaced. It runs the e2b-compatible backend against a mock E2B control plane and envd that enforces the Basic user (`user` by default, `root` when configured), and the Kubernetes backend against a mock API server and router, covering the claim lifecycle safety net, failed cleanup, renewal, expired claims, and idempotent dispose. Every request on the wire is checked for leaked credentials and host environment. A mock E2B control plane that requires an API key checks that the key appears only as `X-API-Key` on control requests, that a rejected create is reported and never repeated, that a rejected renewal is repeated once only when the credential was renewed, and that a 401 body echoing the key never reaches an error.
- Credentials: `packages/core/src/sandbox-credential.test.ts` and `branded-sandbox.test.ts` cover `sandbox login` (no-echo prompt, first stdin line, no argv or environment path, validation), persistence, the origin rule (no secret read for another origin), principal binding across user switches with injected crashes and failing deletes, `logout`, `sandbox logout`, `purge`, update and rollback to a release without the state key, audit events, and a scan of the state directory. `packages/pi/src/governance/sandbox-credential.test.ts` checks what each backend sends and to where, the fail-closed endpoint change, rejection, and a custom adapter's in-memory `sandboxCredential`. `tests/e2e/sandbox-credential.test.ts` runs `sandbox login` over stdin, a launch whose bash runs in a mock Kubernetes Agent Sandbox that requires the token, the endpoint change, and `logout`.
