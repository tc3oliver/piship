# Reference container sandbox

The custom sandbox of the [AcmeCode reference distribution](../README.md#reference-container-sandbox): what a company that runs its own sandbox service writes for PiShip. The [service](service/server.mjs) runs each user's commands in a container with the user's project bind-mounted, and the [adapter](acme-container-sandbox.mjs) is the single file that lets PiShip use it (`sandbox.provider: custom`). The workspace is `shared`: the agent's file tools and its shell touch the same files, which PiShip verifies before the first command of a session.

It is example code for tests and local exploration, not a package and not a production service. It uses Node 22 built-ins and the `docker` command line only, and has no dependencies to install. PiShip ships no sandbox service; the [sandbox contract](../../../docs/sandbox.md#the-contract) and the [adapter SDK](../../../docs/adapter-sdk.md) are what an organization builds against.

| File | Contents |
| --- | --- |
| [`service/server.mjs`](service/server.mjs) | Entry point: configuration from the environment, HTTP server, shutdown |
| [`service/src/app.mjs`](service/src/app.mjs) | Routes, the Host and credential checks, request bodies, the streamed answer of a command |
| [`service/src/sandboxes.mjs`](service/src/sandboxes.mjs) | What may be mounted, the container lifecycle, commands and their cancellation, idle and lifetime limits |
| [`service/src/docker.mjs`](service/src/docker.mjs) | Every `docker` argument list: what a sandbox container is allowed to be is read here |
| [`service/src/auth.mjs`](service/src/auth.mjs), [`config.mjs`](service/src/config.mjs), [`log.mjs`](service/src/log.mjs) | The key registry, the settings, the allowlisting logger |
| [`scripts/generate-key.mjs`](scripts/generate-key.mjs) | The administrator's script: issues a user's key, records only its hash and the host user whose projects it may mount |
| [`acme-container-sandbox.mjs`](acme-container-sandbox.mjs) | The custom adapter: one file, imports only `@piship/adapter-sdk` |
| [`piship.yaml`](piship.yaml), [`piship.lock`](piship.lock), [`resources/`](resources) | The reference distribution with this sandbox (below) |
| [`test/`](test) | Contract tests for the service and the adapter, with a fake `docker`; no Docker needed |

## Run it

Needs Docker and Node 22.19 or later. The project must be a git repository with a `.git` directory, under a directory the service is configured to mount.

```sh
cd examples/enterprise-reference/sandbox

# The administrator issues a key. Only its SHA-256 goes into registry.json,
# with the host user whose projects the key may mount (--uid, default: the user
# running this script); the key file is 0600 and its content is never printed.
node scripts/generate-key.mjs --user alice --dir "$HOME/.acme-sandbox"

# The service. Loopback only; one instance name per service on a Docker daemon
# (the default is made of the user's ID and the port).
SANDBOX_REGISTRY="$HOME/.acme-sandbox/registry.json" \
SANDBOX_WORKSPACE_ROOTS="$HOME/Developer/src" \
SANDBOX_IMAGE='ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3' \
SANDBOX_SHELL=/bin/bash \
node service/server.mjs
```

The distribution is the reference distribution built from [`piship.yaml`](piship.yaml) in this directory, with the [reference stack](../README.md) running for sign-in. `COMMAND` is the launcher's name, `app.command` in the manifest:

```sh
COMMAND=acmecode-reference
export ACMECODE_SANDBOX_URL=http://127.0.0.1:18075
# ...and the stack's variables, as in the reference README ("Try it")
node packages/cli/dist/bin.js build examples/enterprise-reference/sandbox/piship.yaml
node dist/acmecode-reference/piship.mjs install dist/acmecode-reference
"$COMMAND" login                                      # sign in on Keycloak
"$COMMAND" sandbox login < "$HOME/.acme-sandbox/alice.key"   # the key never reaches argv or history
cd ~/Developer/src/some-repository && "$COMMAND" doctor
```

`sandbox login` needs a signed-in user: the key is bound to that user and to the origin of `ACMECODE_SANDBOX_URL`. `doctor` then shows the sandbox (`acme-container`, remote, its guarantees), the stored credential (`valid (stored, api_key)`), and the workspace as `pending`: it is verified before the first command the agent runs, never by `doctor`. This build and the reference build have the same ID, command, and state: install one or the other. Both install the launcher `acmecode-reference`, which is not the demo company example's `acmecode`, so neither replaces that one.
### The registry: what a key may mount

The service starts each container as the owner of the project it mounts, so a key that could name any project under `SANDBOX_WORKSPACE_ROOTS` could mount another user's project read-write, as that user. Every registry entry is therefore bound to what it may mount, and `generate-key.mjs` writes the binding:

| Entry | Means | Script |
| --- | --- | --- |
| `{"id", "sha256", "uid": 501}` | The key may mount only projects owned by host user 501 (never root's), under the service's roots | `--uid 501`; the default is the user running the script |
| `{..., "uid": 501, "roots": ["/srv/src/alice"]}` | The same, and only under those directories, which must exist | `--uid 501 --root /srv/src/alice` (repeatable) |
| `{"id", "sha256", "unbound": true}` | Any project of any non-root owner under the service's roots. The explicit opt-in for a service that has one user | `--unbound` |

An entry with neither `uid` nor `unbound: true` is refused at start: the service will not run with a key whose reach it cannot name. A project the key may not mount gets `422`, the same answer as a directory outside the roots, and the service has made nothing in it. **Operator note:** the service takes a workspace path from the caller, so the binding is the whole authorization of that path. Issue one key per person with that person's `uid`; use `--unbound` only where every project under the roots is the key holder's to use, and never where the roots are shared.

## What the service does

| Request | Answer |
| --- | --- |
| `GET /health` | `{"status": "ok", "instance": "<SANDBOX_INSTANCE>"}`; the only route without a credential. The instance name lets a supervisor tell its own service from another one on the same port |
| `GET /v1/status`, `Authorization: Bearer <key>` | `{"runtime": "ok" \| "unavailable", "sandboxes": <this user's>, "limit"}`; the adapter's availability check |
| `POST /v1/sandboxes`, body `{"workspace": "<absolute host path>", "network": "deny" \| "allow", "writeProtect": {"files": [...], "directories": [...]}}` | Starts a container; `201 {"id": "sbx_..."}` |
| `POST /v1/sandboxes/{id}/exec`, body `{"command", "cwd": "<workspace-relative>", "env": {...}}` | A stream of JSON lines: `{"stream": "stdout" \| "stderr", "data": "<base64>"}` as output arrives, then `{"exit": <code or null>, "signal": <name or null>}` |
| `DELETE /v1/sandboxes/{id}` | Removes the container; `204` |

Every answer is JSON (an exec's is newline-delimited JSON) with `cache-control: no-store` and no cross-origin permission. An error body is only `{"error": {"code", "message"}}`, with a fixed message: never the caller's input, a path, or the runtime's own text.

| Status | When |
| --- | --- |
| 400, 413, 415 | A body that is not a JSON object of the shape above, over 512 KiB, or not `application/json`; a command over 100000 bytes; an environment name that is not `[A-Za-z_][A-Za-z0-9_]*`, a value with a line break, or the reserved `PISHIP_EXEC_ID`; a `cwd` outside the workspace; a path with a comma or a quote |
| 401 | No credential, or one the registry does not hold: one answer for both, with `www-authenticate: Bearer`. PiShip reads a 401 or 403 as "the credential was rejected", so this service uses 401 for nothing else |
| 404 | An unknown sandbox, or another user's: the same answer |
| 409 | The workspace is not a git repository with a real `.git` directory; or a git control path that must be read-only does not exist and so cannot be protected (`workspace_unsupported`, `protected_path_missing`) |
| 421 | A `Host` header that is not this service's own loopback name |
| 422 | A workspace the key may not mount: outside `SANDBOX_WORKSPACE_ROOTS` or the key's own roots, not existing, owned by root or in root's group (commands would run as `--user <uid>:0`), or owned by another host user than the key's, after links are resolved: one answer for all |
| 429 + `Retry-After` | The user, or the service, is at its number of sandboxes or of concurrent commands |
| 502, 503 | The container runtime failed or is unavailable; the service is shutting down |

The Host check keeps a web page from reaching a loopback service through a name it controls; with the credential and the content type, which a browser must ask permission for, it is what protects a service on `127.0.0.1` from the browser of the person who runs it.

## The container

A sandbox is `docker run` with exactly the arguments of [`runArguments`](service/src/docker.mjs), and the contract test pins each one:

| Property | How |
| --- | --- |
| Not root | `--user <uid>:<gid>` of the workspace's owner, who must be the key's user (above). A workspace owned by root, or in root's group (`--user 1000:0` would run in it), is refused |
| No privilege | `--cap-drop ALL`, `--security-opt no-new-privileges`; the runtime's default seccomp and AppArmor profiles stay on; no `--privileged`, device, host PID, IPC, UTS, user, or network namespace, published port, or docker socket |
| Only the workspace is mounted | `/workspace` is the project, read-write; that is the `workspace-confinement` guarantee. A read-only root filesystem, and a 256 MB tmpfs at `/tmp` (also `HOME`), are the only other writable places |
| Git control files | `.git` is mounted read-only over the workspace, with only `.git/piship-workspace` writable again (the service makes it, mode 0700, when it is missing): the git config, hooks, `info`, `modules`, `worktrees`, and files git follows cannot be changed, created, or renamed away, whether they exist or not. Each further path PiShip names that exists in the working tree (a `core.hooksPath` directory, a config file the git config includes) is mounted read-only too, and one that does not exist is refused at creation, since it could not be protected. Each directory between the workspace and such a path is bound onto itself, writable, so it is a mount point that cannot be renamed: otherwise `mv tools tools-old` would carry the read-only `tools/git/hooks` away and let a writable one be made in its place. That is `git-control-protection` |
| Network | `--network none` when the profile denies it; the Docker network `SANDBOX_ALLOW_NETWORK` (default `bridge`) when it allows it |
| Environment | A command gets the environment PiShip approved and nothing else of the caller's, plus the image's own. It is written to the standard input of `docker exec --interactive`, one `NAME=value` line each and an empty line, and a reader in the container exports it before it starts the command; an environment cut short starts nothing. No value is on this machine's process list or in the exec's configuration at the Docker daemon, and no file holds it, so nothing is left on disk by a command, a crash, or a `kill -9`. The command line itself is on the process list. (`--env-file /dev/stdin` would not do: on Linux the CLI's standard input is a socket, which cannot be opened by path) |
| Limits | 1 GB of memory and no swap, 512 processes, 2 CPUs (`SANDBOX_MEMORY`, `SANDBOX_PIDS`, `SANDBOX_CPUS`) |
| Lifetime | A sandbox idle for an hour (`SANDBOX_IDLE_SECONDS`) is removed, none lives past 12 hours (`SANDBOX_MAX_LIFETIME_SECONDS`), a command past an hour or past 64 MiB of output is stopped, and the container ends itself at its maximum lifetime even if this service died. On `SIGTERM` the service removes every sandbox it holds, and at start, once it has its port, it removes those an earlier run left: containers that carry both its `SANDBOX_INSTANCE` and the label of the user running it (`piship.sandbox.owner`). The default instance name is `reference-<uid>-<port>`, so two services started with no name on one Docker daemon do not sweep each other's; a name you set must be unique to its service in the same way |

**Commands and cancellation.** A command runs as `<shell> -c <command>` in `/workspace/<cwd>`. Its answer is tied to the caller's connection: when PiShip times a command out or the user cancels it, PiShip closes the connection, and the service stops the command and everything it started. `docker exec` does not do this by itself (killing the client leaves the process running), so a second `docker exec` runs [a script](service/src/docker.mjs) in the sandbox that first leaves a cancel token, so a command that has not begun will not, then stops (`SIGSTOP`, so nothing forks any more) and kills the processes it is to end. Which ones depends on what else runs in the sandbox:

- **The command is the only one running** (the usual case for an agent that runs its commands one after another). The script ends every process of the sandbox except its init and its main process, which the service found at creation, before any command ran. A process that dropped the command's ID (`env -u PISHIP_EXEC_ID`, `env -i`) or started its own session goes too. New commands wait while the sweep runs, so it cannot kill one that has only just started.
- **Another command runs in the same sandbox** (the service allows several at once). The script ends only the processes whose environment carries the cancelled command's random ID, which children inherit: background processes and processes that started their own session are reached, but not one that deliberately dropped the variable.

That is the residual limit: while commands overlap, or when the sandbox's main process could not be found (a runtime without `/proc/<pid>/stat`), a process that scrubs its own environment survives its command's cancellation. It is confined to the same sandbox and the same user's key, and it ends with the sandbox (`DELETE`, the idle limit, the lifetime limit, or the service stopping). Deleting the sandbox removes the container, which ends whatever is left.

**The image.** Any image with a POSIX `sh`, `cat`, `mkdir`, `mv`, `printf`, `sleep`, `env`, `tr`, `grep`, `kill`, and `/proc`, and `bash` with `timeout` (or `nc`) for the conformance kit's network check. The tests use `ubuntu:24.04`, pinned by its index digest, with `bash` as the shell. Prefer a glibc image to Alpine here: PiShip decides that a read-only `.git` cannot be renamed with `[ -w .git ]`, and BusyBox's `test` reads the mode bits and calls a read-only mount writable, so on Alpine PiShip reports the git control files as `not-verified` (a warning in `doctor`; the commands still run). Put the project's toolchain in the image; nothing else of the host is there.

## The credential

The distribution declares `sandbox.credential: stored`. A person runs `sandbox login` and enters the key the organization issued; PiShip keeps it in the secret store, bound to the signed-in user and to the origin of the endpoint, and hands it to the adapter one request at a time.

| Rule | Where it is kept |
| --- | --- |
| Never in a tracked or locked file, argv, the environment, the model context, or a Pi session file | PiShip's `sandbox login` reads it from a prompt or the first line of standard input; `generate-key.mjs` never prints it and writes it `0600` (`*.key` is git-ignored) |
| Refused without it | The service answers 401 to a request with none, a wrong one, or a malformed header, with one answer for all, comparing a hash against every registered key so timing does not say which |
| Only for the user's own sandboxes and projects | A sandbox belongs to the key that created it; another key gets 404. A key mounts only projects owned by the host user it is bound to ([the registry](#the-registry-what-a-key-may-mount)) |
| Bound to the origin | PiShip records the endpoint's origin at `sandbox login` and refuses to read the secret when the resolved endpoint is another one. The adapter also sends the key only to an origin in `credentialOrigins`, only to the endpoint it was given, never to a URL an answer names (the service returns none), and never follows a redirect |
| Rejection | A 401 makes the adapter tell PiShip (`credentialRejected`), which marks the stored credential rejected: the next launch asks for `sandbox login` instead of sending it again. The adapter never repeats a request that creates a sandbox or runs a command |
| Never logged | The service's log has a fixed set of fields (no command, environment value, path, or key) and scrubs the key shape; the adapter builds no message from a transport error or an answer body |
| Gone with the user | `logout`, `sandbox logout`, a different user signing in, `purge`, and a rollback to a release that cannot read it delete it ([sandbox credentials](../../../docs/sandbox.md#credentials)) |

Why the stored source, and not the adapter's own credential: it shows the parts of the contract PiShip owns (the input path, the secret store, the binding to the user and to the origin, rejection, clearing on logout, purge, and rollback), which an adapter-sourced credential leaves to the adapter. An adapter-sourced one would exchange the user's identity token for a short-lived token at the service, and so make the service validate Keycloak's tokens, which the reference keeps out of it. The trade is the one [docs/sandbox.md](../../../docs/sandbox.md#credentials) names: a key a person enters is often shared. Here the service issues one key per user and scopes every sandbox to it, which is the least a stored key needs; a managed deployment that can exchange the identity should do that instead, with the same adapter minus `sandbox.credential` and plus a `sandboxCredential` export.

## What it does and does not isolate

It gives the container's isolation, and what is listed above. It does not give:

- **A VM.** The container shares the host's kernel. On Docker Desktop or OrbStack that kernel is a VM's, and a container escape reaches the VM; on a Linux host it reaches the host. A company that needs more runs the same service over gVisor, Kata, or a VM per session.
- **A trusted-service boundary.** The service starts containers by calling Docker, so whoever can run it can run anything. It is a process of the user or an administrator, not a boundary against them.
- **Protection from a hostile user of the same host.** The service checks the workspace, `.git`, `.git/piship-workspace` and each protected path with `realpath` and `lstat`, then hands the same path strings to `docker run --mount`, and the Docker daemon follows symbolic links when it mounts. A key holder who owns the workspace can replace `.git/piship-workspace` (or the workspace's own path, given write access to its parent) with a link to another directory in the moment between the check and the mount, and repeat it until it lands: the sandbox then gets that directory read-write, including what sits below owner-only directories above it, and escapes the roots. A `uid`-bound key narrows whose projects a key may name; it does not defend against a user who races links on a shared host. Run one service per user on a host with other users, or treat its keys as trusted. A fix would compare the device and inode of every mounted path inside the container after it starts and remove the container on a mismatch; it is not done here.
- **Multi-user workspace check.** The service creates `.git/piship-workspace` itself, mode 0700, owned by the service's user. When the service runs as another user than a key's, neither the container (which runs as the workspace's owner) nor PiShip can write into it, so PiShip's workspace check does not verify. Run the service as the user whose projects it serves.
- **Network control when the network is allowed.** `allow` is the Docker network `SANDBOX_ALLOW_NETWORK`: full outbound access, and reach to other containers on it.
- **PiShip's path rules.** `sandbox.filesystem` keeps governing PiShip's own file tools. Inside, every file of the project is readable and writable (`.env` files, `package.json` scripts the user runs later), except the git control paths above.
- **Git writes.** `.git` is read-only, so with a git in the image, `git commit`, `add`, `checkout`, and `stash` fail inside the sandbox; run them outside. Reading works (`git diff`, `git log`); git cannot refresh its index, and says so.
- **TLS.** PiShip allows plain HTTP only to loopback, and the service binds nothing else. Reaching it from other machines is a TLS-terminating proxy the organization runs in front of it; the bearer key must never cross a network in the clear.
- **Concealing the command line.** `docker exec` puts the command on this machine's process list, visible to its users; the environment is not. A service that cannot accept that uses the container runtime's API.
- **More than one background process's output.** A command that leaves a process holding its output open keeps `docker exec`, and so the command, running until that process ends or PiShip times it out.

Also: paths with a comma or a quote are refused (a mount option is a comma-separated list), a command over 100000 bytes is refused (the operating system's argument limit), a linked worktree (a `.git` file) is not supported, an SELinux host needs the mounts relabelled, which this service does not do, and rootless Docker and Podman, which map the user's ID to another one inside the container, are not supported: the service passes the workspace owner's numeric user and group and expects the runtime to keep them. It has been run on macOS under OrbStack; a Linux Docker Engine is what the Reference E2E workflow runs it on.

## Settings

The service reads its environment only, and refuses to start on a bad value, naming the variable and never its value.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SANDBOX_REGISTRY` | required | The key registry `generate-key.mjs` writes (`piship-reference-sandbox-registry/v1`: user IDs and SHA-256 hashes) |
| `SANDBOX_WORKSPACE_ROOTS` | required | Directories the service may mount from, separated as `PATH` is; a workspace must lie inside one after links are resolved |
| `SANDBOX_IMAGE` | required | The sandbox image, by digest |
| `SANDBOX_SHELL` | `/bin/sh` | The shell that runs each command, an absolute path in the image |
| `SANDBOX_LISTEN_PORT` | `18075` | The port on `127.0.0.1` (or `::1` with `SANDBOX_LISTEN_HOST`). Nothing wider is accepted |
| `SANDBOX_INSTANCE` | `reference-<uid>-<port>` | This service's name: the label `piship.sandbox.instance` on every container it starts (beside `piship.sandbox.owner`, the user's ID), and, with the owner, what its start-up sweep removes. Also answered by `/health`. Unique per service on a Docker daemon |
| `SANDBOX_EXIT_ON_STDIN_END` | unset | `1`: a supervisor that gave the service a pipe for its standard input owns it. When the pipe closes, even because the supervisor was killed, the service removes its sandboxes and exits. Leave it unset under a service manager (an ordinary service reads no input, and would then exit at once) |
| `SANDBOX_ALLOW_NETWORK` | `bridge` | The Docker network of a sandbox whose network is allowed; `host` and `none` are refused |
| `SANDBOX_MEMORY`, `SANDBOX_CPUS`, `SANDBOX_PIDS`, `SANDBOX_TMP_SIZE` | `1g`, `2`, `512`, `256m` | Per-sandbox limits |
| `SANDBOX_IDLE_SECONDS`, `SANDBOX_MAX_LIFETIME_SECONDS`, `SANDBOX_MAX_EXEC_SECONDS`, `SANDBOX_MAX_OUTPUT_BYTES` | 3600, 43200, 3600, 64 MiB | Time and size limits |
| `SANDBOX_MAX_PER_KEY`, `SANDBOX_MAX_TOTAL`, `SANDBOX_MAX_EXECS` | 8, 32, 8 | Sandboxes per key, in all, and commands at once in one sandbox |
| `SANDBOX_ALLOWED_HOSTS` | none | More `Host` values to answer to, such as a proxy's, comma-separated |
| `SANDBOX_DOCKER` | `docker` | The docker command (the contract tests point it at a fake) |

## Tests

| Where | What it runs |
| --- | --- |
| [`test/service.test.mjs`](test/service.test.mjs), [`test/adapter.test.mjs`](test/adapter.test.mjs): `node --test test/*.test.mjs` here | The service against a [fake docker](test/fake-docker.mjs) that runs commands with `/bin/sh` on this machine: configuration, the registry (its bindings, and an entry with none) and `generate-key`, credential and Host checks, refusals, every argument of `docker run` and `docker exec` (no privilege, the mounts, the environment on standard input and nowhere else), ownership by key and by host user, root's user and group, streaming, cancellation when the caller goes away (a sweep, and only the marked processes while another command runs), delete, idle, lifetime, and size limits, shutdown, the start-up sweep and its two labels, the exit when a supervisor's pipe closes, and what the log holds. The adapter against a stub `fetch`: what it declares (and that PiShip accepts it), what it sends and to whom, that it never repeats a create, and that no credential, body, or transport message reaches an error |
| [`tests/sandbox.test.ts`](../tests/sandbox.test.ts), with the reference tests (`npm run test:reference`) | The service as a user starts it, with real containers: its boundary, the container as `docker inspect` shows it, a project only for the key bound to its owner, a command's environment off the process list and out of every file, the strays a cancelled command leaves, the sandbox conformance kit (and a scan of its report and output for the user's real key), a service that exits when its supervisor is gone, and a governed session built from the committed manifest and lock (below) |
| [`tests/reference-sandbox-variant.test.ts`](../../../tests/reference-sandbox-variant.test.ts), with the unit tests | The variant differs from the reference manifest only in its sandbox and one runtime variable, has the same resources, the same ID and launcher command (`acmecode-reference`, not the demo company's), and its adapter is one file that imports only the SDK; the committed lock is kept current by the example-lock test |

The live test starts the service on `127.0.0.1:48075` (`SANDBOX_PORT` changes it; a second service the orphan test starts uses the next port), as instance `piship-reftest-<pid>-sandbox-<random>`, with keys made by `generate-key.mjs` in a temporary directory, alice's bound to the user running the tests and bob's to another. Every container it starts carries that instance's label. The service removes its own on `SIGTERM`; the test then removes anything still carrying the label, by ID, and its directory, and checks that the service left none.

A run killed outright leaves neither its containers nor its service behind. The test starts the service with a pipe as its standard input and `SANDBOX_EXIT_ON_STDIN_END=1`, so when the run is gone the pipe closes and the service removes its sandboxes and exits, freeing its port. A start waits up to 20 s for the port, then fails naming it (another run's service holds it) and makes nothing; it counts as ready only when `/health` names this run's instance, so a service on the port that is not its own is never mistaken for it. The reference suite's global setup removes, at the next start, only containers whose instance name has the run shape and whose process is gone. Nothing is pruned and no container the test did not start is touched.

### Conformance

`testSandboxAdapter` from `@piship/adapter-conformance` against the service, with real containers: 16 behaviors passed, 0 failed, 0 skipped (about 25 s on macOS 27 with OrbStack and Docker 29). `network claims` needs a listener the sandbox can reach with the network allowed, which the test starts in a container of its own on the default bridge. The kit gives the adapter a fake credential of its own; the test swaps that one header for the user's real key on its way out, after the kit has watched where it goes, because the service knows only the keys it issued. So the kit's own leak evidence covers only its fake credential; the test therefore scans the kit's report and everything the run printed for the user's real key as well, and finds none.

Defects seeded by hand while the service was written failed exactly the behaviors they should: a writable `.git` mount failed `git control protection`; a network that stayed on with the profile denying it failed `network claims`; a cancel that only killed the `docker exec` client failed `timeout` and `cancellation`. No test seeds them again and runs the kit against the result. Each defect is pinned where it would be introduced, though:

| Defect | Pinned by |
| --- | --- |
| A `.git` that is not read-only, or a writable place other than `.git/piship-workspace` | `test/service.test.mjs`, "starts a container with no privilege and only the mounts it lists" (the exact `--mount` list); `tests/sandbox.test.ts`, "starts each sandbox unprivileged with only the workspace mounted" (`docker inspect`: `/workspace/.git` is not `RW`, and a write to it fails inside) |
| A network that is on when the profile denies it | The same two tests (`--network none`; `NetworkMode: none` and only `lo` inside), and "gives an allowed network the configured Docker network" for the other direction |
| A cancel that does not reach the command | `test/service.test.mjs`, "stops a command, and what it started, when the caller goes away" (the second `docker exec` is issued and the command ends); `tests/sandbox.test.ts`, "does not let a command outlive its cancellation by dropping its ID" (real containers) |

### The workspace check in a governed session

The test builds the distribution from a copy of the committed `piship.yaml`, lock, adapter, and resources (`piship build` refuses a lock that no longer matches), and opens a `GovernanceSession` on the built payload as `launch` does: the lock it carries, the managed fetch under the reference manifest's private-only network policy, the endpoint from `ACMECODE_SANDBOX_URL`, and the sandbox credential stored for a principal and checked against the endpoint's origin. Then:

- Activation creates the sandbox and runs PiShip's outside check in it (`verification: backend-attested`, `isolation: remote`); the workspace is `pending` and nothing has been written into the project. The adapter declares no network probe, so network denial is attested by the service (`networkDenial: {evidence: "attested"}`) and no second container is created.
- The first command is preceded by the check, in both directions: the sandbox reads the file the host wrote and the host reads the file the sandbox wrote, both immediate, and no protected git path could be written or created (`effective: shared`, `verification: verified`, `complete: true`, git control `attested-renames`). The containment line reads `Workspace: shared (verified <time>, both directions immediate).`
- The next commands do not check again; the check leaves nothing in `.git/piship-workspace`; ending the session removes the sandbox; the key is in no state file, audit log, lock, or built file.
- A `core.hooksPath` directory in the working tree is read-only in the sandbox (PiShip reports git control `not-verified`, as it does for any hooks directory in the working tree), and one that does not exist stops the session before any container starts.
- A key the service never issued fails activation and marks the stored credential rejected; the next launch asks for `sandbox login`. A runtime variable that names another host sends nothing there.
