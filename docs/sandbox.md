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

| Provider | Runs commands | Guarantees reported | Contains MCP stdio servers | Verification | Status |
| --- | --- | --- | --- | --- | --- |
| `native` (default) | Local processes inside bubblewrap (Linux) or Seatbelt (macOS) | `filesystem-read-deny`, `filesystem-write-allowlist`, `network-deny` (deny mode), `environment-filter` | Yes | Live probe | Candidate, with the boundary and escape tests below |
| `custom` | Wherever the company adapter runs them | What the adapter declares, checked against the policy | Only a local adapter that wraps processes | Live probe for a local wrapping adapter; otherwise backend-attested | Contract and lifecycle tested with fake adapters; no company adapter is shipped |
| `e2b-compatible` | In a remote sandbox created through the E2B API | `host-filesystem-isolation`, `network-deny` (deny mode), `environment-filter` | No | Backend-attested | Tested against a mock E2B server; no live E2B or CubeSandbox evidence |
| `kubernetes-agent-sandbox` | In a sandbox pod claimed from a warm pool | `host-filesystem-isolation`, `network-deny` (deny mode), `environment-filter` | No | Backend-attested | Tested against a mock API server and router; no live cluster evidence |

A report never claims more than the backend enforces. The `filesystem-read-deny` and `filesystem-write-allowlist` planes mean that `sandbox.filesystem.read.deny` and `sandbox.filesystem.write.allow` are enforced on the commands. `host-filesystem-isolation` means something narrower and different: commands run on another machine or VM and cannot reach this host's files at all. It is not PiShip's path policy. Inside the remote sandbox, what a command may read or write is up to the template or image, and the path rules still govern PiShip's local file tools. The E2B and Kubernetes backends therefore report `host-filesystem-isolation` and never the `filesystem-*` planes, and `doctor` says that the path rules are not enforced inside the remote sandbox.

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
  credential: runtime             # default: none; see Credentials below
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
| `credential` | remote and `custom` | `none` (default) or `runtime`: send the inference runtime credential to the endpoint (and router); see [Credentials](#credentials) |

Fields that do not apply to the chosen provider are rejected. There is no field for an API key: secrets are never written in `piship.yaml`, and runtime references cannot name secret-looking variables.

### Credentials

`credential: runtime` is deliberately narrow. It does not add a sandbox credential: it reuses the **inference** runtime credential the company broker issues for the LLM gateway, and it keeps that credential's origin protection. PiShip sends it only when every URL it would reach (the endpoint, and for Kubernetes the router) is on an origin the credential is issued for, which is the inference gateway origin, the same rule [MCP servers](security.md#mcp) follow; otherwise activation fails closed. It therefore works only when the company puts the sandbox API behind its gateway, on the gateway's origin, and that gateway accepts the runtime credential.

It is not a general sandbox authentication model. It cannot supply an E2B API key, Kubernetes API credentials (service account tokens, client certificates, exec plugins), a company sandbox's own bearer token, or a short-lived credential scoped to the sandbox service, and PiShip has no setting for them. Use `credential: none` with an endpoint that needs no client credential, such as `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy. A custom adapter can obtain its own credential in company code. A purpose-scoped sandbox credential provider is future work ([roadmap](roadmap.md#remote-execution-backends)).

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
2. **Capabilities.** The backend declares its isolation kind (`local` or `remote`), the guarantees it enforces, the network modes it can enforce, and whether it can contain local processes. A required sandbox needs `environment-filter`, plus `network-deny` when `sandbox.network.mode` is `deny`, plus a filesystem guarantee that depends on where commands run. A local backend runs commands against this host's files, so it needs `filesystem-read-deny` and `filesystem-write-allowlist`. A remote backend needs `host-filesystem-isolation`: the host's files must be out of reach. The `filesystem-*` planes are not accepted in its place, and a local backend's `host-filesystem-isolation` is ignored. A missing guarantee, or a malformed declaration, fails closed before anything is created.
3. **Create or prepare.** The backend receives the resolved profile (paths, network mode, environment allowlist) and creates its sandbox: nothing for native, a sandbox for E2B, a SandboxClaim for Kubernetes.
4. **Verify.** A backend whose instance can wrap local processes is live-probed exactly like the native sandbox. Any other backend is checked from outside: a command must run and report back, a marker variable PiShip set in its own source environment must not arrive (this confirms PiShip's filtering end to end; the backend's own environment plane is attested), and in `deny` mode an outbound connection from inside must fail. The network check needs `bash` and `timeout`, or `nc`, in the sandbox; if it cannot run, a `deny` policy fails closed. The report says which: `verification: live-probe` or `backend-attested`.
5. **Exec.** See below.
6. **Dispose.** Called once when the session ends, or right away when verification fails. A remote sandbox is deleted; E2B sandboxes also expire on their own after the renewed lifetime.

`doctor` shows the backend, level, guarantees, and verification. The path policy counts as enforced by the backend only when it reports both `filesystem-read-deny` and `filesystem-write-allowlist`. Otherwise `doctor` adds that `sandbox.filesystem` path rules are not enforced inside the sandbox, or, when the backend reports only one of the two planes, that they are only partly enforced. The `--smoke` summary adds the provider, and local metrics record the level and backend. `policy explain` and file-tool denials count filesystem actions as sandbox-enforced only with both path planes; otherwise they are `control-plane`, decided by PiShip for its local file tools.

## What PiShip controls

- **Policy and approvals.** Every `bash` and `!` command is decided as `shell.execute` before any backend sees it. File tools (`read`, `write`, `edit`) always run in the Pi process under PiShip's governed file access.
- **Environment.** A backend receives one command, its working directory, and the environment PiShip approved: the `sandbox.environment.allow` list, with credential-looking names always removed. A remote backend additionally never receives host-bound variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`); its own environment provides them. Nothing else is sent when a sandbox is created: no environment, no files, and no credential other than the declared control-plane credential.
- **Filesystem.** PiShip does not upload or sync the workspace. A remote backend runs commands in `workdir` plus the command's path relative to the workspace, and refuses a working directory outside the workspace. The template, image, or volume must provide the code. Local file tools and remote commands therefore see different copies unless the company keeps them in sync. The remote sandbox does not apply `sandbox.filesystem` path rules; they keep governing the local file tools.
- **Credentials.** Only `credential: runtime` sends a credential, only the inference runtime credential, and only to allowed origins ([Credentials](#credentials)). E2B's per-sandbox envd access token is used only for that sandbox's data plane and never leaves the process.
- **Timeout and cancellation.** PiShip starts the timer and listens to the user's cancel. On either, it aborts the signal it passed to the backend, stops forwarding output, and reports `timeout` or `aborted` whatever the backend returns afterwards. A backend that does not settle within five seconds is retired: its instance is disposed, and later commands in that session fail with `SANDBOX_UNAVAILABLE`. Native commands get SIGTERM, then SIGKILL of the whole process group. E2B commands get `SendSignal(SIGKILL)` for the command's tagged process, which works even before its pid is known; background processes it started in the sandbox are removed when the sandbox is. The Kubernetes runtime API cannot stop a running command, so a cancelled command retires its claim: the next command gets a fresh sandbox, and the retired claim is deleted once no other command still running in it needs it. If that DELETE fails, the claim's `shutdownTime` still removes it (see below); a failed cleanup is not logged and never exposes the command, environment, or credential.
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
    // host-filesystem-isolation (remote only): cannot reach this host's files.
    planes: ("filesystem-read-deny" | "filesystem-write-allowlist" | "network-deny"
      | "environment-filter" | "host-filesystem-isolation")[];
    network: ("deny" | "allow")[];
    localProcesses: boolean;
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
}
```

A backend never decides policy, never reads PiShip's state, and must pass `env` through as given. `exec` must stop when `io.signal` aborts. `wrap` is only for local backends: spawning the returned command on this host must run it contained.

### Custom adapters

A custom adapter is a module in the distribution, declared as `sandbox.adapter`, locked with a SHA-256 digest, and loaded from the verified payload. Its default export is a factory:

```js
// sandbox/acme-sandbox.mjs
export default ({ distributionId, fetch, endpoint, credential }) => ({
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

The factory receives the distribution ID, PiShip's managed fetch, the resolved endpoint, and the runtime credential only under the rule above. PiShip fixes the provider to `custom`, rejects ids that belong to built-in backends, checks the shape of every returned object, and fails closed if the module is missing or throws. The adapter runs in the Pi process with the user's privileges, like other company adapters, so it is reviewed and shipped by the distribution owner.

### e2b-compatible

The backend speaks the E2B sandbox API: `GET /health`, `POST /sandboxes` (template, lifetime, `allow_internet_access` from the network mode, no environment), `POST /sandboxes/{id}/timeout` before each command, and `DELETE /sandboxes/{id}` on dispose, with `credential: runtime` sent as `X-API-Key` to the control endpoint only. Commands run through envd's `process.Process/Start` (Connect streaming over JSON) as `/bin/bash -l -c <command>` at `https://49983-<id>.<domain>`, where the domain comes from the create response or the endpoint host, with `Authorization: Basic <user>:` naming the sandbox user (`sandbox.user`, default `user`). Output streams as it arrives.

CubeSandbox and other services that implement the E2B API use the same backend: point `endpoint` at their API URL and set the user they run commands as (`user: root` for CubeSandbox). Nothing in PiShip depends on or detects a specific vendor.

### kubernetes-agent-sandbox

A thin client for [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox): it creates a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) with `spec.warmPoolRef`, waits for its `Ready` condition, runs each command through the router's `POST /execute` with the `X-Sandbox-ID`, `X-Sandbox-Namespace`, and `X-Sandbox-Port` headers, and deletes the claim when the session ends. Because the runtime splits the command without a shell, PiShip sends `env NAME=value ... /bin/sh -c '<command>'`. Output arrives when the command ends.

Every claim is created with a bounded lifecycle as a safety net, using Agent Sandbox's `spec.lifecycle`: `shutdownTime` one hour after creation (rounded up to the second) and `shutdownPolicy: Delete`. The cluster removes the claim at that time even if PiShip's DELETE never arrives, for example because the API was down when a command was cancelled. A session in use is not cut short: before a command, PiShip extends `shutdownTime` by a merge patch when less than half the lifetime is left, and while a command runs it extends it every quarter of the lifetime. A claim past its `shutdownTime`, or one the cluster already removed, is replaced before the command runs and is never revived; a claim that disappears while a command runs is not reused. A session idle for longer than one lifetime therefore continues in a fresh sandbox pod, and anything the earlier commands left inside the old pod is gone. No claim is created after the session is disposed. A renewal that fails otherwise fails the command, rather than run it in a sandbox about to be removed. Retired and disposed claims are never renewed, so they are gone at most one lifetime after their last renewal. The cluster owns images, scheduling, and isolation; network denial is the template's NetworkPolicy, which PiShip checks with the outbound connection test. Use `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy ([Credentials](#credentials)).

## Tests

- Native: the live boundary and escape tests in `packages/sandbox/src/boundary.test.ts` (writes, reads, network, environment, git control files, process-tree kill on timeout and cancel, the macOS launchd escape test) run unchanged through the backend contract.
- Contract: `backends.test.ts` covers the custom adapter lifecycle order, fail-closed availability, preparation, and verification, capability mismatch for every guarantee and isolation kind (path planes never stand in for host isolation or the reverse), the environment a backend receives, and PiShip-owned timeout, cancellation, retirement, and dispose. A local adapter that wraps nothing is rejected by the live probe.
- Remote: `remote.test.ts` checks that the E2B and Kubernetes backends never report `filesystem-*` planes, including the exact `doctor` line. It runs the e2b-compatible backend against a mock E2B control plane and envd that enforces the Basic user (`user` by default, `root` when configured), and the Kubernetes backend against a mock API server and router, covering the claim lifecycle safety net, failed cleanup, renewal, expired claims, and idempotent dispose. Every request on the wire is checked for leaked credentials and host environment.
