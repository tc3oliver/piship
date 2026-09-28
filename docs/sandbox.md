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

| Provider | Runs commands | Contains MCP stdio servers | Verification | Status |
| --- | --- | --- | --- | --- |
| `native` (default) | Local processes inside bubblewrap (Linux) or Seatbelt (macOS) | Yes | Live probe | Candidate, with the boundary and escape tests below |
| `custom` | Wherever the company adapter runs them | Only a local adapter that wraps processes | Live probe for a local wrapping adapter; otherwise backend-attested | Contract and lifecycle tested with fake adapters; no company adapter is shipped |
| `e2b-compatible` | In a remote sandbox created through the E2B API | No | Backend-attested | Tested against a mock E2B server; no live E2B or CubeSandbox evidence |
| `kubernetes-agent-sandbox` | In a sandbox pod claimed from a warm pool | No | Backend-attested | Tested against a mock API server and router; no live cluster evidence |

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
  credential: runtime             # default: none
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
| `credential` | remote and `custom` | `none` (default) or `runtime`: send the runtime credential to the endpoint (and router) |

Fields that do not apply to the chosen provider are rejected. There is no field for an API key: secrets are never written in `piship.yaml`, and runtime references cannot name secret-looking variables. `credential: runtime` sends the scoped runtime credential the company broker issued, and only when every URL it would reach is on an origin that credential is issued for (the inference gateway origin, the same rule [MCP servers](security.md#mcp) follow). Put an E2B or Kubernetes endpoint behind the company gateway to use it; otherwise activation fails closed.

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
2. **Capabilities.** The backend declares its isolation kind (`local` or `remote`), the containment planes it enforces, the network modes it can enforce, and whether it can contain local processes. A required sandbox needs `filesystem-read-deny`, `filesystem-write-allowlist`, and `environment-filter`, plus `network-deny` when `sandbox.network.mode` is `deny`. A missing capability, or a malformed declaration, fails closed before anything is created.
3. **Create or prepare.** The backend receives the resolved profile (paths, network mode, environment allowlist) and creates its sandbox: nothing for native, a sandbox for E2B, a SandboxClaim for Kubernetes.
4. **Verify.** A backend whose instance can wrap local processes is live-probed exactly like the native sandbox. Any other backend is checked from outside: a command must run and report back, a marker variable PiShip set in its own source environment must not arrive, and in `deny` mode an outbound connection from inside must fail. If that network check cannot run in the sandbox (no `bash` or `timeout`), the report carries a warning and network denial rests on the backend's word. The report says which: `verification: live-probe` or `backend-attested`.
5. **Exec.** See below.
6. **Dispose.** Called once when the session ends, or right away when verification fails. A remote sandbox is deleted; E2B sandboxes also expire on their own after the renewed lifetime.

`doctor` shows the backend, level, planes, and verification; the `--smoke` summary adds the provider; local metrics record the level and backend.

## What PiShip controls

- **Policy and approvals.** Every `bash` and `!` command is decided as `shell.execute` before any backend sees it. File tools (`read`, `write`, `edit`) always run in the Pi process under PiShip's governed file access.
- **Environment.** A backend receives one command, its working directory, and the environment PiShip approved: the `sandbox.environment.allow` list, with credential-looking names always removed. A remote backend additionally never receives host-bound variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `PWD`); its own environment provides them. Nothing is sent when a sandbox is created: no environment, no files, no credentials.
- **Filesystem.** PiShip does not upload or sync the workspace. A remote backend runs commands in `workdir` plus the command's path relative to the workspace, and refuses a working directory outside the workspace. The template, image, or volume must provide the code. Local file tools and remote commands therefore see different copies unless the company keeps them in sync.
- **Credentials.** Only `credential: runtime` sends a credential, only the runtime credential, and only to allowed origins. E2B's per-sandbox envd access token is used only for that sandbox's data plane and never leaves the process.
- **Timeout and cancellation.** PiShip starts the timer and listens to the user's cancel. On either, it aborts the signal it passed to the backend, stops forwarding output, and reports `timeout` or `aborted` whatever the backend returns afterwards. A backend that does not settle within five seconds is retired: its instance is disposed, and later commands in that session fail with `SANDBOX_UNAVAILABLE`. Native commands get SIGTERM, then SIGKILL of the whole process group. E2B commands get `SendSignal(SIGKILL)`. A Kubernetes command's claim is deleted and the next command gets a fresh sandbox, because the runtime API cannot stop a running command.
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
    planes: ("filesystem-read-deny" | "filesystem-write-allowlist" | "network-deny" | "environment-filter")[];
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
    planes: ["filesystem-read-deny", "filesystem-write-allowlist", "network-deny", "environment-filter"],
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

The backend speaks the E2B sandbox API: `GET /health`, `POST /sandboxes` (template, lifetime, `allow_internet_access` from the network mode, no environment), `POST /sandboxes/{id}/timeout` before each command, and `DELETE /sandboxes/{id}` on dispose, with `credential: runtime` sent as `X-API-Key` to the control endpoint only. Commands run through envd's `process.Process/Start` (Connect streaming over JSON) as `/bin/bash -l -c <command>` at `https://49983-<id>.<domain>`, where the domain comes from the create response or the endpoint host. Output streams as it arrives.

CubeSandbox and other services that implement the E2B API use the same backend: point `endpoint` at their API URL. Nothing in PiShip depends on a specific vendor.

### kubernetes-agent-sandbox

A thin client for [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox): it creates a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) with `spec.warmPoolRef`, waits for its `Ready` condition, runs each command through the router's `POST /execute` with the `X-Sandbox-ID`, `X-Sandbox-Namespace`, and `X-Sandbox-Port` headers, and deletes the claim when the session ends. Because the runtime splits the command without a shell, PiShip sends `env NAME=value ... /bin/sh -c '<command>'`. Output arrives when the command ends. The cluster owns images, scheduling, and isolation; network denial is the template's NetworkPolicy, which PiShip checks with the outbound connection test. Use `kubectl proxy` and a port-forwarded router on loopback, or an authenticating proxy with `credential: runtime`.

## Tests

- Native: the live boundary and escape tests in `packages/sandbox/src/boundary.test.ts` (writes, reads, network, environment, git control files, process-tree kill on timeout and cancel, the macOS launchd escape test) run unchanged through the backend contract.
- Contract: `backends.test.ts` covers the custom adapter lifecycle order, fail-closed availability, preparation, and verification, capability mismatch for every plane, the environment a backend receives, and PiShip-owned timeout, cancellation, retirement, and dispose. A local adapter that wraps nothing is rejected by the live probe.
- Remote: `remote.test.ts` runs the e2b-compatible backend against a mock E2B control plane and envd, and the Kubernetes backend against a mock API server and router, checking every request on the wire for leaked credentials and host environment.
