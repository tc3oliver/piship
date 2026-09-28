// The kubernetes-agent-sandbox backend: a thin client for Kubernetes Agent
// Sandbox (kubernetes-sigs/agent-sandbox). PiShip creates a SandboxClaim
// from a warm pool, waits until it is ready, runs each command through the
// sandbox router, and deletes the claim when the session ends. Scheduling,
// images, NetworkPolicy, and isolation stay with the cluster.
import { randomBytes } from "node:crypto";
import type { AdapterAvailability } from "../adapter.js";
import {
  HOST_FILESYSTEM_ISOLATION,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxInstance,
  type SandboxPrepareRequest,
} from "../backend.js";
import {
  describeFailure,
  errorText,
  type RemoteBackendOptions,
  readJson,
  remoteDirectory,
  shellQuote,
  trimSlashes,
} from "./http.js";

export interface KubernetesAgentSandboxOptions extends RemoteBackendOptions {
  /** The sandbox router URL that proxies to sandbox pods. */
  readonly router: string;
  /** The SandboxWarmPool claims are made from (`spec.warmPoolRef.name`). */
  readonly template: string;
  /** Namespace of the claims. Default `default`. */
  readonly namespace?: string;
  /** Port of the runtime inside the sandbox pod. Default 8888. */
  readonly port?: number;
  /** How long to wait for a claim to become ready. Default 120 s. */
  readonly readyTimeoutMs?: number;
  /** Poll interval while waiting. Default 1 s. */
  readonly pollMs?: number;
  /**
   * The claim's bounded lifetime in seconds (`spec.lifecycle.shutdownTime`),
   * renewed while the session uses it. Default 3600.
   */
  readonly lifetimeSeconds?: number;
  /** Test seam: the clock `shutdownTime` is computed from. */
  readonly now?: () => number;
}

const GROUP = "extensions.agents.x-k8s.io/v1beta1";
/** The runtime returns output in one response; larger output fails the command. */
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** Ready reasons after which a claim never becomes ready. */
const TERMINAL_REASONS = new Set([
  "InvalidMetadata",
  "EnvVarsInjectionRejected",
  "VolumeClaimTemplatesError",
  "ClaimExpired",
  "SandboxExpired",
  "InvalidConfiguration",
]);

// A pod on the cluster: the host's files are out of reach, but PiShip's path
// rules are not mapped into it, so no filesystem-* plane is claimed. Network
// denial is the SandboxTemplate's NetworkPolicy: the backend declares it, and
// PiShip checks an outbound connection before use.
const CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  planes: [HOST_FILESYSTEM_ISOLATION, "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
};

interface Claim {
  readonly claim: string;
  readonly sandbox: string;
  /** When the cluster deletes the claim unless it is renewed (epoch ms). */
  expiresAt: number;
}

/** The claim no longer exists (deleted or expired). */
class ClaimGone extends Error {}

/** RFC 3339 at whole seconds, rounded up so the lifetime is never shorter. */
function shutdownTime(ms: number): string {
  return new Date(Math.ceil(ms / 1000) * 1000)
    .toISOString()
    .replace(".000Z", "Z");
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function wait(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    if (signal?.aborted) return reject(new Error("aborted"));
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolvePromise();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * The runtime splits the command like a POSIX shell without running one, so
 * the command is passed as `env NAME=value ... /bin/sh -c '<script>'`.
 */
export function runtimeCommand(
  request: SandboxExecRequest,
  workdir: string | undefined,
): string {
  const directory =
    workdir !== undefined
      ? remoteDirectory(workdir, request.workspacePath)
      : request.workspacePath && request.workspacePath !== "."
        ? remoteDirectory(".", request.workspacePath).replace(/^\.\//, "")
        : undefined;
  const script =
    directory === undefined
      ? request.command
      : `cd -- ${shellQuote(directory)} && ${request.command}`;
  const assignments = Object.entries(request.env)
    .filter(([name]) => ENV_NAME.test(name))
    .map(([name, value]) => shellQuote(`${name}=${value}`));
  return ["env", ...assignments, "/bin/sh", "-c", shellQuote(script)].join(" ");
}

export class KubernetesAgentSandboxBackend implements SandboxBackend {
  readonly id = "kubernetes-agent-sandbox";
  readonly provider = "kubernetes-agent-sandbox" as const;
  readonly #options: KubernetesAgentSandboxOptions;
  readonly #api: string;
  readonly #router: string;
  readonly #namespace: string;

  constructor(options: KubernetesAgentSandboxOptions) {
    this.#options = options;
    this.#api = trimSlashes(options.endpoint);
    this.#router = trimSlashes(options.router);
    this.#namespace = options.namespace ?? "default";
    if (!NAME.test(this.#namespace) || !NAME.test(options.template))
      throw new Error(
        "the namespace and warm pool must be Kubernetes resource names",
      );
  }

  capabilities(): SandboxCapabilities {
    return CAPABILITIES;
  }

  async available(): Promise<AdapterAvailability> {
    try {
      const response = await this.#request(`${this.#claims()}?limit=1`, {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      await response.body?.cancel().catch(() => undefined);
      if (response.ok) return { available: true };
      return {
        available: false,
        reason: `listing SandboxClaims returned HTTP ${response.status}`,
      };
    } catch (error) {
      return {
        available: false,
        reason: `the Kubernetes API is unreachable: ${errorText(error)}`,
      };
    }
  }

  async prepare({ signal }: SandboxPrepareRequest): Promise<SandboxInstance> {
    interface Lease {
      readonly claim: Promise<Claim>;
      users: number;
      retired: boolean;
      keepalive: NodeJS.Timeout | undefined;
    }
    const lease = (claim: Promise<Claim>): Lease => {
      claim.catch(() => undefined);
      return { claim, users: 0, retired: false, keepalive: undefined };
    };
    let current: Lease | undefined = lease(
      Promise.resolve(await this.#claim(signal)),
    );
    let disposed = false;
    const release = async (entry: Lease) => {
      if (entry.users > 0) return;
      if (entry.keepalive) clearInterval(entry.keepalive);
      entry.keepalive = undefined;
      if (!entry.retired) return;
      const claim = await entry.claim.catch(() => undefined);
      // Normal cleanup. If it fails, the claim's shutdownTime still removes
      // it, at most one lifetime after its last renewal.
      if (claim) await this.#delete(claim);
    };
    const retire = (entry: Lease) => {
      entry.retired = true;
      if (current === entry) current = undefined;
    };
    /** The live claim for a command, renewed or replaced as needed. */
    const acquire = async (io: SandboxExecIO): Promise<[Lease, Claim]> => {
      for (let attempt = 0; ; attempt++) {
        // Never create a claim once the session is disposed: nothing would
        // delete it before its shutdownTime.
        if (disposed) throw new Error("the sandbox was disposed");
        current ??= lease(this.#claim(io.signal));
        const entry = current;
        let claim: Claim;
        try {
          claim = await entry.claim;
        } catch (error) {
          // A claim that failed to become ready is not reused.
          if (current === entry) current = undefined;
          throw error;
        }
        try {
          await this.#renewIfDue(claim, io.signal);
        } catch (error) {
          // An expired claim is replaced once; any other renewal failure
          // fails the command rather than run it in a sandbox about to go.
          if (!(error instanceof ClaimGone) || attempt > 0) throw error;
          retire(entry);
          void release(entry);
          continue;
        }
        if (disposed) throw new Error("the sandbox was disposed");
        return [entry, claim];
      }
    };
    return {
      exec: async (request, io) => {
        if (disposed) throw new Error("the sandbox was disposed");
        const [entry, claim] = await acquire(io);
        entry.users++;
        entry.keepalive ??= setInterval(() => {
          if (entry.retired) return;
          void this.#renew(claim).catch((error: unknown) => {
            // Gone mid-command: the next command must not reuse it.
            if (error instanceof ClaimGone) retire(entry);
          });
        }, this.#renewEveryMs());
        entry.keepalive.unref?.();
        // The runtime cannot stop a running command. A cancelled command
        // retires its claim: the next command gets a fresh sandbox, and the
        // retired claim is deleted once no command uses it any more.
        const onAbort = () => retire(entry);
        io.signal.addEventListener("abort", onAbort, { once: true });
        try {
          return await this.#execute(claim, request, io);
        } finally {
          io.signal.removeEventListener("abort", onAbort);
          entry.users--;
          await release(entry);
        }
      },
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        const entry = current;
        current = undefined;
        if (entry) {
          entry.retired = true;
          await release(entry);
        }
      },
    };
  }

  #lifetimeMs(): number {
    const value = this.#options.lifetimeSeconds ?? 3600;
    return (Number.isFinite(value) && value > 0 ? value : 3600) * 1000;
  }

  /** While a command runs, renew four times per lifetime. */
  #renewEveryMs(): number {
    return Math.max(250, Math.floor(this.#lifetimeMs() / 4));
  }

  #now(): number {
    return this.#options.now?.() ?? Date.now();
  }

  async #renewIfDue(claim: Claim, signal: AbortSignal): Promise<void> {
    const left = claim.expiresAt - this.#now();
    // Past its shutdownTime the claim may already be shutting down, even if
    // the controller has not removed it yet: replace it, never revive it.
    if (left <= 0) throw new ClaimGone("the SandboxClaim expired");
    if (left >= this.#lifetimeMs() / 2) return;
    await this.#renew(claim, signal);
  }

  /** Move the claim's shutdownTime one lifetime ahead. */
  async #renew(claim: Claim, signal?: AbortSignal): Promise<void> {
    const expiresAt = this.#now() + this.#lifetimeMs();
    const response = await this.#request(`${this.#claims()}/${claim.claim}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/merge-patch+json" },
      body: JSON.stringify({
        spec: { lifecycle: { shutdownTime: shutdownTime(expiresAt) } },
      }),
      ...(signal ? { signal } : {}),
    });
    if (response.status === 404) {
      await response.body?.cancel().catch(() => undefined);
      throw new ClaimGone("the SandboxClaim no longer exists");
    }
    if (!response.ok)
      throw new Error(
        `renewing the SandboxClaim failed: ${await describeFailure(response)}`,
      );
    await response.body?.cancel().catch(() => undefined);
    claim.expiresAt = Math.max(claim.expiresAt, expiresAt);
  }

  #claims(): string {
    return `${this.#api}/apis/${GROUP}/namespaces/${this.#namespace}/sandboxclaims`;
  }

  async #request(url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    const credential = await this.#options.credential?.();
    if (credential) headers.set("Authorization", `Bearer ${credential}`);
    return this.#options.fetch(url, {
      ...init,
      headers,
      signal: init.signal ?? AbortSignal.timeout(30_000),
    });
  }

  async #claim(signal: AbortSignal | undefined): Promise<Claim> {
    const name = `piship-${randomBytes(6).toString("hex")}`;
    const expiresAt = this.#now() + this.#lifetimeMs();
    const created = await this.#request(this.#claims(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        apiVersion: GROUP,
        kind: "SandboxClaim",
        metadata: {
          name,
          labels: { "agents.x-k8s.io/created-by": "piship" },
        },
        spec: {
          warmPoolRef: { name: this.#options.template },
          // The safety net: the cluster deletes the claim at shutdownTime
          // even if PiShip's DELETE never arrives.
          lifecycle: {
            shutdownTime: shutdownTime(expiresAt),
            shutdownPolicy: "Delete",
          },
        },
      }),
      ...(signal ? { signal } : {}),
    });
    if (!created.ok)
      throw new Error(
        `creating the SandboxClaim failed: ${await describeFailure(created)}`,
      );
    await created.body?.cancel().catch(() => undefined);
    try {
      return { ...(await this.#ready(name, signal)), expiresAt };
    } catch (error) {
      await this.#delete({ claim: name, sandbox: name, expiresAt });
      throw error;
    }
  }

  async #ready(
    name: string,
    signal: AbortSignal | undefined,
  ): Promise<Omit<Claim, "expiresAt">> {
    const deadline = Date.now() + (this.#options.readyTimeoutMs ?? 120_000);
    for (;;) {
      const response = await this.#request(`${this.#claims()}/${name}`, {
        method: "GET",
        ...(signal ? { signal } : {}),
      });
      if (!response.ok)
        throw new Error(
          `reading the SandboxClaim failed: ${await describeFailure(response)}`,
        );
      const status = record((await readJson(response)).status);
      const conditions = Array.isArray(status.conditions)
        ? status.conditions.map(record)
        : [];
      const ready = conditions.find((condition) => condition.type === "Ready");
      if (ready?.status === "True") {
        const sandbox = record(status.sandbox).name;
        return {
          claim: name,
          sandbox:
            typeof sandbox === "string" && NAME.test(sandbox) ? sandbox : name,
        };
      }
      if (
        typeof ready?.reason === "string" &&
        TERMINAL_REASONS.has(ready.reason)
      )
        throw new Error(`the SandboxClaim failed: ${ready.reason}`);
      if (Date.now() >= deadline)
        throw new Error("the SandboxClaim did not become ready in time");
      await wait(this.#options.pollMs ?? 1000, signal);
    }
  }

  async #delete(claim: Claim): Promise<void> {
    try {
      const response = await this.#request(`${this.#claims()}/${claim.claim}`, {
        method: "DELETE",
      });
      await response.body?.cancel().catch(() => undefined);
    } catch {
      // best effort: the claim's lifecycle policy also removes it
    }
  }

  async #execute(
    claim: Claim,
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ): Promise<SandboxExecResult> {
    const response = await this.#request(`${this.#router}/execute`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sandbox-ID": claim.sandbox,
        "X-Sandbox-Namespace": this.#namespace,
        "X-Sandbox-Port": String(this.#options.port ?? 8888),
      },
      body: JSON.stringify({
        command: runtimeCommand(request, this.#options.workdir),
      }),
      signal: io.signal,
    });
    if (!response.ok)
      throw new Error(
        `running the command failed: ${await describeFailure(response)}`,
      );
    const body = await readJson(response, MAX_OUTPUT_BYTES);
    if (typeof body.stdout === "string" && body.stdout)
      io.onStdout(Buffer.from(body.stdout, "utf8"));
    if (typeof body.stderr === "string" && body.stderr)
      io.onStderr(Buffer.from(body.stderr, "utf8"));
    return {
      exitCode: Number.isInteger(body.exit_code)
        ? (body.exit_code as number)
        : null,
    };
  }
}
