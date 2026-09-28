// The kubernetes-agent-sandbox backend: a thin client for Kubernetes Agent
// Sandbox (kubernetes-sigs/agent-sandbox). PiShip creates a SandboxClaim
// from a warm pool, waits until it is ready, runs each command through the
// sandbox router, and deletes the claim when the session ends. Scheduling,
// images, NetworkPolicy, and isolation stay with the cluster.
import { randomBytes } from "node:crypto";
import type { AdapterAvailability } from "../adapter.js";
import type {
  SandboxBackend,
  SandboxCapabilities,
  SandboxExecIO,
  SandboxExecRequest,
  SandboxExecResult,
  SandboxInstance,
  SandboxPrepareRequest,
} from "../backend.js";
import { CONTAINMENT_PLANES } from "../probe.js";
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
}

const GROUP = "extensions.agents.x-k8s.io/v1beta1";
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

// Network denial is the SandboxTemplate's NetworkPolicy: the backend
// declares it, and PiShip checks an outbound connection before use.
const CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  planes: CONTAINMENT_PLANES,
  network: ["deny", "allow"],
  localProcesses: false,
};

interface Claim {
  readonly claim: string;
  readonly sandbox: string;
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
    let current: Claim | undefined = await this.#claim(signal);
    let disposed = false;
    return {
      exec: async (request, io) => {
        if (disposed) throw new Error("the sandbox was disposed");
        // A cancelled command may still run in its pod: its claim was
        // deleted, and the next command gets a fresh sandbox.
        current ??= await this.#claim(io.signal);
        const claim = current;
        const onAbort = () => {
          if (current === claim) current = undefined;
          void this.#delete(claim);
        };
        io.signal.addEventListener("abort", onAbort, { once: true });
        try {
          return await this.#execute(claim, request, io);
        } finally {
          io.signal.removeEventListener("abort", onAbort);
        }
      },
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        if (current) await this.#delete(current);
        current = undefined;
      },
    };
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
        spec: { warmPoolRef: { name: this.#options.template } },
      }),
      ...(signal ? { signal } : {}),
    });
    if (!created.ok)
      throw new Error(
        `creating the SandboxClaim failed: ${await describeFailure(created)}`,
      );
    await created.body?.cancel().catch(() => undefined);
    try {
      return await this.#ready(name, signal);
    } catch (error) {
      await this.#delete({ claim: name, sandbox: name });
      throw error;
    }
  }

  async #ready(name: string, signal: AbortSignal | undefined): Promise<Claim> {
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
    const body = await readJson(response);
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
