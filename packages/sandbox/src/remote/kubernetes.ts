// The kubernetes-agent-sandbox backend: a thin client for Kubernetes Agent
// Sandbox (kubernetes-sigs/agent-sandbox). PiShip creates a SandboxClaim
// from a warm pool, waits until it is ready, runs each command through the
// sandbox router, and deletes the claim when the session ends. Scheduling,
// images, NetworkPolicy, and isolation stay with the cluster.
import { randomBytes } from "node:crypto";
import { PiShipError } from "@piship/contracts";
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
  credentialedFetch,
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
  /** Test seam: the wall clock a claim's `shutdownTime` is anchored to. */
  readonly now?: () => number;
  /**
   * Test seam: the monotonic clock. The readiness wait uses it alone; a
   * claim's elapsed time is the larger of it and the wall clock. Default
   * `performance.now`.
   */
  readonly monotonic?: () => number;
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
// PiShip checks an outbound connection before use. The pod comes from a warm
// pool whose volumes PiShip does not know, so its workspace is a snapshot.
const CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  // A claim selects one preconfigured warm pool. This adapter has no way to
  // prove the pool's NetworkPolicy or create a corresponding allow-mode peer.
  planes: [HOST_FILESYSTEM_ISOLATION, "environment-filter"],
  network: ["allow"],
  localProcesses: false,
  workspace: { mode: "snapshot" },
};

interface Claim {
  readonly claim: string;
  readonly sandbox: string;
  /**
   * The last `shutdownTime` the cluster accepted (epoch ms, whole seconds):
   * when it deletes the claim unless it is renewed.
   */
  expiresAt: number;
  /**
   * The wall clock and the monotonic clock when the claim was created. The
   * claim's time is the first plus the larger of the two clocks' elapsed
   * time: the monotonic clock stops while the machine sleeps, and the wall
   * clock can be set back, so neither alone may shorten the elapsed time.
   */
  readonly wallAt: number;
  readonly monotonicAt: number;
}

/** The claim no longer exists (deleted or expired). */
class ClaimGone extends Error {}

/**
 * A command was sent, and whether it ran, is running, or finished is
 * unknown: the connection to the router failed, or a gateway in front of it
 * answered 5xx, before the result arrived. Its claim is retired, so it is
 * deleted with whatever still runs in it once no other command uses it; the
 * command is never repeated and never reported as retryable.
 */
class OutcomeUnknown extends PiShipError {
  constructor(reason: string) {
    super(
      "SANDBOX_UNAVAILABLE",
      `The command's outcome is unknown: ${reason} before its result arrived. It may have run in part or in full, or still be running; PiShip retired its sandbox, which is deleted once no other command runs in it, and runs the next command in a new one. Check the command's effects before running it again`,
      { component: "sandbox", retryable: false },
    );
  }
}

/** Rounded up to the second, so the lifetime is never shorter. */
function wholeSecond(ms: number): number {
  return Math.ceil(ms / 1000) * 1000;
}

/** RFC 3339 of a whole-second time. */
function shutdownTime(ms: number): string {
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

/** Elapsed time on the clock that advanced more; never negative. */
function elapsedSince(
  monotonicAt: number,
  wallAt: number,
  monotonic: number,
  wall: number,
): number {
  return Math.max(monotonic - monotonicAt, wall - wallAt, 0);
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * The shared value, or this command's own cancellation: a command that gives
 * up waiting never cancels the work other commands wait on too.
 */
function untilAborted<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error("aborted"));
  return new Promise<T>((resolvePromise, reject) => {
    const onAbort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    value.then(
      (result) => {
        signal.removeEventListener("abort", onAbort);
        resolvePromise(result);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
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
      /** No new command uses it; it is deleted once no command does. */
      retired: boolean;
      /** The cluster removed it: renewing it is pointless. */
      gone: boolean;
      keepalive: NodeJS.Timeout | undefined;
    }
    const lease = (claim: Promise<Claim>): Lease => {
      claim.catch(() => undefined);
      return {
        claim,
        users: 0,
        retired: false,
        gone: false,
        keepalive: undefined,
      };
    };
    // Every command that waits for a claim shares it, so creating one is
    // cancelled only by the session ending, never by one command's signal.
    const session = new AbortController();
    let current: Lease | undefined = lease(
      Promise.resolve(await this.#claim(signal)),
    );
    let disposed = false;
    /** The claim the last command ran in: a replaced claim is a new environment. */
    let lastClaim: string | undefined;
    const release = async (entry: Lease) => {
      if (entry.users > 0) return;
      if (entry.keepalive) clearInterval(entry.keepalive);
      entry.keepalive = undefined;
      if (!entry.retired) return;
      const claim = await entry.claim.catch(() => undefined);
      // Normal cleanup. If it fails, the claim's shutdownTime still removes
      // it, at most one lifetime after its last renewal.
      if (claim) await this.#delete(claim.claim);
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
        current ??= lease(this.#claim(session.signal));
        const entry = current;
        let claim: Claim;
        try {
          claim = await untilAborted(entry.claim, io.signal);
        } catch (error) {
          // A claim that failed to become ready is not reused; one this
          // command stopped waiting for still serves the others.
          if (current === entry && !io.signal.aborted) current = undefined;
          throw error;
        }
        try {
          await this.#renewIfDue(claim, io.signal);
          await this.#assertClaimExists(claim, io.signal);
        } catch (error) {
          // An expired claim is replaced once; any other renewal failure
          // fails the command rather than run it in a sandbox about to go.
          if (!(error instanceof ClaimGone) || attempt > 0) throw error;
          entry.gone = true;
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
        lastClaim = claim.claim;
        entry.users++;
        // Renewed while any command runs in it, retired or not: a command
        // cancelled beside it must not let the claim expire under it.
        entry.keepalive ??= setInterval(() => {
          if (entry.gone) return;
          void this.#renew(claim).catch((error: unknown) => {
            // Gone mid-command: the next command must not reuse it.
            if (error instanceof ClaimGone) {
              entry.gone = true;
              retire(entry);
            }
          });
        }, this.#renewEveryMs());
        entry.keepalive.unref?.();
        // The runtime cannot stop a running command. A cancelled command
        // retires its claim: the next command gets a fresh sandbox, and the
        // retired claim is deleted once no command uses it any more, so the
        // commands still running in it finish there.
        const onAbort = () => retire(entry);
        io.signal.addEventListener("abort", onAbort, { once: true });
        try {
          return await this.#execute(claim, request, io);
        } catch (error) {
          if (error instanceof ClaimGone) {
            entry.gone = true;
            retire(entry);
          } else if (error instanceof OutcomeUnknown) retire(entry);
          throw error;
        } finally {
          io.signal.removeEventListener("abort", onAbort);
          entry.users--;
          await release(entry);
        }
      },
      epoch: () => lastClaim,
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        session.abort();
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

  #monotonic(): number {
    return this.#options.monotonic?.() ?? performance.now();
  }

  /**
   * The wall clock on the claim's timeline: its creation plus elapsed time,
   * counted on whichever clock advanced more. A suspend is counted (the wall
   * clock dominates) and a clock set back is not (the monotonic one does); a
   * clock set forward is indistinguishable from a suspend and counts too.
   */
  #claimTime(claim: Claim): number {
    return (
      claim.wallAt +
      elapsedSince(
        claim.monotonicAt,
        claim.wallAt,
        this.#monotonic(),
        this.#now(),
      )
    );
  }

  async #renewIfDue(claim: Claim, signal: AbortSignal): Promise<void> {
    const left = claim.expiresAt - this.#claimTime(claim);
    // Past its shutdownTime the claim may already be shutting down, even if
    // the controller has not removed it yet: replace it, never revive it.
    if (left <= 0) throw new ClaimGone("the SandboxClaim expired");
    if (left >= this.#lifetimeMs() / 2) return;
    await this.#renew(claim, signal);
  }

  async #assertClaimExists(claim: Claim, signal: AbortSignal): Promise<void> {
    const response = await this.#request(`${this.#claims()}/${claim.claim}`, {
      method: "GET",
      signal,
    });
    if (response.status === 404) {
      await response.body?.cancel().catch(() => undefined);
      throw new ClaimGone("the SandboxClaim no longer exists");
    }
    if (!response.ok)
      throw new Error(
        `checking the SandboxClaim failed: ${await describeFailure(response)}`,
      );
    await response.body?.cancel().catch(() => undefined);
  }

  /** Move the claim's shutdownTime one lifetime ahead, never back. */
  async #renew(claim: Claim, signal?: AbortSignal): Promise<void> {
    // A claim past its shutdownTime (a keepalive late after a suspend) may
    // already be shutting down: it is never revived.
    if (this.#claimTime(claim) >= claim.expiresAt)
      throw new ClaimGone("the SandboxClaim expired");
    const expiresAt = Math.max(
      claim.expiresAt,
      wholeSecond(this.#claimTime(claim) + this.#lifetimeMs()),
    );
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
    // Both values are on the claim's timeline; a concurrent renewal that was
    // accepted first may have committed a later one.
    claim.expiresAt = Math.max(claim.expiresAt, expiresAt);
  }

  #claims(): string {
    return `${this.#api}/apis/${GROUP}/namespaces/${this.#namespace}/sandboxclaims`;
  }

  /**
   * A request to the API or the router, both of which receive the
   * credential as a bearer token. A POST (a claim or a command) may have
   * created something and is never sent twice.
   */
  #request(
    url: string,
    init: RequestInit,
    timeoutMs = 30_000,
  ): Promise<Response> {
    return credentialedFetch(
      this.#options,
      url,
      init,
      (credential) => ["Authorization", `Bearer ${credential}`],
      init.method !== "POST",
      timeoutMs,
    );
  }

  async #claim(signal: AbortSignal | undefined): Promise<Claim> {
    const name = `piship-${randomBytes(6).toString("hex")}`;
    const wallAt = this.#now();
    const monotonicAt = this.#monotonic();
    const expiresAt = wholeSecond(wallAt + this.#lifetimeMs());
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
      return {
        ...(await this.#ready(name, signal)),
        expiresAt,
        wallAt,
        monotonicAt,
      };
    } catch (error) {
      await this.#delete(name);
      throw error;
    }
  }

  async #ready(
    name: string,
    signal: AbortSignal | undefined,
  ): Promise<Pick<Claim, "claim" | "sandbox">> {
    const deadline =
      this.#monotonic() + (this.#options.readyTimeoutMs ?? 120_000);
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
      if (this.#monotonic() >= deadline)
        throw new Error("the SandboxClaim did not become ready in time");
      await wait(this.#options.pollMs ?? 1000, signal);
    }
  }

  async #delete(name: string): Promise<void> {
    try {
      const response = await this.#request(`${this.#claims()}/${name}`, {
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
    /** A transport failure once the command may have been sent. */
    const unknown = (error: unknown): unknown =>
      io.signal.aborted ||
      (error instanceof PiShipError && error.code !== "GATEWAY_UNREACHABLE")
        ? error
        : new OutcomeUnknown(
            `the connection to the sandbox router failed (${errorText(error)})`,
          );
    const response = await this.#request(
      `${this.#router}/execute`,
      {
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
      },
      0,
    ).catch((error: unknown) => {
      throw unknown(error);
    });
    if (response.status === 404) {
      await response.body?.cancel().catch(() => undefined);
      throw new ClaimGone("the sandbox router no longer knows this sandbox");
    }
    // A 5xx comes from the router or a gateway in front of it, such as one
    // that stopped waiting for a long command: the command may still run.
    if (response.status >= 500)
      throw new OutcomeUnknown(
        `the sandbox router answered ${await describeFailure(response)}`,
      );
    if (!response.ok)
      throw new Error(
        `running the command failed: ${await describeFailure(response)}`,
      );
    const body = await readJson(response, MAX_OUTPUT_BYTES).catch(
      (error: unknown) => {
        // A body that ends early is a transport failure (undici's
        // TypeError); one that is too large or not JSON came complete.
        throw error instanceof TypeError ? unknown(error) : error;
      },
    );
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
