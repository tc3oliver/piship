// The e2b-compatible backend: the E2B sandbox API (control plane) and the
// envd process service (data plane). Any service that implements that API,
// such as E2B or CubeSandbox, works through this one compatibility layer.
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
  trimSlashes,
} from "./http.js";

export interface E2bCompatibleOptions extends RemoteBackendOptions {
  /** The template the sandbox is created from. Default `base`. */
  readonly template?: string;
  /**
   * Sandbox lifetime in seconds, renewed before every command so an idle
   * session's sandbox expires on its own. Default 3600.
   */
  readonly lifetimeSeconds?: number;
  /**
   * The user commands run as inside the sandbox (envd's Basic user). Default
   * `user`, as E2B templates expect; CubeSandbox runs commands as `root`.
   */
  readonly user?: string;
  /** Test seam: the envd base URL for a created sandbox. */
  readonly envdUrl?: (sandbox: {
    readonly sandboxId: string;
    readonly domain: string;
  }) => string;
}

const ENVD_PORT = 49983;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const SANDBOX_ID = /^[A-Za-z0-9][A-Za-z0-9-]{0,127}$/;
const DOMAIN = /^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/;
const SIGNAL_TIMEOUT_MS = 5000;

// A remote VM: the host's files are out of reach, but PiShip's path rules
// are not mapped into it, so no filesystem-* plane is claimed. The network
// is denied at creation (allow_internet_access) and checked before use.
const CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  planes: [HOST_FILESYSTEM_ISOLATION, "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
};

interface CreatedSandbox {
  readonly sandboxId: string;
  readonly accessToken: string | undefined;
  readonly envd: string;
}

/** Connect envelope: flags byte, 4-byte big-endian length, JSON payload. */
export function connectEnvelope(message: unknown, flags = 0): Buffer {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.alloc(5);
  header.writeUInt8(flags, 0);
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

/** Incrementally split a Connect stream into its envelopes. */
export class EnvelopeReader {
  #buffer = Buffer.alloc(0);

  push(chunk: Uint8Array): { flags: number; message: unknown }[] {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    const output: { flags: number; message: unknown }[] = [];
    while (this.#buffer.length >= 5) {
      const flags = this.#buffer.readUInt8(0);
      const length = this.#buffer.readUInt32BE(1);
      if (length > MAX_FRAME_BYTES)
        throw new Error("the sandbox sent an oversized stream frame");
      if (flags & 0x01)
        throw new Error(
          "the sandbox sent a compressed frame, which is not negotiated",
        );
      if (this.#buffer.length < 5 + length) break;
      const payload = this.#buffer.subarray(5, 5 + length).toString("utf8");
      this.#buffer = this.#buffer.subarray(5 + length);
      output.push({ flags, message: payload ? JSON.parse(payload) : {} });
    }
    return output;
  }
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export class E2bCompatibleBackend implements SandboxBackend {
  readonly id = "e2b-compatible";
  readonly provider = "e2b-compatible" as const;
  readonly #options: E2bCompatibleOptions;
  readonly #endpoint: URL;

  constructor(options: E2bCompatibleOptions) {
    this.#options = options;
    this.#endpoint = new URL(`${trimSlashes(options.endpoint)}/`);
  }

  capabilities(): SandboxCapabilities {
    return CAPABILITIES;
  }

  async available(): Promise<AdapterAvailability> {
    try {
      const response = await this.#options.fetch(this.#url("health"), {
        method: "GET",
        signal: AbortSignal.timeout(10_000),
      });
      await response.body?.cancel().catch(() => undefined);
      if (response.ok) return { available: true };
      return {
        available: false,
        reason: `the e2b-compatible endpoint health check returned HTTP ${response.status}`,
      };
    } catch (error) {
      return {
        available: false,
        reason: `the e2b-compatible endpoint is unreachable: ${errorText(error)}`,
      };
    }
  }

  async prepare({
    profile,
    signal,
  }: SandboxPrepareRequest): Promise<SandboxInstance> {
    const created = await this.#create(profile.network, signal);
    const workdir = this.#options.workdir ?? "/home/user";
    let disposed = false;
    return {
      exec: (request, io) => {
        if (disposed) throw new Error("the sandbox was disposed");
        return this.#exec(created, workdir, request, io);
      },
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        try {
          const response = await this.#control(
            `sandboxes/${created.sandboxId}`,
            { method: "DELETE" },
          );
          await response.body?.cancel().catch(() => undefined);
        } catch {
          // best effort: the sandbox also expires on its own
        }
      },
    };
  }

  #url(path: string): URL {
    return new URL(path, this.#endpoint);
  }

  async #control(path: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    const credential = await this.#options.credential?.();
    if (credential) headers.set("X-API-Key", credential);
    return this.#options.fetch(this.#url(path), {
      ...init,
      headers,
      signal: init.signal ?? AbortSignal.timeout(30_000),
    });
  }

  async #create(
    network: "deny" | "allow",
    signal: AbortSignal | undefined,
  ): Promise<CreatedSandbox> {
    const response = await this.#control("sandboxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Nothing from the host environment is sent: commands receive only the
      // approved environment, one command at a time.
      body: JSON.stringify({
        templateID: this.#options.template ?? "base",
        timeout: this.#lifetime(),
        metadata: { "created-by": "piship" },
        allow_internet_access: network === "allow",
      }),
      ...(signal ? { signal } : {}),
    });
    if (!response.ok)
      throw new Error(
        `creating the sandbox failed: ${await describeFailure(response)}`,
      );
    const body = await readJson(response);
    const sandboxId = body.sandboxID;
    if (typeof sandboxId !== "string" || !SANDBOX_ID.test(sandboxId))
      throw new Error("the sandbox service returned no valid sandbox ID");
    const domain =
      typeof body.domain === "string" && DOMAIN.test(body.domain)
        ? body.domain
        : this.#endpoint.host.replace(/^api\./, "");
    const accessToken =
      typeof body.envdAccessToken === "string" && body.envdAccessToken
        ? body.envdAccessToken
        : undefined;
    const envd =
      this.#options.envdUrl?.({ sandboxId, domain }) ??
      `${this.#endpoint.protocol}//${ENVD_PORT}-${sandboxId}.${domain}`;
    return { sandboxId, accessToken, envd: trimSlashes(envd) };
  }

  #lifetime(): number {
    const value = this.#options.lifetimeSeconds ?? 3600;
    return Number.isInteger(value) && value > 0 ? value : 3600;
  }

  #envdHeaders(sandbox: CreatedSandbox, contentType: string): Headers {
    const headers = new Headers({
      "Content-Type": contentType,
      "Connect-Protocol-Version": "1",
      "E2b-Sandbox-Id": sandbox.sandboxId,
      "E2b-Sandbox-Port": String(ENVD_PORT),
    });
    if (sandbox.accessToken) headers.set("X-Access-Token", sandbox.accessToken);
    return headers;
  }

  async #exec(
    sandbox: CreatedSandbox,
    workdir: string,
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ): Promise<SandboxExecResult> {
    // Keep the sandbox alive while it is used; an expired one fails here.
    const renewed = await this.#control(
      `sandboxes/${sandbox.sandboxId}/timeout`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ timeout: this.#lifetime() }),
        signal: io.signal,
      },
    );
    if (!renewed.ok)
      throw new Error(
        `the sandbox is no longer available: ${await describeFailure(renewed)}`,
      );
    await renewed.body?.cancel().catch(() => undefined);
    // The tag lets PiShip kill the command even before its pid is known.
    const tag = `piship-${randomBytes(8).toString("hex")}`;
    const kill = () => void this.#kill(sandbox, tag);
    io.signal.addEventListener("abort", kill, { once: true });
    try {
      return await this.#stream(sandbox, workdir, request, io, tag);
    } finally {
      io.signal.removeEventListener("abort", kill);
    }
  }

  async #stream(
    sandbox: CreatedSandbox,
    workdir: string,
    request: SandboxExecRequest,
    io: SandboxExecIO,
    tag: string,
  ): Promise<SandboxExecResult> {
    const headers = this.#envdHeaders(sandbox, "application/connect+json");
    headers.set("Keepalive-Ping-Interval", "50");
    headers.set(
      "Authorization",
      `Basic ${Buffer.from(`${this.#options.user ?? "user"}:`).toString("base64")}`,
    );
    const response = await this.#options.fetch(
      `${sandbox.envd}/process.Process/Start`,
      {
        method: "POST",
        headers,
        body: connectEnvelope({
          process: {
            cmd: "/bin/bash",
            args: ["-l", "-c", request.command],
            envs: { ...request.env },
            cwd: remoteDirectory(workdir, request.workspacePath),
          },
          stdin: false,
          tag,
        }),
        signal: io.signal,
      },
    );
    if (!response.ok || !response.body)
      throw new Error(
        `starting the command failed: ${await describeFailure(response)}`,
      );
    {
      const reader = new EnvelopeReader();
      let result: SandboxExecResult | undefined;
      for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
        for (const frame of reader.push(chunk)) {
          const message = record(frame.message);
          if (frame.flags & 0x02) {
            const error = record(message.error);
            if (Object.keys(error).length)
              throw new Error(
                `the command stream failed: ${String(error.code ?? "unknown")} ${String(error.message ?? "")}`.trim(),
              );
            if (!result)
              throw new Error(
                "the command stream ended without an exit status",
              );
            return result;
          }
          const event = record(message.event);
          const data = record(event.data);
          if (typeof data.stdout === "string")
            io.onStdout(Buffer.from(data.stdout, "base64"));
          if (typeof data.stderr === "string")
            io.onStderr(Buffer.from(data.stderr, "base64"));
          if (event.end !== undefined) {
            // proto3 JSON omits defaults: a missing exit code is 0.
            const end = record(event.end);
            const status = typeof end.status === "string" ? end.status : "";
            result = {
              // envd reports a signalled process as -1.
              exitCode: Number.isInteger(end.exitCode)
                ? (end.exitCode as number) >= 0
                  ? (end.exitCode as number)
                  : null
                : /signal|killed/i.test(status)
                  ? null
                  : 0,
            };
          }
        }
      }
      if (!result)
        throw new Error("the command stream ended without an exit status");
      return result;
    }
  }

  async #kill(sandbox: CreatedSandbox, tag: string): Promise<void> {
    try {
      const response = await this.#options.fetch(
        `${sandbox.envd}/process.Process/SendSignal`,
        {
          method: "POST",
          headers: this.#envdHeaders(sandbox, "application/json"),
          body: JSON.stringify({
            process: { tag },
            signal: "SIGNAL_SIGKILL",
          }),
          signal: AbortSignal.timeout(SIGNAL_TIMEOUT_MS),
        },
      );
      await response.body?.cancel().catch(() => undefined);
    } catch {
      // best effort; disposing the session removes the sandbox
    }
  }
}
