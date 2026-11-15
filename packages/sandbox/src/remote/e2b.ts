// The e2b-compatible backend: the E2B sandbox API (control plane) and the
// envd process service (data plane). Any service that implements that API,
// such as E2B or CubeSandbox, works through this one compatibility layer.
import { randomBytes } from "node:crypto";
import { redact } from "@piship/contracts";
import type { AdapterAvailability } from "../adapter.js";
import {
  HOST_FILESYSTEM_ISOLATION,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxFiles,
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
  /**
   * Create `workdir` in the sandbox before the first command, for a workdir
   * the template does not have (a remote workspace's project directory).
   */
  readonly createWorkdir?: boolean;
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
const MAX_FILE_BYTES = 100 * 1024 * 1024;

// A remote VM: the host's files are out of reach, but PiShip's path rules
// are not mapped into it, so no filesystem-* plane is claimed. The network
// is denied at creation (allow_internet_access); with no network probe to
// check it against, that denial is attested by the service. The sandbox is
// created from a template and sees a copy of the code, never the files
// PiShip's file tools edit: its workspace is a snapshot.
const CAPABILITIES: SandboxCapabilities = {
  isolation: "remote",
  planes: [HOST_FILESYSTEM_ISOLATION, "network-deny", "environment-filter"],
  network: ["deny", "allow"],
  localProcesses: false,
  workspace: { mode: "snapshot" },
};

interface CreatedSandbox {
  readonly sandboxId: string;
  readonly accessToken: string | undefined;
  readonly envd: string;
  /** When the timeout was last renewed (ms); the file path renews only when it is stale. */
  renewedAt: number;
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
    if (this.#options.createWorkdir)
      await this.#makeWorkdir(created, workdir).catch(async (error) => {
        await this.#control(
          `sandboxes/${created.sandboxId}`,
          { method: "DELETE" },
          true,
        )
          .then((response) => response.body?.cancel())
          .catch(() => undefined);
        throw error;
      });
    let disposed = false;
    // A remote workspace holds the only copy of the project, so an idle
    // session must not lose it: renew four times per lifetime, quietly.
    const keepalive = this.#options.createWorkdir
      ? setInterval(
          () =>
            void this.#renew(created, AbortSignal.timeout(30_000)).catch(
              () => undefined,
            ),
          Math.max(1000, this.#lifetime() * 250),
        )
      : undefined;
    keepalive?.unref();
    return {
      exec: (request, io) => {
        if (disposed) throw new Error("the sandbox was disposed");
        return this.#exec(created, workdir, request, io);
      },
      files: this.#files(created, workdir, () => disposed),
      dispose: async () => {
        if (disposed) return;
        disposed = true;
        clearInterval(keepalive);
        try {
          const response = await this.#control(
            `sandboxes/${created.sandboxId}`,
            { method: "DELETE" },
            true,
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

  /**
   * A control-plane request: the only one that carries the credential, as
   * `X-API-Key`. `repeatable` is false for a request that may have created
   * something, which is never sent twice.
   */
  #control(
    path: string,
    init: RequestInit,
    repeatable: boolean,
  ): Promise<Response> {
    return credentialedFetch(
      this.#options,
      this.#url(path),
      init,
      (credential) => ["X-API-Key", credential],
      repeatable,
    );
  }

  async #create(
    network: "deny" | "allow",
    signal: AbortSignal | undefined,
  ): Promise<CreatedSandbox> {
    const response = await this.#control(
      "sandboxes",
      {
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
      },
      false,
    );
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
    return {
      sandboxId,
      accessToken,
      envd: trimSlashes(envd),
      renewedAt: Date.now(),
    };
  }

  async #makeWorkdir(sandbox: CreatedSandbox, workdir: string): Promise<void> {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), 30_000);
    let stderr = "";
    try {
      // From `/`: the directory does not exist yet to run in.
      const result = await this.#stream(
        sandbox,
        "/",
        {
          command: `mkdir -p -- ${shellQuote(workdir)}`,
          cwd: "/",
          workspacePath: undefined,
          env: {},
        },
        {
          signal: abort.signal,
          onStdout: () => {},
          onStderr: (chunk) => {
            stderr += chunk.toString("utf8");
          },
        },
        `piship-${randomBytes(8).toString("hex")}`,
      );
      if (result.exitCode !== 0)
        throw new Error(
          `creating the workspace directory failed: ${redact(stderr).slice(0, 200)}`,
        );
    } finally {
      clearTimeout(timer);
    }
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

  /**
   * Keep the sandbox alive while it is used; an expired one fails here. A file
   * operation passes `throttled`: it renews only once the last renewal is a
   * tenth of the lifetime old (at most a minute), so the timeout never nears
   * its end while a burst of file calls costs one control-plane request.
   * Every command renews.
   */
  async #renew(
    sandbox: CreatedSandbox,
    signal: AbortSignal,
    throttled = false,
  ): Promise<void> {
    if (
      throttled &&
      Date.now() - sandbox.renewedAt < Math.min(60_000, this.#lifetime() * 100)
    )
      return;
    const renewed = await this.#control(
      `sandboxes/${sandbox.sandboxId}/timeout`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ timeout: this.#lifetime() }),
        signal,
      },
      true,
    );
    if (!renewed.ok) {
      const gone = renewed.status === 404 || renewed.status === 410;
      throw Object.assign(
        new Error(
          gone
            ? `the sandbox expired or was lost: ${await describeFailure(renewed)}; start a new session to get a fresh sandbox`
            : `the sandbox is no longer available (it may have expired): ${await describeFailure(renewed)}; start a new session to get a fresh sandbox`,
        ),
        // The session says what to do next: only it knows its command name.
        gone ? { code: "SANDBOX_GONE" } : {},
      );
    }
    await renewed.body?.cancel().catch(() => undefined);
    sandbox.renewedAt = Date.now();
  }

  #basic(): string {
    return `Basic ${Buffer.from(`${this.#options.user ?? "user"}:`).toString("base64")}`;
  }

  /**
   * File access over envd: `GET`/`POST /files` for content (multipart upload
   * creates parent directories) and the Filesystem `Stat` RPC. envd's own
   * credentials only (access token, Basic user); the control-plane key never
   * goes here, and no secret is placed in a URL.
   */
  #files(
    sandbox: CreatedSandbox,
    workdir: string,
    isDisposed: () => boolean,
  ): SandboxFiles {
    const user = this.#options.user ?? "user";
    const request = async <T>(
      path: string,
      signal: AbortSignal,
      call: (absolute: string, headers: Headers) => Promise<T>,
    ): Promise<T> => {
      if (isDisposed()) throw new Error("the sandbox was disposed");
      if (!path || path === "." || path.includes("\0"))
        throw new Error("the path is not a workspace file");
      const absolute = remoteDirectory(workdir, path);
      await this.#renew(sandbox, signal, true);
      const headers = this.#envdHeaders(sandbox, "application/json");
      headers.set("Authorization", this.#basic());
      return call(absolute, headers);
    };
    const filesUrl = (absolute: string) =>
      `${sandbox.envd}/files?${new URLSearchParams({ path: absolute, username: user })}`;
    return {
      read: (path, { signal }) =>
        request(path, signal, async (absolute, headers) => {
          headers.delete("Content-Type");
          const response = await this.#options.fetch(filesUrl(absolute), {
            method: "GET",
            headers,
            signal,
          });
          if (response.status === 404) {
            await response.body?.cancel().catch(() => undefined);
            throw Object.assign(new Error("no such file in the sandbox"), {
              code: "ENOENT",
            });
          }
          if (!response.ok)
            throw new Error(
              `reading the file failed: ${await describeFailure(response)}`,
            );
          // Content-Encoding changes what Content-Length counts: compare only
          // a body that arrives as sent.
          const declared = response.headers.get("content-encoding")
            ? NaN
            : Number(response.headers.get("content-length") ?? NaN);
          if (declared > MAX_FILE_BYTES) {
            await response.body?.cancel().catch(() => undefined);
            throw new Error("the file is too large");
          }
          const chunks: Buffer[] = [];
          let size = 0;
          for await (const chunk of (response.body ??
            []) as AsyncIterable<Uint8Array>) {
            size += chunk.byteLength;
            if (size > MAX_FILE_BYTES) {
              await response.body?.cancel().catch(() => undefined);
              throw new Error("the file is too large");
            }
            chunks.push(Buffer.from(chunk));
          }
          if (Number.isInteger(declared) && size !== declared)
            throw new Error(
              `the sandbox sent ${size} of the ${declared} bytes it announced for the file`,
            );
          return Buffer.concat(chunks);
        }),
      write: (path, data, { signal }) =>
        request(path, signal, async (absolute, headers) => {
          // Built by hand: the managed fetch sends a FormData body as text.
          const boundary = `piship-${randomBytes(12).toString("hex")}`;
          headers.set(
            "Content-Type",
            `multipart/form-data; boundary=${boundary}`,
          );
          const body = Buffer.concat([
            Buffer.from(
              `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="file"\r\nContent-Type: application/octet-stream\r\n\r\n`,
            ),
            data,
            Buffer.from(`\r\n--${boundary}--\r\n`),
          ]);
          const response = await this.#options.fetch(filesUrl(absolute), {
            method: "POST",
            headers,
            body,
            signal,
          });
          if (!response.ok)
            throw new Error(
              `writing the file failed: ${await describeFailure(response)}`,
            );
          await response.body?.cancel().catch(() => undefined);
        }),
      stat: (path, { signal }) =>
        request(path, signal, async (absolute, headers) => {
          const response = await this.#options.fetch(
            `${sandbox.envd}/filesystem.Filesystem/Stat`,
            {
              method: "POST",
              headers,
              body: JSON.stringify({ path: absolute }),
              signal,
            },
          );
          if (response.status === 404) {
            await response.body?.cancel().catch(() => undefined);
            return undefined;
          }
          if (!response.ok)
            throw new Error(
              `checking the file failed: ${await describeFailure(response)}`,
            );
          const entry = record(record(await readJson(response)).entry);
          return {
            type:
              entry.type === "FILE_TYPE_FILE"
                ? ("file" as const)
                : entry.type === "FILE_TYPE_DIRECTORY"
                  ? ("directory" as const)
                  : ("other" as const),
            size: Number(entry.size ?? 0),
          };
        }),
    };
  }

  async #exec(
    sandbox: CreatedSandbox,
    workdir: string,
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ): Promise<SandboxExecResult> {
    await this.#renew(sandbox, io.signal);
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
    headers.set("Authorization", this.#basic());
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
