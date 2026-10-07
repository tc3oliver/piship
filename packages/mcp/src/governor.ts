// Governed MCP: every server start and every tool call is authorized before
// anything is spawned, connected, or sent.

import { isLoopbackHost, PiShipError } from "@piship/contracts";
import type { SandboxWrapper } from "@piship/sandbox";
import { StreamableHttpTransport } from "./http.js";
import {
  abortError,
  isAbortError,
  mcpDenied,
  mcpUnhealthy,
  truncate,
} from "./jsonrpc.js";
import { defaultProcessRuntime } from "./process.js";
import {
  type McpClientInfo,
  McpSession,
  type McpToolDefinition,
} from "./session.js";
import { StdioTransport } from "./stdio.js";
import {
  DEFAULT_MAX_RESULT_BYTES,
  exposedToolName,
  renderToolResult,
  toolPermitted,
} from "./tools.js";
import type {
  GovernedMcpTool,
  McpAuditEvent,
  McpAuthorize,
  McpAuthorizeResult,
  McpCredentialProvider,
  McpFetch,
  McpIdentityClaimsProvider,
  McpServerConfig,
  McpServerReport,
  McpServerState,
  McpToolResult,
  McpTransport,
  ProcessRuntime,
  SpawnFunction,
} from "./types.js";

export interface McpGovernorOptions {
  readonly servers: readonly McpServerConfig[];
  readonly authorize: McpAuthorize;
  readonly audit?: (event: McpAuditEvent) => void;
  /** Directory that `module` paths resolve against. */
  readonly distributionDir: string;
  /** Working directory of stdio servers. */
  readonly workspace: string;
  /** Managed fetch for Streamable HTTP servers. */
  readonly fetch?: McpFetch;
  /**
   * Managed fetch that also permits plain HTTP to a private or internal
   * host, used for every server but one with `httpTransport: https`. Without
   * it those servers use `fetch`, which keeps plain HTTP to loopback.
   */
  readonly plainHttpFetch?: McpFetch;
  /**
   * The signed-in identity's claims, for servers that declare identity
   * `headers`; asked for by every request, so a sign-out or user switch
   * stops the header at once.
   */
  readonly identityClaims?: McpIdentityClaimsProvider;
  /** Runtime bearer for `credential: runtime` servers. */
  readonly credential?: McpCredentialProvider;
  /**
   * Origins the runtime bearer is issued for (the inference gateway). A
   * `credential: runtime` server on any other origin fails to start.
   */
  readonly credentialOrigins?: readonly string[];
  /**
   * Resolve a Streamable HTTP server's `url` (for example its `${NAME}`
   * runtime references) just before connecting. A throw fails that server:
   * CONFIG_UNAVAILABLE for a required one, unhealthy for an optional one.
   */
  readonly resolveUrl?: (server: McpServerConfig) => string;
  /** Active sandbox (`ActiveSandbox`) that wraps every stdio spawn. */
  readonly sandbox?: SandboxWrapper;
  /** Replaces the sandbox spawner (tests, embedding). */
  readonly spawn?: SpawnFunction;
  /** Replaces the whole process runtime (tests). */
  readonly processRuntime?: ProcessRuntime;
  /** Environment stdio children are filtered from; defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  readonly clientInfo?: McpClientInfo;
  readonly maxResultBytes?: number;
  readonly graceMs?: number;
  /** Delay before a start retry; attempt n waits n times this. */
  readonly retryDelayMs?: number;
  /**
   * Optional exposure filter applied after the server tool lists, e.g. a
   * non-interactive policy pre-check. Calls are still authorized.
   */
  readonly expose?: (tool: {
    readonly server: string;
    readonly tool: string;
    readonly resource: string;
  }) => boolean;
}

interface ServerEntry {
  readonly config: McpServerConfig;
  state: McpServerState | "pending";
  reason?: string;
  /** Error code of a start failure. */
  failure?: string;
  session?: McpSession;
  protocolVersion?: string;
  serverName?: string;
  tools: McpToolDefinition[];
  exposed: string[];
  withheld: string[];
  /** The resolved URL is plain HTTP to a host other than loopback. */
  plainHttp?: boolean;
}

const DEFAULT_CLIENT: McpClientInfo = { name: "piship", version: "0.3.0" };

export class McpGovernor {
  readonly #options: McpGovernorOptions;
  readonly #entries: ServerEntry[];
  #runtime: ProcessRuntime | undefined;
  #descriptors: GovernedMcpTool[] = [];
  #starting: Promise<readonly McpServerReport[]> | undefined;
  #closing: Promise<void> | undefined;

  constructor(options: McpGovernorOptions) {
    this.#options = options;
    const ids = new Set<string>();
    this.#entries = options.servers.map((config) => {
      if (ids.has(config.id))
        throw new PiShipError(
          "CONFIG_INVALID",
          `MCP server ${config.id} is declared more than once`,
          { component: "mcp" },
        );
      ids.add(config.id);
      return {
        config,
        state: "pending",
        tools: [],
        exposed: [],
        withheld: [],
      };
    });
  }

  /**
   * Authorize every server, start the allowed ones, and list their tools.
   * Rejects (after closing everything) when a required server is denied
   * (MCP_DENIED) or cannot start (MCP_UNHEALTHY).
   */
  start(): Promise<readonly McpServerReport[]> {
    this.#starting ??= this.#startAll();
    return this.#starting;
  }

  /** Governed tool descriptors of running servers. */
  tools(): readonly GovernedMcpTool[] {
    if (this.#closing) return [];
    return this.#descriptors.filter((tool) => {
      const entry = this.#entry(tool.server);
      return entry?.state === "healthy" || entry?.state === "degraded";
    });
  }

  health(): readonly McpServerReport[] {
    return this.#entries.map((entry) => report(entry));
  }

  close(): Promise<void> {
    this.#closing ??= this.#closeAll();
    return this.#closing;
  }

  // --------------------------------------------------------------- start

  async #startAll(): Promise<readonly McpServerReport[]> {
    // Authorize sequentially: approvals may be interactive.
    const allowed: ServerEntry[] = [];
    for (const entry of this.#entries) {
      if (this.#closing) break;
      const decision = await this.#authorize({
        action: "mcp.server.start",
        resource: entry.config.id,
      });
      if (decision.allowed) {
        allowed.push(entry);
        continue;
      }
      entry.state = "denied";
      entry.reason = truncate(decision.reason || "denied by policy");
      this.#emit(
        denialEvent(entry.config.id, "mcp.server.start", decision.decision),
      );
    }
    const deniedRequired = this.#entries.find(
      (entry) => entry.state === "denied" && entry.config.required,
    );
    if (deniedRequired) {
      await this.close();
      throw mcpDenied(
        `Required MCP server ${deniedRequired.config.id} is denied by policy`,
        deniedRequired.reason,
      );
    }
    await Promise.all(allowed.map((entry) => this.#startServer(entry)));
    const failedRequired = this.#entries.find(
      (entry) => entry.state === "failed" && entry.config.required,
    );
    if (failedRequired) {
      await this.close();
      if (failedRequired.failure === "CONFIG_UNAVAILABLE")
        throw new PiShipError(
          "CONFIG_UNAVAILABLE",
          `Required MCP server ${failedRequired.config.id} cannot start: ${failedRequired.reason ?? "its configuration is unavailable"}`,
          {
            component: "mcp",
            sanitizedDetail: { server: failedRequired.config.id },
          },
        );
      throw mcpUnhealthy(
        `Required MCP server ${failedRequired.config.id} failed to start: ${failedRequired.reason ?? "unknown error"}`,
        { detail: { server: failedRequired.config.id } },
      );
    }
    if (this.#closing)
      throw mcpUnhealthy("MCP governor was closed during start");
    return this.health();
  }

  async #startServer(entry: ServerEntry): Promise<void> {
    const { config } = entry;
    const attempts = Math.max(1, Math.floor(config.retry.attempts));
    let lastError: unknown;
    let attempt = 0;
    while (attempt < attempts && !this.#closing) {
      attempt++;
      try {
        await this.#connect(entry);
        lastError = undefined;
        break;
      } catch (error) {
        lastError = error;
        if (!(error instanceof PiShipError && error.retryable)) break;
        if (attempt < attempts)
          await delay((this.#options.retryDelayMs ?? 250) * attempt);
      }
    }
    if (lastError !== undefined || !entry.session) {
      entry.state = "failed";
      entry.reason = failureReason(lastError ?? "closed during start");
      if (lastError instanceof PiShipError) entry.failure = lastError.code;
    }
    this.#emit({
      event: "mcp.server.start",
      resource: config.id,
      decision: "allowed",
      detail: {
        transport: config.transport,
        state: entry.state,
        attempts: attempt,
        tools: entry.exposed.length,
        protocolVersion: entry.protocolVersion ?? null,
      },
    });
  }

  async #connect(entry: ServerEntry): Promise<void> {
    const { config } = entry;
    const transport = this.#transport(entry);
    const session = new McpSession(transport, config.id);
    const deadline = Date.now() + config.startupTimeoutMs;
    try {
      await withDeadline(transport.start(), deadline, config.id);
      const info = await session.initialize({
        timeoutMs: remaining(deadline, config.id),
        clientInfo: this.#options.clientInfo ?? DEFAULT_CLIENT,
        ...(config.expectedServerName === undefined
          ? {}
          : { expectedServerName: config.expectedServerName }),
      });
      const listed = info.hasTools
        ? await session.listTools({ timeoutMs: remaining(deadline, config.id) })
        : { tools: [], invalid: [] };
      if (this.#closing) throw mcpUnhealthy("MCP governor is closing");
      entry.session = session;
      entry.protocolVersion = info.protocolVersion;
      entry.serverName = info.serverName;
      entry.tools = [...listed.tools];
      entry.state = listed.invalid.length > 0 ? "degraded" : "healthy";
      if (listed.invalid.length > 0)
        entry.reason = `withheld ${listed.invalid.length} tool(s) with invalid definitions`;
      entry.withheld = [...listed.invalid];
      this.#expose(entry);
      session.client.onClosed = (error) => {
        if (this.#closing || entry.session !== session) return;
        entry.state = "failed";
        entry.reason = failureReason(error);
      };
    } catch (error) {
      await session.close().catch(() => undefined);
      throw withStderr(error, transport);
    }
  }

  #transport(entry: ServerEntry): McpTransport {
    const { config } = entry;
    if (config.transport === "stdio")
      return new StdioTransport({
        server: config,
        distributionDir: this.#options.distributionDir,
        workspace: this.#options.workspace,
        runtime: this.#processRuntime(),
        ...(this.#options.env ? { env: this.#options.env } : {}),
        ...(this.#options.sandbox === undefined
          ? {}
          : { sandbox: this.#options.sandbox }),
        ...(this.#options.graceMs === undefined
          ? {}
          : { graceMs: this.#options.graceMs }),
      });
    if (!config.url)
      throw mcpUnhealthy(`MCP server ${config.id} declares no url`);
    if (!this.#options.fetch)
      throw mcpUnhealthy(
        `MCP server ${config.id} needs a managed fetch for Streamable HTTP`,
      );
    if (config.credential === "runtime" && !this.#options.credential)
      throw mcpUnhealthy(
        `MCP server ${config.id} requires the runtime credential, which is not available`,
      );
    const url = this.#resolveUrl(config);
    const plainHttp = config.httpTransport !== "https";
    const transport = new StreamableHttpTransport({
      serverId: config.id,
      url,
      fetch:
        plainHttp && this.#options.plainHttpFetch
          ? this.#options.plainHttpFetch
          : this.#options.fetch,
      ...(plainHttp ? { plainHttp } : {}),
      ...(config.credential === "runtime" && this.#options.credential
        ? {
            credential: this.#options.credential,
            credentialOrigins: this.#options.credentialOrigins ?? [],
          }
        : {}),
      ...(config.headers && Object.keys(config.headers).length
        ? {
            identityHeaders: config.headers,
            ...(this.#options.identityClaims
              ? { identityClaims: this.#options.identityClaims }
              : {}),
          }
        : {}),
    });
    const target = new URL(url);
    entry.plainHttp =
      target.protocol === "http:" && !isLoopbackHost(target.hostname);
    return transport;
  }

  #resolveUrl(config: McpServerConfig): string {
    const resolve = this.#options.resolveUrl;
    if (!resolve) return config.url ?? "";
    try {
      return resolve(config);
    } catch (error) {
      const message = `MCP server ${config.id} url cannot be resolved: ${error instanceof Error ? error.message : "unknown error"}`;
      // Not retryable: the launch environment does not change between attempts.
      throw config.required
        ? new PiShipError("CONFIG_UNAVAILABLE", message, { component: "mcp" })
        : mcpUnhealthy(message);
    }
  }

  #processRuntime(): ProcessRuntime {
    if (!this.#runtime) {
      const base = this.#options.processRuntime ?? defaultProcessRuntime();
      this.#runtime = this.#options.spawn
        ? { ...base, spawn: this.#options.spawn }
        : base;
    }
    return this.#runtime;
  }

  #expose(entry: ServerEntry): void {
    const { config } = entry;
    for (const tool of entry.tools) {
      const resource = `${config.id}:${tool.name}`;
      const permitted =
        toolPermitted(config.tools, tool.name) &&
        (this.#options.expose?.({
          server: config.id,
          tool: tool.name,
          resource,
        }) ??
          true);
      if (!permitted) {
        entry.withheld.push(tool.name);
        continue;
      }
      const name = exposedToolName(config.id, tool.name);
      entry.exposed.push(name);
      this.#descriptors.push({
        name,
        server: config.id,
        tool: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        call: (args, signal) => this.#call(entry, tool.name, args, signal),
      });
    }
  }

  // ---------------------------------------------------------------- call

  async #call(
    entry: ServerEntry,
    tool: string,
    args: unknown,
    signal?: AbortSignal,
  ): Promise<McpToolResult> {
    const { config } = entry;
    const resource = `${config.id}:${tool}`;
    if (this.#closing) throw mcpUnhealthy("MCP governor is closed");
    if (!toolPermitted(config.tools, tool)) {
      this.#emit({
        ...denialEvent(resource, "mcp.tool.call"),
        rule: `mcp.servers.${config.id}.tools`,
        enforcement: "control-plane",
      });
      throw mcpDenied(
        `MCP tool ${tool} on server ${config.id} is not allowed by the server tool list`,
      );
    }
    const decision = await this.#authorize({
      action: "mcp.tool.call",
      resource,
    });
    if (!decision.allowed) {
      this.#emit(denialEvent(resource, "mcp.tool.call", decision.decision));
      throw mcpDenied(
        `MCP tool ${tool} on server ${config.id} is denied by policy`,
        decision.reason,
      );
    }
    if (signal?.aborted) throw abortError(signal);
    const session = entry.session;
    if (
      !session ||
      (entry.state !== "healthy" && entry.state !== "degraded") ||
      this.#closing
    )
      throw mcpUnhealthy(
        `MCP server ${config.id} is not available: ${entry.reason ?? entry.state}`,
      );
    const input = toArguments(args, config.id, tool);
    const started = Date.now();
    const policy = policyFields(decision);
    try {
      const result = await session.callTool(tool, input, {
        timeoutMs: config.timeoutMs,
        ...(signal ? { signal } : {}),
      });
      const rendered = renderToolResult(
        result,
        this.#options.maxResultBytes ?? DEFAULT_MAX_RESULT_BYTES,
      );
      this.#emit({
        event: "mcp.call",
        resource,
        decision: "allowed",
        ...policy,
        detail: {
          outcome: rendered.isError ? "tool-error" : "ok",
          durationMs: Date.now() - started,
          truncated: rendered.truncated,
        },
      });
      return rendered;
    } catch (error) {
      const outcome = isAbortError(error)
        ? "cancelled"
        : isTimeout(error)
          ? "timeout"
          : "error";
      if (outcome === "timeout" && entry.state === "healthy") {
        entry.state = "degraded";
        entry.reason = `tool ${tool} timed out after ${config.timeoutMs} ms`;
      }
      this.#emit({
        event: "mcp.call",
        resource,
        decision: "allowed",
        ...policy,
        detail: { outcome, durationMs: Date.now() - started },
      });
      throw error;
    }
  }

  // ------------------------------------------------------------- helpers

  async #authorize(request: {
    readonly action: "mcp.server.start" | "mcp.tool.call";
    readonly resource: string;
  }): Promise<McpAuthorizeResult> {
    try {
      const result = await this.#options.authorize(request);
      return result.allowed === true
        ? result
        : { ...result, allowed: false, reason: result.reason ?? "denied" };
    } catch {
      // Fail closed: an authorizer error is a denial.
      return { allowed: false, reason: "authorization failed" };
    }
  }

  #emit(event: McpAuditEvent): void {
    try {
      this.#options.audit?.(event);
    } catch {
      // Sink failures are handled and reported by the audit log itself.
    }
  }

  #entry(id: string): ServerEntry | undefined {
    return this.#entries.find((entry) => entry.config.id === id);
  }

  async #closeAll(): Promise<void> {
    await Promise.all(
      this.#entries.map(async (entry) => {
        const session = entry.session;
        if (!session) return;
        await session.close().catch(() => undefined);
      }),
    );
    this.#descriptors = [];
  }
}

// ----------------------------------------------------------------- helpers

function report(entry: ServerEntry): McpServerReport {
  return {
    id: entry.config.id,
    state: entry.state === "pending" ? "failed" : entry.state,
    required: entry.config.required,
    transport: entry.config.transport,
    ...(entry.plainHttp ? { plainHttp: true } : {}),
    ...(entry.state === "pending"
      ? { reason: "not started" }
      : entry.reason
        ? { reason: entry.reason }
        : {}),
    ...(entry.protocolVersion
      ? { protocolVersion: entry.protocolVersion }
      : {}),
    ...(entry.serverName ? { serverName: entry.serverName } : {}),
    tools: [...entry.exposed],
    ...(entry.withheld.length > 0 ? { withheld: [...entry.withheld] } : {}),
  };
}

function policyFields(
  result: McpAuthorizeResult,
): Pick<McpAuditEvent, "policy" | "rule" | "enforcement"> {
  const decision = result.decision;
  if (!decision) return {};
  return {
    policy: decision.policyId,
    rule: decision.ruleId,
    enforcement: decision.enforcement,
  };
}

function denialEvent(
  resource: string,
  action: "mcp.server.start" | "mcp.tool.call",
  decision?: McpAuthorizeResult["decision"],
): McpAuditEvent {
  return {
    event: "mcp.denied",
    resource,
    decision: "denied",
    ...(decision
      ? {
          policy: decision.policyId,
          rule: decision.ruleId,
          enforcement: decision.enforcement,
        }
      : {}),
    detail: { action },
  };
}

function toArguments(
  args: unknown,
  server: string,
  tool: string,
): Record<string, unknown> {
  if (args === undefined || args === null) return {};
  if (typeof args !== "object" || Array.isArray(args))
    throw new PiShipError(
      "CONFIG_INVALID",
      `MCP tool ${tool} on server ${server} requires an object of arguments`,
      { component: "mcp" },
    );
  return args as Record<string, unknown>;
}

function isTimeout(error: unknown): boolean {
  return (
    error instanceof PiShipError &&
    error.code === "MCP_UNHEALTHY" &&
    typeof error.sanitizedDetail?.timeoutMs === "number"
  );
}

function failureReason(error: unknown): string {
  if (error instanceof PiShipError) {
    const stderr = error.sanitizedDetail?.stderr;
    return truncate(
      typeof stderr === "string" && stderr.length > 0
        ? `${error.message} (stderr: ${stderr})`
        : error.message,
      1200,
    );
  }
  if (typeof error === "string") return error;
  return "unexpected error";
}

function withStderr(error: unknown, transport: McpTransport): unknown {
  if (!(error instanceof PiShipError) || !(transport instanceof StdioTransport))
    return error;
  if (error.sanitizedDetail?.stderr !== undefined) return error;
  const stderr = transport.stderrSummary();
  if (!stderr) return error;
  return new PiShipError(error.code, error.message, {
    component: "mcp",
    retryable: error.retryable,
    sanitizedDetail: { ...(error.sanitizedDetail ?? {}), stderr },
  });
}

function remaining(deadline: number, server: string): number {
  const left = deadline - Date.now();
  if (left <= 0)
    throw mcpUnhealthy(`MCP server ${server} did not start in time`, {
      retryable: true,
      detail: { timeoutMs: 0 },
    });
  return left;
}

async function withDeadline<T>(
  work: Promise<T>,
  deadline: number,
  server: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          mcpUnhealthy(`MCP server ${server} did not start in time`, {
            retryable: true,
          }),
        ),
      Math.max(0, deadline - Date.now()),
    );
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}
