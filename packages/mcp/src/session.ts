// An MCP client session: initialize with version negotiation, paginated
// tools/list, and tools/call.

import { JsonRpcClient, mcpUnhealthy, truncate } from "./jsonrpc.js";
import type { McpTransport } from "./types.js";

export const OFFERED_PROTOCOL_VERSION = "2025-06-18";
export const ACCEPTED_PROTOCOL_VERSIONS: readonly string[] = [
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
];

const MAX_TOOL_PAGES = 100;
const MAX_TOOLS = 1000;
const MAX_DESCRIPTION = 4096;

export interface McpClientInfo {
  readonly name: string;
  readonly version: string;
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
}

export interface InitializeResult {
  readonly protocolVersion: string;
  readonly serverName: string;
  readonly serverVersion: string;
  readonly hasTools: boolean;
}

export class McpSession {
  readonly transport: McpTransport;
  readonly client: JsonRpcClient;
  readonly #label: string;
  #initialized: InitializeResult | undefined;

  constructor(transport: McpTransport, label: string) {
    this.transport = transport;
    this.#label = label;
    this.client = new JsonRpcClient(transport, label);
  }

  get info(): InitializeResult | undefined {
    return this.#initialized;
  }

  async initialize(options: {
    readonly timeoutMs: number;
    readonly clientInfo: McpClientInfo;
    readonly expectedServerName?: string;
  }): Promise<InitializeResult> {
    const result = await this.client.request(
      "initialize",
      {
        protocolVersion: OFFERED_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { ...options.clientInfo },
      },
      { timeoutMs: options.timeoutMs, cancellable: false },
    );
    const version = result.protocolVersion;
    if (
      typeof version !== "string" ||
      !ACCEPTED_PROTOCOL_VERSIONS.includes(version)
    )
      throw mcpUnhealthy(
        `MCP server ${this.#label} negotiated unsupported protocol version ${truncate(String(version), 40)}; supported: ${ACCEPTED_PROTOCOL_VERSIONS.join(", ")}`,
        { detail: { protocolVersion: truncate(String(version), 40) } },
      );
    const serverInfo = result.serverInfo as
      | { name?: unknown; version?: unknown }
      | undefined;
    if (
      typeof serverInfo !== "object" ||
      serverInfo === null ||
      typeof serverInfo.name !== "string"
    )
      throw mcpUnhealthy(`MCP server ${this.#label} sent no serverInfo.name`);
    if (
      options.expectedServerName !== undefined &&
      serverInfo.name !== options.expectedServerName
    )
      throw mcpUnhealthy(
        `MCP server ${this.#label} identified as ${truncate(serverInfo.name, 80)}, expected ${options.expectedServerName}`,
        {
          detail: {
            expected: options.expectedServerName,
            actual: truncate(serverInfo.name, 80),
          },
        },
      );
    const capabilities = result.capabilities;
    if (typeof capabilities !== "object" || capabilities === null)
      throw mcpUnhealthy(`MCP server ${this.#label} sent no capabilities`);
    this.transport.setProtocolVersion(version);
    await this.client.notify(
      "notifications/initialized",
      undefined,
      options.timeoutMs,
    );
    this.#initialized = {
      protocolVersion: version,
      serverName: serverInfo.name,
      serverVersion:
        typeof serverInfo.version === "string" ? serverInfo.version : "",
      hasTools: "tools" in capabilities,
    };
    return this.#initialized;
  }

  /** List every tool, following `nextCursor`. Invalid entries are dropped. */
  async listTools(options: { readonly timeoutMs: number }): Promise<{
    readonly tools: readonly McpToolDefinition[];
    readonly invalid: readonly string[];
  }> {
    const tools: McpToolDefinition[] = [];
    const invalid: string[] = [];
    const seen = new Set<string>();
    let cursor: string | undefined;
    for (let page = 0; page < MAX_TOOL_PAGES; page++) {
      const result = await this.client.request(
        "tools/list",
        cursor === undefined ? undefined : { cursor },
        { timeoutMs: options.timeoutMs },
      );
      if (!Array.isArray(result.tools))
        throw mcpUnhealthy(`MCP server ${this.#label} sent no tools array`);
      for (const entry of result.tools) {
        const tool = toolDefinition(entry);
        if (!tool || seen.has(tool.name)) {
          invalid.push(
            typeof (entry as { name?: unknown })?.name === "string"
              ? truncate((entry as { name: string }).name, 80)
              : "<unnamed>",
          );
          continue;
        }
        seen.add(tool.name);
        tools.push(tool);
        if (tools.length > MAX_TOOLS)
          throw mcpUnhealthy(
            `MCP server ${this.#label} offers more than ${MAX_TOOLS} tools`,
          );
      }
      const next = result.nextCursor;
      if (next === undefined || next === null || next === "")
        return { tools, invalid };
      if (typeof next !== "string" || next === cursor)
        throw mcpUnhealthy(
          `MCP server ${this.#label} sent an invalid tools/list cursor`,
        );
      cursor = next;
    }
    throw mcpUnhealthy(
      `MCP server ${this.#label} tools/list exceeded ${MAX_TOOL_PAGES} pages`,
    );
  }

  callTool(
    name: string,
    args: Record<string, unknown>,
    options: { readonly timeoutMs: number; readonly signal?: AbortSignal },
  ): Promise<Record<string, unknown>> {
    return this.client.request(
      "tools/call",
      { name, arguments: args },
      options,
    );
  }

  async close(): Promise<void> {
    this.client.close();
    await this.transport.close();
  }
}

/** Tool names exposable to model APIs: letters, digits, `_`, `-`. */
const TOOL_NAME = /^[A-Za-z0-9_-]{1,64}$/;

function toolDefinition(entry: unknown): McpToolDefinition | undefined {
  if (typeof entry !== "object" || entry === null) return undefined;
  const { name, description, inputSchema } = entry as Record<string, unknown>;
  if (typeof name !== "string" || !TOOL_NAME.test(name)) return undefined;
  if (
    typeof inputSchema !== "object" ||
    inputSchema === null ||
    Array.isArray(inputSchema) ||
    (inputSchema as { type?: unknown }).type !== "object"
  )
    return undefined;
  return {
    name,
    description:
      typeof description === "string"
        ? truncate(description, MAX_DESCRIPTION)
        : "",
    inputSchema: inputSchema as Record<string, unknown>,
  };
}
