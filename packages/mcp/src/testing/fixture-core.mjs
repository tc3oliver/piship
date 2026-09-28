// Dependency-free MCP fixture logic shared by the stdio and HTTP fixture
// servers. It exposes a few document tools and records every tools/call it
// receives, so tests can prove that a denied call never reached the server.

export const FIXTURE_TOOLS = [
  {
    name: "search",
    description: "Search fixture documents.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  },
  {
    name: "get_document",
    description: "Read one fixture document.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "delete_document",
    description: "Delete one fixture document.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "slow",
    description: "Wait before answering.",
    inputSchema: { type: "object", properties: { ms: { type: "number" } } },
  },
  {
    name: "echo_env",
    description: "Return the names (never values) of visible env variables.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "big",
    description: "Return a large text result.",
    inputSchema: { type: "object", properties: { bytes: { type: "number" } } },
  },
];

/**
 * Create a fixture. Options: serverName, protocolVersion (answered verbatim;
 * default echoes the client's offer), pageSize (tools/list page size),
 * envNames (function returning visible env names), record (called with each
 * received tools/call or cancellation).
 */
export function createFixture(options = {}) {
  const calls = [];
  const cancelled = [];
  const inflight = new Map();
  const record = (entry) => {
    if (entry.type === "call") calls.push(entry);
    else cancelled.push(entry);
    options.record?.(entry);
  };
  const pageSize = options.pageSize ?? 2;

  async function callTool(id, params) {
    const name = params?.name;
    const args = params?.arguments ?? {};
    record({ type: "call", name, args });
    switch (name) {
      case "search":
        return text(`results for ${String(args.query)}`);
      case "get_document":
        return {
          content: [
            { type: "text", text: `document ${String(args.id)}` },
            { type: "image", mimeType: "image/png", data: "iVBORw0KGgo=" },
          ],
        };
      case "delete_document":
        return text(`deleted ${String(args.id)}`);
      case "slow": {
        const ms = Number(args.ms ?? 1000);
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, ms);
          inflight.set(id, () => {
            clearTimeout(timer);
            resolve();
          });
        });
        inflight.delete(id);
        return text(`slept ${ms}`);
      }
      case "echo_env":
        return text(JSON.stringify(options.envNames?.() ?? []));
      case "big":
        return text("x".repeat(Number(args.bytes ?? 1024)));
      default:
        throw Object.assign(new Error(`Unknown tool: ${String(name)}`), {
          rpcCode: -32602,
        });
    }
  }

  /** Handle one message; resolves to a response object or undefined. */
  async function handle(message) {
    if (message?.jsonrpc !== "2.0")
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid Request" },
      };
    const { id, method, params } = message;
    if (method === "notifications/cancelled") {
      record({ type: "cancelled", requestId: params?.requestId });
      inflight.get(params?.requestId)?.();
      return undefined;
    }
    if (id === undefined) return undefined;
    try {
      const result = await dispatch(id, method, params);
      return { jsonrpc: "2.0", id, result };
    } catch (error) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: error.rpcCode ?? -32603, message: error.message },
      };
    }
  }

  async function dispatch(id, method, params) {
    switch (method) {
      case "initialize":
        return {
          protocolVersion: options.protocolVersion ?? params?.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: {
            name: options.serverName ?? "fixture-docs",
            version: "1.0.0",
          },
        };
      case "ping":
        return {};
      case "tools/list": {
        const start = Number(params?.cursor ?? 0);
        const tools = FIXTURE_TOOLS.slice(start, start + pageSize);
        const next = start + pageSize;
        return next < FIXTURE_TOOLS.length
          ? { tools, nextCursor: String(next) }
          : { tools };
      }
      case "tools/call":
        return callTool(id, params);
      default:
        throw Object.assign(new Error("Method not found"), { rpcCode: -32601 });
    }
  }

  return { handle, calls, cancelled };
}

function text(value) {
  return { content: [{ type: "text", text: value }] };
}
