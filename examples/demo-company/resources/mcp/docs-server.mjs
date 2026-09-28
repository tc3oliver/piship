#!/usr/bin/env node
// A tiny, dependency-free MCP server for the fictional AcmeCode demo. It
// speaks newline-delimited JSON-RPC over stdio and serves a fixed, in-memory
// handbook. `delete_document` exists only so the demo policy can deny it: the
// distribution never lets that call reach this process.
import { createInterface } from "node:readline";

const documents = new Map([
  [
    "handbook/review",
    "Reviews check tests, error handling, and documentation before merge.",
  ],
  [
    "handbook/release",
    "Releases are cut from main after every required check is green.",
  ],
]);

const tools = [
  {
    name: "search",
    description: "Search the demo handbook by keyword.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "get_document",
    description: "Read one demo handbook document by id.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "delete_document",
    description: "Delete a demo handbook document (denied by the demo policy).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
];

function send(message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
}

function text(value) {
  return { content: [{ type: "text", text: value }] };
}

function call(name, args) {
  if (name === "search") {
    const query = String(args?.query ?? "").toLowerCase();
    const hits = [...documents.entries()]
      .filter(([, body]) => body.toLowerCase().includes(query))
      .map(([id]) => id);
    return text(hits.length ? hits.join("\n") : "No matching documents.");
  }
  if (name === "get_document") {
    const body = documents.get(String(args?.id ?? ""));
    return body
      ? text(body)
      : { ...text("Document not found."), isError: true };
  }
  if (name === "delete_document") {
    documents.delete(String(args?.id ?? ""));
    return text("Deleted.");
  }
  return undefined;
}

const lines = createInterface({ input: process.stdin });
lines.on("line", (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    send({ id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  if (message.id === undefined) return;
  if (message.method === "initialize")
    return send({
      id: message.id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "acme-docs", version: "1.0.0" },
      },
    });
  if (message.method === "ping") return send({ id: message.id, result: {} });
  if (message.method === "tools/list")
    return send({ id: message.id, result: { tools } });
  if (message.method === "tools/call") {
    const result = call(message.params?.name, message.params?.arguments);
    if (result) return send({ id: message.id, result });
    return send({
      id: message.id,
      error: { code: -32602, message: "Unknown tool" },
    });
  }
  send({
    id: message.id,
    error: { code: -32601, message: "Method not found" },
  });
});
lines.on("close", () => process.exit(0));
