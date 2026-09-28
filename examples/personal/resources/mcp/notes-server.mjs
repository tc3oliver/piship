#!/usr/bin/env node
// A tiny, dependency-free MCP server for the MyPi personal example. It speaks
// newline-delimited JSON-RPC over stdio and serves a fixed, in-memory set of
// notes. It opens no network connection and reads no files.
import { createInterface } from "node:readline";

const notes = new Map([
  ["setup", "MyPi keeps its state apart from ~/.pi."],
  ["mcp", "This server is declared by the distribution, not by a project."],
]);

const tools = [
  {
    name: "list_notes",
    description: "List the ids of the bundled MyPi notes.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "read_note",
    description: "Read one bundled MyPi note by id.",
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
  if (name === "list_notes") return text([...notes.keys()].join("\n"));
  if (name === "read_note") {
    const body = notes.get(String(args?.id ?? ""));
    return body ? text(body) : { ...text("Note not found."), isError: true };
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
        serverInfo: { name: "mypi-notes", version: "1.0.0" },
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
