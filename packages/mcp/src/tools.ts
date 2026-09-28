// Tool filtering and result rendering.

import { redact } from "@piship/contracts";
import type { McpServerConfig, McpToolResult } from "./types.js";

export const DEFAULT_MAX_RESULT_BYTES = 256 * 1024;

function patternToRegExp(pattern: string): RegExp {
  const source = pattern
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${source}$`);
}

/** Match a tool name against a list of exact names or `*` globs. */
export function matchesToolPattern(
  patterns: readonly string[],
  name: string,
): boolean {
  return patterns.some((pattern) => patternToRegExp(pattern).test(name));
}

/**
 * The server's own tool lists: deny wins; an empty allow list admits every
 * tool that is not denied.
 */
export function toolPermitted(
  tools: McpServerConfig["tools"],
  name: string,
): boolean {
  if (matchesToolPattern(tools.deny, name)) return false;
  return tools.allow.length === 0 || matchesToolPattern(tools.allow, name);
}

export function exposedToolName(server: string, tool: string): string {
  return `mcp__${server}__${tool}`;
}

/**
 * Render a `tools/call` result as text: text parts are joined, other parts are
 * summarized, and the result is redacted and capped.
 */
export function renderToolResult(
  result: Record<string, unknown>,
  maxBytes = DEFAULT_MAX_RESULT_BYTES,
): McpToolResult {
  const parts: string[] = [];
  const content = Array.isArray(result.content) ? result.content : [];
  for (const item of content) parts.push(renderPart(item));
  if (parts.length === 0 && result.structuredContent !== undefined)
    parts.push(safeJson(result.structuredContent));
  const text = redact(parts.join("\n"));
  const capped = capBytes(text, maxBytes);
  return {
    text: capped.text,
    isError: result.isError === true,
    truncated: capped.truncated,
  };
}

function renderPart(item: unknown): string {
  if (typeof item !== "object" || item === null) return "[invalid content]";
  const part = item as Record<string, unknown>;
  switch (part.type) {
    case "text":
      return typeof part.text === "string" ? part.text : "[invalid text]";
    case "image":
    case "audio":
      return `[${part.type} content: ${stringField(part.mimeType, "unknown type")}, ${
        typeof part.data === "string"
          ? `${base64Bytes(part.data)} bytes`
          : "no data"
      } omitted]`;
    case "resource": {
      const resource = (part.resource ?? {}) as Record<string, unknown>;
      const uri = stringField(resource.uri, "unknown");
      if (typeof resource.text === "string")
        return `[resource ${uri}]\n${resource.text}`;
      return `[resource ${uri}: ${stringField(resource.mimeType, "binary")} content omitted]`;
    }
    case "resource_link":
      return `[resource link: ${stringField(part.uri, "unknown")}${
        typeof part.name === "string" ? ` (${part.name})` : ""
      }]`;
    default:
      return `[unsupported content type: ${stringField(part.type, "unknown")}]`;
  }
}

function base64Bytes(data: string): number {
  const padding = data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((data.length * 3) / 4) - padding);
}

function stringField(value: unknown, fallback: string): string {
  return typeof value === "string" ? value.slice(0, 200) : fallback;
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "[unserializable structured content]";
  }
}

function capBytes(
  text: string,
  maxBytes: number,
): { text: string; truncated: boolean } {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.byteLength <= maxBytes) return { text, truncated: false };
  // Drop a possibly split trailing character.
  const cut = bytes.subarray(0, maxBytes).toString("utf8").replace(/�$/, "");
  return {
    text: `${cut}\n[output truncated at ${maxBytes} bytes]`,
    truncated: true,
  };
}
