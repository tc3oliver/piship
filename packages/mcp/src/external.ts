// Parse `.mcp.json`-style definitions from project or user files. They are
// untrusted: the result is never started without policy and trust checks,
// never receives the runtime credential, and carries no secret values.

import {
  DEFAULT_NETWORK_POLICY,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import type { McpServerConfig } from "./types.js";

export interface ExternalMcpServer extends McpServerConfig {
  readonly source: "project" | "user";
  readonly trusted: false;
}

export interface ExternalMcpIssue {
  readonly server: string;
  readonly message: string;
}

export interface ExternalMcpDefinitions {
  readonly servers: readonly ExternalMcpServer[];
  /** Entries that were rejected entirely. */
  readonly invalid: readonly ExternalMcpIssue[];
  /** Parts of accepted entries that were dropped (e.g. secret-looking env). */
  readonly warnings: readonly ExternalMcpIssue[];
}

const SERVER_NAME = /^[A-Za-z0-9_-]{1,64}$/;
const COMMAND_NAME = /^[A-Za-z0-9._+-]{1,128}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const ENV_REFERENCE = /^\$\{?([A-Za-z_][A-Za-z0-9_]{0,127})\}?$/;
const MAX_SERVERS = 64;
const MAX_ARGS = 64;
const MAX_TEXT = 1024;

export const EXTERNAL_MCP_DEFAULTS = {
  timeoutMs: 30_000,
  startupTimeoutMs: 10_000,
  attempts: 1,
} as const;

/** True when a variable name matches the managed credential patterns. */
export function isCredentialVariableName(name: string): boolean {
  return (
    sanitizeManagedEnvironment({ [name]: "x" }, DEFAULT_NETWORK_POLICY).length >
    0
  );
}

function looksSecret(value: string): boolean {
  if (redact(value) !== value) return true;
  // Long unbroken high-variety strings are treated as tokens.
  return (
    value.length >= 24 &&
    /^[A-Za-z0-9+/_=.-]+$/.test(value) &&
    /[A-Za-z]/.test(value) &&
    /\d/.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseExternalMcpDefinitions(
  json: unknown,
  source: "project" | "user",
): ExternalMcpDefinitions {
  const servers: ExternalMcpServer[] = [];
  const invalid: ExternalMcpIssue[] = [];
  const warnings: ExternalMcpIssue[] = [];
  if (!isRecord(json) || !isRecord(json.mcpServers)) {
    invalid.push({
      server: "*",
      message: "expected an object with an mcpServers object",
    });
    return { servers, invalid, warnings };
  }
  const entries = Object.entries(json.mcpServers);
  if (entries.length > MAX_SERVERS)
    invalid.push({
      server: "*",
      message: `only the first ${MAX_SERVERS} servers are read`,
    });
  for (const [name, value] of entries.slice(0, MAX_SERVERS)) {
    const label = SERVER_NAME.test(name) ? name : printable(name);
    try {
      servers.push(parseServer(name, value, source, warnings));
    } catch (error) {
      invalid.push({ server: label, message: (error as Error).message });
    }
  }
  return { servers, invalid, warnings };
}

function parseServer(
  name: string,
  value: unknown,
  source: "project" | "user",
  warnings: ExternalMcpIssue[],
): ExternalMcpServer {
  if (!SERVER_NAME.test(name))
    throw new Error("server names may use letters, digits, _ and - only");
  if (!isRecord(value)) throw new Error("definition must be an object");
  const type = value.type;
  if (type === "sse")
    throw new Error("legacy HTTP+SSE transport is not supported");
  if (
    type !== undefined &&
    type !== "stdio" &&
    type !== "http" &&
    type !== "streamable-http"
  )
    throw new Error(`unsupported transport type ${printable(String(type))}`);
  if (value.headers !== undefined)
    warnings.push({
      server: name,
      message: "headers are ignored; external definitions carry no credentials",
    });
  const base = {
    id: name,
    source,
    trusted: false as const,
    credential: "none" as const,
    timeoutMs: EXTERNAL_MCP_DEFAULTS.timeoutMs,
    startupTimeoutMs: EXTERNAL_MCP_DEFAULTS.startupTimeoutMs,
    retry: { attempts: EXTERNAL_MCP_DEFAULTS.attempts },
    required: false,
    tools: { allow: [], deny: [] },
  };
  const http =
    type === "http" ||
    type === "streamable-http" ||
    (type === undefined && value.url !== undefined);
  if (http) {
    if (value.command !== undefined)
      throw new Error("an HTTP server must not declare a command");
    return {
      ...base,
      transport: "streamable-http",
      url: parseUrl(value.url),
      args: [],
      env: { allow: [], set: {} },
    };
  }
  if (value.url !== undefined)
    throw new Error("a stdio server must not declare a url");
  const command = value.command;
  if (typeof command !== "string" || !COMMAND_NAME.test(command))
    throw new Error("command must be an executable name resolved on PATH");
  return {
    ...base,
    transport: "stdio",
    command,
    args: parseArgs(value.args),
    env: parseEnv(name, value.env, warnings),
  };
}

function parseUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > MAX_TEXT)
    throw new Error("url must be a string");
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("url is not a valid URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new Error("url must use https (or http for loopback)");
  if (url.username || url.password)
    throw new Error("url must not embed credentials");
  if (url.search || url.hash)
    throw new Error("url must not contain a query string or fragment");
  return url.toString();
}

function parseArgs(value: unknown): string[] {
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length > MAX_ARGS ||
    !value.every((item) => typeof item === "string" && item.length <= MAX_TEXT)
  )
    throw new Error(`args must be at most ${MAX_ARGS} strings`);
  if (value.some((item) => looksSecret(item)))
    throw new Error("args must not contain secret-looking values");
  return [...value];
}

function parseEnv(
  server: string,
  value: unknown,
  warnings: ExternalMcpIssue[],
): McpServerConfig["env"] {
  if (value === undefined) return { allow: [], set: {} };
  if (!isRecord(value)) throw new Error("env must be an object");
  const allow: string[] = [];
  const set: Record<string, string> = {};
  for (const [name, raw] of Object.entries(value)) {
    if (!ENV_NAME.test(name)) {
      warnings.push({ server, message: "dropped an invalid env name" });
      continue;
    }
    if (isCredentialVariableName(name)) {
      warnings.push({
        server,
        message: `dropped env ${name}: credential variables are not passed to external servers`,
      });
      continue;
    }
    if (typeof raw !== "string") {
      warnings.push({ server, message: `dropped env ${name}: not a string` });
      continue;
    }
    const reference = ENV_REFERENCE.exec(raw);
    if (reference) {
      // `${NAME}` passes the variable through by name; its value is never read.
      const target = reference[1] as string;
      if (target !== name || isCredentialVariableName(target)) {
        warnings.push({
          server,
          message: `dropped env ${name}: only same-name references are passed through`,
        });
        continue;
      }
      if (!allow.includes(name)) allow.push(name);
      continue;
    }
    if (looksSecret(raw) || raw.length > MAX_TEXT) {
      warnings.push({
        server,
        message: `dropped env ${name}: value looks like a secret`,
      });
      continue;
    }
    set[name] = raw;
  }
  return { allow, set };
}

function printable(text: string): string {
  return JSON.stringify(text.slice(0, 64));
}
