// MCP: server admission, transports, child environment, and tool filters.
import type { DeploymentMode } from "../access.js";
import type {
  McpConfig,
  McpServerConfig,
  TrustSetting,
} from "../governance.js";
import {
  bool,
  conflict,
  durationMs,
  envName,
  fail,
  isRecord,
  list,
  modulePath,
  nonSecretValue,
  oneOf,
  optionalRecord,
  plainString,
  positiveInteger,
  record,
  referenceUrl,
  unsafe,
} from "./fields.js";
import { TRUST } from "./policy.js";

const SERVER_ID = /^[a-z][a-z0-9-]{0,31}$/;
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const LEGACY_TRANSPORTS = ["sse", "http+sse", "http-sse"];

function toolName(value: unknown, path: string): string {
  const name = plainString(value, path, 128);
  if (!TOOL_NAME.test(name))
    fail(path, "Tool names use letters, digits, and _ . - (at most 128)");
  return name;
}

function parseServer(
  id: string,
  value: unknown,
  variables: readonly string[],
): McpServerConfig {
  const path = `mcp.servers.${id}`;
  if (!SERVER_ID.test(id))
    unsafe(
      path,
      "Server IDs use lowercase letters, digits, and hyphens (at most 32); start with a letter",
    );
  const server = record(value, path, [
    "transport",
    "module",
    "command",
    "args",
    "url",
    "env",
    "credential",
    "expectedServerName",
    "timeout",
    "startupTimeout",
    "retry",
    "required",
    "tools",
  ]);
  if (
    typeof server.transport === "string" &&
    LEGACY_TRANSPORTS.includes(server.transport)
  )
    fail(
      `${path}.transport`,
      "Legacy HTTP+SSE transport is not supported; use streamable-http",
    );
  const transport = oneOf(server.transport, `${path}.transport`, [
    "stdio",
    "streamable-http",
  ] as const);
  const credential = oneOf(
    server.credential,
    `${path}.credential`,
    ["none", "runtime"] as const,
    "none",
  );
  let launch: Pick<McpServerConfig, "module" | "command" | "url">;
  let args: string[] = [];
  let env: McpServerConfig["env"] = { allow: [], set: {} };
  if (transport === "stdio") {
    if (server.url !== undefined)
      conflict(`${path}.url`, "url applies only to streamable-http servers");
    if (credential === "runtime")
      conflict(
        `${path}.credential`,
        "credential runtime binds a bearer to streamable-http servers only; it is never placed in a stdio child environment",
      );
    if ((server.module === undefined) === (server.command === undefined))
      fail(path, "A stdio server declares exactly one of module or command");
    if (server.module !== undefined)
      launch = { module: modulePath(server.module, `${path}.module`) };
    else {
      const command = plainString(server.command, `${path}.command`, 128);
      if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(command))
        unsafe(
          `${path}.command`,
          "Use a bare executable name without path separators; use module for a ./ script",
        );
      launch = { command };
    }
    if (server.args !== undefined && !Array.isArray(server.args))
      fail(`${path}.args`, "Expected a list");
    args = ((server.args ?? []) as unknown[]).map((entry, index) =>
      nonSecretValue(entry, `${path}.args[${index}]`),
    );
    env = parseServerEnv(server.env, `${path}.env`);
  } else {
    for (const key of ["module", "command", "args", "env"])
      if (server[key] !== undefined)
        conflict(`${path}.${key}`, `${key} applies only to stdio servers`);
    if (server.url === undefined)
      fail(`${path}.url`, "A streamable-http server needs a url");
    launch = { url: referenceUrl(server.url, `${path}.url`, variables) };
  }
  const retry = optionalRecord(server.retry, `${path}.retry`, ["attempts"]);
  const tools = optionalRecord(server.tools, `${path}.tools`, [
    "allow",
    "deny",
  ]);
  const allow = list(tools.allow, `${path}.tools.allow`, toolName);
  const deny = list(tools.deny, `${path}.tools.deny`, toolName);
  for (const [index, name] of deny.entries())
    if (allow.includes(name))
      conflict(
        `${path}.tools.deny[${index}]`,
        `${name} is both allowed and denied`,
      );
  return {
    id,
    transport,
    ...launch,
    args,
    env,
    credential,
    ...(server.expectedServerName === undefined
      ? {}
      : {
          expectedServerName: plainString(
            server.expectedServerName,
            `${path}.expectedServerName`,
            128,
          ),
        }),
    timeoutMs: durationMs(server.timeout, `${path}.timeout`, "30s"),
    startupTimeoutMs: durationMs(
      server.startupTimeout,
      `${path}.startupTimeout`,
      "10s",
    ),
    retry: {
      attempts: positiveInteger(
        retry.attempts,
        `${path}.retry.attempts`,
        1,
        10,
      ),
    },
    required: bool(server.required, `${path}.required`, false),
    tools: { allow, deny },
  };
}

function parseServerEnv(value: unknown, path: string): McpServerConfig["env"] {
  const env = optionalRecord(value, path, ["allow", "set"]);
  const allow = list(env.allow, `${path}.allow`, envName);
  const set: Record<string, string> = {};
  if (env.set !== undefined) {
    if (!isRecord(env.set)) fail(`${path}.set`, "Expected an object");
    for (const [name, entry] of Object.entries(env.set)) {
      const at = `${path}.set.${name}`;
      envName(name, at);
      if (allow.includes(name))
        conflict(
          at,
          `${name} is both inherited through allow and set explicitly`,
        );
      set[name] = nonSecretValue(entry, at);
    }
  }
  return { allow, set };
}

export function parseMcp(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
): McpConfig {
  const mcp = optionalRecord(value, "mcp", [
    "mode",
    "project",
    "user",
    "servers",
  ]);
  const managed = mode === "managed";
  if (managed && mcp.mode === "explicit")
    fail(
      "mcp.mode",
      "Managed mode admits only declared servers; expected off or allowlist",
    );
  const mcpMode = oneOf(
    mcp.mode,
    "mcp.mode",
    managed
      ? (["off", "allowlist"] as const)
      : (["off", "allowlist", "explicit"] as const),
    managed ? "allowlist" : "explicit",
  );
  const serversSource = mcp.servers === undefined ? {} : mcp.servers;
  if (!isRecord(serversSource))
    fail("mcp.servers", "Expected an object keyed by server ID");
  const servers = Object.entries(serversSource).map(([id, entry]) =>
    parseServer(id, entry, variables),
  );
  if (mcpMode === "off" && servers.length)
    conflict("mcp.servers", "mcp.mode off cannot declare servers");
  const fallback: TrustSetting = managed ? "deny" : "allow";
  return {
    mode: mcpMode,
    servers,
    project: oneOf(mcp.project, "mcp.project", TRUST, fallback),
    user: oneOf(mcp.user, "mcp.user", TRUST, fallback),
  };
}
