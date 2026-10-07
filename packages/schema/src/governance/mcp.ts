// MCP: server admission, transports, child environment, and tool filters.
import {
  MCP_IDENTITY_HEADER_CLAIMS,
  mcpIdentityHeaderProblem,
} from "@piship/contracts";
import type { DeploymentMode } from "../access.js";
import {
  defaultMcpServerClass,
  DEFAULT_MCP_EXPOSURE,
  MCP_HTTP_TRANSPORTS,
  MCP_SERVER_CLASSES,
  type McpConfig,
  type McpIdentityHeader,
  type McpServerConfig,
  type TrustSetting,
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
import { plainHttpPermitted } from "../http-transport.js";
import { TRUST } from "./policy.js";
import { exposure, exposureRules } from "./runtime.js";

const SERVER_ID = /^[a-z][a-z0-9-]{0,31}$/;
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const LEGACY_TRANSPORTS = ["sse", "http+sse", "http-sse"];
const MAX_HEADERS = 8;

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
  mode: DeploymentMode,
  v6: boolean,
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
    ...(v6 ? ["exposure", "class", "httpTransport", "headers"] : []),
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
  let http: Pick<McpServerConfig, "httpTransport" | "headers"> = {};
  if (transport === "stdio") {
    for (const key of ["url", "httpTransport", "headers"])
      if (server[key] !== undefined)
        conflict(
          `${path}.${key}`,
          `${key} applies only to streamable-http servers`,
        );
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
    const httpTransport =
      server.httpTransport === undefined
        ? undefined
        : oneOf(
            server.httpTransport,
            `${path}.httpTransport`,
            MCP_HTTP_TRANSPORTS,
          );
    if (httpTransport === "http-allowed" && credential === "runtime")
      conflict(
        `${path}.httpTransport`,
        // No `credential: <word>` text: the CLI redactor reads it as a value.
        "http-allowed cannot be combined with the credential field set to runtime; the runtime credential is never sent over plain HTTP",
      );
    launch = {
      url: referenceUrl(
        server.url,
        `${path}.url`,
        variables,
        // A runtime credential is never sent over plain HTTP, so such a
        // server's URL is https (or loopback) whatever the default.
        plainHttpPermitted(httpTransport) && credential !== "runtime",
      ),
    };
    const headers =
      server.headers === undefined
        ? undefined
        : parseHeaders(server.headers, `${path}.headers`);
    http = {
      ...(httpTransport === undefined ? {} : { httpTransport }),
      ...(headers ? { headers } : {}),
    };
  }
  const retry = optionalRecord(server.retry, `${path}.retry`, ["attempts"]);
  let tools: McpServerConfig["tools"];
  let v6Fields: Pick<McpServerConfig, "class" | "exposure" | "toolExposure"> =
    {};
  if (v6) {
    // piship/v1alpha6: `tools` maps tool globs to an exposure.
    if (
      isRecord(server.tools) &&
      (Array.isArray(server.tools.allow) || Array.isArray(server.tools.deny))
    )
      fail(
        `${path}.tools`,
        "piship/v1alpha6 maps tool globs to an exposure (such as get_*: deferred or delete_*: hidden); run piship migrate to convert tools.allow and tools.deny",
      );
    const serverExposure = exposure(
      server.exposure,
      `${path}.exposure`,
      DEFAULT_MCP_EXPOSURE,
    );
    const toolExposure = exposureRules(server.tools, `${path}.tools`);
    // The v0.8 allow/deny filter is not used: which tools are visible is
    // resolved from `exposure` and `toolExposure` where tools are registered.
    tools = { allow: [], deny: [] };
    v6Fields = {
      class: oneOf(
        server.class,
        `${path}.class`,
        MCP_SERVER_CLASSES,
        defaultMcpServerClass(mode),
      ),
      exposure: serverExposure,
      toolExposure,
    };
  } else {
    const filter = optionalRecord(server.tools, `${path}.tools`, [
      "allow",
      "deny",
    ]);
    const allow = list(filter.allow, `${path}.tools.allow`, toolName);
    const deny = list(filter.deny, `${path}.tools.deny`, toolName);
    for (const [index, name] of deny.entries())
      if (allow.includes(name))
        conflict(
          `${path}.tools.deny[${index}]`,
          `${name} is both allowed and denied`,
        );
    tools = { allow, deny };
  }
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
    tools,
    ...v6Fields,
    ...http,
  };
}

function parseHeaders(
  value: unknown,
  path: string,
): Record<string, McpIdentityHeader> {
  if (!isRecord(value)) fail(path, "Expected an object keyed by header name");
  const entries = Object.entries(value);
  if (entries.length === 0)
    fail(path, "Declare at least one header, or leave headers out");
  if (entries.length > MAX_HEADERS)
    fail(path, `At most ${MAX_HEADERS} headers may be declared`);
  const seen = new Set<string>();
  const headers: Record<string, McpIdentityHeader> = {};
  for (const [name, entry] of entries) {
    const at = `${path}.${name}`;
    const problem = mcpIdentityHeaderProblem(name);
    if (problem) unsafe(at, problem);
    const lower = name.toLowerCase();
    if (seen.has(lower))
      conflict(
        at,
        `${name} is declared more than once (header names ignore case)`,
      );
    seen.add(lower);
    if (!isRecord(entry))
      fail(
        at,
        "Expected { identityClaim: <claim> }; a header value comes only from the signed-in identity, never a literal or an environment variable",
      );
    const header = record(entry, at, ["identityClaim"]);
    headers[name] = {
      identityClaim: oneOf(
        header.identityClaim,
        `${at}.identityClaim`,
        MCP_IDENTITY_HEADER_CLAIMS,
      ),
    };
  }
  return headers;
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
  /** piship/v1alpha6 and later: server `class`, `exposure`, and exposure `tools`. */
  v6 = false,
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
    parseServer(id, entry, variables, mode, v6),
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
