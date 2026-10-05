// Types shared by the MCP client, its transports, and the governor. The
// server configuration mirrors `McpServerConfig` from @piship/schema
// structurally; MCP is a governance leaf and does not import the schema.

import type {
  EnforcementPlane,
  PolicyDecision,
  SecretValue,
} from "@piship/contracts";
import type { SandboxWrapper } from "@piship/sandbox";
import type { Readable, Writable } from "node:stream";

export interface McpServerConfig {
  readonly id: string;
  readonly transport: "stdio" | "streamable-http";
  /** stdio: `./` module run with the distribution's Node. */
  readonly module?: string;
  /** stdio: an executable name resolved on PATH. */
  readonly command?: string;
  readonly args: readonly string[];
  /** Streamable HTTP endpoint (runtime references already resolved). */
  readonly url?: string;
  readonly env: {
    readonly allow: readonly string[];
    readonly set: Readonly<Record<string, string>>;
  };
  readonly credential: "none" | "runtime";
  readonly expectedServerName?: string;
  readonly timeoutMs: number;
  readonly startupTimeoutMs: number;
  readonly retry: { readonly attempts: number };
  readonly required: boolean;
  readonly tools: {
    readonly allow: readonly string[];
    readonly deny: readonly string[];
  };
  /**
   * `http-allowed` also permits plain HTTP to a private or internal host;
   * absent or `https` keeps plain HTTP to loopback only.
   */
  readonly httpTransport?: "https" | "http-allowed";
  /** Request headers whose value is a claim of the signed-in identity. */
  readonly headers?: Readonly<
    Record<string, { readonly identityClaim: string }>
  >;
}

// ------------------------------------------------------------ JSON-RPC

export type JsonRpcId = string | number;

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

export interface JsonRpcNotification {
  readonly jsonrpc: "2.0";
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

export interface JsonRpcErrorObject {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export type JsonRpcResponse =
  | {
      readonly jsonrpc: "2.0";
      readonly id: JsonRpcId;
      readonly result: Record<string, unknown>;
    }
  | {
      readonly jsonrpc: "2.0";
      readonly id: JsonRpcId | null;
      readonly error: JsonRpcErrorObject;
    };

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcNotification
  | JsonRpcResponse;

// ----------------------------------------------------------- transports

/**
 * A message transport. `send` delivers one outgoing message; incoming
 * messages (including responses carried in an HTTP response body) reach the
 * `onMessage` handler. A transport that fails calls `onClose` with the error.
 */
export interface McpTransport {
  readonly kind: "stdio" | "streamable-http";
  start(): Promise<void>;
  send(message: JsonRpcMessage, signal?: AbortSignal): Promise<void>;
  /** Called by the session once the protocol version is negotiated. */
  setProtocolVersion(version: string): void;
  close(): Promise<void>;
  /** Receives each parsed JSON value; the client validates its shape. */
  onMessage: ((message: unknown) => void) | undefined;
  onClose: ((error: Error | undefined) => void) | undefined;
}

// ------------------------------------------------- child processes (stdio)

/** A spawn request, matching `spawnManaged` from @piship/sandbox. */
export interface SpawnRequest {
  readonly file: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  /** The active sandbox (an `ActiveSandbox`), or undefined when not required. */
  readonly sandbox: SandboxWrapper | undefined;
  readonly timeoutMs?: number;
  readonly graceMs: number;
  readonly signal?: AbortSignal;
  readonly onStdout?: (chunk: Buffer | string) => void;
  readonly onStderr?: (chunk: Buffer | string) => void;
  readonly stdin: "pipe" | "ignore";
}

export interface ChildExit {
  readonly code: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
}

export interface ChildHandle {
  readonly pid: number | undefined;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly exited: Promise<ChildExit>;
  terminate(): unknown;
}

export type SpawnFunction = (request: SpawnRequest) => ChildHandle;

/** Process helpers from @piship/sandbox, injectable for tests. */
export interface ProcessRuntime {
  readonly spawn: SpawnFunction;
  readonly filterEnvironment: (
    env: NodeJS.ProcessEnv,
    allow: readonly string[],
    set: Readonly<Record<string, string>>,
  ) => Record<string, string>;
  readonly sanitizeStderr: (text: string, maxBytes: number) => string;
}

// ------------------------------------------------------------ governance

export type McpFetch = (
  url: string | URL,
  init?: RequestInit,
) => Promise<Response>;

/**
 * The claims of the signed-in identity, asked for by every request that
 * carries an identity header; throws (or returns null) when that identity is
 * no longer signed in. Called per request, so it must be cheap. Only
 * PiShip's retained, non-secret claims; never a token.
 */
export type McpIdentityClaimsProvider = () => Promise<Readonly<
  Record<string, unknown>
> | null>;

/** Supplies the runtime bearer for `credential: runtime` HTTP servers. */
export type McpCredentialProvider = (
  serverId: string,
) => Promise<SecretValue | string>;

export interface McpAuthorizeRequest {
  readonly action: "mcp.server.start" | "mcp.tool.call";
  readonly resource: string;
}

export interface McpAuthorizeResult {
  readonly allowed: boolean;
  readonly reason: string;
  readonly decision?: PolicyDecision;
}

export type McpAuthorize = (
  request: McpAuthorizeRequest,
) => Promise<McpAuthorizeResult>;

/** Metadata-only audit record; the caller adds schema, time, user, session. */
export interface McpAuditEvent {
  readonly event: "mcp.server.start" | "mcp.call" | "mcp.denied";
  readonly resource: string;
  readonly decision?: "allowed" | "denied";
  readonly policy?: string;
  readonly rule?: string;
  readonly enforcement?: EnforcementPlane;
  readonly detail?: Readonly<Record<string, string | number | boolean | null>>;
}

export type McpServerState = "healthy" | "degraded" | "failed" | "denied";

export interface McpServerReport {
  readonly id: string;
  readonly state: McpServerState;
  readonly required: boolean;
  readonly reason?: string;
  readonly transport: "stdio" | "streamable-http";
  /** The resolved URL is plain HTTP to a host other than loopback. */
  readonly plainHttp?: boolean;
  /** Negotiated protocol version, once initialized. */
  readonly protocolVersion?: string;
  readonly serverName?: string;
  /** Exposed tool names (`mcp__<server>__<tool>`), after allow/deny filtering. */
  readonly tools: readonly string[];
  /** Tools the server offered that were withheld, with the reason class. */
  readonly withheld?: readonly string[];
}

export interface McpToolResult {
  /** Redacted text rendering of the result content, capped in size. */
  readonly text: string;
  /** The server reported a tool-level error (`isError: true`). */
  readonly isError: boolean;
  readonly truncated: boolean;
}

export interface GovernedMcpTool {
  /** Name exposed to the agent: `mcp__<server>__<tool>`. */
  readonly name: string;
  readonly server: string;
  readonly tool: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  call(args: unknown, signal?: AbortSignal): Promise<McpToolResult>;
}
