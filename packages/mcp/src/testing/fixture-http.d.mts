// Types for the plain JavaScript Streamable HTTP fixture, so the tests that
// start it are type-checked against what it actually returns.

export interface FixtureHttpOptions {
  readonly mode?: "json" | "sse";
  readonly serverName?: string;
  readonly protocolVersion?: string;
  readonly pageSize?: number;
  /** The Authorization bearer value every request must carry. */
  readonly bearer?: string;
  /** Issue an Mcp-Session-Id (default true). */
  readonly session?: boolean;
  /** Answer every POST with a 307. */
  readonly redirect?: boolean;
  /** A request header whose value each request records as `recorded`. */
  readonly recordHeader?: string;
}

/** One request the fixture received, with the headers it checks. */
export interface FixtureHttpRequest {
  readonly method: string;
  readonly accept: string | undefined;
  readonly sessionId: string | undefined;
  readonly protocolVersion: string | undefined;
  readonly authorized: boolean | undefined;
  readonly recorded?: string | string[] | undefined;
}

export interface FixtureToolCall {
  readonly type: "call";
  readonly name: string;
  readonly args: Record<string, unknown>;
}

export interface FixtureCancellation {
  readonly type: "cancelled";
  readonly requestId: unknown;
}

export interface FixtureHttpServer {
  readonly url: string;
  readonly calls: FixtureToolCall[];
  readonly cancelled: FixtureCancellation[];
  readonly requests: FixtureHttpRequest[];
  /** The session id of each DELETE received. */
  readonly deleted: (string | undefined)[];
  readonly sessionId: string | undefined;
  close(): Promise<void>;
}

export function startFixtureHttpServer(
  options?: FixtureHttpOptions,
): Promise<FixtureHttpServer>;
