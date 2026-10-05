// Streamable HTTP transport (MCP 2025-03-26 and later): each JSON-RPC message
// is POSTed; the reply is `application/json` or a `text/event-stream` carrying
// messages until the response for the request arrives. The legacy HTTP+SSE
// transport is not implemented.

import {
  isLoopbackHost,
  isPrivateNetworkHost,
  redact,
  SecretValue,
} from "@piship/contracts";
import {
  DEFAULT_MAX_MESSAGE_BYTES,
  isAbortError,
  mcpUnhealthy,
  parseFrame,
  truncate,
} from "./jsonrpc.js";
import type {
  JsonRpcId,
  JsonRpcMessage,
  McpCredentialProvider,
  McpFetch,
  McpIdentityClaimsProvider,
  McpTransport,
} from "./types.js";

export interface StreamableHttpTransportOptions {
  readonly serverId: string;
  readonly url: string;
  /** The caller's managed fetch (TLS, proxy, private-only policy). */
  readonly fetch: McpFetch;
  /** Present only for `credential: runtime`; the bearer is never logged. */
  readonly credential?: McpCredentialProvider;
  /**
   * Origins the runtime credential is issued for (the inference gateway).
   * With `credential`, the server URL must be on one of them, or the
   * transport refuses to start rather than send the bearer elsewhere.
   */
  readonly credentialOrigins?: readonly string[];
  readonly maxMessageBytes?: number;
  /** Upper bound on a whole response body or event stream. */
  readonly maxResponseBytes?: number;
  /**
   * `httpTransport: http-allowed`: also permit plain HTTP to a private or
   * internal host. Without it plain HTTP is accepted only on loopback.
   */
  readonly plainHttp?: boolean;
  /** Header name to identity claim; each value is read per request. */
  readonly identityHeaders?: Readonly<
    Record<string, { readonly identityClaim: string }>
  >;
  /** The signed-in identity's claims; required with `identityHeaders`. */
  readonly identityClaims?: McpIdentityClaimsProvider;
}

/** The longest identity header value sent. */
export const MAX_IDENTITY_HEADER_LENGTH = 256;

/** Normalized origins; entries that are not URLs are dropped. */
function credentialOrigins(values: readonly string[]): string[] {
  const origins: string[] = [];
  for (const value of values) {
    try {
      const { origin } = new URL(value);
      if (origin !== "null") origins.push(origin);
    } catch {
      // Not a URL: it cannot authorize any origin.
    }
  }
  return origins;
}

const SESSION_ID = /^[\x21-\x7e]{1,512}$/;

export class StreamableHttpTransport implements McpTransport {
  readonly kind = "streamable-http" as const;
  onMessage: ((message: unknown) => void) | undefined;
  onClose: ((error: Error | undefined) => void) | undefined;
  readonly #options: StreamableHttpTransportOptions;
  readonly #url: URL;
  readonly #maxMessage: number;
  readonly #maxResponse: number;
  #sessionId: string | undefined;
  #protocolVersion: string | undefined;
  #closed = false;

  constructor(options: StreamableHttpTransportOptions) {
    this.#options = options;
    let url: URL;
    try {
      url = new URL(options.url);
    } catch {
      throw mcpUnhealthy(`MCP server ${options.serverId} URL is invalid`);
    }
    if (url.protocol !== "https:" && url.protocol !== "http:")
      throw mcpUnhealthy(
        `MCP server ${options.serverId} URL must use http or https`,
      );
    if (url.username || url.password)
      throw mcpUnhealthy(
        `MCP server ${options.serverId} URL must not embed credentials`,
      );
    if (options.credential) {
      const allowed = credentialOrigins(options.credentialOrigins ?? []);
      if (!allowed.includes(url.origin))
        throw mcpUnhealthy(
          `MCP server ${options.serverId} is at ${url.origin}, but the runtime credential is only sent to ${allowed.length ? allowed.join(", ") : "the inference gateway origin, which is not configured"}`,
        );
    }
    // Plain HTTP beyond loopback only with http-allowed, to a private or
    // internal host, and never with the runtime credential.
    if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
      if (!options.plainHttp)
        throw mcpUnhealthy(
          `MCP server ${options.serverId} URL must use https; plain HTTP is accepted only for loopback, or for a private or internal host with httpTransport: http-allowed`,
        );
      if (!isPrivateNetworkHost(url.hostname))
        throw mcpUnhealthy(
          `MCP server ${options.serverId} URL is plain HTTP to ${url.hostname}, which is public; httpTransport: http-allowed permits plain HTTP only to a private or internal host`,
        );
      if (options.credential)
        throw mcpUnhealthy(
          `MCP server ${options.serverId} URL is plain HTTP; the runtime credential is never sent over plain HTTP`,
        );
    }
    if (options.identityHeaders && !options.identityClaims)
      throw mcpUnhealthy(
        `MCP server ${options.serverId} sends identity headers, but no signed-in identity is available`,
      );
    this.#url = url;
    this.#maxMessage = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
    this.#maxResponse = options.maxResponseBytes ?? this.#maxMessage * 4;
  }

  get sessionId(): string | undefined {
    return this.#sessionId;
  }

  async start(): Promise<void> {}

  setProtocolVersion(version: string): void {
    this.#protocolVersion = version;
  }

  async send(message: JsonRpcMessage, signal?: AbortSignal): Promise<void> {
    if (this.#closed)
      throw mcpUnhealthy(`MCP server ${this.#options.serverId} is closed`);
    const body = JSON.stringify(message);
    if (Buffer.byteLength(body, "utf8") > this.#maxMessage)
      throw mcpUnhealthy(
        `MCP request exceeds the ${this.#maxMessage}-byte message limit`,
      );
    const headers = await this.#headers({
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    });
    const response = await this.#fetch({
      method: "POST",
      headers,
      body,
      ...(signal ? { signal } : {}),
    });
    this.#captureSession(response, message);
    const expected =
      "id" in message && "method" in message ? message.id : undefined;
    if (response.status === 202 || response.status === 204) {
      await response.body?.cancel().catch(() => undefined);
      if (expected !== undefined)
        throw mcpUnhealthy(
          `MCP server ${this.#options.serverId} accepted a request without answering it`,
        );
      return;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw this.#statusError(response.status);
    }
    const type = (response.headers.get("content-type") ?? "")
      .split(";")[0]
      ?.trim()
      .toLowerCase();
    if (type === "text/event-stream") {
      // Only requests are answered on a stream; nothing waits on the rest.
      if (expected === undefined) {
        await response.body?.cancel().catch(() => undefined);
        return;
      }
      await this.#readEventStream(response, expected);
      return;
    }
    if (type === "application/json") {
      const text = await readBounded(response, this.#maxResponse);
      if (text.trim().length === 0) {
        if (expected !== undefined)
          throw mcpUnhealthy(
            `MCP server ${this.#options.serverId} returned an empty response`,
          );
        return;
      }
      this.onMessage?.(parseFrame(text, this.#maxResponse));
      return;
    }
    await response.body?.cancel().catch(() => undefined);
    throw mcpUnhealthy(
      `MCP server ${this.#options.serverId} returned unsupported content type ${truncate(type ?? "", 80)}`,
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    const sessionId = this.#sessionId;
    if (sessionId) {
      try {
        const headers = await this.#headers({});
        const response = await this.#options.fetch(this.#url, {
          method: "DELETE",
          headers,
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
        });
        await response.body?.cancel().catch(() => undefined);
      } catch {
        // The server may not support explicit termination (405) or be gone.
      }
    }
    this.onClose?.(undefined);
  }

  async #headers(base: Record<string, string>): Promise<Headers> {
    const headers = new Headers(base);
    if (this.#sessionId) headers.set("mcp-session-id", this.#sessionId);
    if (this.#protocolVersion)
      headers.set("mcp-protocol-version", this.#protocolVersion);
    if (this.#options.credential) {
      let secret: SecretValue;
      try {
        const value = await this.#options.credential(this.#options.serverId);
        secret = value instanceof SecretValue ? value : new SecretValue(value);
      } catch {
        throw mcpUnhealthy(
          `MCP server ${this.#options.serverId} runtime credential is unavailable`,
        );
      }
      headers.set("authorization", `Bearer ${secret.reveal()}`);
    }
    await this.#identityHeaders(headers);
    return headers;
  }

  /**
   * Set each identity header from the identity signed in now. The value is
   * identity data: it is never logged, and no error message quotes it.
   */
  async #identityHeaders(headers: Headers): Promise<void> {
    const declared = Object.entries(this.#options.identityHeaders ?? {});
    if (!declared.length) return;
    const id = this.#options.serverId;
    let claims: Readonly<Record<string, unknown>> | null;
    try {
      claims = (await this.#options.identityClaims?.()) ?? null;
    } catch {
      throw mcpUnhealthy(
        `MCP server ${id} sends identity headers, but the signed-in identity is unavailable`,
      );
    }
    if (!claims)
      throw mcpUnhealthy(
        `MCP server ${id} sends identity headers, but nobody is signed in`,
      );
    for (const [name, { identityClaim }] of declared) {
      const value = Object.hasOwn(claims, identityClaim)
        ? claims[identityClaim]
        : undefined;
      if (value === undefined || value === null)
        throw mcpUnhealthy(
          `MCP server ${id} cannot send header ${name}: the signed-in identity has no ${identityClaim} claim`,
        );
      if (!usableHeaderValue(value))
        throw mcpUnhealthy(
          `MCP server ${id} cannot send header ${name}: the ${identityClaim} claim is not a usable header value (a non-empty string of printable ASCII, at most ${MAX_IDENTITY_HEADER_LENGTH} characters, without leading or trailing spaces)`,
        );
      headers.set(name, value);
    }
  }

  async #fetch(init: RequestInit): Promise<Response> {
    let response: Response;
    try {
      response = await this.#options.fetch(this.#url, {
        ...init,
        redirect: "manual",
      });
    } catch (error) {
      if (isAbortError(error)) throw error;
      const message = redact((error as Error)?.message ?? String(error));
      throw mcpUnhealthy(
        `MCP server ${this.#options.serverId} request failed: ${truncate(message)}`,
        { retryable: true },
      );
    }
    if (
      (response.status >= 300 && response.status < 400) ||
      response.type === "opaqueredirect"
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw mcpUnhealthy(
        `MCP server ${this.#options.serverId} redirected; redirects are not followed`,
      );
    }
    return response;
  }

  #captureSession(response: Response, message: JsonRpcMessage): void {
    const value = response.headers.get("mcp-session-id");
    if (value === null) return;
    if (!SESSION_ID.test(value))
      throw mcpUnhealthy(
        `MCP server ${this.#options.serverId} sent an invalid session id`,
      );
    // The session is established by the initialize response only.
    if ("method" in message && message.method === "initialize")
      this.#sessionId = value;
  }

  #statusError(status: number): Error {
    const id = this.#options.serverId;
    if (status === 401 || status === 403)
      return mcpUnhealthy(
        `MCP server ${id} rejected the request authorization (HTTP ${status})`,
        { detail: { status } },
      );
    if (status === 404 && this.#sessionId)
      return mcpUnhealthy(`MCP server ${id} session expired (HTTP 404)`, {
        detail: { status },
      });
    return mcpUnhealthy(`MCP server ${id} returned HTTP ${status}`, {
      retryable: status >= 500 || status === 429,
      detail: { status },
    });
  }

  async #readEventStream(
    response: Response,
    expected: JsonRpcId,
  ): Promise<void> {
    const body = response.body;
    if (!body)
      throw mcpUnhealthy(
        `MCP server ${this.#options.serverId} sent an empty event stream`,
      );
    const reader = body.pipeThrough(new TextDecoderStream()).getReader();
    const parser = new SseParser(this.#maxMessage);
    let total = 0;
    let answered = false;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > this.#maxResponse)
          throw mcpUnhealthy(
            `MCP event stream exceeds the ${this.#maxResponse}-byte limit`,
          );
        for (const data of parser.push(value)) {
          const message = parseFrame(data, this.#maxMessage);
          if (answers(message, expected)) answered = true;
          this.onMessage?.(message);
        }
        if (answered) break;
      }
      if (!answered)
        throw mcpUnhealthy(
          `MCP server ${this.#options.serverId} ended the event stream before responding`,
          { retryable: true },
        );
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }
}

/**
 * A claim value that can be sent as a header as it is: printable ASCII
 * (no CR, LF, or other control characters), not padded, at most 256.
 */
function usableHeaderValue(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_IDENTITY_HEADER_LENGTH &&
    /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/.test(value)
  );
}

function answers(message: unknown, id: JsonRpcId): boolean {
  const items = Array.isArray(message) ? message : [message];
  return items.some(
    (item) =>
      typeof item === "object" &&
      item !== null &&
      !("method" in item) &&
      (item as { id?: unknown }).id === id,
  );
}

/** Incremental `text/event-stream` parser yielding each event's data. */
export class SseParser {
  readonly #maxBytes: number;
  #buffer = "";
  #data: string[] = [];
  #event = "";

  constructor(maxBytes: number) {
    this.#maxBytes = maxBytes;
  }

  push(chunk: string): string[] {
    this.#buffer += chunk;
    const events: string[] = [];
    let match = /\r\n|\r|\n/.exec(this.#buffer);
    while (match) {
      // A lone trailing CR may be the first half of CRLF; wait for more.
      if (match[0] === "\r" && match.index === this.#buffer.length - 1) break;
      const line = this.#buffer.slice(0, match.index);
      this.#buffer = this.#buffer.slice(match.index + match[0].length);
      const data = this.#line(line);
      if (data !== undefined) events.push(data);
      match = /\r\n|\r|\n/.exec(this.#buffer);
    }
    if (this.#buffer.length > this.#maxBytes)
      throw mcpUnhealthy(`MCP event exceeds the ${this.#maxBytes}-byte limit`);
    return events;
  }

  #line(line: string): string | undefined {
    if (line === "") return this.#dispatch();
    if (line.startsWith(":")) return undefined;
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      this.#data.push(value);
      if (this.#data.join("\n").length > this.#maxBytes)
        throw mcpUnhealthy(
          `MCP event exceeds the ${this.#maxBytes}-byte limit`,
        );
    } else if (field === "event") this.#event = value;
    // `id` and `retry` are accepted and ignored: resumption is not implemented.
    return undefined;
  }

  #dispatch(): string | undefined {
    const data = this.#data.join("\n");
    const event = this.#event;
    this.#data = [];
    this.#event = "";
    if (data.length === 0) return undefined;
    if (event !== "" && event !== "message") return undefined;
    return data;
  }
}

async function readBounded(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const body = response.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes)
        throw mcpUnhealthy(`MCP response exceeds the ${maxBytes}-byte limit`);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).toString("utf8");
}
