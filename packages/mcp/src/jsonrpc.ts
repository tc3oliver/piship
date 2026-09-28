// Minimal JSON-RPC 2.0 client: request correlation, per-request timeouts,
// cancellation through `notifications/cancelled`, strict message validation,
// and error mapping to PiShipError.

import { PiShipError, redact } from "@piship/contracts";
import type {
  JsonRpcErrorObject,
  JsonRpcId,
  JsonRpcMessage,
  JsonRpcNotification,
  JsonRpcRequest,
  McpTransport,
} from "./types.js";

export const DEFAULT_MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
const MAX_ERROR_TEXT = 300;

export function mcpUnhealthy(
  message: string,
  options: { retryable?: boolean; detail?: Record<string, unknown> } = {},
): PiShipError {
  return new PiShipError("MCP_UNHEALTHY", message, {
    component: "mcp",
    retryable: options.retryable ?? false,
    ...(options.detail ? { sanitizedDetail: options.detail } : {}),
  });
}

export function mcpDenied(message: string, reason?: string): PiShipError {
  return new PiShipError("MCP_DENIED", message, {
    component: "mcp",
    retryable: false,
    ...(reason ? { sanitizedDetail: { reason: truncate(reason) } } : {}),
  });
}

export function truncate(text: string, max = MAX_ERROR_TEXT): string {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

/** The error an aborted operation rejects with. */
export function abortError(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  if (reason instanceof Error) return reason;
  return new DOMException("The operation was aborted", "AbortError");
}

export function isAbortError(error: unknown): boolean {
  return (error as { name?: unknown } | null)?.name === "AbortError";
}

// ------------------------------------------------------------ validation

export type IncomingMessage =
  | { readonly kind: "request"; readonly message: JsonRpcRequest }
  | { readonly kind: "notification"; readonly message: JsonRpcNotification }
  | {
      readonly kind: "result";
      readonly id: JsonRpcId;
      readonly result: Record<string, unknown>;
    }
  | {
      readonly kind: "error";
      readonly id: JsonRpcId | null;
      readonly error: JsonRpcErrorObject;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isId(value: unknown): value is JsonRpcId {
  return (
    (typeof value === "string" && value.length > 0 && value.length <= 256) ||
    (typeof value === "number" && Number.isSafeInteger(value))
  );
}

/** Validate one incoming JSON-RPC 2.0 message. Throws MCP_UNHEALTHY. */
export function parseIncoming(value: unknown): IncomingMessage {
  if (!isRecord(value) || value.jsonrpc !== "2.0")
    throw mcpUnhealthy("MCP peer sent a message that is not JSON-RPC 2.0");
  if ("method" in value) {
    if (typeof value.method !== "string" || value.method.length === 0)
      throw mcpUnhealthy("MCP peer sent a message with an invalid method");
    if (value.params !== undefined && !isRecord(value.params))
      throw mcpUnhealthy("MCP peer sent a message with invalid params");
    const params = value.params as Record<string, unknown> | undefined;
    if ("id" in value) {
      if (!isId(value.id))
        throw mcpUnhealthy("MCP peer sent a request with an invalid id");
      return {
        kind: "request",
        message: {
          jsonrpc: "2.0",
          id: value.id,
          method: value.method,
          ...(params ? { params } : {}),
        },
      };
    }
    return {
      kind: "notification",
      message: {
        jsonrpc: "2.0",
        method: value.method,
        ...(params ? { params } : {}),
      },
    };
  }
  const hasResult = "result" in value;
  const hasError = "error" in value;
  if (hasResult === hasError)
    throw mcpUnhealthy(
      "MCP peer sent a response without exactly one of result or error",
    );
  if (hasResult) {
    if (!isId(value.id))
      throw mcpUnhealthy("MCP peer sent a response with an invalid id");
    if (!isRecord(value.result))
      throw mcpUnhealthy("MCP peer sent a result that is not an object");
    return { kind: "result", id: value.id, result: value.result };
  }
  if (value.id !== null && !isId(value.id))
    throw mcpUnhealthy("MCP peer sent an error with an invalid id");
  const error = value.error;
  if (
    !isRecord(error) ||
    !Number.isInteger(error.code) ||
    typeof error.message !== "string"
  )
    throw mcpUnhealthy("MCP peer sent a malformed error object");
  return {
    kind: "error",
    id: value.id as JsonRpcId | null,
    error: {
      code: error.code as number,
      message: error.message,
      ...(error.data === undefined ? {} : { data: error.data }),
    },
  };
}

/** Parse a JSON text frame after checking its size. */
export function parseFrame(text: string, maxBytes: number): unknown {
  if (Buffer.byteLength(text, "utf8") > maxBytes)
    throw mcpUnhealthy(`MCP message exceeds the ${maxBytes}-byte limit`);
  try {
    return JSON.parse(text);
  } catch {
    throw mcpUnhealthy("MCP peer sent invalid JSON");
  }
}

// ---------------------------------------------------------------- client

export interface RequestOptions {
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  /** `initialize` must not be cancelled; everything else sends a cancel. */
  readonly cancellable?: boolean;
}

interface Pending {
  readonly method: string;
  resolve(result: Record<string, unknown>): void;
  reject(error: Error): void;
}

export class JsonRpcClient {
  readonly #transport: McpTransport;
  readonly #label: string;
  readonly #pending = new Map<JsonRpcId, Pending>();
  #nextId = 1;
  #closed: Error | undefined;
  /** Called once when the connection fails or closes. */
  onClosed: ((error: Error) => void) | undefined;

  constructor(transport: McpTransport, label: string) {
    this.#transport = transport;
    this.#label = label;
    transport.onMessage = (value) => this.#receive(value);
    transport.onClose = (error) =>
      this.#fail(
        error ?? mcpUnhealthy(`MCP server ${label} closed the connection`),
      );
  }

  get closed(): Error | undefined {
    return this.#closed;
  }

  async request(
    method: string,
    params: Record<string, unknown> | undefined,
    options: RequestOptions,
  ): Promise<Record<string, unknown>> {
    if (this.#closed) throw this.#closed;
    const { signal } = options;
    if (signal?.aborted) throw abortError(signal);
    const id = this.#nextId++;
    const message: JsonRpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params ? { params } : {}),
    };
    const sending = new AbortController();
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      let settled = false;
      const finish = (): boolean => {
        if (settled) return false;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        this.#pending.delete(id);
        return true;
      };
      const abandon = (reason: string, error: Error) => {
        if (!finish()) return;
        if (options.cancellable !== false && !this.#closed)
          this.notify("notifications/cancelled", {
            requestId: id,
            reason,
          }).catch(() => undefined);
        sending.abort();
        reject(error);
      };
      const onAbort = () =>
        abandon("cancelled", abortError(signal as AbortSignal));
      const timer = setTimeout(
        () =>
          abandon(
            "timeout",
            mcpUnhealthy(
              `MCP server ${this.#label} did not answer ${method} within ${options.timeoutMs} ms`,
              {
                retryable: true,
                detail: { method, timeoutMs: options.timeoutMs },
              },
            ),
          ),
        options.timeoutMs,
      );
      signal?.addEventListener("abort", onAbort, { once: true });
      this.#pending.set(id, {
        method,
        resolve: (result) => {
          if (finish()) resolve(result);
        },
        reject: (error) => {
          if (finish()) reject(error);
        },
      });
      this.#transport.send(message, sending.signal).catch((error: unknown) => {
        if (settled) return;
        finish();
        reject(this.#mapSendError(error, method));
      });
    });
  }

  /** Send a notification; bounded by `timeoutMs` so a stalled peer cannot hang. */
  async notify(
    method: string,
    params?: Record<string, unknown>,
    timeoutMs = 10_000,
  ): Promise<void> {
    if (this.#closed) throw this.#closed;
    try {
      await this.#transport.send(
        { jsonrpc: "2.0", method, ...(params ? { params } : {}) },
        AbortSignal.timeout(timeoutMs),
      );
    } catch (error) {
      throw this.#mapSendError(error, method);
    }
  }

  /** Reject every pending request and stop accepting new ones. */
  close(error?: Error): void {
    this.#fail(
      error ?? mcpUnhealthy(`MCP server ${this.#label} connection closed`),
    );
  }

  #mapSendError(error: unknown, method: string): Error {
    if (error instanceof PiShipError) return error;
    if ((error as { name?: unknown } | null)?.name === "TimeoutError")
      return mcpUnhealthy(
        `MCP server ${this.#label} did not accept ${method} in time`,
        { retryable: true },
      );
    if (isAbortError(error)) return error as Error;
    return mcpUnhealthy(
      `MCP server ${this.#label} transport failed during ${method}: ${truncate(redact((error as Error)?.message ?? String(error)))}`,
      { retryable: true },
    );
  }

  #fail(error: Error): void {
    if (this.#closed) return;
    this.#closed = error;
    this.onClosed?.(error);
    for (const pending of [...this.#pending.values()]) pending.reject(error);
    this.#pending.clear();
  }

  #receive(value: unknown): void {
    if (this.#closed) return;
    const messages = Array.isArray(value) ? value : [value];
    if (messages.length === 0) {
      this.#protocolFailure(mcpUnhealthy("MCP peer sent an empty batch"));
      return;
    }
    for (const item of messages) {
      let incoming: IncomingMessage;
      try {
        incoming = parseIncoming(item);
      } catch (error) {
        this.#protocolFailure(error as Error);
        return;
      }
      this.#dispatch(incoming);
    }
  }

  #protocolFailure(error: Error): void {
    const wrapped = mcpUnhealthy(
      `MCP server ${this.#label} violated the protocol: ${error.message}`,
    );
    this.#fail(wrapped);
    this.#transport.close().catch(() => undefined);
  }

  #dispatch(incoming: IncomingMessage): void {
    switch (incoming.kind) {
      case "result": {
        this.#pending.get(incoming.id)?.resolve(incoming.result);
        return;
      }
      case "error": {
        if (incoming.id === null) {
          this.#protocolFailure(
            mcpUnhealthy(
              `peer reported error ${incoming.error.code} without a request id`,
            ),
          );
          return;
        }
        const pending = this.#pending.get(incoming.id);
        pending?.reject(
          mcpUnhealthy(
            `MCP server ${this.#label} rejected ${pending.method}: ${truncate(redact(incoming.error.message))}`,
            {
              detail: { method: pending.method, rpcCode: incoming.error.code },
            },
          ),
        );
        return;
      }
      case "request": {
        // The client declares no capabilities; it answers ping and refuses
        // sampling, roots, elicitation, and anything else.
        const { id, method } = incoming.message;
        const reply =
          method === "ping"
            ? { jsonrpc: "2.0" as const, id, result: {} }
            : {
                jsonrpc: "2.0" as const,
                id,
                error: { code: -32601, message: "Method not found" },
              };
        this.#transport.send(reply).catch(() => undefined);
        return;
      }
      case "notification":
        // Progress, logging, and list-changed notifications are ignored.
        return;
    }
  }
}

export type { JsonRpcMessage };
