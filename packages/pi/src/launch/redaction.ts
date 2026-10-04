import type {
  InlineExtension,
  MessageEndEvent,
} from "@earendil-works/pi-coding-agent";
import { redact, redactValue } from "@piship/contracts";
import { installCrashRedaction } from "./crash-redaction.js";

type AssistantMessage = Extract<
  MessageEndEvent["message"],
  { role: "assistant" }
>;

/**
 * Every field of Pi's assistant message, by what it holds: provider error
 * text PiShip redacts, the model's own output, or metadata PiShip or Pi set.
 * A Pi upgrade that adds or removes a field fails to compile here until the
 * field is classified, so new provider text cannot reach the session file
 * unnoticed.
 */
export const ASSISTANT_MESSAGE_FIELDS: Record<
  keyof AssistantMessage,
  "redacted" | "model-output" | "metadata"
> = {
  role: "metadata",
  content: "model-output",
  api: "metadata",
  provider: "metadata",
  model: "metadata",
  responseModel: "metadata",
  responseId: "metadata",
  providerThinkingLevel: "metadata",
  thinkingLevel: "metadata",
  diagnostics: "redacted",
  usage: "metadata",
  stopReason: "metadata",
  deferred: "metadata",
  errorMessage: "redacted",
  rawStopReason: "metadata",
  endTurn: "metadata",
  timestamp: "metadata",
};

/**
 * The assistant message with its provider error text redacted, or undefined
 * when there is nothing to redact. Pi records a failed request's error text
 * (`errorMessage`) and the provider's diagnostics (`diagnostics`, each an
 * error message, stack, and details) in the session file, and a gateway that
 * echoes the request's Authorization header into its error body would
 * otherwise leave the runtime credential there. `redact` removes every
 * registered secret value and the common token shapes, so the status code and
 * wording that retry and credential-rejection classification read stay.
 */
export function redactProviderError(message: unknown): unknown {
  const value = message as
    | { role?: string; errorMessage?: unknown; diagnostics?: unknown }
    | null
    | undefined;
  if (value?.role !== "assistant") return undefined;
  const changes: Record<string, unknown> = {};
  if (typeof value.errorMessage === "string") {
    const errorMessage = redact(value.errorMessage);
    if (errorMessage !== value.errorMessage)
      changes.errorMessage = errorMessage;
  }
  if (value.diagnostics !== undefined) {
    const diagnostics = redactValue(value.diagnostics);
    if (JSON.stringify(diagnostics) !== JSON.stringify(value.diagnostics))
      changes.diagnostics = diagnostics;
  }
  return Object.keys(changes).length ? { ...value, ...changes } : undefined;
}

type ToolResultMessage = Extract<
  MessageEndEvent["message"],
  { role: "toolResult" }
>;

/**
 * Every field of Pi's tool result message, by what it holds. The calls a
 * tool made to other tools (`nestedCalls`, attached by Pi; a Codemode
 * result's `details.calls`) hold their arguments and error text, which
 * PiShip redacts; the result content itself is tool output. A Pi upgrade
 * that adds or removes a field fails to compile here until it is classified.
 */
export const TOOL_RESULT_MESSAGE_FIELDS: Record<
  keyof ToolResultMessage,
  "redacted" | "tool-output" | "metadata"
> = {
  role: "metadata",
  toolCallId: "metadata",
  toolName: "metadata",
  content: "tool-output",
  details: "redacted",
  usage: "metadata",
  nestedCalls: "redacted",
  isError: "metadata",
  timestamp: "metadata",
};

type NestedCall = {
  id?: unknown;
  arguments?: unknown;
  argumentsBytes?: number;
  error?: unknown;
};
type CodemodeCall = { id?: unknown; args?: unknown; error?: unknown };

const changed = (before: unknown, after: unknown) =>
  JSON.stringify(before) !== JSON.stringify(after);

/** Codemode's argument preview: JSON cut to 200 characters, ending `...`. */
const ARGS_PREVIEW_CHARS = 200;
/** Codemode's error preview length. */
const ERROR_PREVIEW_CHARS = 500;

function preview(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

/**
 * A Codemode preview redacted. A cut can leave only the start of a secret,
 * which `redact` no longer recognizes, so a cut preview also loses its last
 * unbroken token.
 */
function redactPreview(text: string, max: number): string {
  const redacted = redact(text);
  if (text.length !== max || !text.endsWith("...")) return redacted;
  return redacted.replace(/[^\s"'`,:;=()[\]{}<>]*\.\.\.$/, "...");
}

/**
 * The tool result with the nested calls' arguments and error text redacted,
 * or undefined when there is nothing to redact: Pi's `nestedCalls` record,
 * and the `details.calls` a Codemode result keeps (a 200-character argument
 * preview and the error). Both are persisted with the message and shown in
 * the HTML export.
 */
export function redactToolResult(message: unknown): unknown {
  const value = message as
    | {
        role?: string;
        toolName?: string;
        nestedCalls?: { calls?: NestedCall[] };
        details?: { calls?: CodemodeCall[] };
      }
    | null
    | undefined;
  if (value?.role !== "toolResult") return undefined;
  const changes: Record<string, unknown> = {};
  const nested = value.nestedCalls;
  if (Array.isArray(nested?.calls)) {
    const calls = nested.calls.map((call) => ({
      ...call,
      ...(call.arguments === undefined
        ? {}
        : { arguments: redactValue(call.arguments) }),
      ...(typeof call.error === "string" ? { error: redact(call.error) } : {}),
    }));
    if (changed(nested.calls, calls))
      changes.nestedCalls = { ...nested, calls };
  }
  const details = value.details;
  if (value.toolName === "codemode" && Array.isArray(details?.calls)) {
    // The preview is rebuilt from the full arguments Pi recorded for the
    // same call, redacted before the cut.
    const full = new Map<unknown, unknown>();
    for (const call of Array.isArray(nested?.calls) ? nested.calls : [])
      if (call.arguments !== undefined) full.set(call.id, call.arguments);
    const args = (call: CodemodeCall): string => {
      const source = full.get(call.id);
      if (source !== undefined)
        return preview(
          JSON.stringify(redactValue(source)) ?? "",
          ARGS_PREVIEW_CHARS,
        );
      return redactPreview(call.args as string, ARGS_PREVIEW_CHARS);
    };
    const calls = details.calls.map((call) => ({
      ...call,
      ...(typeof call.args === "string" ? { args: args(call) } : {}),
      ...(typeof call.error === "string"
        ? { error: redactPreview(call.error, ERROR_PREVIEW_CHARS) }
        : {}),
    }));
    if (changed(details.calls, calls)) changes.details = { ...details, calls };
  }
  return Object.keys(changes).length ? { ...value, ...changes } : undefined;
}

/**
 * `redactToolResult` that fails closed: the nested calls' arguments are
 * dropped (Pi's own `argumentsBytes` form), their error text replaced by a
 * fixed marker, and the Codemode argument previews blanked.
 */
export function redactToolResultOrDrop(message: unknown): unknown {
  try {
    return redactToolResult(message);
  } catch {
    const value = message as {
      role?: string;
      nestedCalls?: { calls?: NestedCall[] };
      details?: { calls?: CodemodeCall[] };
    };
    if (value?.role !== "toolResult") return undefined;
    const scrub = <T extends { error?: unknown }>(call: T) =>
      call.error === undefined
        ? call
        : { ...call, error: REDACTION_FAILED_TEXT };
    const nested = value.nestedCalls;
    const details = value.details;
    return {
      ...value,
      ...(Array.isArray(nested?.calls)
        ? {
            nestedCalls: {
              ...nested,
              complete: false,
              calls: nested.calls.map(({ arguments: _dropped, ...call }) =>
                scrub({ ...call, argumentsBytes: call.argumentsBytes ?? 0 }),
              ),
            },
          }
        : {}),
      ...(Array.isArray(details?.calls)
        ? {
            details: {
              ...details,
              calls: details.calls.map((call) => scrub({ ...call, args: "" })),
            },
          }
        : {}),
    };
  }
}

/**
 * Redacts provider error text, and the nested tool calls a tool result
 * records, before Pi persists the message. Pi runs the
 * handlers of extensions loaded from paths before inline ones, in order, and
 * persists the message the last replacement produced, so this extension goes
 * last: whatever an earlier handler returned is redacted too. At
 * `session_start` it also puts the crash redaction in front of Pi's crash
 * handler (see crash-redaction.ts).
 */
export const providerErrorRedaction: InlineExtension = {
  name: "piship-redaction",
  factory: (pi) => {
    pi.on("session_start", () => installCrashRedaction());
    pi.on("message_end", (event) => {
      const message =
        redactProviderErrorOrDrop(event.message) ??
        redactToolResultOrDrop(event.message);
      return message ? { message: message as typeof event.message } : undefined;
    });
  },
};

export const REDACTION_FAILED_TEXT = "[REDACTED error text]";

/**
 * `redactProviderError` that fails closed. Pi reports a handler that throws
 * and persists the original message, so when redaction itself fails the
 * provider text is replaced whole: the error text by a fixed marker, and the
 * diagnostics by none.
 */
export function redactProviderErrorOrDrop(message: unknown): unknown {
  try {
    return redactProviderError(message);
  } catch {
    const value = message as {
      role?: string;
      errorMessage?: unknown;
      diagnostics?: unknown;
    };
    if (value?.role !== "assistant") return undefined;
    return {
      ...value,
      ...(value.errorMessage === undefined
        ? {}
        : { errorMessage: REDACTION_FAILED_TEXT }),
      ...(value.diagnostics === undefined ? {} : { diagnostics: [] }),
    };
  }
}
