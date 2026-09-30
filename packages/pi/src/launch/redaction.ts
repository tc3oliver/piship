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

/**
 * Redacts provider error text before Pi persists the message. Pi runs the
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
      const message = redactProviderErrorOrDrop(event.message);
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
