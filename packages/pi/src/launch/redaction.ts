import type { InlineExtension } from "@earendil-works/pi-coding-agent";
import { redact } from "@piship/contracts";
import { installCrashRedaction } from "./crash-redaction.js";

/**
 * The assistant message with its provider error text redacted, or undefined
 * when there is nothing to redact. Pi records a failed request's error text
 * (`errorMessage`) in the session file, and a gateway that echoes the request's
 * Authorization header into its error body would otherwise leave the runtime
 * credential there. `redact` removes every registered secret value and the
 * common token shapes, so the status code and wording that retry and
 * credential-rejection classification read stay.
 */
export function redactProviderError(message: unknown): unknown {
  const value = message as
    | { role?: string; errorMessage?: unknown }
    | null
    | undefined;
  if (value?.role !== "assistant" || typeof value.errorMessage !== "string")
    return undefined;
  const errorMessage = redact(value.errorMessage);
  return errorMessage === value.errorMessage
    ? undefined
    : { ...value, errorMessage };
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
      const message = redactProviderError(event.message);
      return message ? { message: message as typeof event.message } : undefined;
    });
  },
};
