import type { InlineExtension } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { providerErrorRedaction, REDACTION_FAILED_TEXT } from "./redaction.js";

// Redaction itself fails: Pi would report the throwing handler and persist
// the original message, so the handler must replace the provider text whole.
vi.mock("@piship/contracts", async (original) => ({
  ...(await original<typeof import("@piship/contracts")>()),
  redact: () => {
    throw new Error("redaction failed");
  },
}));

/** The factory of an inline extension, in either of its public shapes. */
const factoryOf = (extension: InlineExtension) =>
  typeof extension === "function" ? extension : extension.factory;

function messageEnd() {
  const handlers = new Map<string, (event: unknown) => unknown>();
  const pi = {
    on: (name: string, handler: (event: unknown) => unknown) =>
      handlers.set(name, handler),
  };
  (factoryOf(providerErrorRedaction) as (api: unknown) => void)(pi);
  const handler = handlers.get("message_end");
  if (!handler) throw new Error("no message_end handler");
  return handler;
}

describe("the provider error redaction when redaction fails", () => {
  it("replaces the error text and drops the diagnostics instead of keeping them", () => {
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "assistant",
        stopReason: "error",
        errorMessage: `500 echoed ${secret}`,
        diagnostics: [{ error: { message: secret } }],
        content: [],
      },
    }) as { message: Record<string, unknown> };
    expect(result.message).toEqual({
      role: "assistant",
      stopReason: "error",
      errorMessage: REDACTION_FAILED_TEXT,
      diagnostics: [],
      content: [],
    });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("drops nested call arguments and replaces their error text instead of keeping them", () => {
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "toolResult",
        toolName: "codemode",
        content: [],
        isError: false,
        nestedCalls: {
          complete: true,
          calls: [
            {
              id: "call_1/1",
              name: "bash",
              arguments: { command: `echo ${secret}` },
              status: "error",
              error: `failed: ${secret}`,
            },
          ],
        },
        details: {
          calls: [
            {
              id: "call_1/1",
              name: "bash",
              args: `{"command":"echo ${secret}"}`,
              status: "error",
              error: `failed: ${secret}`,
            },
          ],
        },
      },
    }) as { message: Record<string, unknown> };
    expect(result.message.nestedCalls).toEqual({
      complete: false,
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          argumentsBytes: 0,
          status: "error",
          error: REDACTION_FAILED_TEXT,
        },
      ],
    });
    expect(result.message.details).toEqual({
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          args: "",
          status: "error",
          error: REDACTION_FAILED_TEXT,
        },
      ],
    });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("leaves messages of other roles alone", () => {
    expect(
      messageEnd()({ type: "message_end", message: { role: "user" } }),
    ).toBeUndefined();
  });
});
