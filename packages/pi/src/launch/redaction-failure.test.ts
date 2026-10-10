import type { InlineExtension } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { providerErrorRedaction, REDACTION_FAILED_TEXT } from "./redaction.js";

// Redaction itself fails: Pi would report the throwing handler and persist
// the original message, so the handler must replace the provider text whole.
// Both entry points throw — a string goes through `redact`, opaque JSON (a
// nested call record, a non-codemode tool's `details`) through `redactValue`.
vi.mock("@piship/contracts", async (original) => ({
  ...(await original<typeof import("@piship/contracts")>()),
  redact: () => {
    throw new Error("redaction failed");
  },
  redactValue: () => {
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
          // Pi's dropped-arguments form: the real byte length of the
          // arguments JSON, not a fabricated 0.
          argumentsBytes: `{"command":"echo ${secret}"}`.length,
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

  it("keeps the inert metadata a Codemode record carries at runtime", () => {
    // `cost` and `durationMs` are set by the codemode extension when the call
    // finishes (they are not in Pi's `CodemodeCall` type), and `snapshot()`
    // spreads them into `details.calls`, so they persist. They are numbers, so
    // the normal path keeps them; the fail-closed path must too, or the HTML
    // export would lose the cost it prints. An unclassified field is still
    // dropped.
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "toolResult",
        toolName: "codemode",
        content: [],
        isError: false,
        details: {
          calls: [
            {
              id: "call_1/1",
              name: "bash",
              args: "{}",
              status: "ok",
              durationMs: 12,
              cost: 0.003,
              futureCostField: "whatever a later Pi adds",
            },
          ],
        },
      },
    }) as { message: Record<string, unknown> };
    expect(result.message.details).toEqual({
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          args: "",
          status: "ok",
          durationMs: 12,
          cost: 0.003,
        },
      ],
    });
  });

  it("drops another tool's details whole instead of letting the spread carry a secret", () => {
    // A non-codemode tool whose `details` are arbitrary JSON carrying a secret.
    // The success path redacts them; on failure the spread must not carry the
    // original `details` back, so they are dropped entirely.
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "toolResult",
        toolName: "company_batch",
        content: [],
        isError: false,
        details: {
          request: { headers: { Authorization: `Bearer ${secret}` } },
          fullOutputPath: "/tmp/out.txt",
        },
      },
    }) as { message: Record<string, unknown> };
    expect(result.message.details).toBeUndefined();
    expect("details" in result.message).toBe(false);
    expect(JSON.stringify(result)).not.toContain(secret);
    // Non-secret metadata that is not in `details` survives.
    expect(result.message.toolName).toBe("company_batch");
  });

  it("drops message and record fields no classification knows instead of letting a spread carry them", () => {
    // This path cannot scrub what it does not know, so the same reasoning that
    // drops a non-codemode `details` whole applies to every field outside the
    // classification tables: an unknown top-level field, an unknown field on a
    // nested call record, and an unknown field on a Codemode call record are
    // dropped, while the structural fields the record needs survive.
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "toolResult",
        toolName: "codemode",
        content: [],
        isError: false,
        futureMessageField: `Bearer ${secret}`,
        nestedCalls: {
          complete: true,
          futureRecordWrapperField: secret,
          calls: [
            {
              id: "call_1/1",
              name: "bash",
              arguments: { command: "echo hi" },
              status: "ok",
              futureCallField: secret,
            },
          ],
        },
        details: {
          calls: [
            {
              id: "call_1/1",
              name: "bash",
              args: "{}",
              status: "ok",
              futureCallField: secret,
            },
          ],
        },
      },
    }) as { message: Record<string, unknown> };
    expect("futureMessageField" in result.message).toBe(false);
    expect(result.message.nestedCalls).toEqual({
      complete: false,
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          status: "ok",
          argumentsBytes: `{"command":"echo hi"}`.length,
        },
      ],
    });
    expect(result.message.details).toEqual({
      calls: [{ id: "call_1/1", name: "bash", args: "", status: "ok" }],
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    // Inert classified metadata survives.
    expect(result.message.toolName).toBe("codemode");
    expect(result.message.isError).toBe(false);
  });

  it("drops an assistant message field no classification knows", () => {
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "assistant",
        stopReason: "error",
        errorMessage: "500 upstream",
        content: [],
        futureProviderDump: { headers: { authorization: secret } },
      },
    }) as { message: Record<string, unknown> };
    expect("futureProviderDump" in result.message).toBe(false);
    expect(result.message.errorMessage).toBe(REDACTION_FAILED_TEXT);
    expect(result.message.stopReason).toBe("error");
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("drops a malformed nestedCalls record whole instead of carrying it", () => {
    // `nestedCalls` is classified "redacted", so the fail-closed output must
    // never be the original object: a shape this path does not recognize is
    // dropped, not spread through.
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "toolResult",
        toolName: "company_batch",
        content: [],
        isError: false,
        nestedCalls: { calls: secret, complete: true },
      },
    }) as { message: Record<string, unknown> };
    expect("nestedCalls" in result.message).toBe(false);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("drops a deferred handle's data whole instead of letting the spread carry a secret", () => {
    // `DeferredHandle.data` is arbitrary provider JSON. The success path
    // redacts it; on failure the spread must not carry the original back.
    const secret = "piship-fake-unredacted-credential-0123";
    const result = messageEnd()({
      type: "message_end",
      message: {
        role: "assistant",
        stopReason: "deferred",
        content: [],
        deferred: {
          provider: "acmecode",
          id: "batch_42/row_7",
          data: { headers: { authorization: secret } },
        },
      },
    }) as { message: Record<string, unknown> };
    expect("deferred" in result.message).toBe(false);
    expect(JSON.stringify(result)).not.toContain(secret);
    // Fields outside the untrusted handle survive.
    expect(result.message.stopReason).toBe("deferred");
  });

  it("leaves messages of other roles alone", () => {
    expect(
      messageEnd()({ type: "message_end", message: { role: "user" } }),
    ).toBeUndefined();
  });
});
