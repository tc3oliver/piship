import { describe, expect, it } from "vitest";
import { replyText } from "./session.js";

describe("replyText", () => {
  it("reads the text of the last assistant message", () => {
    expect(
      replyText({
        role: "assistant",
        content: [
          { type: "text", text: "Hello" },
          { type: "toolCall", id: "x" },
          { type: "text", text: " world" },
        ],
      }),
    ).toBe("Hello world");
  });
  it("is empty for a failed reply instead of an earlier answer", () => {
    // Pi 1.6.0's getLastAssistantText() would return the previous reply here.
    expect(replyText({ role: "assistant", content: [] })).toBe("");
  });
  it("is empty when the last message is not the assistant's", () => {
    expect(
      replyText({ role: "toolResult", content: [{ type: "text", text: "x" }] }),
    ).toBe("");
    expect(replyText(undefined)).toBe("");
  });
});
