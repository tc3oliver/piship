import { describe, expect, it } from "vitest";
import * as upstreamPi from "@earendil-works/pi-coding-agent";

describe("Pi public SDK", () => {
  it("imports createAgentSession from the public package entrypoint", () => {
    expect(typeof upstreamPi.createAgentSession).toBe("function");
  });
});
