import { describe, expect, it } from "vitest";
import * as upstreamPi from "@earendil-works/pi-coding-agent";
import { PI_VERSION } from "@piship/core";
import { PINNED_PI_VERSION } from "./index.js";

describe("Pi public SDK", () => {
  it("imports createAgentSession from the public package entrypoint", () => {
    expect(typeof upstreamPi.createAgentSession).toBe("function");
    expect(upstreamPi.VERSION).toBe(PINNED_PI_VERSION);
    expect(PI_VERSION).toBe(PINNED_PI_VERSION);
  });
});
