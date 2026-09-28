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
  // Managed model governance narrows these public ModelRuntime methods on the
  // instance PiShip creates. If an upgrade renames or removes one, governance
  // could be bypassed, so the upgrade must fail here first.
  it("exposes every ModelRuntime method that managed governance narrows", () => {
    const prototype = upstreamPi.ModelRuntime.prototype as unknown as Record<
      string,
      unknown
    >;
    for (const method of [
      "getModel",
      "getModels",
      "getAvailable",
      "getAvailableSnapshot",
      "checkAuth",
      "getAuth",
      "stream",
      "streamSimple",
      "complete",
      "completeSimple",
      "login",
      "setRuntimeApiKey",
      "registerProvider",
    ])
      expect(typeof prototype[method], method).toBe("function");
    expect(typeof upstreamPi.DefaultResourceLoader).toBe("function");
  });
});
