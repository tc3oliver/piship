import type { ModelDefinition } from "@piship/contracts";
import type { CapabilityConfig } from "@piship/schema";
import { describe, expect, it } from "vitest";
import {
  incompatibleCapabilities,
  modelRequirementGaps,
} from "./model-requirements.js";

describe("capability model requirements", () => {
  const capability = (
    requirements: CapabilityConfig["requirements"],
    enabled = true,
  ): CapabilityConfig => ({
    name: "workflow",
    enabled,
    settings: {},
    ...(requirements ? { requirements } : {}),
  });
  const model = (capabilities: ModelDefinition["capabilities"]) =>
    ({
      id: "m",
      name: "M",
      provider: "p",
      capabilities,
      policyTags: [],
      availability: { available: true },
    }) satisfies ModelDefinition;

  it("treats unknown metadata as not meeting a requirement", () => {
    expect(
      modelRequirementGaps(model({}), {
        tools: true,
        structuredOutput: true,
        minContextWindow: 1000,
        input: ["image"],
      }),
    ).toEqual([
      "tool calling support is unknown",
      "structured output support is unknown",
      "the context window is unknown",
      "the accepted input types are unknown",
    ]);
    expect(
      modelRequirementGaps(
        model({
          tools: false,
          structuredOutput: false,
          contextWindow: 500,
          input: ["text"],
        }),
        {
          tools: true,
          structuredOutput: true,
          minContextWindow: 1000,
          input: ["text", "image"],
        },
      ),
    ).toEqual([
      "tool calling is not supported",
      "structured output is not supported",
      "the context window 500 is below the required 1000",
      "image input is not accepted",
    ]);
    expect(
      modelRequirementGaps(
        model({
          tools: true,
          structuredOutput: true,
          contextWindow: 2000,
          input: ["text", "image"],
        }),
        {
          tools: true,
          structuredOutput: true,
          minContextWindow: 1000,
          input: ["image"],
        },
      ),
    ).toEqual([]);
    expect(modelRequirementGaps(undefined, { tools: true })).toEqual([
      "tool calling support is unknown",
    ]);
    // Disabled capabilities and capabilities without requirements never block.
    expect(
      incompatibleCapabilities(model({}), [
        capability({ tools: true }, false),
        capability(undefined),
      ]),
    ).toEqual([]);
  });
});
