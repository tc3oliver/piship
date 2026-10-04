import type { ActivatedAccess } from "@piship/core";
import type { CatalogModel } from "@piship/schema";
import { describe, expect, it } from "vitest";
import { toPiModels } from "./model-runtime.js";

const definition = (id: string) => ({
  id,
  name: id,
  provider: "acmecode",
  capabilities: {
    input: ["text"],
    contextWindow: 32000,
    maxOutputTokens: 2048,
  },
  policyTags: [],
  availability: { available: true },
});
const entry = (
  id: string,
  extra: Partial<CatalogModel> = {},
): CatalogModel => ({
  id,
  name: id,
  contextWindow: 32000,
  maxOutputTokens: 2048,
  input: ["text"],
  reasoning: false,
  tools: false,
  streaming: true,
  policyTags: [],
  type: "chat",
  ...extra,
});

describe("managed Pi models", () => {
  it("registers physical models with their type and API, and leaves virtual ones to their router", () => {
    const activated = {
      runtime: {
        models: ["acme/coder", "acme/auto", "acme/classify", "acme/image"].map(
          definition,
        ),
      },
    } as unknown as ActivatedAccess;
    const models = toPiModels(activated, [
      entry("acme/coder"),
      entry("acme/auto", {
        virtual: { router: "./extensions/router.ts", routes: ["acme/coder"] },
      }),
      entry("acme/classify", { type: "classifier", api: "llama-cpp-classify" }),
      entry("acme/image", {
        type: "image",
        api: "openrouter-images",
        output: ["image"],
      }),
    ]);
    expect(models.map((model) => model.id)).toEqual([
      "acme/coder",
      "acme/classify",
      "acme/image",
    ]);
    expect(models[0]).toMatchObject({ contextWindow: 32000, maxTokens: 2048 });
    expect(models[0]).not.toHaveProperty("type");
    expect(models[1]).toMatchObject({
      type: "classifier",
      api: "llama-cpp-classify",
      contextWindow: 32000,
    });
    expect(models[2]).toMatchObject({
      type: "image",
      api: "openrouter-images",
      output: ["image"],
    });
    // Without catalog metadata (a v1alpha5 lock), every model is chat.
    expect(toPiModels(activated).map((model) => model.type)).toEqual([
      undefined,
      undefined,
      undefined,
      undefined,
    ]);
  });
});
