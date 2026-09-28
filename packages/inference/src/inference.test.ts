import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  buildModelDefinitions,
  classifyGatewayStatus,
  OpenAICompatibleInferenceProvider,
  PiNativeInferenceProvider,
  resolveRequestedModel,
} from "./index.js";

const catalog = ["acme/coder", "acme/general", "acme/review"].map((id) => ({
  id,
  name: id.toUpperCase(),
  contextWindow: 64000,
  maxOutputTokens: 4096,
  input: ["text"],
  reasoning: false,
  tools: true,
  streaming: true,
  policyTags: [id.split("/")[1] ?? ""],
}));

describe("model catalog", () => {
  it("intersects distribution, entitlement, live catalog, and user narrowing without widening", () => {
    const models = buildModelDefinitions("acmecode", catalog, {
      allowed: ["acme/coder", "acme/general", "acme/review"],
      entitled: ["acme/coder", "acme/general", "other/unlisted"],
      live: ["acme/coder", "acme/general", "acme/review"],
      userAllowed: ["acme/coder"],
    });
    expect(models.map((model) => [model.id, model.availability])).toEqual([
      ["acme/coder", { available: true }],
      [
        "acme/general",
        { available: false, reason: "excluded by user preference" },
      ],
      [
        "acme/review",
        {
          available: false,
          reason: "not included in the runtime credential entitlement",
        },
      ],
    ]);
    expect(models[0]).toMatchObject({
      provider: "acmecode",
      policyTags: ["coder"],
      capabilities: { tools: true, contextWindow: 64000 },
    });
    expect(
      buildModelDefinitions("acmecode", catalog, {
        allowed: ["acme/coder"],
      }).map((model) => model.id),
    ).toEqual(["acme/coder"]);
  });
  it("rejects disallowed and unavailable models instead of substituting", () => {
    const models = buildModelDefinitions("acmecode", catalog, {
      allowed: ["acme/coder", "acme/review"],
      entitled: ["acme/coder"],
    });
    const ctx = { models, allowed: ["acme/coder"] };
    expect(resolveRequestedModel("acme/coder", ctx).model.id).toBe(
      "acme/coder",
    );
    expect(() => resolveRequestedModel("acme/general", ctx)).toThrow(
      "not allowed",
    );
    expect(() => resolveRequestedModel("acme/review", ctx)).toThrow(
      "unavailable",
    );
  });
  it("classifies gateway failures for retry decisions", () => {
    expect(classifyGatewayStatus(200)).toBeNull();
    expect(classifyGatewayStatus(401)).toMatchObject({
      code: "CREDENTIAL_REVOKED",
      retryable: false,
    });
    expect(classifyGatewayStatus(403)).toMatchObject({
      code: "MODEL_DENIED",
      retryable: false,
    });
    expect(classifyGatewayStatus(429, { "retry-after": "3" })).toMatchObject({
      code: "GATEWAY_RATE_LIMITED",
      retryable: true,
      retryAfterMs: 3000,
    });
    expect(classifyGatewayStatus(503)).toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
    });
    expect(classifyGatewayStatus(400)).toMatchObject({
      code: "GATEWAY_PROTOCOL_ERROR",
      retryable: false,
    });
  });
  it("limits Pi-native personal selection to the owner allowlist when present", async () => {
    const provider = new PiNativeInferenceProvider(["openai/gpt-4o"]);
    await expect(
      provider.resolveModel("anthropic/claude", { models: [], allowed: [] }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    expect(
      (
        await provider.resolveModel("openai/gpt-4o", {
          models: [],
          allowed: [],
        })
      ).model.provider,
    ).toBe("openai");
    expect(
      await provider.configureRuntime({
        providerId: "mypi",
        credential: null,
        models: [],
      }),
    ).toMatchObject({ kind: "pi-native" });
  });
});

describe("OpenAI-compatible endpoint", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  beforeEach(async () => {
    services = await startLocalServices({
      knobs: {
        acceptedKeys: ["sk-local-owner-key"],
        gatewayModels: ["acme/coder", "acme/general"],
      },
    });
  });
  afterEach(() => services.close());
  const provider = (secret: SecretValue | null) =>
    new OpenAICompatibleInferenceProvider({
      providerId: "acmecode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      catalog,
      allowed: ["acme/coder", "acme/general", "acme/review"],
      liveCatalog: true,
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
      secret: () => secret,
    });
  it("marks models the live gateway does not list as unavailable", async () => {
    const models = await provider(
      new SecretValue("sk-local-owner-key"),
    ).listModels(null, null);
    expect(
      models.map((model) => [model.id, model.availability.available]),
    ).toEqual([
      ["acme/coder", true],
      ["acme/general", true],
      ["acme/review", false],
    ]);
    const runtime = await provider(null).configureRuntime({
      providerId: "acmecode",
      credential: null,
      models,
    });
    expect(runtime).toMatchObject({
      kind: "managed-endpoint",
      requiresCredential: false,
      baseUrl: services.gatewayUrl,
    });
    expect(runtime.models.map((model) => model.id)).toEqual([
      "acme/coder",
      "acme/general",
    ]);
  });
  it("fails visibly when the gateway rejects the credential or is down", async () => {
    await expect(
      provider(new SecretValue("sk-wrong-key-000")).listModels(null, null),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REVOKED" });
    await services.close();
    await expect(
      provider(new SecretValue("sk-local-owner-key")).probe(),
    ).rejects.toMatchObject({ code: "GATEWAY_UNREACHABLE", retryable: true });
    services = await startLocalServices();
  });
});
