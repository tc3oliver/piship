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
  isUpstreamProviderError,
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
  it("carries structured output only when the catalog declares it", () => {
    const [declared, unknown] = buildModelDefinitions(
      "acmecode",
      [
        { ...catalog[0], structuredOutput: true } as (typeof catalog)[number],
        catalog[1] as (typeof catalog)[number],
      ],
      { allowed: ["acme/coder", "acme/general"] },
    );
    expect(declared?.capabilities.structuredOutput).toBe(true);
    expect(unknown?.capabilities).not.toHaveProperty("structuredOutput");
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
    const inAMinute = new Date(Date.now() + 60_000).toUTCString();
    const dated = classifyGatewayStatus(429, { "retry-after": inAMinute });
    expect(dated?.retryAfterMs).toBeGreaterThan(55_000);
    expect(dated?.retryAfterMs).toBeLessThanOrEqual(60_000);
    expect(classifyGatewayStatus(503)).toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
    });
    expect(classifyGatewayStatus(400)).toMatchObject({
      code: "GATEWAY_PROTOCOL_ERROR",
      retryable: false,
    });
  });
  // Bodies as LiteLLM v1.103.0 answered them (tests/enterprise-reference/
  // gateway-evidence.test.ts).
  const litellm = (type: string, message: string, code: string) => ({
    error: { message, type, param: null, code },
  });
  it("tells a model provider's 401 and 403 relayed by LiteLLM from the gateway's own", () => {
    const upstream401 = litellm(
      "authentication_error",
      "litellm.AuthenticationError: AuthenticationError: OpenAIException - Incorrect API key provided.. Received Model Group=acme/coder",
      "401",
    );
    const upstream403 = litellm(
      "permission_error",
      "litellm.APIError: APIError: OpenAIException - Mock upstream denies this request.. Received Model Group=acme/coder",
      "403",
    );
    for (const [status, body] of [
      [401, upstream401],
      [403, upstream403],
    ] as const) {
      expect(isUpstreamProviderError(body)).toBe(true);
      expect(classifyGatewayStatus(status, {}, body)).toMatchObject({
        code: "GATEWAY_UNREACHABLE",
        retryable: false,
        message: expect.stringContaining(
          `model provider refused the request (HTTP ${status})`,
        ),
      });
    }
    // The gateway's own refusals of the key and the model keep their codes.
    for (const body of [
      litellm("auth_error", "Authentication Error, Key is blocked.", "401"),
      litellm(
        "token_not_found_in_db",
        "Authentication Error, Invalid proxy server token passed.",
        "401",
      ),
      litellm(
        "expired_key",
        "Authentication Error - Expired Key. Key Expiry time ...",
        "401",
      ),
    ]) {
      expect(isUpstreamProviderError(body)).toBe(false);
      expect(classifyGatewayStatus(401, {}, body)?.code).toBe(
        "CREDENTIAL_REVOKED",
      );
    }
    const denied = litellm(
      "key_model_access_denied",
      "The requested model 'acme/general' is not available for this API key",
      "403",
    );
    expect(classifyGatewayStatus(403, {}, denied)?.code).toBe("MODEL_DENIED");
    // The error object alone, as Pi's error message carries it.
    expect(isUpstreamProviderError(upstream401.error)).toBe(true);
    expect(isUpstreamProviderError(undefined)).toBe(false);
    // LiteLLM's own refusal types are the gateway's, even under a
    // `litellm.` message.
    for (const type of [
      "auth_error",
      "token_not_found_in_db",
      "expired_key",
      "key_model_access_denied",
    ]) {
      const own = litellm(type, "litellm.ProxyException: refused", "401");
      expect(isUpstreamProviderError(own)).toBe(false);
      expect(classifyGatewayStatus(401, {}, own)?.code).toBe(
        "CREDENTIAL_REVOKED",
      );
    }
    expect(isUpstreamProviderError("litellm.AuthenticationError")).toBe(false);
  });
  it("reads a retry time the gateway relays from its provider, bounded", () => {
    expect(
      classifyGatewayStatus(429, { "llm_provider-retry-after": "1" })
        ?.retryAfterMs,
    ).toBe(1000);
    // The gateway's own retry-after comes first.
    expect(
      classifyGatewayStatus(429, {
        "retry-after": "5",
        "llm_provider-retry-after": "1",
      })?.retryAfterMs,
    ).toBe(5000);
    expect(
      classifyGatewayStatus(429, { "llm_provider-retry-after": "86400" })
        ?.retryAfterMs,
    ).toBe(3_600_000);
    expect(
      classifyGatewayStatus(429, { "llm_provider-retry-after": "soon" })
        ?.retryAfterMs,
    ).toBeUndefined();
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
    // PiShip has no verified metadata for Pi's catalog; nothing is invented.
    expect(
      (
        await provider.resolveModel("openai/gpt-4o", {
          models: [],
          allowed: [],
        })
      ).model.capabilities,
    ).toEqual({});
    expect(
      await provider.configureRuntime({
        providerId: "mypi",
        credential: null,
        models: [],
      }),
    ).toMatchObject({ kind: "pi-native" });
  });
});

describe("effective model catalog (§10)", () => {
  const [A, B, C] = ["acme/coder", "acme/general", "acme/review"];
  const offered = (constraints: Parameters<typeof buildModelDefinitions>[2]) =>
    buildModelDefinitions("acmecode", catalog, constraints)
      .filter((model) => model.availability.available)
      .map((model) => model.id);

  it("narrows to the credential entitlement", () => {
    expect(offered({ allowed: [A, B, C], entitled: [A] })).toEqual([A]);
  });

  it("never offers an entitled model outside the distribution allowlist", () => {
    const models = buildModelDefinitions("acmecode", catalog, {
      allowed: [A],
      entitled: [A, B, C, "other/unlisted"],
    });
    expect(models.map((model) => model.id)).toEqual([A]);
  });

  it("lets the live gateway remove a model but never authorize one", () => {
    expect(offered({ allowed: [A, B], live: [A] })).toEqual([A]);
    expect(
      offered({ allowed: [A], live: [A, B, C, "other/unlisted"] }),
    ).toEqual([A]);
  });

  it("lets a user preference only narrow the catalog", () => {
    expect(offered({ allowed: [A, B], userAllowed: [B, C] })).toEqual([B]);
  });

  it("treats the allowlist as the ceiling whatever every other list says", () => {
    expect(
      buildModelDefinitions("acmecode", catalog, {
        allowed: [],
        entitled: [A, B, C],
        live: [A, B, C],
        userAllowed: [A, B, C],
      }),
    ).toEqual([]);
  });

  it("reports an unentitled allowed model as MODEL_UNAVAILABLE and a model outside the allowlist as MODEL_DENIED", () => {
    const models = buildModelDefinitions("acmecode", catalog, {
      allowed: [A, B],
      entitled: [A],
    });
    const ctx = { models, allowed: [A] };
    expect(() => resolveRequestedModel(B, ctx)).toThrow(
      expect.objectContaining({
        code: "MODEL_UNAVAILABLE",
        message: expect.stringContaining("runtime credential entitlement"),
      }),
    );
    expect(() => resolveRequestedModel(C, ctx)).toThrow(
      expect.objectContaining({ code: "MODEL_DENIED" }),
    );
  });

  it("yields exactly B for allowlist A,B, entitlement B,C, and live gateway B,C,D", () => {
    expect(
      offered({
        allowed: [A, B],
        entitled: [B, C],
        live: [B, C, "acme/unlisted"],
      }),
    ).toEqual([B]);
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
  it("identifies the client on the model list request only when given one", async () => {
    const client =
      'distribution="acmecode", version="1.0.0", piship="0.7.0", protocol=1';
    const secret = new SecretValue("sk-local-owner-key");
    await new OpenAICompatibleInferenceProvider({
      providerId: "acmecode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      catalog,
      allowed: ["acme/coder"],
      liveCatalog: true,
      fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
      secret: () => secret,
      client,
    }).probe();
    await provider(secret).probe();
    expect(
      services.state.requests
        .filter((item: { path: string }) => item.path.endsWith("/models"))
        .map((item: { client: string | null }) => item.client),
    ).toEqual([client, null]);
    const configure = (options: { client?: string }) =>
      new OpenAICompatibleInferenceProvider({
        providerId: "acmecode",
        baseUrl: services.gatewayUrl,
        api: "openai-completions",
        catalog,
        allowed: ["acme/coder"],
        liveCatalog: true,
        fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
        secret: () => secret,
        ...options,
      }).configureRuntime({
        providerId: "acmecode",
        credential: null,
        models: [],
      });
    expect((await configure({ client })).headers).toEqual({
      "piship-client": client,
    });
    expect((await configure({})).headers).toBeUndefined();
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
  it("reports a gateway that does not answer in time as unreachable", async () => {
    const timedOut = new OpenAICompatibleInferenceProvider({
      providerId: "acmecode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      catalog,
      allowed: ["acme/coder"],
      liveCatalog: true,
      fetch: async () => {
        throw new DOMException("The operation timed out", "TimeoutError");
      },
      secret: () => null,
    });
    await expect(timedOut.probe()).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
      message: "The inference gateway did not answer within 15 s",
    });
    const slowBody = new OpenAICompatibleInferenceProvider({
      providerId: "acmecode",
      baseUrl: services.gatewayUrl,
      api: "openai-completions",
      catalog,
      allowed: ["acme/coder"],
      liveCatalog: true,
      fetch: async () =>
        ({
          status: 200,
          headers: new Headers(),
          json: async () => {
            throw new DOMException("The operation timed out", "TimeoutError");
          },
        }) as unknown as Response,
      secret: () => null,
    });
    await expect(slowBody.probe()).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
    });
  });
});
