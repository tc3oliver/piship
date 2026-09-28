import {
  type CredentialRef,
  type IdentitySession,
  type InferenceContext,
  type InferenceProvider,
  type ManagedFetch,
  type ModelDefinition,
  PiShipError,
  type ResolvedModel,
  type RuntimeConfigurationContext,
  type RuntimeProviderConfiguration,
  type SecretValue,
} from "@piship/contracts";

export interface CatalogEntry {
  readonly id: string;
  readonly name: string;
  readonly contextWindow: number;
  readonly maxOutputTokens: number;
  readonly input: readonly string[];
  readonly reasoning: boolean;
  readonly tools: boolean;
  readonly streaming: boolean;
  readonly policyTags: readonly string[];
}

export interface CatalogConstraints {
  /** Distribution allowlist (upper bound). */
  readonly allowed: readonly string[];
  /** Models the runtime credential is entitled to, when the broker says so. */
  readonly entitled?: readonly string[];
  /** Models the live gateway currently lists, when discovery is enabled. */
  readonly live?: readonly string[];
  /** Permitted user narrowing; can only remove models. */
  readonly userAllowed?: readonly string[];
}

/** Combine static metadata with every allowlist; lists intersect, never widen. */
export function buildModelDefinitions(
  providerId: string,
  catalog: readonly CatalogEntry[],
  constraints: CatalogConstraints,
): ModelDefinition[] {
  return catalog
    .filter((entry) => constraints.allowed.includes(entry.id))
    .map((entry) => {
      let reason: string | undefined;
      if (constraints.entitled && !constraints.entitled.includes(entry.id))
        reason = "not included in the runtime credential entitlement";
      else if (constraints.live && !constraints.live.includes(entry.id))
        reason = "not currently listed by the inference gateway";
      else if (
        constraints.userAllowed &&
        !constraints.userAllowed.includes(entry.id)
      )
        reason = "excluded by user preference";
      return {
        id: entry.id,
        name: entry.name,
        provider: providerId,
        capabilities: {
          input: [...entry.input],
          reasoning: entry.reasoning,
          tools: entry.tools,
          streaming: entry.streaming,
          contextWindow: entry.contextWindow,
          maxOutputTokens: entry.maxOutputTokens,
        },
        policyTags: [...entry.policyTags],
        availability: reason
          ? { available: false, reason }
          : { available: true },
      };
    });
}

/** Resolve a requested model against the effective catalog. Never substitutes silently. */
export function resolveRequestedModel(
  requested: string,
  ctx: InferenceContext,
): ResolvedModel {
  const model = ctx.models.find((item) => item.id === requested);
  if (model && !model.availability.available)
    throw new PiShipError(
      "MODEL_UNAVAILABLE",
      `Model ${requested} is unavailable: ${model.availability.reason ?? "not currently offered"}`,
      {
        component: "inference",
        userAction: `Choose one of: ${ctx.allowed.join(", ") || "(none)"}`,
      },
    );
  if (!model || !ctx.allowed.includes(requested))
    throw new PiShipError(
      "MODEL_DENIED",
      `Model ${requested} is not allowed by this distribution`,
      {
        component: "inference",
        userAction: `Choose one of: ${ctx.allowed.join(", ") || "(none)"}`,
      },
    );
  return { model, source: "catalog" };
}

export interface GatewayFailure {
  readonly error: PiShipError;
}

/** Map a gateway HTTP status to the error contract and retry rules. */
export function classifyGatewayStatus(
  status: number,
  headers: Readonly<Record<string, string>> = {},
): PiShipError | null {
  if (status < 400) return null;
  const retryAfterHeader = headers["retry-after"];
  const retryAfterMs =
    retryAfterHeader && Number.isFinite(Number(retryAfterHeader))
      ? Number(retryAfterHeader) * 1000
      : undefined;
  if (status === 401)
    return new PiShipError(
      "CREDENTIAL_REVOKED",
      "The inference gateway rejected the runtime credential",
      {
        component: "inference",
        userAction:
          "PiShip will re-acquire once; if it persists, run login again",
      },
    );
  if (status === 403)
    return new PiShipError(
      "MODEL_DENIED",
      "The inference gateway denied this model or user",
      {
        component: "inference",
      },
    );
  if (status === 404)
    return new PiShipError(
      "MODEL_UNAVAILABLE",
      "The inference gateway does not serve this model",
      {
        component: "inference",
      },
    );
  if (status === 429)
    return new PiShipError(
      "GATEWAY_RATE_LIMITED",
      "The inference gateway is rate limiting requests",
      {
        component: "inference",
        retryable: true,
        ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
      },
    );
  if (status >= 500)
    return new PiShipError(
      "GATEWAY_UNREACHABLE",
      `The inference gateway returned HTTP ${status}`,
      {
        component: "inference",
        retryable: true,
      },
    );
  return new PiShipError(
    "GATEWAY_PROTOCOL_ERROR",
    `The inference gateway returned HTTP ${status}`,
    {
      component: "inference",
    },
  );
}

export interface OpenAICompatibleOptions {
  readonly providerId: string;
  readonly baseUrl: string;
  readonly api: "openai-completions" | "openai-responses";
  readonly catalog: readonly CatalogEntry[];
  readonly allowed: readonly string[];
  readonly userAllowed?: readonly string[];
  readonly liveCatalog: boolean;
  readonly fetch: ManagedFetch;
  /** Request-time accessor for the credential secret (null when none is needed). */
  readonly secret: () => SecretValue | null;
}

/** Explicit OpenAI-compatible endpoint (managed gateway or local server). */
export class OpenAICompatibleInferenceProvider implements InferenceProvider {
  readonly kind = "openai-compatible";
  constructor(readonly options: OpenAICompatibleOptions) {}

  /** GET {baseUrl}/models, used for live availability and gateway reachability. */
  async probe(): Promise<string[]> {
    const secret = this.options.secret();
    const response = await this.options.fetch(
      `${this.options.baseUrl.replace(/\/+$/, "")}/models`,
      {
        headers: {
          accept: "application/json",
          ...(secret ? { authorization: `Bearer ${secret.reveal()}` } : {}),
        },
        signal: AbortSignal.timeout(15_000),
      },
    );
    const failure = classifyGatewayStatus(
      response.status,
      Object.fromEntries(response.headers),
    );
    if (failure) throw failure;
    let body: { data?: { id?: unknown }[] };
    try {
      body = (await response.json()) as typeof body;
    } catch {
      throw new PiShipError(
        "GATEWAY_PROTOCOL_ERROR",
        "The inference gateway model list is not JSON",
        {
          component: "inference",
        },
      );
    }
    if (!Array.isArray(body.data))
      throw new PiShipError(
        "GATEWAY_PROTOCOL_ERROR",
        "The inference gateway model list has no data array",
        {
          component: "inference",
        },
      );
    return body.data
      .map((item) => item.id)
      .filter((id): id is string => typeof id === "string");
  }

  async listModels(
    _identity: IdentitySession | null,
    credential: CredentialRef | null,
  ): Promise<ModelDefinition[]> {
    const live = this.options.liveCatalog ? await this.probe() : undefined;
    return buildModelDefinitions(
      this.options.providerId,
      this.options.catalog,
      {
        allowed: this.options.allowed,
        ...(credential?.models ? { entitled: credential.models } : {}),
        ...(live ? { live } : {}),
        ...(this.options.userAllowed
          ? { userAllowed: this.options.userAllowed }
          : {}),
      },
    );
  }

  async resolveModel(
    requested: string,
    ctx: InferenceContext,
  ): Promise<ResolvedModel> {
    return resolveRequestedModel(requested, ctx);
  }

  async configureRuntime(
    ctx: RuntimeConfigurationContext,
  ): Promise<RuntimeProviderConfiguration> {
    return {
      kind: "managed-endpoint",
      providerId: ctx.providerId,
      baseUrl: this.options.baseUrl,
      api: this.options.api,
      models: ctx.models.filter((model) => model.availability.available),
      requiresCredential: ctx.credential !== null,
    };
  }
}

/** Explicit delegation to Pi's own provider catalog and authentication (personal only). */
export class PiNativeInferenceProvider implements InferenceProvider {
  readonly kind = "pi-native";
  constructor(readonly allowed: readonly string[]) {}
  async listModels(): Promise<ModelDefinition[]> {
    return [];
  }
  async resolveModel(
    requested: string,
    ctx: InferenceContext,
  ): Promise<ResolvedModel> {
    if (this.allowed.length && !this.allowed.includes(requested))
      throw new PiShipError(
        "MODEL_DENIED",
        `Model ${requested} is not in the owner allowlist`,
        {
          component: "inference",
        },
      );
    const [provider = "", ...rest] = requested.split("/");
    return {
      model: ctx.models.find(
        (model) => `${model.provider}/${model.id}` === requested,
      ) ?? {
        id: rest.join("/"),
        name: requested,
        provider,
        capabilities: { input: ["text"] },
        policyTags: [],
        availability: { available: true },
      },
      source: "pi-native",
    };
  }
  async configureRuntime(
    ctx: RuntimeConfigurationContext,
  ): Promise<RuntimeProviderConfiguration> {
    return {
      kind: "pi-native",
      providerId: ctx.providerId,
      models: [],
      requiresCredential: false,
    };
  }
}
