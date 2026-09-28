import type { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";

type Model = NonNullable<ReturnType<ModelRuntime["getModel"]>>;
type AuthResult = Awaited<ReturnType<ModelRuntime["getAuth"]>>;
type AuthCheck = Awaited<ReturnType<ModelRuntime["checkAuth"]>>;

export interface ManagedEndpointGovernance {
  readonly kind: "managed-endpoint";
  readonly providerId: string;
  readonly allowedModelIds: readonly string[];
  /** Request-time key; `force` re-acquires after a gateway rejection. */
  readonly apiKey: (options: { force: boolean }) => Promise<string>;
}

export interface PiNativeGovernance {
  readonly kind: "pi-native";
  /** Empty means the personal owner allows any configured Pi model... */
  readonly allowedModelKeys: readonly string[];
  /** ...unless a policy restricts models, in which case empty allows none. */
  readonly restricted?: boolean;
}

export type ModelGovernance = ManagedEndpointGovernance | PiNativeGovernance;

/** A further model.use check from the distribution policy (v1alpha3). */
export interface ModelPolicy {
  allows(provider: string, id: string): boolean;
  /** Called when a request for a disallowed model is refused. */
  denied?(provider: string, id: string): void;
}

export interface GovernedRuntime {
  isAllowed(provider: string, id: string): boolean;
  /** Mark the current credential as rejected so the next request re-acquires. */
  markCredentialRejected(): void;
}

function denied(provider: string, id: string): PiShipError {
  return new PiShipError(
    "MODEL_DENIED",
    `Model ${provider}/${id} is not allowed by this distribution`,
    {
      component: "inference",
    },
  );
}

/**
 * Enforce the distribution's model policy on a Pi ModelRuntime instance through
 * its public methods. Every path Pi uses to list, authorize, select, or call a
 * model is narrowed: pickers see only allowed models, setModel is refused for
 * others (no auth), and a request for a disallowed model throws MODEL_DENIED.
 * In managed mode no other provider — built-in, environment, auth.json, or
 * extension-registered — can obtain credentials.
 */
export function governModelRuntime(
  runtime: ModelRuntime,
  governance: ModelGovernance,
  policy?: ModelPolicy,
): GovernedRuntime {
  const original = {
    getModel: runtime.getModel.bind(runtime),
    getModels: runtime.getModels.bind(runtime),
    getAvailable: runtime.getAvailable.bind(runtime),
    getAvailableSnapshot: runtime.getAvailableSnapshot.bind(runtime),
    checkAuth: runtime.checkAuth.bind(runtime),
    getAuth: runtime.getAuth.bind(runtime) as (
      model: unknown,
      overrides?: unknown,
    ) => Promise<AuthResult>,
    stream: runtime.stream.bind(runtime),
    streamSimple: runtime.streamSimple.bind(runtime),
    complete: runtime.complete.bind(runtime),
    completeSimple: runtime.completeSimple.bind(runtime),
  };
  let force = false;
  const managed =
    governance.kind === "managed-endpoint" ? governance : undefined;
  const unrestricted =
    governance.kind === "pi-native" &&
    !governance.restricted &&
    !governance.allowedModelKeys.length;
  const isAllowed = (provider: string, id: string): boolean =>
    (managed
      ? provider === managed.providerId && managed.allowedModelIds.includes(id)
      : governance.kind === "pi-native" &&
        (unrestricted ||
          governance.allowedModelKeys.includes(`${provider}/${id}`))) &&
    (policy?.allows(provider, id) ?? true);
  const providerHasAllowed = (provider: string): boolean =>
    managed
      ? provider === managed.providerId
      : governance.kind === "pi-native" &&
        (unrestricted ||
          governance.allowedModelKeys.some((key) =>
            key.startsWith(`${provider}/`),
          ));
  const managedModels = (): Model[] =>
    managed
      ? original
          .getModels(managed.providerId)
          .filter((model) => isAllowed(model.provider, model.id))
      : [];
  const guard = (model: { provider: string; id: string }) => {
    if (!isAllowed(model.provider, model.id)) {
      policy?.denied?.(model.provider, model.id);
      throw denied(model.provider, model.id);
    }
  };

  const target = runtime as unknown as Record<string, unknown>;
  target.getModel = (providerId: string, modelId: string): Model | undefined =>
    isAllowed(providerId, modelId)
      ? original.getModel(providerId, modelId)
      : undefined;
  target.getModels = (providerId?: string): readonly Model[] =>
    original
      .getModels(providerId)
      .filter((model) => isAllowed(model.provider, model.id));
  target.getAvailableSnapshot = (): readonly Model[] =>
    managed
      ? managedModels()
      : original
          .getAvailableSnapshot()
          .filter((model) => isAllowed(model.provider, model.id));
  target.getAvailable = async (
    providerId?: string,
    options?: Parameters<ModelRuntime["getAvailable"]>[1],
  ) =>
    managed
      ? managedModels().filter(
          (model) => !providerId || model.provider === providerId,
        )
      : (await original.getAvailable(providerId, options)).filter((model) =>
          isAllowed(model.provider, model.id),
        );
  target.checkAuth = async (
    providerId: string,
    options?: Parameters<ModelRuntime["checkAuth"]>[1],
  ): Promise<AuthCheck> => {
    if (!providerHasAllowed(providerId)) return undefined;
    if (managed)
      return { type: "api_key", source: "PiShip managed credential" };
    return original.checkAuth(providerId, options);
  };
  target.getAuth = async (
    model: string | Model,
    overrides?: unknown,
  ): Promise<AuthResult> => {
    const provider = typeof model === "string" ? model : model.provider;
    if (typeof model !== "string" && !isAllowed(model.provider, model.id))
      return undefined;
    if (!providerHasAllowed(provider)) return undefined;
    if (managed) {
      const apiKey = await managed.apiKey({ force });
      force = false;
      return {
        auth: { apiKey },
        source: "PiShip managed credential",
      } as AuthResult;
    }
    return original.getAuth(model, overrides);
  };
  target.stream = ((model: Model, ...rest: unknown[]) => {
    guard(model);
    return (original.stream as (...args: unknown[]) => unknown)(model, ...rest);
  }) as unknown;
  target.streamSimple = ((model: Model, ...rest: unknown[]) => {
    guard(model);
    return (original.streamSimple as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  }) as unknown;
  target.complete = ((model: Model, ...rest: unknown[]) => {
    guard(model);
    return (original.complete as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  }) as unknown;
  target.completeSimple = ((model: Model, ...rest: unknown[]) => {
    guard(model);
    return (original.completeSimple as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  }) as unknown;
  if (managed) {
    target.login = async () => {
      throw new PiShipError(
        "POLICY_DENIED",
        "Provider login is disabled; this distribution manages credentials",
        {
          component: "inference",
        },
      );
    };
    target.setRuntimeApiKey = async () => {
      throw new PiShipError(
        "POLICY_DENIED",
        "User-supplied API keys are disabled in managed mode",
        {
          component: "inference",
        },
      );
    };
  }
  return {
    isAllowed,
    markCredentialRejected: () => {
      force = true;
    },
  };
}

/**
 * Pi reports a rejected request (the SDK throws before a response event) as
 * an assistant message with stopReason "error". Recognize authentication
 * rejections so the next request re-acquires the runtime credential.
 */
export function isCredentialRejection(message: unknown): boolean {
  const value = message as
    | { role?: string; stopReason?: string; errorMessage?: string }
    | undefined;
  return (
    value?.role === "assistant" &&
    value.stopReason === "error" &&
    /(^|\D)401(\D|$)|unauthori[sz]ed|invalid api key|authentication failed/i.test(
      value.errorMessage ?? "",
    )
  );
}
