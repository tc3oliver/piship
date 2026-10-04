import type { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { PiShipError, redact } from "@piship/contracts";
import { classifyGatewayStatus, isUpstreamProviderError } from "@piship/core";

type Model = NonNullable<ReturnType<ModelRuntime["getModel"]>>;
type ModelRef = { readonly provider: string; readonly id: string };
type AuthResult = Awaited<ReturnType<ModelRuntime["getAuth"]>>;
type AuthCheck = Awaited<ReturnType<ModelRuntime["checkAuth"]>>;

export interface ManagedEndpointGovernance {
  readonly kind: "managed-endpoint";
  readonly providerId: string;
  /** Models that may be selected, virtual ones included. */
  readonly allowedModelIds: readonly string[];
  /**
   * Physical models that may receive a request; `allowedModelIds` when
   * absent. A virtual model is selected, never dispatched.
   */
  readonly dispatchModelIds?: readonly string[];
  /** Request-time key; `force` re-acquires after a gateway rejection. */
  readonly apiKey: (options: { force: boolean }) => Promise<string>;
  /** The distribution's command, named where Pi asks the user to sign in. */
  readonly command?: string;
}

export interface PiNativeGovernance {
  readonly kind: "pi-native";
  /** Empty means the personal owner allows any configured Pi model... */
  readonly allowedModelKeys: readonly string[];
  /** ...unless a policy restricts models, in which case empty allows none. */
  readonly restricted?: boolean;
}

export type ModelGovernance = ManagedEndpointGovernance | PiNativeGovernance;

/**
 * The API id Pi gives a virtual catalog entry. Pi exports it only as a type
 * from its root, so it is matched by value; a compatibility test pins it.
 */
export const PI_VIRTUAL_MODEL_API = "pi-virtual";

/** A declared virtual model and the closed set of physical models it may route to. */
export interface VirtualModelRule {
  readonly provider: string;
  readonly id: string;
  readonly routes: readonly ModelRef[];
  /** The router as the manifest declares it, recorded in audit. */
  readonly router: string;
  /**
   * The built path of the router extension, which alone may register the
   * model; undefined when the declaration resolves to no built extension.
   */
  readonly routerPath?: string;
}

export type ModelAction = "model.select" | "model.dispatch";

/** One routed request: the selected virtual model and its physical target. */
export interface ModelDispatch {
  readonly selected: string;
  readonly dispatched: string;
  readonly router: string;
  readonly type: string;
}

/** Further model checks from the distribution policy. */
export interface ModelPolicy {
  /** model.select: the model a session selects, possibly virtual. */
  selects(provider: string, id: string): boolean;
  /**
   * model.dispatch: the physical model that receives a request. Absent, a
   * physical model is checked against `selects`.
   */
  dispatches?(provider: string, id: string): boolean;
  /** Called when a request or a registration is refused. */
  denied?(
    action: ModelAction,
    provider: string,
    id: string,
    detail?: Readonly<Record<string, string>>,
  ): void;
  /** Called when a virtual model is routed to an allowed physical model. */
  dispatched?(dispatch: ModelDispatch): void;
  /**
   * Called before every request; throws to refuse it. A prompt can carry
   * workspace content, so a request must not leave while a required control
   * (a required audit sink that lost events) is down.
   */
  available?(): void;
}

export interface GovernedRuntime {
  /** Whether a model may be selected (the allowlist and model.select). */
  isSelectable(provider: string, id: string): boolean;
  /**
   * Run `fn` with virtual model registration open. Outside it, registering
   * or unregistering a virtual model is refused: only PiShip registers the
   * declared ones, from the declared router, when extensions load.
   */
  withRegistrationWindow<T>(fn: () => T): T;
  /** Mark the current credential as rejected so the next request re-acquires. */
  markCredentialRejected(): void;
  /**
   * The failed request message with the PiShip action appended, when the
   * request failed on the managed credential: PiShip refused to issue it
   * (identity or credential failure, changed principal) or the gateway
   * rejected it. Undefined for any other message. Pi shows only the error
   * text in the TUI, so without it the user gets no instruction.
   */
  withAccessAction(message: unknown): unknown;
}

function denied(provider: string, id: string, reason?: string): PiShipError {
  return new PiShipError(
    "MODEL_DENIED",
    `Model ${provider}/${id} is not allowed by this distribution${reason ? ` (${reason})` : ""}`,
    {
      component: "inference",
    },
  );
}

/** A refused classify or generateImages call, in the shape Pi returns instead of rejecting. */
function errorResult(model: ModelRef & { api?: string }, error: unknown) {
  return {
    api: model.api,
    provider: model.provider,
    model: model.id,
    stopReason: "error" as const,
    errorMessage:
      error instanceof PiShipError
        ? `${error.code}: ${error.message}`
        : error instanceof Error
          ? error.message
          : String(error),
    timestamp: Date.now(),
  };
}

/**
 * Enforce the distribution's model policy on a Pi ModelRuntime instance through
 * its public methods. Every path Pi uses to list, authorize, select, or call a
 * model is narrowed: pickers see only allowed models, setModel is refused for
 * others (no auth), and a request for a disallowed model throws MODEL_DENIED.
 * In managed mode no other provider — built-in, environment, auth.json, or
 * extension-registered — can obtain credentials.
 *
 * A selected model is checked by model.select, the physical model that
 * receives a request by model.dispatch. A virtual model is routed through
 * `resolveModel`, the one routing step of every Pi path (agent loop, direct
 * stream, summaries): its target must be one of its declared routes and
 * dispatchable, and only that routed request may reach a model the session
 * could not select itself. Classifier, image, and deferred requests and the
 * type-aware listings are narrowed the same way.
 */
export function governModelRuntime(
  runtime: ModelRuntime,
  governance: ModelGovernance,
  policy?: ModelPolicy,
  virtual: readonly VirtualModelRule[] = [],
): GovernedRuntime {
  const original = {
    getModel: runtime.getModel.bind(runtime),
    getModels: runtime.getModels.bind(runtime),
    getAvailable: runtime.getAvailable.bind(runtime),
    getAvailableSnapshot: runtime.getAvailableSnapshot.bind(runtime),
    checkAuth: runtime.checkAuth.bind(runtime),
    getProviders: runtime.getProviders.bind(runtime),
    getAuth: runtime.getAuth.bind(runtime) as (
      model: unknown,
      overrides?: unknown,
    ) => Promise<AuthResult>,
    stream: runtime.stream.bind(runtime),
    streamSimple: runtime.streamSimple.bind(runtime),
    complete: runtime.complete.bind(runtime),
    completeSimple: runtime.completeSimple.bind(runtime),
    streamDeferred: runtime.streamDeferred.bind(runtime),
    fetchDeferred: runtime.fetchDeferred.bind(runtime),
    cancelDeferred: runtime.cancelDeferred.bind(runtime),
    classify: runtime.classify.bind(runtime),
    generateImages: runtime.generateImages.bind(runtime),
    getModelsOfType: runtime.getModelsOfType.bind(runtime),
    getModelOfType: runtime.getModelOfType.bind(runtime),
    getAllModels: runtime.getAllModels.bind(runtime),
    getAvailableOfType: runtime.getAvailableOfType.bind(runtime),
    getAllAvailable: runtime.getAllAvailable.bind(runtime),
    resolveModel: runtime.resolveModel.bind(runtime),
    registerVirtualModel: runtime.registerVirtualModel.bind(runtime),
    unregisterVirtualModel: runtime.unregisterVirtualModel.bind(runtime),
  };
  let force = false;
  /** The PiShip error the last managed key request failed with. */
  let accessFailure: PiShipError | undefined;
  const managed =
    governance.kind === "managed-endpoint" ? governance : undefined;
  const unrestricted =
    governance.kind === "pi-native" &&
    !governance.restricted &&
    !governance.allowedModelKeys.length;
  const key = (model: ModelRef) => `${model.provider}/${model.id}`;
  const rules = new Map(virtual.map((rule) => [key(rule), rule]));
  /** The distribution's allowlist: managed ids, or pi-native keys. */
  const listed = (provider: string, id: string): boolean =>
    managed
      ? provider === managed.providerId && managed.allowedModelIds.includes(id)
      : governance.kind === "pi-native" &&
        (unrestricted ||
          governance.allowedModelKeys.includes(`${provider}/${id}`));
  const isSelectable = (provider: string, id: string): boolean =>
    listed(provider, id) && (policy?.selects(provider, id) ?? true);
  const selectable = (model: ModelRef) =>
    isSelectable(model.provider, model.id);
  /** A physical model that may receive a request. */
  const dispatchable = (model: ModelRef): boolean =>
    !rules.has(key(model)) &&
    (managed
      ? model.provider === managed.providerId &&
        (managed.dispatchModelIds ?? managed.allowedModelIds).includes(model.id)
      : listed(model.provider, model.id)) &&
    (policy
      ? (policy.dispatches ?? policy.selects).call(
          policy,
          model.provider,
          model.id,
        )
      : true);
  const isVirtual = (model: { api?: string }) =>
    model.api === PI_VIRTUAL_MODEL_API;
  /** Copies of physical models a declared virtual model routed a request to. */
  const routed = new WeakSet<object>();
  let registering = false;
  const providerHasAllowed = (provider: string): boolean =>
    managed
      ? provider === managed.providerId
      : governance.kind === "pi-native" &&
        (unrestricted ||
          governance.allowedModelKeys.some((key) =>
            key.startsWith(`${provider}/`),
          ));
  const managedModels = (): Model[] =>
    managed ? original.getModels(managed.providerId).filter(selectable) : [];
  const refuse = (
    action: ModelAction,
    model: ModelRef,
    detail?: Readonly<Record<string, string>>,
  ): never => {
    policy?.denied?.(action, model.provider, model.id, detail);
    throw denied(model.provider, model.id, detail?.reason);
  };
  const guard = (model: ModelRef & { api?: string }) => {
    if (isVirtual(model)) {
      // Pi routes it next; resolveModel checks the model it routes to.
      if (!rules.has(key(model)) || !selectable(model))
        refuse("model.select", model);
    } else if (routed.has(model)) {
      if (!dispatchable(model)) refuse("model.dispatch", model);
    } else {
      // Selected and dispatched are the same model.
      if (!selectable(model)) refuse("model.select", model);
      if (!dispatchable(model)) refuse("model.dispatch", model);
    }
    policy?.available?.();
  };

  const target = runtime as unknown as Record<string, unknown>;
  target.getModel = (providerId: string, modelId: string): Model | undefined =>
    isSelectable(providerId, modelId)
      ? original.getModel(providerId, modelId)
      : undefined;
  target.getModels = (providerId?: string): readonly Model[] =>
    original.getModels(providerId).filter(selectable);
  target.getAvailableSnapshot = (): readonly Model[] =>
    managed
      ? managedModels()
      : original.getAvailableSnapshot().filter(selectable);
  target.getAvailable = async (
    providerId?: string,
    options?: Parameters<ModelRuntime["getAvailable"]>[1],
  ) =>
    managed
      ? managedModels().filter(
          (model) => !providerId || model.provider === providerId,
        )
      : (await original.getAvailable(providerId, options)).filter(selectable);
  target.getModelsOfType = (type: never, providerId?: string) =>
    original.getModelsOfType(type, providerId).filter(selectable);
  target.getModelOfType = (type: never, providerId: string, modelId: string) =>
    isSelectable(providerId, modelId)
      ? original.getModelOfType(type, providerId, modelId)
      : undefined;
  target.getAllModels = (providerId?: string) =>
    original.getAllModels(providerId).filter(selectable);
  const inManaged = (model: ModelRef, providerId?: string) =>
    selectable(model) && (!providerId || model.provider === providerId);
  target.getAvailableOfType = async (
    type: never,
    providerId?: string,
    options?: Parameters<ModelRuntime["getAvailableOfType"]>[2],
  ) =>
    managed
      ? original
          .getModelsOfType(type, managed.providerId)
          .filter((model) => inManaged(model, providerId))
      : (await original.getAvailableOfType(type, providerId, options)).filter(
          selectable,
        );
  target.getAllAvailable = async (
    providerId?: string,
    options?: Parameters<ModelRuntime["getAllAvailable"]>[1],
  ) =>
    managed
      ? original
          .getAllModels(managed.providerId)
          .filter((model) => inManaged(model, providerId))
      : (await original.getAllAvailable(providerId, options)).filter(
          selectable,
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
  if (managed) {
    // PiShip supplies the managed provider's credential at request time, so
    // Pi's snapshot never records one; a routed request checks it here.
    target.hasConfiguredAuth = (providerId: string) =>
      providerId === managed.providerId;
    // Pi's `/login` offers the login methods of `getProviders()`. A managed
    // distribution signs in with its own command, so only its provider is
    // listed, with a method that has no `login`: Pi shows it as configured
    // outside Pi, under a name that says where to sign in.
    const signIn = managed.command
      ? ` (run ${managed.command} login in a terminal)`
      : "";
    target.getProviders = () =>
      original.getProviders().flatMap((provider) =>
        provider.id === managed.providerId
          ? [
              {
                ...provider,
                auth: {
                  apiKey: {
                    name: `${provider.name} sign-in${signIn}`,
                    resolve: async () => undefined,
                  },
                },
              },
            ]
          : [],
      );
  }
  target.getAuth = async (
    model: string | Model,
    overrides?: unknown,
  ): Promise<AuthResult> => {
    const provider = typeof model === "string" ? model : model.provider;
    // A routed model needs only dispatch; a virtual one is never sent.
    if (
      typeof model !== "string" &&
      (isVirtual(model)
        ? !rules.has(key(model)) || !selectable(model)
        : !dispatchable(model))
    )
      return undefined;
    if (!providerHasAllowed(provider)) return undefined;
    if (managed) {
      let apiKey: string;
      try {
        apiKey = await managed.apiKey({ force });
      } catch (error) {
        if (error instanceof PiShipError) accessFailure = error;
        throw error;
      }
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
    return observeTransport(
      original.stream as (...args: unknown[]) => unknown,
      model,
      rest,
      !!managed,
    );
  }) as unknown;
  target.streamSimple = ((model: Model, ...rest: unknown[]) => {
    guard(model);
    return observeTransport(
      original.streamSimple as (...args: unknown[]) => unknown,
      model,
      rest,
      !!managed,
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
  target.streamDeferred = (model: Model, ...rest: unknown[]) => {
    guard(model);
    return (original.streamDeferred as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  };
  for (const name of ["fetchDeferred", "cancelDeferred"] as const) {
    const call = original[name] as (...args: unknown[]) => Promise<unknown>;
    target[name] = async (model: Model, ...rest: unknown[]) => {
      guard(model);
      return call(model, ...rest);
    };
  }
  // Pi's contract for these is "never rejects": a refusal is an error result.
  target.classify = async (model: Model, ...rest: unknown[]) => {
    try {
      guard(model);
    } catch (error) {
      return { ...errorResult(model, error), answers: {} };
    }
    return (original.classify as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  };
  target.generateImages = async (model: Model, ...rest: unknown[]) => {
    try {
      guard(model);
    } catch (error) {
      return { ...errorResult(model, error), output: [] };
    }
    return (original.generateImages as (...args: unknown[]) => unknown)(
      model,
      ...rest,
    );
  };
  target.resolveModel = async (
    model: Model,
    messages: Parameters<ModelRuntime["resolveModel"]>[1],
    options: Parameters<ModelRuntime["resolveModel"]>[2],
  ) => {
    const selected = key(model);
    const rule = rules.get(selected);
    if (!rule || !selectable(model)) return refuse("model.select", model);
    const route = await original.resolveModel(model, messages, options);
    const physical = route.model;
    const detail = { selected, router: rule.router };
    if (!rule.routes.some((item) => key(item) === key(physical)))
      refuse("model.dispatch", physical, {
        ...detail,
        reason: "not a declared route",
      });
    if (!dispatchable(physical)) refuse("model.dispatch", physical, detail);
    // A copy, so that only this routed request is checked by dispatch
    // alone; the catalog object itself still needs model.select.
    const tagged = { ...physical };
    routed.add(tagged);
    policy?.dispatched?.({
      selected,
      dispatched: key(physical),
      router: rule.router,
      type: "chat",
    });
    return { ...route, model: tagged };
  };
  const registration = (provider: string, id: string, apply: () => void) => {
    if (!registering) {
      policy?.denied?.("model.select", provider, id, { router: "<unknown>" });
      throw new PiShipError(
        "POLICY_DENIED",
        `Virtual model ${provider}/${id} is refused: only the declared router registers a virtual model, when extensions load`,
        { component: "inference" },
      );
    }
    apply();
  };
  target.registerVirtualModel = (
    definition: Parameters<ModelRuntime["registerVirtualModel"]>[0],
  ) =>
    registration(definition.provider, definition.id, () =>
      original.registerVirtualModel(definition),
    );
  target.unregisterVirtualModel = (provider: string, id: string) =>
    registration(provider, id, () =>
      original.unregisterVirtualModel(provider, id),
    );
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
    isSelectable,
    withRegistrationWindow: (fn) => {
      registering = true;
      try {
        return fn();
      } finally {
        registering = false;
      }
    },
    markCredentialRejected: () => {
      force = true;
    },
    withAccessAction: (message) => {
      const pending = accessFailure;
      accessFailure = undefined;
      const failure = requestFailure(message);
      const command = managed?.command;
      if (!failure || !command) return undefined;
      let action: string | undefined;
      if (pending && failure.message.includes(pending.message)) {
        // PiShip's actions say "run login"; in the TUI that reads as Pi's
        // `/login`, so the action names the command and where to run it.
        const named = (pending.userAction ?? "Run login").replace(
          /\b(run) login\b/gi,
          `$1 ${command} login`,
        );
        action = named.includes(`${command} login`)
          ? `In a terminal, ${named[0]?.toLowerCase()}${named.slice(1)}`
          : named;
      } else if (isCredentialRejection(message))
        action = `Send the message again; if it fails again, run ${command} login in a terminal`;
      if (!action) return undefined;
      return {
        ...(message as object),
        errorMessage: `${failure.message}\nAction: ${action}`,
      };
    },
  };
}

/**
 * How a failed request's fetch failed before any response arrived, by the
 * message Pi reported for it: a system error code (`ECONNREFUSED`), `timeout`,
 * or `network error`. Pi's message keeps only the SDK's text ("Connection
 * error."), so PiShip records what its own fetch saw.
 */
const transportFailures = new WeakMap<object, string>();

/**
 * Call a managed endpoint's stream through a fetch PiShip owns (Pi's public
 * `fetch` request option, which the OpenAI-compatible adapters a managed
 * endpoint uses accept), so a request that never got an answer keeps the
 * structured reason: the system error code, or that the client's deadline
 * aborted it. The fetch forwards to the caller's fetch or the global one
 * unchanged. Only the last attempt counts: a later answer clears an earlier
 * failure. A Pi-native provider's request is left as it is, because some of
 * Pi's adapters refuse a custom fetch.
 */
function observeTransport(
  call: (...args: unknown[]) => unknown,
  model: Model,
  rest: unknown[],
  managed: boolean,
): unknown {
  if (!managed) return call(model, ...rest);
  const [context, options] = rest as [
    unknown,
    { fetch?: typeof fetch; signal?: AbortSignal } | undefined,
  ];
  let failure: string | undefined;
  const fetchThrough: typeof fetch = async (input, init) => {
    try {
      const response = await (options?.fetch ?? globalThis.fetch)(input, init);
      failure = undefined;
      return response;
    } catch (error) {
      failure = transportFailure(error, options?.signal);
      throw error;
    }
  };
  const stream = call(model, context, { ...options, fetch: fetchThrough }) as {
    result?: () => Promise<{ stopReason?: string }>;
  };
  void stream.result?.().then((message) => {
    if (failure && message?.stopReason === "error")
      transportFailures.set(message, failure);
  });
  return stream;
}

function transportFailure(
  error: unknown,
  signal: AbortSignal | undefined,
): string | undefined {
  // The caller cancelled: Pi reports that itself as "aborted".
  if (signal?.aborted) return undefined;
  const name = (error as { name?: unknown })?.name;
  // Aborted although the caller did not: the client's request deadline.
  if (name === "AbortError" || name === "TimeoutError") return "timeout";
  const code = (error as { cause?: { code?: unknown } })?.cause?.code;
  // Only a system error code, never a message, which may quote a header.
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)
    ? code
    : "network error";
}

/** A failed request as Pi reports it: the status and error body, when its message carries them. */
export interface RequestFailure {
  readonly message: string;
  readonly status?: number;
  readonly body?: unknown;
}

/**
 * Pi reports a failed request (the SDK throws before a response event) as an
 * assistant message with stopReason "error". For an HTTP error its message
 * is the status and the gateway's error object, `401: {"message": ...}`;
 * a stream that failed after it started carries the message alone.
 */
export function requestFailure(message: unknown): RequestFailure | undefined {
  const value = message as
    | { role?: string; stopReason?: string; errorMessage?: string }
    | undefined;
  if (value?.role !== "assistant" || value.stopReason !== "error")
    return undefined;
  const text = value.errorMessage ?? "";
  const match = /^(\d{3})\b:?\s*/.exec(text);
  if (!match?.[1]) return { message: text };
  const rest = text.slice(match[0].length);
  let body: unknown;
  try {
    body = rest.startsWith("{") ? JSON.parse(rest) : undefined;
  } catch {
    // Not a JSON body: the status alone is known.
  }
  return {
    message: text,
    status: Number(match[1]),
    ...(body === undefined ? {} : { body }),
  };
}

/**
 * Whether a failed request was the gateway rejecting the runtime credential,
 * so the next request re-acquires it. A 401 the gateway relays from its own
 * model provider (a provider key the gateway holds) is not: the user's
 * credential was accepted.
 */
export function isCredentialRejection(message: unknown): boolean {
  const failure = requestFailure(message);
  return (
    failure !== undefined &&
    /(^|\D)401(\D|$)|unauthori[sz]ed|invalid api key|authentication failed/i.test(
      failure.message,
    ) &&
    !isUpstreamProviderError(failure.body)
  );
}

/**
 * Whether a failed request was the gateway denying the model (HTTP 403): the
 * credential may be fine while what it is entitled to has changed, so the
 * entitlement is re-read once (`refreshEntitlement`). A 403 the gateway
 * relays from its model provider is not a decision about the entitlement.
 */
export function isModelDenial(message: unknown): boolean {
  const failure = requestFailure(message);
  return (
    failure !== undefined &&
    /(^|\D)403(\D|$)|forbidden/i.test(failure.message) &&
    !isUpstreamProviderError(failure.body)
  );
}

/**
 * The error a failed acceptance request (`--smoke-model`) is reported with.
 * When Pi's message carries the gateway's status, it is classified as the
 * model list check classifies that status (with the error body, so a
 * provider's refusal relayed by the gateway reads as such). A request to a
 * managed endpoint that got no answer (a refused or reset connection, a DNS
 * failure, the client's deadline) is an unreachable gateway, by what PiShip's
 * fetch saw. Pi's "aborted" stop reason, which it sets only when the caller's
 * signal aborted the request, is a cancellation. Anything else without a
 * status (a stream that failed after it started) is a protocol error.
 * Pi's message carries no response headers, so there is no retry time.
 */
export function acceptanceFailure(message: unknown): PiShipError {
  const value = message as
    | { stopReason?: string; errorMessage?: string }
    | undefined;
  const detail = redact(value?.errorMessage ?? value?.stopReason ?? "unknown");
  if (value?.stopReason === "aborted")
    return new PiShipError(
      "REQUEST_CANCELLED",
      `The acceptance model request was cancelled: ${detail}`,
      { component: "inference" },
    );
  const failure = requestFailure(message);
  const transport =
    failure && failure.status === undefined
      ? transportFailures.get(message as object)
      : undefined;
  if (transport)
    return new PiShipError(
      "GATEWAY_UNREACHABLE",
      `The acceptance model request failed: ${detail} (${transport})`,
      {
        component: "inference",
        retryable: true,
        sanitizedDetail: { transport },
      },
    );
  const classified =
    failure?.status === undefined
      ? null
      : classifyGatewayStatus(failure.status, {}, failure.body);
  return new PiShipError(
    classified?.code ?? "GATEWAY_PROTOCOL_ERROR",
    `The acceptance model request failed: ${detail}`,
    {
      component: "inference",
      retryable: classified?.retryable ?? false,
      ...(classified?.userAction ? { userAction: classified.userAction } : {}),
    },
  );
}
