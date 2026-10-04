import { join } from "node:path";
import {
  ModelRuntime,
  type ProviderModelConfig,
} from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import type { ActivatedAccess } from "@piship/core";
import type { CatalogModel } from "@piship/schema";
import {
  governModelRuntime,
  type GovernedRuntime,
  type ModelPolicy,
  type VirtualModelRule,
} from "../governance.js";
import type { LaunchContext, PreparedAccess } from "./context.js";
import { virtualModelRules } from "./virtual-models.js";

/** Sent as the bearer only for `credential.provider: none`; it is not a secret. */
export const NO_CREDENTIAL_PLACEHOLDER = "piship-no-credential";

export type Model = NonNullable<ReturnType<ModelRuntime["getModel"]>>;

/**
 * The managed provider's physical models. A virtual entry is registered by
 * its router instead (Pi refuses a virtual model whose id is a physical
 * one); a classifier or image model carries its type and API.
 */
export function toPiModels(
  activated: ActivatedAccess,
  catalog: readonly CatalogModel[] = [],
): ProviderModelConfig[] {
  return activated.runtime.models.flatMap((model): ProviderModelConfig[] => {
    const entry = catalog.find((item) => item.id === model.id);
    if (entry?.virtual) return [];
    const base = {
      id: model.id,
      name: model.name,
      input: (model.capabilities.input ?? ["text"]).filter(
        (item): item is "text" | "image" => item === "text" || item === "image",
      ),
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    };
    const contextWindow = model.capabilities.contextWindow ?? 128_000;
    if (entry?.type === "classifier")
      return [
        {
          ...base,
          type: "classifier" as const,
          api: entry.api as never,
          contextWindow,
        },
      ];
    if (entry?.type === "image")
      return [
        {
          ...base,
          type: "image" as const,
          api: entry.api as never,
          output: [...(entry.output ?? ["image"])],
        },
      ];
    return [
      {
        ...base,
        reasoning: model.capabilities.reasoning ?? false,
        contextWindow,
        maxTokens: model.capabilities.maxOutputTokens ?? 8192,
      },
    ];
  });
}

/** An in-memory Pi credential store: managed runtimes never read ~/.pi or auth.json. */
function isolatedCredentialStore() {
  const values = new Map<string, unknown>();
  return {
    async read(id: string) {
      return values.get(id) as never;
    },
    async list() {
      return [];
    },
    async modify(id: string, fn: (current: never) => Promise<unknown>) {
      const next = await fn(values.get(id) as never);
      if (next !== undefined) values.set(id, next);
      return values.get(id) as never;
    },
    async delete(id: string) {
      values.delete(id);
    },
  };
}

export async function createModelRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  policy?: ModelPolicy,
  /** The declared virtual models (`launchVirtualModels`). */
  virtual: readonly VirtualModelRule[] = [],
): Promise<{ modelRuntime: ModelRuntime; governed: GovernedRuntime | null }> {
  const { activated, access } = prepared;
  if (!activated || !access || activated.runtime.kind === "pi-native") {
    const modelRuntime = await ModelRuntime.create({
      authPath: join(ctx.agentDir, "auth.json"),
      modelsPath: join(ctx.agentDir, "models.json"),
    });
    // The effective allowlist includes an enforced model and user narrowing,
    // not only the manifest's list. They limit selection only: the routes
    // of a selectable virtual model may still receive a request.
    const effective = activated?.config;
    const allowedModelKeys = effective
      ? effective.allowedModels
      : (ctx.metadata.access?.models.allowed ?? []);
    const governed =
      ctx.metadata.access || policy
        ? governModelRuntime(
            modelRuntime,
            {
              kind: "pi-native",
              allowedModelKeys,
              restricted: effective?.modelsRestricted ?? false,
              ...(allowedModelKeys.length
                ? {
                    dispatchModelKeys: [
                      ...new Set([
                        ...allowedModelKeys,
                        ...virtual
                          .filter((rule) =>
                            allowedModelKeys.includes(
                              `${rule.provider}/${rule.id}`,
                            ),
                          )
                          .flatMap((rule) =>
                            rule.routes.map(
                              (route) => `${route.provider}/${route.id}`,
                            ),
                          ),
                      ]),
                    ],
                  }
                : {}),
            },
            policy,
            virtual,
          )
        : null;
    return { modelRuntime, governed };
  }
  const catalog = ctx.metadata.access?.models.catalog ?? [];
  // Models that miss an enabled capability's model requirements are not
  // offered for switching or routing; the launch model was checked at
  // activation.
  const allowedModelIds = activated.runtime.models
    .map((model) => model.id)
    .filter(
      (id) =>
        activated.config.allowedModels.includes(id) &&
        !activated.incompatibleModels[id],
    );
  // An enforced model and user narrowing limit selection only: the routes of
  // a selectable virtual model may receive a request. The runtime models are
  // already within the manifest allowlist and the credential entitlement.
  const routes = new Set(
    allowedModelIds.flatMap(
      (id) => catalog.find((item) => item.id === id)?.virtual?.routes ?? [],
    ),
  );
  const dispatchModelIds = activated.runtime.models
    .map((model) => model.id)
    .filter(
      (id) =>
        !catalog.find((item) => item.id === id)?.virtual &&
        !activated.incompatibleModels[id] &&
        (allowedModelIds.includes(id) || routes.has(id)),
    );
  const modelRuntime = await ModelRuntime.create({
    credentials: isolatedCredentialStore() as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  modelRuntime.registerProvider(activated.runtime.providerId, {
    name: ctx.metadata.app.name,
    baseUrl: activated.runtime.baseUrl ?? "",
    api: activated.runtime.api ?? "openai-completions",
    models: toPiModels(activated, catalog),
    // PiShip-Client, so the gateway sees what calls it.
    ...(activated.runtime.headers
      ? { headers: { ...activated.runtime.headers } }
      : {}),
  });
  const governed = governModelRuntime(
    modelRuntime,
    {
      kind: "managed-endpoint",
      providerId: activated.runtime.providerId,
      command: ctx.metadata.app.command,
      allowedModelIds,
      // A virtual model is selected, never dispatched.
      dispatchModelIds,
      apiKey: async ({ force }) => {
        if (!activated.runtime.requiresCredential)
          return NO_CREDENTIAL_PLACEHOLDER;
        const secret = await access.requestSecret({ force });
        if (!secret)
          throw new PiShipError(
            "CREDENTIAL_REQUIRED",
            "No runtime credential is available",
            {
              userAction: `Run ${ctx.metadata.app.command} login`,
            },
          );
        return secret.reveal();
      },
    },
    policy,
    virtual,
  );
  return { modelRuntime, governed };
}

/** The declared virtual models of this launch, under the provider they are registered with. */
export function launchVirtualModels(
  ctx: LaunchContext,
  prepared: PreparedAccess | null,
): VirtualModelRule[] {
  const runtime = prepared?.activated?.runtime;
  return virtualModelRules(
    ctx.metadata,
    ctx.distributionDir,
    runtime?.kind === "managed-endpoint" ? runtime.providerId : undefined,
  );
}
