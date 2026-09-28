import { join } from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import type { ActivatedAccess } from "@piship/core";
import {
  governModelRuntime,
  type GovernedRuntime,
  type ModelPolicy,
} from "../governance.js";
import type { LaunchContext, PreparedAccess } from "./context.js";

/** Sent as the bearer only for `credential.provider: none`; it is not a secret. */
export const NO_CREDENTIAL_PLACEHOLDER = "piship-no-credential";

export type Model = NonNullable<ReturnType<ModelRuntime["getModel"]>>;

function toPiModels(activated: ActivatedAccess) {
  return activated.runtime.models.map((model) => ({
    id: model.id,
    name: model.name,
    reasoning: model.capabilities.reasoning ?? false,
    input: (model.capabilities.input ?? ["text"]).filter(
      (item): item is "text" | "image" => item === "text" || item === "image",
    ),
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: model.capabilities.contextWindow ?? 128_000,
    maxTokens: model.capabilities.maxOutputTokens ?? 8192,
  }));
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
): Promise<{ modelRuntime: ModelRuntime; governed: GovernedRuntime | null }> {
  const { activated, access } = prepared;
  if (!activated || !access || activated.runtime.kind === "pi-native") {
    const modelRuntime = await ModelRuntime.create({
      authPath: join(ctx.agentDir, "auth.json"),
      modelsPath: join(ctx.agentDir, "models.json"),
    });
    // The effective allowlist includes an enforced model and user narrowing,
    // not only the manifest's list.
    const effective = activated?.config;
    const governed =
      ctx.metadata.access || policy
        ? governModelRuntime(
            modelRuntime,
            {
              kind: "pi-native",
              allowedModelKeys: effective
                ? effective.allowedModels
                : (ctx.metadata.access?.models.allowed ?? []),
              restricted: effective?.modelsRestricted ?? false,
            },
            policy,
          )
        : null;
    return { modelRuntime, governed };
  }
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
    models: toPiModels(activated),
  });
  const governed = governModelRuntime(
    modelRuntime,
    {
      kind: "managed-endpoint",
      providerId: activated.runtime.providerId,
      // Models that miss an enabled capability's model requirements are not
      // offered for switching; the launch model was checked at activation.
      allowedModelIds: activated.runtime.models
        .map((model) => model.id)
        .filter(
          (id) =>
            activated.config.allowedModels.includes(id) &&
            !activated.incompatibleModels[id],
        ),
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
  );
  return { modelRuntime, governed };
}
