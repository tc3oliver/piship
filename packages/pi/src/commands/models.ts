import { join } from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { type LaunchContext, prepareAccess } from "../launch/context.js";

/**
 * The models Pi has a usable provider for, read from Pi's own configuration
 * (`models.json` and stored credentials) without any network request.
 */
async function piModels(ctx: LaunchContext): Promise<Set<string> | undefined> {
  try {
    const runtime = await ModelRuntime.create({
      authPath: join(ctx.agentDir, "auth.json"),
      modelsPath: join(ctx.agentDir, "models.json"),
      allowModelNetwork: false,
      signal: AbortSignal.timeout(5000),
    });
    // Configured auth is read from the local credential store and
    // models.json; nothing is asked of a provider.
    return new Set(
      runtime
        .getModels()
        .filter((model) => runtime.hasConfiguredAuth(model.provider))
        .map((model) => `${model.provider}/${model.id}`),
    );
  } catch {
    return undefined;
  }
}

/** `json` prints the same fields as the text, as one JSON object. */
export async function runModels(
  ctx: LaunchContext,
  json = false,
): Promise<void> {
  const prepared = await prepareAccess(ctx, undefined, true);
  if (!prepared.activated || prepared.activated.runtime.kind === "pi-native") {
    // Pi owns the catalog and the sign-in, so the list is what the
    // distribution allows (when it narrows it) among what Pi can use here,
    // read offline.
    const manifest = ctx.metadata.access?.models;
    const allowed =
      prepared.activated?.config.allowedModels ?? manifest?.allowed ?? [];
    const selected = prepared.activated?.selectedModel ?? manifest?.default;
    const usable = await piModels(ctx);
    const names = new Map(
      (manifest?.catalog ?? []).map((entry) => [entry.id, entry.name]),
    );
    const ids = allowed.length > 0 ? allowed : [...(usable ?? [])].sort();
    if (json) {
      ctx.out(
        JSON.stringify(
          {
            inference: "pi-native",
            source: allowed.length > 0 ? "allowlist" : "pi",
            models: ids.map((id) => ({
              id,
              ...(names.has(id) ? { name: names.get(id) } : {}),
              selected: id === selected,
              ...(usable === undefined ? {} : { ready: usable.has(id) }),
            })),
          },
          null,
          2,
        ),
      );
      return;
    }
    if (ids.length === 0) {
      ctx.out(
        "Pi-native inference: no model has a provider set up yet. Start the command and use /login to sign in to a provider, then /model to choose a model.",
      );
      return;
    }
    ctx.out(
      allowed.length > 0
        ? "Models this distribution allows (Pi-native inference; sign in with /login inside the session, choose with /model):"
        : "Models Pi can use here (Pi-native inference; choose with /model inside the session):",
    );
    for (const id of ids) {
      const marker = id === selected ? "*" : " ";
      const state =
        usable === undefined
          ? ""
          : usable.has(id)
            ? "  ready"
            : "  needs /login";
      ctx.out(
        `${marker} ${id.padEnd(40)} ${names.get(id) ?? ""}${state}`.trimEnd(),
      );
    }
    return;
  }
  const { activated } = prepared;
  if (json) {
    ctx.out(
      JSON.stringify(
        {
          inference: activated.runtime.kind,
          models: activated.models.map((model) => {
            const available =
              activated.config.allowedModels.includes(model.id) &&
              model.availability.available;
            return {
              id: model.id,
              name: model.name,
              selected: model.id === activated.selectedModel,
              available,
              ...(available
                ? {}
                : { reason: model.availability.reason ?? "excluded" }),
              contextWindow: model.capabilities.contextWindow ?? null,
              tools: model.capabilities.tools,
              policyTags: model.policyTags,
            };
          }),
        },
        null,
        2,
      ),
    );
    return;
  }
  for (const model of activated.models) {
    const allowed = activated.config.allowedModels.includes(model.id);
    const marker = model.id === activated.selectedModel ? "*" : " ";
    ctx.out(
      `${marker} ${model.id.padEnd(28)} ${model.name.padEnd(24)} ${allowed && model.availability.available ? "available" : `unavailable (${model.availability.reason ?? "excluded"})`}  ctx=${model.capabilities.contextWindow ?? "?"} tools=${model.capabilities.tools ? "yes" : "no"} tags=${model.policyTags.join(",") || "-"}`,
    );
  }
}
