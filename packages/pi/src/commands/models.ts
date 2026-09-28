import { type LaunchContext, prepareAccess } from "../launch/context.js";

export async function runModels(ctx: LaunchContext): Promise<void> {
  const prepared = await prepareAccess(ctx, undefined);
  if (!prepared.activated || prepared.activated.runtime.kind === "pi-native") {
    ctx.out(
      "Pi-native inference: use /model inside the session to choose from Pi's configured providers.",
    );
    const allowed = ctx.metadata.access?.models.allowed ?? [];
    if (allowed.length) ctx.out(`Owner allowlist: ${allowed.join(", ")}`);
    return;
  }
  const { activated } = prepared;
  for (const model of activated.models) {
    const allowed = activated.config.allowedModels.includes(model.id);
    const marker = model.id === activated.selectedModel ? "*" : " ";
    ctx.out(
      `${marker} ${model.id.padEnd(28)} ${model.name.padEnd(24)} ${allowed && model.availability.available ? "available" : `unavailable (${model.availability.reason ?? "excluded"})`}  ctx=${model.capabilities.contextWindow ?? "?"} tools=${model.capabilities.tools ? "yes" : "no"} tags=${model.policyTags.join(",") || "-"}`,
    );
  }
}
