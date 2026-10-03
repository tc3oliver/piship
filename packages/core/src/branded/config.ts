import { PiShipError, redact } from "@piship/contracts";
import {
  accessStatePaths,
  explainConfiguration,
  formatExplanation,
  setPreference,
} from "../index.js";
import type { BrandedContext } from "./context.js";

export async function runConfig(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const [action, key, ...rest] = args;
  const paths = accessStatePaths(ctx.stateDir);
  if (action === "explain") {
    const governance = ctx.metadata.governance?.manifest;
    const rows = await explainConfiguration({
      app: ctx.metadata.app,
      mode: ctx.mode,
      access: ctx.metadata.access,
      stateDir: ctx.stateDir,
      distributionDir: ctx.distributionDir,
      schema: ctx.metadata.manifest.schema,
      ...(governance ? { governance } : {}),
      ...(ctx.metadata.updates ? { updates: ctx.metadata.updates } : {}),
    });
    if (key === "--json") ctx.out(redact(JSON.stringify(rows, null, 2)));
    else ctx.out(formatExplanation(ctx.metadata.app.name, rows));
    return;
  }
  if (
    (action === "set" && key && rest.length === 1) ||
    (action === "unset" && key && rest.length === 0)
  ) {
    setPreference(
      paths.preferences,
      ctx.metadata.access,
      ctx.metadata.app.theme,
      key,
      action === "set" ? rest[0] : undefined,
    );
    ctx.out(
      action === "set"
        ? `Set ${key} (user preference).`
        : `Removed ${key} (user preference).`,
    );
    return;
  }
  throw new PiShipError(
    "CONFIG_INVALID",
    `Usage: ${ctx.metadata.app.command} config explain [--json] | config set <key> <value> | config unset <key>`,
  );
}
