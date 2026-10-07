import { PiShipError, redact } from "@piship/contracts";
import {
  accessStatePaths,
  explainConfiguration,
  forgetProjectTrust,
  formatExplanation,
  listRememberedProjects,
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
      ...(ctx.metadata.searchTools
        ? {
            searchTools: Object.fromEntries(
              Object.entries(ctx.metadata.searchTools).map(([tool, entry]) => [
                tool,
                entry.version,
              ]),
            ),
          }
        : {}),
    });
    if (key === "--json") ctx.out(redact(JSON.stringify(rows, null, 2)));
    else ctx.out(formatExplanation(ctx.metadata.app.name, rows));
    return;
  }
  if (action === "trust" && key === "list" && rest.length === 0) {
    const remembered = listRememberedProjects(ctx.stateDir);
    ctx.out(
      remembered.length
        ? remembered
            .map(
              (item) =>
                `${item.answer === "allow" ? "trusted    " : "not trusted"} ${item.root} (${item.items.length} item${item.items.length === 1 ? "" : "s"}, ${item.answeredAt})`,
            )
            .join("\n")
        : "No project answers are remembered.",
    );
    return;
  }
  if (action === "trust" && key === "forget" && rest.length <= 1) {
    const target = rest[0] === "--all" ? "all" : (rest[0] ?? process.cwd());
    const count = forgetProjectTrust(ctx.stateDir, target);
    ctx.out(
      count
        ? `Forgot the remembered answer for ${count} project${count === 1 ? "" : "s"}; ${ctx.metadata.app.command} asks again at the next launch there.`
        : "No remembered answer for that project.",
    );
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
      (notice) => ctx.err(`Notice: ${notice}`),
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
    `Usage: ${ctx.metadata.app.command} config explain [--json] | config set <key> <value> | config unset <key> | config trust list | config trust forget [<path>|--all]`,
  );
}
