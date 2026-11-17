import { PiShipError, redact } from "@piship/contracts";
import {
  accessStatePaths,
  explainConfiguration,
  forgetProjectTrust,
  formatExplanation,
  listRememberedProjects,
  setPreference,
} from "../index.js";
import { type BrandedContext, openAccess } from "./context.js";

export async function runConfig(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const [action, key, ...rest] = args;
  const paths = accessStatePaths(ctx.stateDir);
  const usage = `Usage: ${ctx.metadata.app.command} config explain [--json] | config set <key> <value> | config unset <key> | config trust list | config trust forget [<path>|--all]`;
  if (args.includes("--help") || args.includes("-h")) {
    ctx.out(
      `${usage}\n\nexplain shows every effective setting and where it comes from; set and unset change your own preferences; trust lists or forgets your remembered project answers.`,
    );
    return;
  }
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
    const count = forgetProjectTrust(ctx.stateDir, target, ctx.forgetPiTrust);
    ctx.out(
      count
        ? `Forgot the remembered answer for ${count} project${count === 1 ? "" : "s"}; ${ctx.metadata.app.command} asks again at the next launch there.`
        : target === "all"
          ? "No project answers are remembered."
          : "No remembered answer for that project.",
    );
    return;
  }
  if (
    (action === "set" && key && rest.length === 1) ||
    (action === "unset" && key && rest.length === 0)
  ) {
    // --smoke and Pi name a model with its provider, `<app id>/<model id>`;
    // the preference holds the catalog id that `models` lists.
    const prefix = `${ctx.metadata.app.id}/`;
    const value =
      key === "model" &&
      rest[0]?.startsWith(prefix) &&
      !ctx.metadata.access?.models.allowed.includes(rest[0])
        ? rest[0].slice(prefix.length)
        : rest[0];
    // Only a current credential's entitlement: an expired one is renewed,
    // and its entitlement re-read, at the next launch.
    let entitled: readonly string[] | undefined;
    if (key === "model" && action === "set")
      try {
        const { credential } = await openAccess(ctx).status();
        if (credential.state === "valid" || credential.state === "expiring")
          entitled = credential.metadata?.models;
      } catch {
        // No readable sign-in: the launch decides.
      }
    setPreference(
      paths.preferences,
      ctx.metadata.access,
      ctx.metadata.app.theme,
      key,
      action === "set" ? value : undefined,
      (notice) => ctx.err(`Notice: ${notice}`),
      ctx.metadata.app.command,
      ctx.mode,
      entitled,
    );
    ctx.out(
      action === "set"
        ? `Set ${key} (user preference).`
        : `Removed ${key} (user preference).`,
    );
    return;
  }
  throw new PiShipError("CONFIG_INVALID", usage, { usage: true });
}
