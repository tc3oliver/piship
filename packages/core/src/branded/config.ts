import { PiShipError, redact } from "@piship/contracts";
import {
  accessStatePaths,
  explainConfiguration,
  formatExplanation,
  setPreference,
} from "../index.js";
import { type BrandedContext, governedLock } from "./context.js";

/** Governance settings as `config explain` rows; all distribution-enforced. */
function governanceRows(ctx: BrandedContext) {
  const lock = governedLock(ctx);
  if (!lock) return [];
  const { policy, mcp, sandbox, audit } = lock.governance.manifest;
  const row = (key: string, value: unknown, note?: string) => ({
    key,
    value,
    source: "distribution-enforced" as const,
    overridable: false,
    ...(note ? { note } : {}),
  });
  return [
    row(
      "policy",
      `${policy.id}@${policy.version}`,
      `default ${policy.default}; ${policy.enforced.length} enforced and ${policy.defaults.length} default rule(s); user rules in config/policy.json may only relax defaults`,
    ),
    row("mcp.mode", mcp.mode, `${mcp.servers.length} server(s)`),
    row(
      "sandbox.required",
      sandbox.required,
      "run doctor for the effective containment level",
    ),
    row("sandbox.provider", sandbox.provider ?? "native"),
    ...(sandbox.user ? [row("sandbox.user", sandbox.user)] : []),
    row("sandbox.network", sandbox.network.mode),
    row(
      "audit.sinks",
      audit.enabled
        ? audit.sinks.map(
            (sink) =>
              `${sink.id} (${sink.type}${sink.required ? ", required" : ""})`,
          )
        : [],
      audit.enabled
        ? "metadata only unless content capture is opted in"
        : "disabled",
    ),
  ];
}

export async function runConfig(
  ctx: BrandedContext,
  args: readonly string[],
): Promise<void> {
  const [action, key, ...rest] = args;
  const paths = accessStatePaths(ctx.stateDir);
  if (action === "explain") {
    const rows = [
      ...(await explainConfiguration({
        app: ctx.metadata.app,
        mode: ctx.mode,
        access: ctx.metadata.access,
        stateDir: ctx.stateDir,
        distributionDir: ctx.distributionDir,
      })),
      ...governanceRows(ctx),
    ];
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
