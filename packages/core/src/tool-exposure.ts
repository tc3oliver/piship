// Static tool exposure checks and lock evidence for piship/v1alpha6: what
// can be decided from the manifest alone, before any extension code runs.
// Tools that extensions register are checked at launch (packages/pi).
import { PiShipError } from "@piship/contracts";
import {
  matchAction,
  matchGlob,
  overlappingTies,
  resolveExposure,
} from "@piship/policy";
import {
  type Manifest,
  ManifestError,
  type ToolExposureRule,
} from "@piship/schema";
import type { LockedToolExposure } from "./lock-schema.js";

/** PiShip's own tools; `ask_user` only with the piship-ask-user builtin. */
function pishipTools(manifest: Manifest): string[] {
  const askUser =
    manifest.governance?.resources.builtin.includes("piship-ask-user") ?? false;
  return ["read", "write", "edit", "bash", ...(askUser ? ["ask_user"] : [])];
}

function declaredServers(manifest: Manifest) {
  const mcp = manifest.governance?.mcp;
  return !mcp || mcp.mode === "off" ? [] : mcp.servers;
}

function rejectTies(rules: readonly ToolExposureRule[], path: string): void {
  const [tie] = overlappingTies(rules);
  if (tie)
    throw new ManifestError(
      "invalid field",
      path,
      `${tie[0]} and ${tie[1]} are equally specific and can match the same tool; make one more specific`,
    );
}

/**
 * Exposure rules no tool can resolve (two equally specific globs that can
 * match the same name) are invalid. In managed mode, Codemode is refused
 * while a PiShip tool it can reach is decided only by the policy's default:
 * a script would otherwise run it on a fallback nobody wrote. MCP and
 * extension tools are known only at launch, which checks them again.
 */
export function checkToolExposure(manifest: Manifest): void {
  const tools = manifest.runtime.tools;
  if (!tools) return;
  rejectTies(tools.exposure, "runtime.tools.exposure");
  for (const server of declaredServers(manifest))
    rejectTies(server.toolExposure ?? [], `mcp.servers.${server.id}.tools`);
  const policy = manifest.governance?.policy;
  if (
    tools.codemode === "off" ||
    manifest.deployment.mode !== "managed" ||
    !policy
  )
    return;
  const rules = [...policy.enforced, ...policy.defaults];
  for (const name of pishipTools(manifest)) {
    const resolved = resolveExposure(name, tools.exposure, "direct");
    if (
      "tie" in resolved ||
      !["direct", "codemode", "deferred"].includes(resolved.exposure)
    )
      continue;
    const decided = rules.some(
      (rule) =>
        matchAction(rule.action, "tool.execute") &&
        matchGlob(rule.resource, name),
    );
    if (!decided)
      throw new PiShipError(
        "POLICY_DENIED",
        `runtime.tools.codemode is ${tools.codemode}, but no policy rule decides tool.execute ${name}, which Codemode can call`,
        {
          userAction: `Add a policy rule for tool.execute ${name}, hide it with runtime.tools.exposure, or set runtime.tools.codemode: off`,
          component: "policy",
        },
      );
  }
}

/**
 * The exposure the lock records: PiShip's own tools resolved against
 * `runtime.tools.exposure`, and each declared MCP server's rules as
 * `<server>:<glob>`, with its default as `<server>:*`. A policy deny still
 * hides a tool at launch; that is not decided here.
 */
export function lockedTools(manifest: Manifest): LockedToolExposure[] {
  const tools = manifest.runtime.tools;
  if (!tools) return [];
  const locked: LockedToolExposure[] = pishipTools(manifest).map((name) => {
    const resolved = resolveExposure(name, tools.exposure, "direct");
    return {
      tool: name,
      origin: "piship",
      exposure: "tie" in resolved ? "hidden" : resolved.exposure,
    };
  });
  for (const server of declaredServers(manifest)) {
    const rules = server.toolExposure ?? [];
    if (!rules.some((rule) => rule.pattern === "*"))
      locked.push({
        tool: `${server.id}:*`,
        origin: "mcp",
        exposure: server.exposure ?? "direct",
      });
    for (const rule of rules)
      locked.push({
        tool: `${server.id}:${rule.pattern}`,
        origin: "mcp",
        exposure: rule.exposure,
      });
  }
  return locked;
}
