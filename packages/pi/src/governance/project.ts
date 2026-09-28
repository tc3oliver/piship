// Project resources and project MCP definitions, admitted by project trust
// and policy.
import { readFileSync } from "node:fs";
import { relative, sep } from "node:path";
import { type ApprovalChannel, resolveDecision } from "@piship/contracts";
import { type McpServerConfig, parseExternalMcpDefinitions } from "@piship/mcp";
import {
  type ProjectResourceCandidate,
  resourceTrustDecision,
} from "@piship/policy";
import type { GovernanceSession } from "../governance-session.js";
import { KIND_ACTION, type ResourceEvidence } from "./options.js";

export async function resolveProject(
  session: GovernanceSession,
  projectServers: McpServerConfig[],
): Promise<void> {
  const channel = session.startupChannel();
  for (const candidate of session.projectCandidates) {
    if (candidate.dimension === "restrictions") continue;
    const shown = projectPath(session, candidate.path);
    const resource = `project:${shown}`;
    let loaded = false;
    let reason = candidate.reason;
    const kind = candidate.kind;
    const loadable = [
      "instructions",
      "instruction-import",
      "system-prompt",
      "prompts",
      "skills",
      "extensions",
      "themes",
    ].includes(kind);
    if (kind === "mcp") {
      loaded = await projectMcp(session, projectServers, candidate, channel);
      reason = loaded ? "project MCP definitions admitted" : reason;
    } else if (!loadable) {
      reason =
        candidate.effect === "deny"
          ? reason
          : `${kind} from projects are not loaded by this release`;
    } else if (
      candidate.effect !== "deny" &&
      candidate.effect !== "company-approved"
    ) {
      const trust = resourceTrustDecision(
        session.manifest.policy,
        "project",
        kind === "skills" || kind === "extensions" || kind === "themes"
          ? kind
          : kind === "prompts"
            ? "prompts"
            : "instructions",
        session.project.origin,
      );
      if (!trust.allowed) reason = trust.reason;
      else {
        const dimensionDecision =
          candidate.effect === "ask"
            ? await resolveDecision(
                {
                  effect: "ask",
                  policyId: session.engine.id,
                  ruleId: `project-trust.${candidate.dimension}`,
                  enforcement: "control-plane",
                  action: KIND_ACTION[kind] ?? "resource.load",
                  resource,
                  layer: "distribution-enforced",
                },
                channel,
                {
                  title: "Project resource",
                  message: `Load ${shown} from ${session.project.origin} project ${session.project.root}?`,
                },
              )
            : undefined;
        if (dimensionDecision && dimensionDecision.outcome !== "allow")
          reason = `project trust ${candidate.dimension}: ${dimensionDecision.approval ?? "denied"}`;
        else {
          const decision = await session.decide(
            KIND_ACTION[
              kind === "instruction-import" || kind === "system-prompt"
                ? "instructions"
                : kind
            ] ?? "resource.load",
            resource,
            channel,
          );
          loaded = decision.outcome === "allow";
          if (!loaded) reason = `policy ${decision.ruleId}`;
        }
      }
    }
    if (loaded && loadable) loadProject(session, candidate);
    session.emit(loaded ? "resource.load" : "resource.denied", {
      resource,
      detail: {
        kind,
        class: "project",
        origin: candidate.origin,
        dimension: candidate.dimension,
      },
    });
    session.resources.push({
      kind:
        kind === "instruction-import" || kind === "system-prompt"
          ? "instructions"
          : kind === "settings"
            ? "settings"
            : (kind as ResourceEvidence["kind"]),
      class: "project",
      path: shown,
      loaded,
      reason,
      origin: candidate.origin,
    });
  }
}

/** A project path as shown to people and audit: relative to the project root. */
function projectPath(session: GovernanceSession, path: string): string {
  const rel = relative(session.project.root, path);
  return rel && !rel.startsWith("..") ? rel.split(sep).join("/") : path;
}

function loadProject(
  session: GovernanceSession,
  candidate: ProjectResourceCandidate,
): void {
  const path = candidate.resolvedPath;
  switch (candidate.kind) {
    case "instructions":
    case "instruction-import":
    case "system-prompt":
      session.loader.instructions.push({
        path,
        content: readFileSync(path, "utf8"),
      });
      return;
    case "skills":
      session.loader.skills.push(path);
      return;
    case "extensions":
      session.loader.extensions.push(path);
      return;
    case "prompts":
      session.loader.prompts.push(path);
      return;
    case "themes":
      session.loader.themes.push(path);
      return;
  }
}

async function projectMcp(
  session: GovernanceSession,
  projectServers: McpServerConfig[],
  candidate: ProjectResourceCandidate,
  channel: ApprovalChannel | undefined,
): Promise<boolean> {
  const mcp = session.manifest.mcp;
  if (candidate.effect === "deny") return false;
  if (candidate.allowlistOnly || mcp.mode !== "explicit") return false;
  if (mcp.project !== "allow") return false;
  if (candidate.effect === "ask") {
    const answer = await resolveDecision(
      {
        effect: "ask",
        policyId: session.engine.id,
        ruleId: "project-trust.mcp",
        enforcement: "control-plane",
        action: "mcp.server.start",
        resource: `project:${projectPath(session, candidate.path)}`,
        layer: "distribution-enforced",
      },
      channel,
      {
        title: "Project MCP servers",
        message: `Use MCP servers defined in ${projectPath(session, candidate.path)}?`,
      },
    );
    if (answer.outcome !== "allow") return false;
  }
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(candidate.resolvedPath, "utf8"));
  } catch {
    return false;
  }
  const parsed = parseExternalMcpDefinitions(json, "project");
  const declared = new Set(mcp.servers.map((server) => server.id));
  for (const server of parsed.servers)
    if (!declared.has(server.id)) projectServers.push(server);
  return parsed.servers.length > 0;
}
