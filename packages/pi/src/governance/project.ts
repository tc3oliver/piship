// Project resources and project MCP definitions, admitted by project trust
// and policy.
import { existsSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import {
  type ApprovalChannel,
  redact,
  resolveDecision,
} from "@piship/contracts";
import { type McpServerConfig, parseExternalMcpDefinitions } from "@piship/mcp";
import {
  assessExtensionProjectTrust,
  claudeDirectories,
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
  await resolveExtensionConfig(session, channel);
  for (const candidate of session.projectCandidates) {
    // Decided as a unit by resolveExtensionConfig.
    if (candidate.kind === "claude" || candidate.kind === "extension-config")
      continue;
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

/**
 * The project configuration that extensions load by themselves once Pi
 * reports the project as trusted: the Claude Code files (`.claude/*`) and
 * the project MCP and agent files. Pi gives an extension one boolean, so the
 * items are admitted as a unit: each item's dimension, then one question for
 * the person when any is `ask`, then a policy decision (`resource.load`) per
 * Claude item. A denial of any item leaves all of them unloaded, and the
 * result is what `isProjectTrusted()` reports. PiShip loads none of these
 * files itself.
 */
async function resolveExtensionConfig(
  session: GovernanceSession,
  channel: ApprovalChannel | undefined,
): Promise<void> {
  const mode = session.options.lock.deployment.mode;
  const assessment = assessExtensionProjectTrust(session.projectCandidates, {
    policy: session.manifest.policy,
    identity: session.project,
    mode,
  });
  const surfaces = assessment.surfaces;
  const shownPaths = surfaces.map((item) => projectPath(session, item.path));
  let blocker: ProjectResourceCandidate | undefined =
    assessment.effect === "deny" ? assessment.decidedBy : undefined;
  let blocked: string | undefined =
    assessment.effect === "deny"
      ? `${blocker ? `${projectPath(session, blocker.path)}: ` : ""}${assessment.reason}`
      : undefined;
  if (
    mode === "managed" &&
    session.options.lock.governance.providers.some(
      (item) => item.capability === "permissions" && item.package,
    ) &&
    claudeDirectories(
      session.project.root,
      session.options.cwd,
      session.sandbox.profile.homeDir,
    ).some((directory) =>
      [
        ".pi/extensions/pi-permission-system/config.json",
        ".pi/agent/pi-permissions.jsonc",
      ].some((path) => existsSync(join(directory, path))),
    )
  )
    blocked = "managed permission provider project overrides are not admitted";
  if (
    !blocked &&
    mode === "managed" &&
    session.options.lock.governance.providers.some(
      (item) => item.capability === "permissions" && item.package,
    ) &&
    (session.sandbox.report.level !== "enforced" ||
      !session.sandbox.report.planes.includes("git-control-protection"))
  )
    blocked =
      "managed permission provider project trust requires enforced protected paths";
  if (!blocked && assessment.effect === "ask") {
    const answer = await resolveDecision(
      {
        effect: "ask",
        policyId: session.engine.id,
        ruleId: "project-trust.claude",
        enforcement: "control-plane",
        action: "resource.load",
        resource: "project:.claude",
        layer: "distribution-enforced",
      },
      channel,
      {
        title: "Project Claude Code configuration",
        message: `Load the Claude Code configuration of ${session.project.origin} project ${safePrompt(session.project.root)}?\n${shownPaths.map(safePrompt).join("\n")}`,
      },
    );
    if (answer.outcome !== "allow")
      blocked = `project trust: ${answer.approval ?? "denied"}`;
  }
  if (!blocked)
    for (const item of surfaces) {
      if (item.kind !== "claude") continue;
      const decision = await session.decide(
        "resource.load",
        `project:${projectPath(session, item.path)}`,
        channel,
      );
      if (decision.outcome === "allow") continue;
      blocked = `policy ${decision.ruleId}`;
      blocker = item;
      break;
    }
  const trusted = blocked === undefined;
  const reason = trusted ? assessment.reason : redact(blocked ?? "");
  session.projectTrust = { trusted, surfaces: surfaces.length, reason };
  for (const item of surfaces) {
    if (item.kind !== "claude" && item.kind !== "extension-config") continue;
    const shown = projectPath(session, item.path);
    const resource = `project:${shown}`;
    session.emit(trusted ? "resource.load" : "resource.denied", {
      resource,
      detail: {
        kind: item.kind,
        class: "project",
        origin: item.origin,
        dimension: item.dimension,
      },
    });
    session.resources.push({
      kind: item.kind,
      class: "project",
      path: shown,
      loaded: trusted,
      reason: trusted
        ? "admitted for extensions that read project configuration; PiShip loads none of it itself"
        : item === blocker
          ? redact(blocked ?? item.reason)
          : `not loaded: the project configuration is admitted as a unit (${redact(reason)})`,
      origin: item.origin,
    });
  }
  if (surfaces.length === 0 && trusted) return;
  session.emit(trusted ? "resource.load" : "resource.denied", {
    resource: "project:.claude",
    detail: {
      kind: "claude",
      class: "project",
      origin: session.project.origin,
      seam: "project-trust",
      items: surfaces.length,
    },
  });
  if (!trusted)
    session.notice(
      `Project Claude Code configuration (${shownPaths.slice(0, 4).join(", ")}${surfaces.length > 4 ? ", ..." : ""}) is not loaded: ${redact(reason)}.`,
    );
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

function safePrompt(value: string): string {
  return Array.from(value, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || (code >= 127 && code <= 159) ? "?" : character;
  }).join("");
}
