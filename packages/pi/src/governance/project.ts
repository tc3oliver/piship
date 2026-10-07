// Project resources and project MCP definitions, admitted by project trust
// and policy.
import { existsSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { type ApprovalChannel, redact } from "@piship/contracts";
import { type McpServerConfig, parseExternalMcpDefinitions } from "@piship/mcp";
import {
  assessExtensionProjectTrust,
  claudeDirectories,
  type ExtensionTrustAssessment,
  type ProjectResourceCandidate,
  resourceTrustDecision,
} from "@piship/policy";
import type { GovernanceSession } from "../governance-session.js";
import { KIND_ACTION, type ResourceEvidence } from "./options.js";
import {
  type AskItem,
  answerReason,
  LeftOut,
  ProjectAsk,
} from "./project-ask.js";

const LOADABLE = [
  "instructions",
  "instruction-import",
  "system-prompt",
  "prompts",
  "skills",
  "extensions",
  "themes",
];

function trustKind(
  kind: string,
): "skills" | "extensions" | "themes" | "prompts" | "instructions" {
  return kind === "skills" || kind === "extensions" || kind === "themes"
    ? kind
    : kind === "prompts"
      ? "prompts"
      : "instructions";
}

export async function resolveProject(
  session: GovernanceSession,
  projectServers: McpServerConfig[],
): Promise<void> {
  const channel = session.startupChannel();
  const mode = session.options.lock.deployment.mode;
  const assessment = assessExtensionProjectTrust(session.projectCandidates, {
    policy: session.manifest.policy,
    identity: session.project,
    mode,
  });
  const blocking = extensionBlock(session, assessment);
  const items = askItems(session, assessment, blocking.blocked === undefined);
  // One question for every item of the project that policy asks about.
  const ask = new ProjectAsk(
    session,
    channel,
    items,
    items.every((item) => item.claude),
  );
  const leftOut = new LeftOut(session);
  await resolveExtensionConfig(
    session,
    channel,
    assessment,
    blocking,
    ask,
    leftOut,
  );
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
    const loadable = LOADABLE.includes(kind);
    if (kind === "mcp") {
      loaded = await projectMcp(
        session,
        projectServers,
        candidate,
        ask,
        leftOut,
      );
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
        trustKind(kind),
        session.project.origin,
      );
      if (!trust.allowed && trust.effect !== "ask") {
        reason = trust.reason;
        leftOut.add(
          shown,
          candidate.resolvedPath,
          leftOut.manifestHint(
            session.manifest.policy.resourceTrust.project === "deny"
              ? "policy.resourceTrust.project"
              : `policy.projectTrust.${candidate.origin}.${candidate.dimension}`,
          ),
        );
      } else {
        const dimensionDecision =
          candidate.effect === "ask" ? await ask.answer() : undefined;
        if (dimensionDecision && dimensionDecision.outcome !== "allow") {
          reason = answerReason(
            dimensionDecision,
            session.options.lock.app.command,
          );
          leftOut.add(
            shown,
            candidate.resolvedPath,
            leftOut.askedHint(dimensionDecision),
          );
        } else {
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
          if (!loaded) {
            reason = `policy ${decision.ruleId}`;
            leftOut.add(
              shown,
              candidate.resolvedPath,
              `denied by policy rule ${decision.ruleId}`,
            );
          }
        }
      }
    } else if (candidate.effect === "deny") {
      leftOut.add(
        shown,
        candidate.resolvedPath,
        leftOut.manifestHint(
          `policy.projectTrust.${candidate.origin}.${candidate.dimension}`,
        ),
      );
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
  leftOut.flush();
}

/**
 * Why the project configuration an extension reads is closed before anyone is
 * asked, when it is: a denied item, or a managed permission provider whose
 * project overrides or protected paths cannot be admitted.
 */
function extensionBlock(
  session: GovernanceSession,
  assessment: ExtensionTrustAssessment,
): {
  blocked: string | undefined;
  blocker: ProjectResourceCandidate | undefined;
} {
  const mode = session.options.lock.deployment.mode;
  const blocker: ProjectResourceCandidate | undefined =
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
  return { blocked, blocker };
}

/**
 * The project items policy asks the person about, so one question covers
 * them: the configuration an extension reads when its unit is `ask`, and each
 * item whose own dimension is `ask`.
 */
function askItems(
  session: GovernanceSession,
  assessment: ExtensionTrustAssessment,
  open: boolean,
): (AskItem & { claude: boolean })[] {
  const items = new Map<string, AskItem & { claude: boolean }>();
  const add = (candidate: ProjectResourceCandidate, claude: boolean): void => {
    const path = projectPath(session, candidate.path);
    const known = items.get(path);
    if (known) known.claude = known.claude && claude;
    else
      items.set(path, { path, resolvedPath: candidate.resolvedPath, claude });
  };
  if (open && assessment.effect === "ask")
    for (const surface of assessment.surfaces)
      add(
        surface,
        surface.kind === "claude" || surface.kind === "extension-config",
      );
  const mcp = session.manifest.mcp;
  for (const candidate of session.projectCandidates) {
    if (candidate.kind === "claude" || candidate.kind === "extension-config")
      continue;
    if (candidate.dimension === "restrictions" || candidate.effect !== "ask")
      continue;
    if (candidate.kind === "mcp") {
      if (
        !candidate.allowlistOnly &&
        mcp.mode === "explicit" &&
        mcp.project === "allow"
      )
        add(candidate, false);
      continue;
    }
    if (!LOADABLE.includes(candidate.kind)) continue;
    const trust = resourceTrustDecision(
      session.manifest.policy,
      "project",
      trustKind(candidate.kind),
      session.project.origin,
    );
    if (trust.allowed || trust.effect === "ask") add(candidate, false);
  }
  return [...items.values()];
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
  assessment: ExtensionTrustAssessment,
  blocking: ReturnType<typeof extensionBlock>,
  ask: ProjectAsk,
  leftOut: LeftOut,
): Promise<void> {
  const surfaces = assessment.surfaces;
  let { blocked, blocker } = blocking;
  let hint: string | undefined = blocked
    ? assessment.effect === "deny" && assessment.decidedBy
      ? leftOut.manifestHint(
          `policy.projectTrust.${assessment.decidedBy.origin}.${assessment.decidedBy.dimension}`,
        )
      : "the distribution policy does not admit it"
    : undefined;
  if (!blocked && assessment.effect === "ask") {
    const answer = await ask.answer();
    if (answer.outcome !== "allow") {
      blocked = answerReason(answer, session.options.lock.app.command);
      hint = leftOut.askedHint(answer);
    }
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
      hint = `denied by policy rule ${decision.ruleId}`;
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
    for (const item of surfaces)
      if (item.kind === "claude" || item.kind === "extension-config")
        leftOut.add(
          projectPath(session, item.path),
          item.resolvedPath,
          hint ?? redact(reason),
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
  ask: ProjectAsk,
  leftOut: LeftOut,
): Promise<boolean> {
  const mcp = session.manifest.mcp;
  const shown = projectPath(session, candidate.path);
  if (candidate.effect === "deny") {
    leftOut.add(
      shown,
      candidate.resolvedPath,
      leftOut.manifestHint(
        `policy.projectTrust.${candidate.origin}.${candidate.dimension}`,
      ),
    );
    return false;
  }
  if (candidate.allowlistOnly || mcp.mode !== "explicit") return false;
  if (mcp.project !== "allow") return false;
  if (candidate.effect === "ask") {
    const answer = await ask.answer();
    if (answer.outcome !== "allow") {
      leftOut.add(shown, candidate.resolvedPath, leftOut.askedHint(answer));
      return false;
    }
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
