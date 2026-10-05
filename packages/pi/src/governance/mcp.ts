import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  type McpAuditEvent,
  McpGovernor,
  type McpServerConfig,
} from "@piship/mcp";
import { trustDecision } from "@piship/policy";
import { defaultMcpServerClass } from "@piship/schema";
import type { GovernanceSession } from "../governance-session.js";
import { mcpToolExposure } from "./exposure.js";

/** Start the declared and admitted project MCP servers under policy. */
export async function startMcp(
  session: GovernanceSession,
  projectServers: McpServerConfig[],
): Promise<void> {
  const mcp = session.manifest.mcp;
  const servers = [
    ...(mcp.mode === "off" ? [] : mcp.servers),
    ...projectServers,
  ] as McpServerConfig[];
  if (!servers.length) return;
  const channel = session.startupChannel();
  // Only distribution-declared urls may carry `${NAME}` references; a
  // project file never gets launch environment values interpolated.
  const declared = new Set(
    mcp.mode === "off" ? [] : mcp.servers.map((server) => server.id),
  );
  // A declared server's trust class is decided by policy.resourceTrust
  // before its start is authorized; a project server was already decided by
  // project trust when it was admitted.
  const classes = new Map(
    (mcp.mode === "off" ? [] : mcp.servers).map((server) => [
      server.id,
      server.class ??
        defaultMcpServerClass(session.options.lock.deployment.mode),
    ]),
  );
  const governor = new McpGovernor({
    servers,
    distributionDir: join(session.options.distributionDir, "resources"),
    workspace: session.project.root,
    fetch: session.options.fetch,
    ...(session.options.mcpPlainHttpFetch
      ? { plainHttpFetch: session.options.mcpPlainHttpFetch }
      : {}),
    ...(session.options.identityClaims
      ? { identityClaims: session.options.identityClaims }
      : {}),
    resolveUrl: (server) =>
      declared.has(server.id)
        ? session.options.resolveTemplate(
            `mcp.servers.${server.id}.url`,
            server.url ?? "",
          )
        : (server.url ?? ""),
    ...(session.sandbox.report.level === "enforced"
      ? { sandbox: session.sandbox }
      : {}),
    ...(session.options.credential
      ? {
          credentialOrigins: session.options.credentialOrigins ?? [],
          credential: async () => {
            const value = await session.options.credential?.();
            if (!value)
              throw new PiShipError(
                "CREDENTIAL_REQUIRED",
                "No runtime credential is available for the MCP server",
              );
            return value;
          },
        }
      : {}),
    // A hidden tool (by its server's exposure rules, or because the policy
    // always denies it) is never offered to the model; every call is still
    // authorized when it happens.
    expose: ({ server, tool }) =>
      mcpToolExposure(session, server, tool) !== "hidden",
    authorize: async (request) => {
      const cls =
        request.action === "mcp.server.start"
          ? classes.get(request.resource)
          : undefined;
      if (cls) {
        const trust = trustDecision(
          session.manifest.policy,
          "mcp-servers",
          cls,
        );
        if (!trust.allowed) {
          session.emit("mcp.server.start", {
            resource: request.resource,
            decision: "denied",
            detail: { class: cls, reason: trust.reason },
          });
          return { allowed: false, reason: trust.reason };
        }
      }
      const channelNow =
        request.action === "mcp.server.start"
          ? channel
          : session.currentChannel();
      const resolved = await session.decide(
        request.action,
        request.resource,
        channelNow,
      );
      return {
        allowed: resolved.outcome === "allow",
        reason: resolved.reason ?? `policy ${resolved.ruleId}`,
        decision: resolved,
      };
    },
    audit: (event: McpAuditEvent) => {
      session.emit(event.event, {
        resource: event.resource,
        ...(event.decision ? { decision: event.decision } : {}),
        ...(event.policy ? { policy: event.policy } : {}),
        ...(event.rule ? { rule: event.rule } : {}),
        ...(event.enforcement ? { enforcement: event.enforcement } : {}),
        ...(event.detail ? { detail: event.detail } : {}),
      });
    },
  });
  session.mcp = governor;
  try {
    session.mcpReports = await governor.start();
  } finally {
    for (const report of governor.health())
      if (report.state !== "denied")
        session.metrics.recordMcpHealth(report.id, report.state);
  }
}
