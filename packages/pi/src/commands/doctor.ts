import { VERSION } from "@earendil-works/pi-coding-agent";
import { describeAuditStatus, LocalMetrics } from "@piship/audit";
import {
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  formatError,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  type ActivatedAccess,
  type DistributionAccess,
  type DoctorLine,
  effectivePrivateOnly,
  governedLock,
  lifecycleDoctor,
  openAccess,
  undeclaredGovernanceHosts,
} from "@piship/core";
import { GovernanceSession, inspectGovernance } from "../governance-session.js";
import { saveMetrics } from "../launch-metrics.js";
import type { LaunchContext } from "../launch/context.js";
import { governanceOptions } from "../launch/governance.js";

async function governanceDoctor(
  ctx: LaunchContext,
  lines: string[],
  ok: DoctorLine,
  bad: DoctorLine,
  warn: DoctorLine,
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock) return;
  const manifest = lock.governance.manifest;
  const options = governanceOptions(ctx, lock, null, false);
  let inspection: Awaited<ReturnType<typeof inspectGovernance>> | undefined;
  lines.push("", "Policy");
  try {
    inspection = await inspectGovernance(options);
    const policy = manifest.policy;
    ok("policy", `${inspection.engine.id}; default ${policy.default}`);
    ok(
      "rules",
      `${policy.enforced.length} enforced, ${policy.defaults.length} defaults${policy.adapter ? ", team adapter" : ""}`,
    );
    for (const diagnostic of inspection.engine.diagnostics)
      warn(diagnostic.source, diagnostic.message);
  } catch (error) {
    bad("policy", formatError(error));
  }
  if (!inspection) return;
  lines.push("", "Project");
  ok("origin", `${inspection.project.origin} (${inspection.project.root})`);
  for (const candidate of inspection.candidates) {
    if (candidate.dimension === "restrictions") continue;
    const line = `${candidate.path}: ${candidate.effect} (${candidate.reason})`;
    if (candidate.effect === "deny") warn(candidate.kind, line);
    else ok(candidate.kind, line);
  }
  lines.push("", "Resources");
  for (const item of inspection.resources) {
    const label = `${item.class} ${item.kind}`;
    const detail = `${item.path}${item.integrity === "verified" ? " (integrity verified)" : ""}`;
    if (item.loaded) ok(label, detail);
    else if (item.class === "certified" && item.integrity !== "verified")
      bad(label, `${detail}: ${item.reason}`);
    else warn(label, `${detail}: not loaded, ${item.reason}`);
  }
  lines.push("", "Capabilities");
  for (const state of inspection.capabilities) {
    const effective = state.axes.effective;
    const provider = state.provider ? ` via ${state.provider}` : "";
    const declared = manifest.capabilities.find(
      (item) => item.name === state.name,
    );
    if (effective.value === "yes") ok(state.name, `effective${provider}`);
    else if (!declared?.enabled) ok(state.name, `disabled${provider}`);
    else bad(state.name, `not effective${provider}: ${effective.reason ?? ""}`);
  }
  lines.push("", "Sandbox");
  const report = inspection.sandbox;
  const containment = `${report.level} (${report.adapter}${report.planes.length ? `: ${report.planes.join(", ")}` : ""})`;
  if (report.level === "enforced") ok("containment", containment);
  else if (report.required)
    bad("containment", `${containment}: ${report.reason ?? "required"}`);
  else
    warn(
      "containment",
      `${containment}${report.reason ? `: ${report.reason}` : ""}`,
    );
  ok("network", report.network);
  ok(
    "scope",
    "tool subprocesses and MCP stdio servers; Pi and in-process extensions are not contained",
  );
  for (const warning of report.warnings) warn("sandbox", warning);
  lines.push("", "MCP and audit");
  let session: GovernanceSession | undefined;
  try {
    session = await GovernanceSession.open(options);
    for (const server of session.mcpReports) {
      const label = `mcp ${server.id}`;
      const detail = `${server.state} (${server.transport}${server.tools.length ? `; ${server.tools.length} tool(s)` : ""})${server.reason ? `: ${server.reason}` : ""}`;
      if (server.state === "healthy") ok(label, detail);
      else if (server.state === "denied") warn(label, detail);
      else if (server.required) bad(label, detail);
      else warn(label, detail);
    }
    if (!manifest.mcp.servers.length) ok("mcp", "no servers declared");
    await session.audit.flush();
    const status = session.audit.status();
    for (const line of describeAuditStatus(status))
      if (status.state === "failed") bad("audit", line);
      else if (status.state === "degraded") warn("audit", line);
      else ok("audit", line);
  } catch (error) {
    bad("launch controls", formatError(error));
  } finally {
    await session?.close();
  }
  const metrics = LocalMetrics.load(ctx.stateDir).snapshot();
  const denials = Object.values(metrics.policyDenials).reduce(
    (sum, count) => sum + count,
    0,
  );
  const failures = Object.entries(metrics.startupFailures);
  ok(
    "local metrics",
    `${denials} policy denial(s)${failures.length ? `; startup failures ${failures.map(([code, count]) => `${code}=${count}`).join(", ")}` : ""}`,
  );
}

export async function runDoctor(ctx: LaunchContext): Promise<void> {
  const lines: string[] = [];
  let failed = false;
  const ok = (label: string, value: string) =>
    lines.push(`  ✓ ${label.padEnd(20)} ${value}`);
  const bad = (label: string, value: string) => {
    failed = true;
    lines.push(`  ✗ ${label.padEnd(20)} ${redact(value)}`);
  };
  const warn = (label: string, value: string) =>
    lines.push(`  ! ${label.padEnd(20)} ${redact(value)}`);
  const { app } = ctx.metadata;
  lines.push(`${app.name} Doctor`, "", "Distribution");
  ok(app.name, `${app.version} (${ctx.mode})`);
  ok("PiShip", ctx.metadata.runtime.pishipVersion);
  ok("Pi", VERSION);
  lifecycleDoctor(ctx, lines, ok, warn);
  if (!ctx.metadata.access) {
    lines.push("", "Access");
    ok("mode", "personal Pi-native (no identity; Pi auth in isolated state)");
    await governanceDoctor(ctx, lines, ok, bad, warn);
    ctx.out(lines.join("\n"));
    if (failed)
      throw new PiShipError(
        "CONFIG_UNAVAILABLE",
        `${app.name} doctor found problems`,
      );
    return;
  }
  const access = ctx.metadata.access;
  // Checked before the managed environment is sanitized, which removes the
  // variable; a real launch refuses in this state, so doctor must too.
  let tlsError: unknown;
  try {
    assertTlsVerificationEnabled();
  } catch (error) {
    tlsError = error;
  }
  let opened: DistributionAccess | undefined;
  const metrics = LocalMetrics.load(ctx.stateDir);
  try {
    opened = openAccess(ctx, undefined, metrics);
    if (ctx.mode === "managed")
      sanitizeManagedEnvironment(process.env, opened.network, access.variables);
  } catch (error) {
    bad("configuration", formatError(error));
  }
  lines.push("", "Identity");
  if (access.identity.mode === "none") ok("mode", "none");
  let activated: ActivatedAccess | undefined;
  if (opened) {
    const status = await opened.status().catch(() => undefined);
    if (access.identity.mode !== "none") {
      if (status?.identity) {
        ok(
          "authenticated",
          status.identity.displayName ?? status.identity.subject,
        );
        ok("issuer", status.identity.issuer);
      } else bad("authenticated", `not signed in; run ${app.command} login`);
    }
    lines.push("Credential");
    ok("provider", access.credential.provider);
    if (opened.store) {
      if (opened.store.kind === "file")
        warn("secret store", opened.store.description);
      else ok("secret store", opened.store.description);
    }
    if (status?.credential.state === "valid")
      ok(
        "valid",
        status.credential.remainingSeconds === undefined
          ? "no expiry"
          : `${Math.floor(status.credential.remainingSeconds / 60)}m remaining`,
      );
    else if (status?.credential.state === "expiring")
      warn(
        "valid",
        `expiring in ${status.credential.remainingSeconds ?? 0}s; refresh on next use`,
      );
    else if (status?.credential.state === "delegated")
      ok("state", "delegated (no PiShip secret)");
    else if (status?.credential.state === "rejected")
      warn("state", "rejected by the gateway; renewed on next use");
    else
      bad(
        "state",
        `${status?.credential.state ?? "unknown"}; run ${app.command} login`,
      );
    lines.push("", "Inference");
    if (tlsError) bad("activation", formatError(tlsError));
    else
      try {
        applyProcessNetworkPolicy(opened.network);
        activated = await opened.activate();
        ok("provider", access.inference.provider);
        if (activated.runtime.kind === "managed-endpoint")
          try {
            const listed = await opened.probeGateway();
            if (listed) ok("gateway", `reachable (${listed.length} listed)`);
          } catch (error) {
            bad("gateway", formatError(error));
          }
        ok(
          "models",
          `${activated.config.allowedModels.length} allowed; default ${activated.selectedModel ?? "Pi default"}`,
        );
      } catch (error) {
        bad("activation", formatError(error));
      }
    // Saved before the governance checks load the metrics again.
    saveMetrics(metrics);
  }
  lines.push("", "Security");
  if (tlsError) bad("TLS verification", "DISABLED in environment");
  else ok("TLS verification", "on");
  // The effective outbound state is what the managed fetch enforces.
  const privateOnly = opened
    ? opened.network.privateOnly
    : effectivePrivateOnly(access, ctx.mode);
  const hosts = opened?.network.allowHosts.join(", ") ?? "";
  if (privateOnly)
    ok(
      "outbound",
      `private-only: declared hosts only${hosts ? ` (${hosts})` : ""}; public fallback denied`,
    );
  else if (ctx.mode === "managed")
    bad("outbound", "not private-only; public fallback is not enforced");
  else
    lines.push(
      `  - ${"outbound".padEnd(20)} any host (personal mode; network.privateOnly is off)`,
    );
  if (privateOnly && opened)
    for (const item of undeclaredGovernanceHosts(
      ctx,
      opened.network.allowHosts,
    ))
      warn(
        item.label,
        `host ${item.host} is not a declared endpoint or in network.allowHosts; private-only requests to it fail with NETWORK_DENIED`,
      );
  ok(
    "proxy environment",
    access.network.proxy.inheritEnvironment ? "inherited" : "ignored",
  );
  ok("enterprise CA", `${access.network.tls.additionalCA.length} bundle(s)`);
  if (ctx.mode === "managed")
    ok("ambient credentials", "removed from the managed runtime environment");
  await governanceDoctor(ctx, lines, ok, bad, warn);
  ctx.out(lines.join("\n"));
  if (failed)
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${app.name} doctor found problems`,
    );
}
