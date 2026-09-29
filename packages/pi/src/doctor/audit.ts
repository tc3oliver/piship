// Audit group: the state of the audit log after doctor's governed session
// closed, each sink with its delivery counts, and local metrics. A sink is
// shown by its host only: the path or query of a sink URL may carry routing
// secrets.
import type { AuditStatus } from "@piship/audit";
import { type GovernanceManifest, resolveTemplate } from "@piship/schema";
import type { LaunchContext } from "../launch/context.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export interface AuditSinkTarget {
  readonly id: string;
  /** `local file`, the host (and port) of an HTTP sink, or `unresolved`. */
  readonly target: string;
}

/** Where each declared sink delivers, without any URL path or query. */
export function auditSinkTargets(
  ctx: LaunchContext,
  manifest: GovernanceManifest,
): AuditSinkTarget[] {
  return manifest.audit.sinks.map((sink) => {
    if (sink.type !== "http" || !sink.url)
      return { id: sink.id, target: "local file" };
    try {
      const url = new URL(
        resolveTemplate(
          "audit.sinks.url",
          sink.url,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
      );
      return { id: sink.id, target: `host ${url.host}` };
    } catch {
      return { id: sink.id, target: "unresolved" };
    }
  });
}

const STATE_TEXT: Record<AuditStatus["state"], string> = {
  disabled: "disabled",
  ok: "healthy",
  degraded: "degraded",
  failed: "failed",
};

export function auditGroup(data: DoctorData, out: DoctorSection): void {
  const governance = data.governance;
  if (!governance) {
    out.info("state", "not configured (the distribution declares no audit)");
  } else {
    const { status, openError, closeError, targets } = governance.audit;
    if (openError) out.bad("state", openError);
    else if (!status)
      out.info("state", "not checked; the governed session did not open");
    else {
      const text = STATE_TEXT[status.state];
      if (status.state === "failed")
        out.bad(
          "state",
          `${text}; governed actions fail closed (AUDIT_UNAVAILABLE) until the required sink recovers`,
        );
      else if (status.state === "degraded") out.warn("state", text);
      else if (status.state === "disabled") out.info("state", text);
      else out.ok("state", text);
      for (const sink of status.sinks) {
        const where =
          targets.find((item) => item.id === sink.id)?.target ?? "unknown";
        const detail = `${sink.type}, ${sink.required ? "required" : "optional"}, ${where}: ${STATE_TEXT[sink.state]}; delivered ${sink.delivered}, pending ${sink.pending}, dropped ${sink.dropped}${sink.lastError ? `; last error: ${sink.lastError}` : ""}`;
        const label = `sink ${sink.id}`;
        if (sink.required && (sink.pending > 0 || sink.dropped > 0))
          out.bad(label, detail);
        else if (sink.state !== "ok" || sink.pending > 0 || sink.dropped > 0)
          out.warn(label, detail);
        else out.ok(label, detail);
      }
      if (status.rejected)
        out.warn("rejected", `${status.rejected} malformed event(s) rejected`);
    }
    if (closeError) out.bad("session end", closeError);
  }
  const denials = Object.values(data.metrics.policyDenials).reduce(
    (sum, count) => sum + count,
    0,
  );
  const failures = Object.entries(data.metrics.startupFailures);
  out.ok(
    "local metrics",
    `${denials} policy denial(s)${failures.length ? `; startup failures ${failures.map(([code, count]) => `${code}=${count}`).join(", ")}` : ""}`,
  );
}
