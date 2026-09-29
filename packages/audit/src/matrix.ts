import type { AuditStatus } from "./log.js";

export interface AuditFailureRule {
  readonly condition: string;
  readonly sink: "optional" | "required" | "any";
  readonly behavior: string;
  readonly logState: "ok" | "degraded" | "failed" | "launch fails";
  readonly governedActions: "continue" | "fail closed";
}

/** The audit failure matrix, as implemented by AuditLog. */
export const AUDIT_FAILURE_MATRIX: readonly AuditFailureRule[] = Object.freeze([
  {
    condition:
      "cannot be opened (file) or reached (http empty-batch probe) at launch",
    sink: "required",
    behavior: "AuditLog.open throws AUDIT_UNAVAILABLE",
    logState: "launch fails",
    governedActions: "fail closed",
  },
  {
    condition: "cannot be opened at launch",
    sink: "optional",
    behavior:
      "sink starts degraded; every flush retries, failed batches are dropped and counted",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition: "delivery fails",
    sink: "optional",
    behavior: "the batch is dropped for that sink and counted as dropped",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition: "buffer for the sink is full",
    sink: "optional",
    behavior: "new events for that sink are dropped and counted",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition: "delivery fails",
    sink: "required",
    behavior:
      "events stay in the bounded buffer and are retried on the next flush; nothing is lost",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition: "buffer is full while delivery keeps failing",
    sink: "required",
    behavior:
      "new events are dropped and counted; assertAvailable() throws AUDIT_UNAVAILABLE until a flush drains the buffer",
    logState: "failed",
    governedActions: "fail closed",
  },
  {
    condition: "close() deadline passes",
    sink: "optional",
    behavior:
      "in-flight delivery is aborted and the batch is counted as dropped",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition:
      "events are still undelivered at close, or were dropped (full buffer, or emitted after close)",
    sink: "required",
    behavior:
      "close() retries the sink until its deadline, then aborts; requiredAuditLoss(status) turns what is left into AUDIT_UNAVAILABLE, which ends the governed session or the login, logout, update, or rollback command with an error (the operation itself is not undone); the log is failed when events were dropped",
    logState: "degraded",
    governedActions: "fail closed",
  },
]);

/** Plain-text rendering of the failure matrix for docs and doctor. */
export function formatAuditFailureMatrix(): string {
  return AUDIT_FAILURE_MATRIX.map(
    (rule) =>
      `${rule.sink} sink, ${rule.condition}: ${rule.behavior} [log ${rule.logState}; governed actions ${rule.governedActions}]`,
  ).join("\n");
}

/** Doctor lines for an audit status. Messages are already redacted. */
export function describeAuditStatus(status: AuditStatus): string[] {
  if (status.state === "disabled") return ["audit: disabled"];
  const lines = [`audit: ${status.state}`];
  for (const sink of status.sinks) {
    const kind = `${sink.type}, ${sink.required ? "required" : "optional"}`;
    let line = `audit sink ${sink.id} (${kind}): ${sink.state}; delivered ${sink.delivered}, pending ${sink.pending}, dropped ${sink.dropped}`;
    if (sink.lastError) line += `; last error: ${sink.lastError}`;
    lines.push(line);
  }
  if (status.rejected)
    lines.push(`audit: ${status.rejected} malformed event(s) rejected`);
  if (status.state === "failed")
    lines.push(
      "audit: governed actions fail closed (AUDIT_UNAVAILABLE) until the required sink recovers",
    );
  return lines;
}
