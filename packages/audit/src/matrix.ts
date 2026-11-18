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
      "events stay in the bounded buffer and in the sink's spool on disk, and are retried on the next flush; nothing is lost",
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
    condition:
      "its spool cannot be written at launch, or a spool a session would replay is corrupt or over the cap",
    sink: "required",
    behavior:
      "AuditLog.open throws AUDIT_UNAVAILABLE; the spool is set aside as <name>.corrupt (the valid lines of a corrupt one kept, unsent), and every open with replaySpool fails until it is removed; an open without it records as usual",
    logState: "launch fails",
    governedActions: "fail closed",
  },
  {
    condition:
      "the collector refuses a replayed event (400, 413, or 422) and takes others",
    sink: "required",
    behavior:
      "the batch is narrowed to that event, which after three refusals in a row, once the collector takes another event alone, moves to <spool>.jsonl.rejected and is never sent again; a collector refusing everything, any other 4xx, and 5xx keep it queued",
    logState: "degraded",
    governedActions: "continue",
  },
  {
    condition: "its spool is full or cannot be written during the session",
    sink: "required",
    behavior:
      "the event stays in the in-memory buffer; assertAvailable() throws AUDIT_UNAVAILABLE until a delivered batch lets the spool be rewritten",
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
      "close() retries the sink until its deadline, then aborts; what is left stays in the spool and is delivered first at the next launch; requiredAuditLoss(status) turns what is left into AUDIT_UNAVAILABLE, which ends the governed session with an error; the login, logout, update, or rollback command, which skips the readiness probe, only warns when every such event is spooled, and fails otherwise (the operation itself is not undone); the log is failed when events were dropped",
    logState: "degraded",
    governedActions: "fail closed",
  },
]);
