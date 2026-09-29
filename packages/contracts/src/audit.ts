// Metadata-first audit event contract. Content fields are absent unless a
// distribution explicitly opts in; credential and token bodies are never part
// of an event.

export const AUDIT_EVENT_TYPES = [
  "session.start",
  "session.end",
  "identity.login",
  "identity.refresh",
  "identity.logout",
  "credential.acquire",
  "credential.refresh",
  "credential.revoke",
  "model.request",
  "model.denied",
  "resource.load",
  "resource.denied",
  "provider.load",
  "provider.denied",
  "tool.request",
  "tool.allowed",
  "tool.denied",
  "mcp.server.start",
  "mcp.call",
  "mcp.denied",
  "policy.loaded",
  "policy.violation",
  "runtime.update",
  "runtime.rollback",
] as const;
export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number];

export const AUDIT_EVENT_SCHEMA = "piship-audit/v1" as const;

export interface AuditEvent {
  readonly schema: typeof AUDIT_EVENT_SCHEMA;
  /**
   * Random UUID assigned once when the event is emitted. A redelivered event
   * keeps its ID, so a receiver drops any ID it has already stored. Every
   * event the audit log emits has one; events written before it was added
   * do not.
   */
  readonly id?: string;
  readonly event: AuditEventType;
  /** RFC 3339 UTC time. */
  readonly time: string;
  /** Identity subject, or null without identity. Never a token. */
  readonly user: string | null;
  readonly session: string | null;
  readonly distribution: string;
  /** Resource the event is about: model key, `server:tool`, tool name, path class. */
  readonly resource?: string;
  readonly decision?: "allowed" | "denied" | "asked" | "approved";
  /** `<policy id>@<version>` when a policy decision is involved. */
  readonly policy?: string;
  readonly rule?: string;
  readonly enforcement?: "control-plane" | "sandbox" | "audit-only";
  /** Short, redacted, content-free metadata. */
  readonly detail?: Readonly<Record<string, string | number | boolean | null>>;
  /** Present only with explicit capture opt-in; always redacted. */
  readonly content?: Readonly<Record<string, string>>;
}

/** Content classes a distribution may opt in to capturing. Off by default. */
export interface AuditCapture {
  readonly promptContent: boolean;
  readonly responseContent: boolean;
  readonly commandText: boolean;
  readonly sourceContent: boolean;
}

export const NO_CONTENT_CAPTURE: AuditCapture = Object.freeze({
  promptContent: false,
  responseContent: false,
  commandText: false,
  sourceContent: false,
});

export const AUDIT_BATCH_SCHEMA = "piship-audit-batch/v1" as const;

/** The body an HTTP audit sink receives: one JSON object per POST. */
export interface AuditBatch {
  readonly schema: typeof AUDIT_BATCH_SCHEMA;
  /** Oldest first. The empty batch is the readiness probe of a required sink. */
  readonly events: readonly AuditEvent[];
}

/**
 * Where the audit log delivers batches. Resolve only once the whole batch is
 * durably accepted; reject otherwise, and the log retries the same events
 * (required sink) or drops and counts them (optional sink). A retry can
 * repeat events that were stored before the failure, so a sink must treat an
 * event whose `id` it has already stored as delivered.
 */
export interface AuditSink {
  write(batch: AuditBatch, signal: AbortSignal): Promise<void>;
}

/** Emits events; implementations handle buffering and sink failures. */
export interface AuditEmitter {
  emit(
    event: Omit<AuditEvent, "schema" | "id" | "time" | "distribution"> & {
      readonly time?: string;
    },
  ): void;
}
