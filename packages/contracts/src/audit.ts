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

/** Emits events; implementations handle buffering and sink failures. */
export interface AuditEmitter {
  emit(
    event: Omit<AuditEvent, "schema" | "time" | "distribution"> & {
      readonly time?: string;
    },
  ): void;
}
