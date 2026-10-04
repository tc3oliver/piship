// Metadata-first audit event contract. Content fields are absent unless a
// distribution explicitly opts in; credential and token bodies are never part
// of an event.

import type { EnforcementPlane } from "./policy.js";

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
  "policy.auto_enabled",
  "policy.auto_disabled",
  "policy.auto_approved",
  "runtime.update",
  "runtime.rollback",
  "model.dispatch",
  "session.export",
  "runtime.mutation.reverted",
  "data.swept",
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
  /**
   * The principal as `principalId` gives it (issuer, `#`, subject), or null
   * without identity. Never a token, an email, or a display name.
   */
  readonly user: string | null;
  readonly session: string | null;
  readonly distribution: string;
  /** Resource the event is about: model key, `server:tool`, tool name, path class. */
  readonly resource?: string;
  readonly decision?: "allowed" | "denied" | "asked" | "approved";
  /** `<policy id>@<version>` when a policy decision is involved. */
  readonly policy?: string;
  readonly rule?: string;
  /** Never `unsupported`: an action without a runtime hook is not recorded. */
  readonly enforcement?: EnforcementPlane;
  /** Short, redacted, content-free metadata. */
  readonly detail?: Readonly<Record<string, string | number | boolean | null>>;
  /** Present only with explicit capture opt-in; always redacted. */
  readonly content?: Readonly<Record<string, string>>;
}

/**
 * Where a tool call came from (`detail.source` of a tool execution event):
 * issued by the model, nested inside a Codemode script, or nested through
 * another extension tool's `ctx.executeTool`.
 */
export const AUDIT_EXECUTION_SOURCES = [
  "top-level",
  "codemode",
  "nested",
] as const;
export type AuditExecutionSource = (typeof AUDIT_EXECUTION_SOURCES)[number];

/**
 * Why a tool call failed before policy was asked (`detail.error` of a tool
 * execution event): the tool name is not registered, or its arguments did
 * not validate.
 */
export const TOOL_CALL_FAILURES = ["not-found", "invalid-arguments"] as const;
export type ToolCallFailure = (typeof TOOL_CALL_FAILURES)[number];

/**
 * `detail` keys added in v0.9. `piship-audit-batch/v1` keeps a closed set of
 * top-level fields, so new metadata travels in `detail`:
 * `source` an AuditExecutionSource, `error` a ToolCallFailure, `parent` the
 * parent tool call ID of a
 * nested call, `exposure` the tool exposure, `selected` the selected
 * (possibly virtual) model, `dispatched` the physical model that received
 * the request, `router` the extension that routed it, and `package` the
 * originating Pi package as `id@version`.
 */
export const AUDIT_GOVERNANCE_DETAIL_KEYS = [
  "source",
  "error",
  "parent",
  "exposure",
  "selected",
  "dispatched",
  "router",
  "package",
] as const;
export type AuditGovernanceDetailKey =
  (typeof AUDIT_GOVERNANCE_DETAIL_KEYS)[number];

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
