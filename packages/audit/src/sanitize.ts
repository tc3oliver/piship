import {
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  type AuditCapture,
  type AuditEvent,
  type AuditEventType,
  PiShipError,
  REDACTED_TEXT,
  redact,
  SECRET_KEY_PATTERN,
  SecretValue,
} from "@piship/contracts";

/** Content classes an event may carry and the capture flag that admits each. */
export const AUDIT_CONTENT_CLASSES = {
  prompt: "promptContent",
  response: "responseContent",
  command: "commandText",
  source: "sourceContent",
} as const satisfies Record<string, keyof AuditCapture>;
export type AuditContentClass = keyof typeof AUDIT_CONTENT_CLASSES;

/** Limits applied by `sanitizeEvent`. */
export const AUDIT_LIMITS = Object.freeze({
  fieldChars: 512,
  detailKeys: 32,
  detailValueChars: 256,
  contentChars: 8192,
});

const TRUNCATED = "…[truncated]";
const DETAIL_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const DECISIONS = new Set(["allowed", "denied", "asked", "approved"]);
const ENFORCEMENT = new Set(["control-plane", "sandbox", "audit-only"]);
const EVENT_TYPES = new Set<string>(AUDIT_EVENT_TYPES);

/** Raw input accepted by `sanitizeEvent`. Anything unexpected is dropped. */
export interface AuditEventInput {
  readonly event: AuditEventType | string;
  readonly distribution: string;
  readonly time?: string | Date;
  readonly user?: string | null;
  readonly session?: string | null;
  readonly resource?: string;
  readonly decision?: AuditEvent["decision"];
  readonly policy?: string;
  readonly rule?: string;
  readonly enforcement?: AuditEvent["enforcement"];
  readonly detail?: Readonly<Record<string, unknown>>;
  /** Keyed by content class; kept only when the class is opted in. */
  readonly content?: Readonly<Partial<Record<AuditContentClass, unknown>>>;
}

/**
 * Redact secret values and token shapes from text. This is `redact` from
 * `@piship/contracts`: audit uses the same pattern set as every other
 * redaction path.
 */
export function scrubText(text: string): string {
  return redact(text);
}

function cap(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - TRUNCATED.length))}${TRUNCATED}`;
}

/** Scrub, strip control characters, and cap one metadata string. */
function metadataString(value: unknown, limit: number): string | undefined {
  if (value instanceof SecretValue) return REDACTED_TEXT;
  if (typeof value !== "string") return undefined;
  // Control characters are removed after scrubbing so they cannot split a token.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional control character removal
  const text = scrubText(value).replace(/[\u0000-\u001f\u007f]+/g, " ");
  return cap(text, limit);
}

function nullableString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return metadataString(value, AUDIT_LIMITS.fieldChars) ?? null;
}

function eventTime(value: unknown, now: () => Date): string {
  const date =
    value instanceof Date
      ? value
      : typeof value === "string"
        ? new Date(value)
        : now();
  if (Number.isNaN(date.getTime())) return now().toISOString();
  return date.toISOString();
}

function detailValue(
  key: string,
  value: unknown,
): string | number | boolean | null | undefined {
  if (value instanceof SecretValue) return undefined;
  if (value === null) return null;
  if (SECRET_KEY_PATTERN.test(key)) return REDACTED_TEXT;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string")
    return metadataString(value, AUDIT_LIMITS.detailValueChars);
  return undefined;
}

function sanitizeDetail(
  detail: unknown,
): Record<string, string | number | boolean | null> | undefined {
  if (!detail || typeof detail !== "object" || Array.isArray(detail))
    return undefined;
  const output: Record<string, string | number | boolean | null> = {};
  let count = 0;
  for (const [key, value] of Object.entries(detail)) {
    if (count >= AUDIT_LIMITS.detailKeys) break;
    if (!DETAIL_KEY.test(key)) continue;
    const sanitized = detailValue(key, value);
    if (sanitized === undefined) continue;
    output[key] = sanitized;
    count += 1;
  }
  return count ? output : undefined;
}

function sanitizeContent(
  content: unknown,
  capture: AuditCapture,
): Record<string, string> | undefined {
  if (!content || typeof content !== "object" || Array.isArray(content))
    return undefined;
  const output: Record<string, string> = {};
  for (const [name, flag] of Object.entries(AUDIT_CONTENT_CLASSES)) {
    if (capture[flag] !== true) continue;
    const value = (content as Record<string, unknown>)[name];
    if (typeof value !== "string") continue;
    output[name] = cap(scrubText(value), AUDIT_LIMITS.contentChars);
  }
  return Object.keys(output).length ? output : undefined;
}

export function isAuditEventType(value: unknown): value is AuditEventType {
  return typeof value === "string" && EVENT_TYPES.has(value);
}

/**
 * Build a complete `piship-audit/v1` event from untrusted input. Metadata is
 * redacted and capped; content survives only for opted-in capture classes and
 * is redacted too; SecretValue instances and token shapes never survive.
 */
export function sanitizeEvent(
  input: AuditEventInput,
  capture: AuditCapture,
  now: () => Date = () => new Date(),
): AuditEvent {
  if (!input || typeof input !== "object")
    throw new PiShipError("CONFIG_INVALID", "Audit event must be an object", {
      component: "audit",
    });
  if (!isAuditEventType(input.event))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown audit event type: ${cap(scrubText(String(input.event)), 64)}`,
      { component: "audit" },
    );
  const distribution = metadataString(input.distribution, 128);
  if (!distribution)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Audit event requires a distribution ID",
      { component: "audit" },
    );
  const event: {
    -readonly [K in keyof AuditEvent]: AuditEvent[K];
  } = {
    schema: AUDIT_EVENT_SCHEMA,
    event: input.event,
    time: eventTime(input.time, now),
    user: nullableString(input.user),
    session: nullableString(input.session),
    distribution,
  };
  const resource = metadataString(input.resource, AUDIT_LIMITS.fieldChars);
  if (resource !== undefined) event.resource = resource;
  if (typeof input.decision === "string" && DECISIONS.has(input.decision))
    event.decision = input.decision;
  const policy = metadataString(input.policy, AUDIT_LIMITS.fieldChars);
  if (policy !== undefined) event.policy = policy;
  const rule = metadataString(input.rule, AUDIT_LIMITS.fieldChars);
  if (rule !== undefined) event.rule = rule;
  if (
    typeof input.enforcement === "string" &&
    ENFORCEMENT.has(input.enforcement)
  )
    event.enforcement = input.enforcement;
  const detail = sanitizeDetail(input.detail);
  if (detail) event.detail = detail;
  const content = sanitizeContent(input.content, capture);
  if (content) event.content = content;
  return event;
}
