// Audit: sinks, buffering, and content capture.
import type { AuditCapture } from "@piship/contracts";
import type { DeploymentMode } from "../access.js";
import type { AuditConfig, AuditSinkConfig } from "../governance.js";
import {
  bool,
  conflict,
  durationMs,
  fail,
  list,
  oneOf,
  optionalRecord,
  plainString,
  positiveInteger,
  record,
  referenceUrl,
  unsafe,
} from "./fields.js";

const SINK_ID = /^[a-z][a-z0-9-]{0,31}$/;
const CAPTURE_KEYS = [
  "promptContent",
  "responseContent",
  "commandText",
  "sourceContent",
] as const;

function parseSink(
  entry: unknown,
  path: string,
  variables: readonly string[],
): AuditSinkConfig {
  const sink = record(entry, path, ["id", "type", "url", "required"]);
  const id = plainString(sink.id, `${path}.id`, 32);
  if (!SINK_ID.test(id))
    unsafe(
      `${path}.id`,
      "Sink IDs use lowercase letters, digits, and hyphens; start with a letter",
    );
  const type = oneOf(sink.type, `${path}.type`, ["file", "http"] as const);
  if (type === "file" && sink.url !== undefined)
    conflict(
      `${path}.url`,
      "File sinks write to the distribution state; url applies only to http sinks",
    );
  if (type === "http" && sink.url === undefined)
    fail(`${path}.url`, "An http sink needs a url");
  return {
    id,
    type,
    ...(type === "http"
      ? { url: referenceUrl(sink.url, `${path}.url`, variables) }
      : {}),
    required: bool(sink.required, `${path}.required`, false),
  };
}

export function parseAudit(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
): AuditConfig {
  const audit = optionalRecord(value, "audit", [
    "enabled",
    "sinks",
    "buffer",
    "capture",
  ]);
  const enabled = bool(audit.enabled, "audit.enabled", mode === "managed");
  const sinks =
    audit.sinks === undefined
      ? enabled
        ? [{ id: "local", type: "file" as const, required: false }]
        : []
      : list(
          audit.sinks,
          "audit.sinks",
          (entry, at) => parseSink(entry, at, variables),
          (sink) => sink.id,
        );
  if (enabled && !sinks.length)
    fail("audit.sinks", "Enabled audit needs at least one sink");
  const buffer = optionalRecord(audit.buffer, "audit.buffer", [
    "maxEvents",
    "flushInterval",
  ]);
  const capture = optionalRecord(audit.capture, "audit.capture", CAPTURE_KEYS);
  const captured = {} as Record<(typeof CAPTURE_KEYS)[number], boolean>;
  for (const key of CAPTURE_KEYS)
    captured[key] = bool(capture[key], `audit.capture.${key}`, false);
  return {
    enabled,
    sinks,
    buffer: {
      maxEvents: positiveInteger(
        buffer.maxEvents,
        "audit.buffer.maxEvents",
        1000,
        1_000_000,
      ),
      flushIntervalMs: durationMs(
        buffer.flushInterval,
        "audit.buffer.flushInterval",
        "2s",
      ),
    },
    capture: captured satisfies AuditCapture,
  };
}
