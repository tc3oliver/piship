import type { GovernanceManifest } from "@piship/schema";
import { byKey, type Collector, compare, keys, safeUrl } from "../collector.js";
import type { Verdict } from "../types.js";

const PLAIN_HTTP: Verdict = [
  "high",
  "Audit sink may be reached over plain HTTP to a private or internal host; audit events are unencrypted and can be dropped or altered in transit.",
];

const HTTPS_ONLY = "Audit sink is reached over https only.";

export function audit(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const x = b.audit;
  const y = a.audit;
  out.scalar("audit", "audit enabled", x?.enabled, y?.enabled, (_, e) =>
    e === "false"
      ? ["high", "Disables the audit log."]
      : ["medium", "Enables the audit log."],
  );
  const before = byKey(x?.sinks, (item) => item.id);
  const after = byKey(y?.sinks, (item) => item.id);
  for (const id of keys(before, after)) {
    const bs = before.get(id);
    const as = after.get(id);
    const item = `audit sink ${id}`;
    if (!bs && as) {
      out.push(
        "audit",
        "added",
        item,
        ["low", "Adds an audit sink."],
        undefined,
        as.type,
      );
      out.transport(
        "audit",
        `${item} httpTransport`,
        undefined,
        { transport: as.httpTransport, url: as.url },
        (_, v) => (v === "http-allowed" ? PLAIN_HTTP : ["low", HTTPS_ONLY]),
      );
      continue;
    }
    if (bs && !as) {
      out.push(
        "audit",
        "removed",
        item,
        bs.required
          ? ["high", "Removes a required audit sink."]
          : ["medium", "Removes an audit sink."],
        bs.type,
      );
      continue;
    }
    if (!bs || !as) continue;
    out.scalar("audit", `${item} required`, bs.required, as.required, (_, r) =>
      r === "false"
        ? ["high", "Audit delivery to this sink is no longer required."]
        : ["medium", "Audit delivery to this sink becomes required."],
    );
    out.scalar("audit", `${item} type`, bs.type, as.type, [
      "medium",
      "Audit sink type changed.",
    ]);
    out.scalar("audit", `${item} url`, safeUrl(bs.url), safeUrl(as.url), [
      "medium",
      "Audit sink endpoint changed.",
    ]);
    // An absent httpTransport and http-allowed are the same default.
    out.transport(
      "audit",
      `${item} httpTransport`,
      bs.type === "http"
        ? { transport: bs.httpTransport, url: bs.url }
        : undefined,
      as.type === "http"
        ? { transport: as.httpTransport, url: as.url }
        : undefined,
      (_, v) => (v === "http-allowed" ? PLAIN_HTTP : ["low", HTTPS_ONLY]),
    );
  }
  const bc: Record<string, boolean> = { ...(x?.capture ?? {}) };
  const ac: Record<string, boolean> = { ...(y?.capture ?? {}) };
  for (const key of [...new Set([...Object.keys(bc), ...Object.keys(ac)])].sort(
    compare,
  ))
    out.scalar("audit", `audit capture.${key}`, bc[key], ac[key], (_, v) =>
      v === "true"
        ? ["high", "Audit captures content that may include sensitive data."]
        : ["medium", "Audit stops capturing this content."],
    );
  const buffer = (config: typeof x) =>
    config?.buffer
      ? `${config.buffer.maxEvents} events, ${config.buffer.flushIntervalMs}ms`
      : undefined;
  out.scalar("audit", "audit buffer", buffer(x), buffer(y), [
    "low",
    "Audit buffering changed.",
  ]);
}
