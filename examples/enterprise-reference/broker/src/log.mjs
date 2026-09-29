// One JSON line per event. Only the fields named in FIELDS are written, and
// only as numbers, booleans, short strings, or arrays of short strings, so a
// token, a key, or an upstream response body cannot reach the log by being
// passed in as an unexpected field. As a second guard every string is
// scrubbed of the configured secrets and of key and token shapes.

const FIELDS = new Set([
  "status",
  "reason",
  "user_id",
  "credential_id",
  "models",
  "idempotency",
  "deleted",
  "duration_ms",
  "route",
  "listen",
  "upstream_status",
]);

// LiteLLM keys start with sk-; JWTs are three base64url segments, the first
// two usually starting with eyJ ("{" encoded).
const KEY_SHAPE = /sk-[A-Za-z0-9_-]{4,}/g;
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*/g;
const MAX_STRING = 200;

/**
 * @param {object} options
 * @param {(line: string) => void} [options.write] where lines go (stdout)
 * @param {string[]} [options.secrets] exact values that must never appear
 * @param {() => number} [options.now]
 */
export function createLogger({
  write = (line) => process.stdout.write(line),
  secrets = [],
  now = Date.now,
} = {}) {
  const exact = secrets.filter(
    (value) => typeof value === "string" && value.length >= 8,
  );
  const scrub = (text) => {
    let out = String(text).slice(0, MAX_STRING);
    for (const secret of exact) out = out.split(secret).join("[REDACTED]");
    return out
      .replace(KEY_SHAPE, "[REDACTED]")
      .replace(JWT_SHAPE, "[REDACTED]");
  };
  const clean = (value) => {
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "string") return scrub(value);
    if (Array.isArray(value))
      return value.filter((item) => typeof item === "string").map(scrub);
    return undefined;
  };
  return function log(event, fields = {}) {
    const line = { time: new Date(now()).toISOString(), event: scrub(event) };
    for (const [name, value] of Object.entries(fields)) {
      if (!FIELDS.has(name)) continue;
      const cleaned = clean(value);
      if (cleaned !== undefined) line[name] = cleaned;
    }
    write(`${JSON.stringify(line)}\n`);
  };
}
