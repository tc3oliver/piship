// One JSON line per event. Only the fields named in FIELDS are written, and
// only as numbers, booleans, or short strings, so a credential, a command, an
// environment value, or a host path cannot reach the log by being passed in
// as an unexpected field. As a second guard every string is scrubbed of the
// key shape this service issues.

const FIELDS = new Set([
  "status",
  "code",
  "route",
  "owner",
  "session",
  "exit",
  "signal",
  "reason",
  "duration_ms",
  "listen",
  "sandboxes",
  "removed",
]);

const KEY_SHAPE = /sbxk_[A-Za-z0-9_-]{8,}/g;
const MAX_STRING = 200;

/**
 * @param {object} [options]
 * @param {(line: string) => void} [options.write] where lines go (stderr)
 * @param {() => number} [options.now]
 */
export function createLogger({
  write = (line) => process.stderr.write(line),
  now = Date.now,
} = {}) {
  const scrub = (text) =>
    String(text).slice(0, MAX_STRING).replace(KEY_SHAPE, "[REDACTED]");
  const clean = (value) => {
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "string") return scrub(value);
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
