import { inspect } from "node:util";

const REDACTED = "[REDACTED]";
const revealed = new Set<string>();

/**
 * A secret as it reads once encoded whole: base64 and base64url (a Basic
 * credential of the secret alone, a token in a data field), percent-encoded
 * (a URL or form), and JSON-escaped (inside a JSON string). Only forms at least
 * as long as a registrable secret are kept; a secret encoded together with
 * other bytes (such as `user:secret` in Basic) is not one of them.
 */
function secretForms(value: string): string[] {
  const bytes = Buffer.from(value, "utf8");
  const base64 = bytes.toString("base64");
  // Base64 pads to a multiple of four with zero, one, or two `=`.
  const padding = (3 - (bytes.length % 3)) % 3;
  const forms = new Set([
    value,
    base64,
    base64.slice(0, base64.length - padding),
    bytes.toString("base64url"),
    encodeURIComponent(value),
    JSON.stringify(value).slice(1, -1),
  ]);
  return [...forms].filter((form) => form.length >= 6);
}

/**
 * A secret that redacts itself in string conversion, JSON serialization, and
 * debug inspection. Only `reveal()` returns the value, and every revealed value
 * is registered so `redact()` can scrub it from later diagnostics.
 */
export class SecretValue {
  readonly #value: string;
  constructor(value: string) {
    if (typeof value !== "string" || value.length === 0)
      throw new TypeError("SecretValue requires a non-empty string");
    this.#value = value;
    if (value.length >= 6)
      for (const form of secretForms(value)) revealed.add(form);
  }
  reveal(): string {
    return this.#value;
  }
  equals(other: SecretValue | null | undefined): boolean {
    return !!other && other.#value === this.#value;
  }
  toString(): string {
    return REDACTED;
  }
  toJSON(): string {
    return REDACTED;
  }
  [inspect.custom](): string {
    return `SecretValue(${REDACTED})`;
  }
  [Symbol.toPrimitive](): string {
    return REDACTED;
  }
}

export function isSecretValue(value: unknown): value is SecretValue {
  return value instanceof SecretValue;
}

/** Forget a value once it is no longer held, so redaction sets stay small. */
export function forgetSecret(value: SecretValue): void {
  for (const form of secretForms(value.reveal())) revealed.delete(form);
}

/**
 * The one set of token shapes PiShip redacts everywhere: diagnostics,
 * errors, stderr, MCP output handed to the model, and audit events.
 */
const SECRET_PATTERNS: readonly RegExp[] = [
  // Any Authorization scheme (Bearer, Basic, Token, ...) or a bare
  // credential, also as a JSON key whose quotes are escaped (`\"`).
  /(authorization(?:\\*")?\s*[:=]\s*(?:\\*")?)(?:[A-Za-z][\w.-]*\s+)?[^\s"',;\\]+/gi,
  // A cookie header carries several `name=value; ` pairs up to the line end.
  /((?:set-)?cookie(?:\\*")?\s*:\s*(?:\\*")?)(?:\\[^"\r\n]|[^"\r\n\\])+/gi,
  /\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  // A standalone Basic credential must look like base64 (a digit, `+`, `/`,
  // `=`, or a lower-to-upper case change), so "basic authentication" stays.
  // Case-sensitive on purpose: the case change is the signal.
  /\b([Bb]asic|BASIC)\s+(?=[A-Za-z0-9+/]*(?:[0-9+/=]|[a-z][A-Z]))[A-Za-z0-9+/]{12,}={0,2}/g,
  /\bsk-[A-Za-z0-9_-]{6,}/g,
  // JWT shapes start only at the beginning of a token run: a match attempt
  // from inside a run (such as "ey-ey-ey-...") would rescan it, which is
  // quadratic on adversarial MCP output.
  /(?<![A-Za-z0-9_-])ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.?[A-Za-z0-9_-]*/g,
  /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g,
  // Vendor-prefixed API keys and access tokens that appear without an
  // Authorization header or key=value context.
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bAIza[A-Za-z0-9_-]{30,}/g,
  /\bglpat-[A-Za-z0-9_-]{16,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  // A key, header, or query parameter whose name ends in a credential word,
  // with any separator or none (`X-Api-Key`, `client_secret`, `?token=`,
  // `secretAccessKey`), quoted, escaped (`\"`), or bare. The match starts at
  // the word, so the rest of the name is never rescanned. Prose that ends a
  // label in a credential word before a problem PiShip reports
  // ("sandbox credential: delete <ref>: ...") is not a value: the words such
  // a problem starts with ("delete", "the", "revocation:") are kept when more
  // text follows them. A value that is only such a word, or one that starts
  // with it, is still redacted.
  /((?:token|secret|passw(?:or)?d|credentials?|(?:api|access|secret|private)[-_]?key)(?:\\*")?\s*[:=]\s*(?:\\*")?)((?!(?:delete|the|revocation:)\s)(?:\\[^"\s]|[^"\s,}&\\])+)/gi,
];

/**
 * Object keys whose values are always secret, whatever they hold: the plain
 * names, their camelCase, snake_case, and kebab-case spellings (`apiToken`,
 * `x-api-key`, `auth_token`), and the header names that carry credentials.
 * Counts such as `maxTokens` are not secret and do not match.
 */
export const SECRET_KEY_PATTERN =
  /^(?:x[-_])?(?:(?:access|refresh|id|auth|api|bearer|session|csrf|xsrf)[-_]?token|token|credential|secret|client[-_]?secret|api[-_]?key|private[-_]?key|password|passwd|(?:proxy[-_]?)?authorization|(?:set[-_]?)?cookie|bearer)$/i;

/** Remove known secret values and common token shapes from diagnostic text. */
export function redact(text: string): string {
  let output = text;
  for (const value of [...revealed].sort((a, b) => b.length - a.length))
    output = output.split(value).join(REDACTED);
  for (const pattern of SECRET_PATTERNS)
    output = output.replace(pattern, (_match, prefix: string) =>
      typeof prefix === "string" &&
      /[:=]\s*(?:\\*")?$|authorization/i.test(prefix)
        ? `${prefix}${REDACTED}`
        : REDACTED,
    );
  return output;
}

/**
 * Deep-copy a value for display, replacing SecretValues and secret-looking
 * keys. Bytes are shown as their redacted UTF-8 text, and a reference back to
 * an object being copied as `[Circular]`.
 */
export function redactValue(value: unknown): unknown {
  return redactWithin(value, new WeakSet());
}

function redactWithin(value: unknown, copying: WeakSet<object>): unknown {
  if (value instanceof SecretValue) return REDACTED;
  if (typeof value === "string") return redact(value);
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Uint8Array)
    return redact(
      Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString(
        "utf8",
      ),
    );
  if (!value || typeof value !== "object") return value;
  if (copying.has(value)) return "[Circular]";
  copying.add(value);
  try {
    if (Array.isArray(value))
      return value.map((item) => redactWithin(item, copying));
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value))
      output[key] =
        SECRET_KEY_PATTERN.test(key) && item !== null
          ? REDACTED
          : redactWithin(item, copying);
    return output;
  } finally {
    // Only an ancestor is circular; the same object twice side by side is not.
    copying.delete(value);
  }
}

export const REDACTED_TEXT = REDACTED;
