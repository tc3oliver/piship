import { inspect } from "node:util";

const REDACTED = "[REDACTED]";
const revealed = new Set<string>();

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
    if (value.length >= 6) revealed.add(value);
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
  revealed.delete(value.reveal());
}

const SECRET_PATTERNS: readonly RegExp[] = [
  /(authorization\s*:\s*)(bearer|basic)\s+[^\s"',;]+/gi,
  /\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\bsk-[A-Za-z0-9_-]{6,}/g,
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g,
  /("?(?:access_token|refresh_token|id_token|credential|api_?key|client_secret|password|secret)"?\s*[:=]\s*"?)([^"\s,}&]+)/gi,
];

/** Remove known secret values and common token shapes from diagnostic text. */
export function redact(text: string): string {
  let output = text;
  for (const value of [...revealed].sort((a, b) => b.length - a.length))
    output = output.split(value).join(REDACTED);
  for (const pattern of SECRET_PATTERNS)
    output = output.replace(pattern, (_match, prefix: string) =>
      typeof prefix === "string" && /[:=]\s*"?$|authorization/i.test(prefix)
        ? `${prefix}${REDACTED}`
        : REDACTED,
    );
  return output;
}

/** Deep-copy a value for display, replacing SecretValues and secret-looking keys. */
export function redactValue(value: unknown): unknown {
  if (value instanceof SecretValue) return REDACTED;
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value instanceof Date) return value.toISOString();
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value))
      output[key] =
        /^(access_?token|refresh_?token|id_?token|credential|secret|api_?key|password|authorization)$/i.test(
          key,
        ) && item !== null
          ? REDACTED
          : redactValue(item);
    return output;
  }
  return value;
}

export const REDACTED_TEXT = REDACTED;
