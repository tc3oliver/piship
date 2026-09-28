import { createHash } from "node:crypto";

/** JSON with object keys sorted, for digests that must not depend on key order. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : item,
  );
}
export function digest(value: unknown): string {
  return `sha256-${hash(canonicalJson(value ?? null))}`;
}

export function hash(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
