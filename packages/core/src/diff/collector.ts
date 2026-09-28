import { createHash } from "node:crypto";
import type {
  AnyLock,
  DiffArea,
  DiffChange,
  DiffRisk,
  DiffSide,
  Kind,
  Verdict,
} from "./types.js";

export const RISK_RANK: Record<DiffRisk, number> = {
  low: 0,
  medium: 1,
  high: 2,
};
export const EFFECT_RANK: Record<string, number> = {
  deny: 0,
  ask: 1,
  allow: 2,
};
export const DIMENSION_RANK: Record<string, number> = {
  deny: 0,
  "company-approved": 1,
  ask: 2,
  allow: 3,
};
export const TRUST_RANK: Record<string, number> = {
  deny: 0,
  policy: 1,
  allow: 2,
};
/** Resource trust classes from most to least reviewed. */
export const CLASS_RANK: Record<string, number> = {
  upstream: 0,
  builtin: 1,
  certified: 2,
  company: 3,
  user: 4,
  project: 5,
};
export const MCP_MODE_RANK: Record<string, number> = {
  off: 0,
  allowlist: 1,
  explicit: 2,
};
export const FAIL_ON_RANK: Record<string, number> = {
  low: 0,
  moderate: 1,
  high: 2,
  critical: 3,
};
export const EXECUTABLE_KINDS: readonly string[] = [
  "extensions",
  "adapters",
  "providers",
];

export class Collector {
  readonly changes: DiffChange[] = [];

  push(
    area: DiffArea,
    kind: Kind,
    item: string,
    [risk, reason]: Verdict,
    before?: string,
    after?: string,
  ): void {
    this.changes.push({
      area,
      kind,
      item,
      ...(before === undefined ? {} : { before: display(before) }),
      ...(after === undefined ? {} : { after: display(after) }),
      risk,
      reason,
    });
  }

  /** Compare one optional scalar; `verdict` sees raw values. */
  scalar(
    area: DiffArea,
    item: string,
    before: string | number | boolean | undefined,
    after: string | number | boolean | undefined,
    verdict: Verdict | ((before: string, after: string) => Verdict),
  ): void {
    if (before === after) return;
    const b = before === undefined ? undefined : String(before);
    const a = after === undefined ? undefined : String(after);
    const kind: Kind =
      b === undefined ? "added" : a === undefined ? "removed" : "changed";
    const result =
      typeof verdict === "function" ? verdict(b ?? "", a ?? "") : verdict;
    this.push(area, kind, item, result, b, a);
  }

  /** Compare two string sets element by element. */
  set(
    area: DiffArea,
    prefix: string,
    before: readonly string[] | undefined,
    after: readonly string[] | undefined,
    added: Verdict | ((value: string) => Verdict),
    removed: Verdict | ((value: string) => Verdict),
  ): void {
    const b = new Set(before ?? []);
    const a = new Set(after ?? []);
    for (const value of a)
      if (!b.has(value))
        this.push(
          area,
          "added",
          `${prefix} ${value}`,
          typeof added === "function" ? added(value) : added,
          undefined,
          value,
        );
    for (const value of b)
      if (!a.has(value))
        this.push(
          area,
          "removed",
          `${prefix} ${value}`,
          typeof removed === "function" ? removed(value) : removed,
          value,
        );
  }
}

export function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function byKey<T>(
  items: readonly T[] | undefined,
  key: (item: T) => string,
): Map<string, T> {
  return new Map((items ?? []).map((item) => [key(item), item]));
}

export function keys<T>(
  before: Map<string, T>,
  after: Map<string, T>,
): string[] {
  return [...new Set([...before.keys(), ...after.keys()])].sort(compare);
}

/** Shorten digests to 12 hex characters and keep other values to one short line. */
export function display(value: string): string {
  const hex = /^(sha256-)?([0-9a-f]{64})$/.exec(value);
  if (hex) return `${hex[1] ?? ""}${hex[2]?.slice(0, 12)}`;
  const sri = /^(sha(?:1|256|384|512))-([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (sri?.[2])
    return `${sri[1]}-${Buffer.from(sri[2], "base64").toString("hex").slice(0, 12)}`;
  const line = [...value]
    .map((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127 ? " " : character;
    })
    .join("");
  return line.length > 80 ? `${line.slice(0, 77)}...` : line;
}

/** A URL without credentials, query, or fragment; `${NAME}` templates as-is. */
export function safeUrl(value: string | undefined): string | undefined {
  if (value === undefined || value.includes("${")) return value;
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "(unparseable URL)";
  }
}

export function origin(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value);
    return url.origin === "null" ? url.protocol : url.origin;
  } catch {
    return "(unparseable URL)";
  }
}

export function fingerprint(publicKey: string): string {
  return `sha256:${createHash("sha256").update(publicKey).digest("hex").slice(0, 12)}`;
}

export function rank(
  order: Record<string, number>,
  before: string,
  after: string,
  looser: string,
  tighter: string,
  tighterRisk: DiffRisk = "medium",
): Verdict {
  return (order[after] ?? 0) > (order[before] ?? 0)
    ? ["high", looser]
    : [tighterRisk, tighter];
}

// ------------------------------------------------------------ sections

export function side(lock: AnyLock): DiffSide {
  return {
    id: lock.app?.id ?? "",
    version: lock.app?.version ?? "",
    pi: lock.runtime?.version ?? "",
    piship: lock.runtime?.pishipVersion ?? "",
    lockSchema: lock.schema ?? "",
  };
}
