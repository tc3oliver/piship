// Tool exposure resolution: which `<glob>: <exposure>` rule decides a tool's
// exposure, and how a policy deny collapses it to `hidden`. Exposure decides
// what the model can see or discover; policy still decides what can run.
// Pure: no Pi import, so the same resolver serves the runtime, validation,
// and explain.
import type { ToolExposure, ToolExposureRule } from "@piship/schema";

/**
 * How visible each exposure is, from excluded to always declared. A tool
 * whose own declared exposure ranks above the manifest's is wider than the
 * distribution allows; `diff` reads "widened" from the same order.
 */
export const EXPOSURE_VISIBILITY: Readonly<Record<ToolExposure, number>> = {
  hidden: 0,
  deferred: 1,
  codemode: 2,
  "model-only": 3,
  direct: 4,
};

/**
 * A pattern's specificity: an exact name outranks every glob; among globs,
 * more literal characters rank higher (`delete_draft*` over `delete_*`).
 */
export function specificity(pattern: string): number {
  if (!pattern.includes("*")) return Number.POSITIVE_INFINITY;
  return pattern.replace(/\*/g, "").length;
}

/** Anchored glob: `*` matches any run of characters. */
function matches(pattern: string, name: string): boolean {
  const source = pattern
    .split(/\*+/)
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${source}$`, "s").test(name);
}

/**
 * Whether some name matches both globs. A `*` (or `**`) is treated as any
 * run of characters, so the answer may be yes for globs whose separator
 * rules keep them apart: a reported overlap is never missed.
 */
export function globsOverlap(left: string, right: string): boolean {
  const a = left.replace(/\*+/g, "*");
  const b = right.replace(/\*+/g, "*");
  const seen = new Map<number, boolean>();
  const visit = (i: number, j: number): boolean => {
    const key = i * (b.length + 1) + j;
    const known = seen.get(key);
    if (known !== undefined) return known;
    seen.set(key, false);
    let result: boolean;
    if (i === a.length && j === b.length) result = true;
    else if (a[i] === "*")
      result = visit(i + 1, j) || (j < b.length && visit(i, j + 1));
    else if (b[j] === "*")
      result = visit(i, j + 1) || (i < a.length && visit(i + 1, j));
    else
      result =
        i < a.length && j < b.length && a[i] === b[j] && visit(i + 1, j + 1);
    seen.set(key, result);
    return result;
  };
  return visit(0, 0);
}

/**
 * Pairs of rules a name could match with equal specificity: the most
 * specific glob would not be unique, which is a validation error.
 */
export function overlappingTies(
  rules: readonly ToolExposureRule[],
): Array<[string, string]> {
  const ties: Array<[string, string]> = [];
  for (let i = 0; i < rules.length; i += 1)
    for (let j = i + 1; j < rules.length; j += 1) {
      const left = rules[i] as ToolExposureRule;
      const right = rules[j] as ToolExposureRule;
      if (
        left.pattern !== right.pattern &&
        specificity(left.pattern) === specificity(right.pattern) &&
        globsOverlap(left.pattern, right.pattern)
      )
        ties.push([left.pattern, right.pattern]);
    }
  return ties;
}

export type ExposureResolution =
  | { readonly exposure: ToolExposure; readonly rule?: string }
  | { readonly tie: readonly [string, string] };

/**
 * The exposure of `name`: the most specific matching rule's, or `fallback`
 * when none matches. Two matching rules of equal specificity are a tie,
 * which callers treat as `hidden` (fail closed).
 */
export function resolveExposure(
  name: string,
  rules: readonly ToolExposureRule[],
  fallback: ToolExposure,
): ExposureResolution {
  let best: ToolExposureRule | undefined;
  let tie: ToolExposureRule | undefined;
  for (const rule of rules) {
    if (!matches(rule.pattern, name)) continue;
    const rank = specificity(rule.pattern);
    const bestRank = best ? specificity(best.pattern) : -1;
    if (!best || rank > bestRank) {
      best = rule;
      tie = undefined;
    } else if (rank === bestRank && rule.pattern !== best.pattern) tie = rule;
  }
  if (best && tie) return { tie: [best.pattern, tie.pattern] };
  return best
    ? { exposure: best.exposure, rule: best.pattern }
    : { exposure: fallback };
}

/**
 * The exposure a session applies: an unconditional policy deny hides the
 * tool whatever the rules say, and a tie is hidden too. `ask` and the
 * session's modes (Plan, user auto mode) leave exposure unchanged.
 */
export function effectiveExposure(
  resolution: ExposureResolution,
  denied: boolean,
): ToolExposure {
  if (denied || "tie" in resolution) return "hidden";
  return resolution.exposure;
}
