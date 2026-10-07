// "Did you mean" support for manifest diagnostics.

/** Levenshtein distance, case-insensitive, with an early exit past `limit`. */
export function editDistance(a: string, b: string, limit = 3): number {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  if (Math.abs(x.length - y.length) > limit) return limit + 1;
  let previous = Array.from({ length: y.length + 1 }, (_, index) => index);
  for (let i = 1; i <= x.length; i += 1) {
    const row = [i];
    for (let j = 1; j <= y.length; j += 1)
      row[j] = Math.min(
        (row[j - 1] ?? 0) + 1,
        (previous[j] ?? 0) + 1,
        (previous[j - 1] ?? 0) + (x[i - 1] === y[j - 1] ? 0 : 1),
      );
    previous = row;
  }
  return previous[y.length] ?? limit + 1;
}

/**
 * The allowed field nearest to `key`, within two edits (one for names of
 * three characters or fewer, where two edits match almost anything).
 */
export function nearestField(
  key: string,
  allowed: readonly string[],
): string | undefined {
  const limit = key.length <= 3 ? 1 : 2;
  let best: string | undefined;
  let bestDistance = limit + 1;
  for (const candidate of allowed) {
    const distance = editDistance(key, candidate, limit);
    if (distance < bestDistance) {
      best = candidate;
      bestDistance = distance;
    }
  }
  return best;
}

/** The message of an unknown field, with a suggestion or the allowed names. */
export function unknownFieldMessage(
  key: string,
  allowed: readonly string[],
): string {
  const near = nearestField(key, allowed);
  if (near) return `Unknown field ${key}; did you mean ${near}?`;
  return allowed.length
    ? `Unknown field ${key}; the fields allowed here are ${allowed.join(", ")}`
    : `Unknown field ${key}; no fields are allowed here`;
}
