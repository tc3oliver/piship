import { redact } from "@piship/contracts";

const MAX_DEPTH = 4;

/**
 * Redact an uncaught error in place: its message and stack and every other
 * own string property, and those of the objects it holds (its `cause`,
 * aggregated `errors`, a response's headers), as far as `MAX_DEPTH`. The object stays the same, so every later handler
 * prints and records the redacted text. A thrown primitive cannot be
 * changed in place and is left as it is.
 */
export function redactErrorInPlace(
  error: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
): void {
  if (!error || typeof error !== "object" || depth > MAX_DEPTH) return;
  if (seen.has(error)) return;
  seen.add(error);
  const record = error as Record<string, unknown>;
  for (const key of new Set([
    "message",
    "stack",
    ...Object.getOwnPropertyNames(error),
  ])) {
    let value: unknown;
    try {
      value = record[key];
    } catch {
      continue;
    }
    if (typeof value === "string") {
      const clean = redact(value);
      if (clean !== value)
        try {
          record[key] = clean;
        } catch {
          // A read-only property keeps its text; nothing else can change it.
        }
    } else redactErrorInPlace(value, depth + 1, seen);
  }
}

function crashRedaction(error: unknown): void {
  try {
    redactErrorInPlace(error);
  } catch {
    // Never keep the crash handlers after this one from running.
  }
}

/**
 * Put a redacting `uncaughtException` listener in front of every listener
 * installed so far. Pi's interactive mode prepends its crash handler (which
 * prints the error, records it in the crash log that `/bug` attaches, and
 * exits) before extensions start, so this runs once Pi's is in place: at
 * `session_start`, again at every later one, which moves it back to the
 * front. Node raises an unhandled rejection as an uncaught exception, so the
 * same listener sees it.
 */
export function installCrashRedaction(): void {
  process.off("uncaughtException", crashRedaction);
  process.prependListener("uncaughtException", crashRedaction);
}

export function uninstallCrashRedaction(): void {
  process.off("uncaughtException", crashRedaction);
}
