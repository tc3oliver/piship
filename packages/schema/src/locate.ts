// Source positions for manifest diagnostics: the parser reports a field
// path, and this finds the line and column of that field in the YAML text.
import {
  type Document,
  isMap,
  isPair,
  isScalar,
  isSeq,
  type LineCounter,
  type Node,
} from "yaml";
import { ManifestError, type SourcePosition } from "./index.js";

/** `a.b[2].c` as ["a", "b", 2, "c"], tolerant of dots inside a key. */
function tokens(field: string): string[] {
  const parts = [...field.matchAll(/\[(\d+)\]|([^.[\]]+)/g)].map(
    (match) => match[1] ?? match[2] ?? "",
  );
  // Paths of the document root are written `manifest.<field>`.
  return parts[0] === "manifest" ? parts.slice(1) : parts;
}

interface Found {
  readonly key?: Node | null;
  readonly value?: Node | null;
  /** Whether every token of the path resolved. */
  readonly exact: boolean;
}

/**
 * Walk the document along `parts`. A map key may itself contain dots, so a
 * step tries the next token alone, then joined with the ones after it.
 */
function walk(node: unknown, parts: readonly string[]): Found {
  if (parts.length === 0) return { value: node as Node, exact: true };
  if (isMap(node)) {
    for (let length = 1; length <= parts.length; length += 1) {
      const wanted = parts.slice(0, length).join(".");
      const pair = node.items.find(
        (item) =>
          isPair(item) &&
          String(isScalar(item.key) ? item.key.value : item.key) === wanted,
      );
      if (!pair) continue;
      const rest = parts.slice(length);
      if (rest.length === 0)
        return {
          key: pair.key as Node,
          value: pair.value as Node | null,
          exact: true,
        };
      const inner = walk(pair.value, rest);
      return inner.exact
        ? inner
        : { key: inner.key ?? (pair.key as Node), exact: false };
    }
    return { exact: false };
  }
  if (isSeq(node)) {
    const index = Number(parts[0]);
    const item = Number.isInteger(index) ? node.items[index] : undefined;
    return item === undefined ? { exact: false } : walk(item, parts.slice(1));
  }
  return { exact: false };
}

/** An unquoted YAML number where text is expected: say how to write it. */
function quotedNumber(reason: string, value: Node | null | undefined): string {
  if (
    !isScalar(value) ||
    typeof value.value !== "number" ||
    !/^Expected (a|an) (non-empty )?string/.test(reason) ||
    reason.includes("quote it")
  )
    return reason;
  const written = value.source ?? String(value.value);
  return `${reason}; this is a number, so quote it: "${written}"`;
}

/** Give one error the line and column of its field. */
function locateOne(
  error: ManifestError,
  document: Document,
  lineCounter: LineCounter,
): ManifestError {
  if (error.position || error.kind === "YAML parse failure") return error;
  const found = walk(document.contents, tokens(error.field));
  // An unknown field is best shown at its name; a bad value at the value; a
  // field that is not there at the section that should hold it.
  const unknownField = error.reason.startsWith("Unknown field");
  const node = unknownField
    ? (found.key ?? found.value)
    : found.exact
      ? (found.value ?? found.key)
      : (found.key ?? found.value);
  // A section missing from the top level has no node of its own: the start of the document.
  const offset = (node ?? document.contents)?.range?.[0];
  if (offset === undefined) return error;
  const { line, col } = lineCounter.linePos(offset);
  const position: SourcePosition = { line, column: col };
  return error.locatedAt(
    position,
    found.exact && !unknownField
      ? quotedNumber(error.reason, found.value)
      : error.reason,
  );
}

/** The same errors with the line and column of each field. */
export function locateErrors(
  error: ManifestError,
  document: Document,
  lineCounter: LineCounter,
): ManifestError {
  return ManifestError.combine(
    error.errors.map((item) => locateOne(item, document, lineCounter)),
  );
}
