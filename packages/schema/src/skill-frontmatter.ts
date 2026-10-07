import { parse } from "yaml";

/**
 * The frontmatter of a skill file, read the way Pi reads it: a document that
 * starts with `---` and has a closing `---` line carries YAML there; one
 * without has none. `error` is set when the YAML does not parse.
 */
export function skillFrontmatter(text: string): {
  readonly frontmatter: Readonly<Record<string, unknown>>;
  readonly error?: string;
} {
  const normalized = text
    .replace(/^﻿/, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  if (!normalized.startsWith("---")) return { frontmatter: {} };
  const end = normalized.indexOf("\n---", 3);
  if (end === -1) return { frontmatter: {} };
  try {
    const parsed: unknown = parse(normalized.slice(4, end));
    return {
      frontmatter:
        typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : {},
    };
  } catch (error) {
    return {
      frontmatter: {},
      error: error instanceof Error ? (error.message.split("\n")[0] ?? "") : "",
    };
  }
}
