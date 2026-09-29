import { existsSync, readFileSync } from "node:fs";

/** Which references a metadata file owns: runtime credentials or identity tokens. */
export type SecretRefClass = "inference" | "identity";

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Every secret-store reference of one distribution and class that the text
 * of a metadata file (credential or identity metadata, or a discarded marker
 * of either) names, read from the text itself so that it works as well for
 * a file that is no longer valid JSON: a truncated or damaged file is not
 * taken to name nothing. As `metadataSecretRefs` does for a readable file,
 * a credential's `generation` also names the next generation (a crash before
 * the metadata commit may have left it), and an identity `secretRef` also
 * names the generations before and after it. A file too damaged to name any
 * reference yields none; nothing can recover what it named, since a secret
 * store cannot be listed.
 */
export function secretRefsFromText(
  text: string,
  distributionId: string,
  refClass: SecretRefClass,
): string[] {
  const prefix = `piship:${distributionId}:${refClass}#`;
  const refs = new Set<string>();
  const add = (generation: number, ...offsets: number[]) => {
    if (!Number.isSafeInteger(generation)) return;
    for (const offset of [0, ...offsets])
      if (generation + offset >= (offset < 0 ? 1 : 0))
        refs.add(`${prefix}${generation + offset}`);
  };
  const ref = `${escapeRegExp(prefix)}(\\d+)`;
  for (const match of text.matchAll(new RegExp(ref, "g")))
    add(Number(match[1]));
  if (refClass === "inference")
    for (const match of text.matchAll(/"generation"\s*:\s*(\d+)/g))
      add(Number(match[1]), 1);
  else
    for (const match of text.matchAll(
      new RegExp(`"secretRef"\\s*:\\s*"${ref}`, "g"),
    ))
      add(Number(match[1]), 1, -1);
  return [...refs].sort();
}

/**
 * The references the metadata file at `path` names (see
 * `secretRefsFromText`), whether or not it is still valid JSON; none when
 * the file does not exist. A file that exists but cannot be read throws, so
 * it is never mistaken for one that names nothing.
 */
export function metadataFileSecretRefs(
  path: string,
  distributionId: string,
  refClass: SecretRefClass,
): string[] {
  if (!existsSync(path)) return [];
  return secretRefsFromText(
    readFileSync(path, "utf8"),
    distributionId,
    refClass,
  );
}
