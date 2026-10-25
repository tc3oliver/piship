import { cpSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { readManifest } from "@piship/schema";
import { expect } from "vitest";

export const esmImport = (path: string) =>
  JSON.stringify(pathToFileURL(path).href);

/** Copy the personal example into `root/source` without fd and rg, and return its manifest. */
export function prepareBundledSource(repository: string, root: string) {
  const source = join(root, "source");
  cpSync(join(repository, "examples", "personal"), source, { recursive: true });
  const manifest = join(source, "piship.yaml");
  // The example also bundles fd and rg, whose archives a build reads from the
  // download cache; this test needs no network and no warm cache, so its copy
  // leaves them out and is locked as it stands.
  writeFileSync(
    manifest,
    readFileSync(manifest, "utf8").replace(
      /^ {2}# fd and rg ship[^\n]*\n[^\n]*\n {2}searchTools:\n {4}mode: bundled\n/m,
      "",
    ),
  );
  // The personal example ships bundled and stripped: build it as it is.
  expect(readManifest(manifest).lifecycle?.release).toMatchObject({
    bundle: true,
    strip: true,
  });
  return manifest;
}
