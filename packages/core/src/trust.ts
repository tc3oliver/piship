// Static trust evidence for piship/v1alpha3: certified tree digests, provider
// declarations, and lifecycle-script checks. Recorded in piship.lock and
// re-verified from the installed payload at launch.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  type CertifiedEvidence,
  type GovernanceManifest,
  ManifestError,
} from "@piship/schema";

/** npm lifecycle scripts that run code at install time. */
const INSTALL_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
  "prepublish",
] as const;

export interface TreeFile {
  /** Path relative to the declared root, `/` separated. */
  readonly path: string;
  readonly sha256: string;
}

/**
 * Digest of a resource tree: SHA-256 over sorted `path NUL sha256 LF` lines.
 * Paths are relative to the declared root, so the digest is stable across
 * checkouts, payloads, and operating systems.
 */
export function treeDigest(files: readonly TreeFile[]): string {
  const lines = [...files]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((file) => `${file.path}\0${file.sha256}\n`)
    .join("");
  return `sha256-${createHash("sha256").update(lines).digest("hex")}`;
}

export interface CertifiedLockEntry {
  readonly kind: string;
  /** Declared `./` path. */
  readonly path: string;
  readonly evidence: CertifiedEvidence;
  /** Digest computed at lock time; equals `evidence.integrity`. */
  readonly integrity: string;
}

export interface ProviderLockEntry {
  readonly capability: string;
  readonly id: string;
  readonly class: string;
  readonly version: string;
  readonly implements: readonly string[];
  /** Declared `./` path for non-builtin providers. */
  readonly path?: string;
  /** piship/v1alpha6: the declared Pi package whose extensions are the provider. */
  readonly package?: string;
  /** Tree digest of the provider files for non-builtin providers. */
  readonly integrity?: string;
  readonly certified?: CertifiedEvidence;
}

export interface GovernanceLock {
  readonly manifest: GovernanceManifest;
  readonly certified: readonly CertifiedLockEntry[];
  readonly providers: readonly ProviderLockEntry[];
}

/** Files of one declared root, from locked `prefix/...` resource paths. */
export function filesUnder(
  locked: readonly { readonly path: string; readonly sha256: string }[],
  declared: string,
): TreeFile[] {
  const prefix = declared.slice(2);
  return locked
    .filter(
      (item) => item.path === prefix || item.path.startsWith(`${prefix}/`),
    )
    .map((item) => ({
      path:
        item.path === prefix
          ? (prefix.split("/").at(-1) ?? prefix)
          : item.path.slice(prefix.length + 1),
      sha256: item.sha256,
    }));
}

/** Reject npm lifecycle scripts in reviewed trees; they would run unreviewed code. */
export function assertNoInstallScripts(
  root: string,
  files: readonly TreeFile[],
  field: string,
): void {
  for (const file of files) {
    const name = file.path.split("/").at(-1);
    // npm runs `node-gyp rebuild` at install for a package with binding.gyp.
    if (name === "binding.gyp")
      throw new ManifestError(
        "invalid field",
        field,
        `${file.path} makes npm build native code at install (node-gyp rebuild); certified and provider trees may not run code at install`,
      );
    if (name !== "package.json") continue;
    const path = join(root, file.path);
    if (!existsSync(path)) continue;
    let scripts: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as {
        scripts?: Record<string, unknown>;
      };
      scripts = parsed.scripts ?? {};
    } catch {
      throw new ManifestError(
        "invalid field",
        field,
        `${file.path} is not valid JSON`,
      );
    }
    const found = INSTALL_SCRIPTS.filter((name) => name in scripts);
    if (found.length)
      throw new ManifestError(
        "invalid field",
        field,
        `${file.path} declares install-time scripts (${found.join(", ")}); certified and provider trees may not run code at install`,
      );
  }
}

/** Compare a computed digest with the reviewed one; any difference fails. */
export function assertIntegrity(
  computed: string,
  expected: string,
  field: string,
): void {
  if (computed !== expected)
    throw new ManifestError(
      "invalid field",
      field,
      `Integrity mismatch: reviewed ${expected}, found ${computed}. The content changed after review; re-review it and update the integrity, or restore the reviewed files.`,
    );
}
