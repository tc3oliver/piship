// Reproducibility comparison of two releases of one source, lock, and target.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { sha256File } from "../archive.js";
import { RELEASE_FILES, REPRODUCIBILITY_SCHEMA } from "./metadata.js";
import { hash } from "./shared.js";
import { verifyRelease } from "./verify.js";

export interface ReproducibilityReport {
  readonly schema: typeof REPRODUCIBILITY_SCHEMA;
  readonly distribution: string;
  readonly version: string;
  readonly target: string;
  /** Declared static payload paths and SHA-256 hashes are equal. */
  readonly payloadEqual: boolean;
  readonly payloadFiles: number;
  readonly payloadDifferences: readonly string[];
  /** Wrapper files compared separately; they may carry build metadata. */
  readonly wrapper: Readonly<Record<string, boolean>>;
  readonly archiveEqual: boolean | null;
  readonly note: string;
}

/**
 * Compare two releases of the same source, lock, and target. Payload
 * equality is the reproducibility claim; wrapper differences are reported
 * separately. Different targets are refused rather than compared.
 */
export async function compareReleases(
  first: string,
  second: string,
): Promise<ReproducibilityReport> {
  const a = await verifyRelease(first);
  try {
    const b = await verifyRelease(second);
    try {
      if (
        a.metadata.target !== b.metadata.target ||
        a.metadata.distribution.id !== b.metadata.distribution.id ||
        a.metadata.distribution.version !== b.metadata.distribution.version
      )
        throw new PiShipError(
          "CONFIG_INVALID",
          `Reproducibility compares one distribution version on one target; got ${a.metadata.distribution.id}@${a.metadata.distribution.version} ${a.metadata.target} and ${b.metadata.distribution.id}@${b.metadata.distribution.version} ${b.metadata.target}`,
        );
      const left = JSON.parse(
        readFileSync(join(a.payload, "metadata", "inventory.json"), "utf8"),
      ) as Record<string, string>;
      const right = JSON.parse(
        readFileSync(join(b.payload, "metadata", "inventory.json"), "utf8"),
      ) as Record<string, string>;
      const paths = [
        ...new Set([...Object.keys(left), ...Object.keys(right)]),
      ].sort();
      const differences = paths.filter((path) => left[path] !== right[path]);
      const wrapper: Record<string, boolean> = {};
      for (const file of RELEASE_FILES.filter(
        (item) => !item.startsWith("payload/"),
      ))
        wrapper[file] =
          hash(readFileSync(join(a.directory, file))) ===
          hash(readFileSync(join(b.directory, file)));
      const archives = [first, second].map((path) => resolve(path));
      const archiveEqual = archives.every((path) => statSync(path).isFile())
        ? (await sha256File(archives[0] as string)) ===
          (await sha256File(archives[1] as string))
        : null;
      return {
        schema: REPRODUCIBILITY_SCHEMA,
        distribution: a.metadata.distribution.id,
        version: a.metadata.distribution.version,
        target: a.metadata.target,
        payloadEqual: differences.length === 0,
        payloadFiles: paths.length,
        payloadDifferences: differences.slice(0, 200),
        wrapper,
        archiveEqual,
        note: "Equality is claimed only for this target; other targets are built and compared separately.",
      };
    } finally {
      b.cleanup();
    }
  } finally {
    a.cleanup();
  }
}

/** Lists `.tar.gz` release archives in a directory, sorted. */
export function listArchives(directory: string): string[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".tar.gz"))
    .sort()
    .map((name) => join(directory, name));
}
