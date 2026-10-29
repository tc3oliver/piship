// Reproducibility comparison of two releases of one source, lock, and target.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { sha256File } from "../archive.js";
import { RELEASE_FILES, REPRODUCIBILITY_SCHEMA } from "./metadata.js";
import { hash } from "./shared.js";
import { releaseKind, RUNTIME_FILES, verifyRuntimeRelease } from "./runtime.js";
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

interface OpenRelease {
  readonly distribution: string;
  readonly version: string;
  readonly target: string;
  readonly directory: string;
  readonly payload: string;
  /** The files beside the payload that are compared as wrapper files. */
  readonly wrapper: readonly string[];
  readonly cleanup: () => void;
}

/** A verified release or runtime release, whichever `input` is. */
async function open(input: string): Promise<OpenRelease> {
  const wrapper = (files: readonly string[]) =>
    files.filter((item) => !item.startsWith("payload/"));
  if ((await releaseKind(input)) === "runtime") {
    const { metadata, ...opened } = await verifyRuntimeRelease(input);
    return {
      distribution: "piship-runtime",
      version: metadata.pishipVersion,
      target: metadata.target,
      wrapper: wrapper(RUNTIME_FILES),
      ...opened,
    };
  }
  const { metadata, ...opened } = await verifyRelease(input);
  return {
    distribution: metadata.distribution.id,
    version: metadata.distribution.version,
    target: metadata.target,
    wrapper: wrapper(RELEASE_FILES),
    ...opened,
  };
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
  const a = await open(first);
  try {
    const b = await open(second);
    try {
      if (
        a.target !== b.target ||
        a.distribution !== b.distribution ||
        a.version !== b.version
      )
        throw new PiShipError(
          "CONFIG_INVALID",
          `Reproducibility compares one distribution version on one target; got ${a.distribution}@${a.version} ${a.target} and ${b.distribution}@${b.version} ${b.target}`,
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
      for (const file of a.wrapper)
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
        distribution: a.distribution,
        version: a.version,
        target: a.target,
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
