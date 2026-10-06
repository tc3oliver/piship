// Consumer verification of a release directory or archive.
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import {
  createTemporaryDirectory,
  PiShipError,
  type TemporaryDirectory,
} from "@piship/contracts";
import { extractArchive, sha256File } from "../archive.js";
import { verifyPayloadContents, type DistributionLock } from "../index.js";
import { LEGACY_STATE_SCHEMAS, type StateSchemaSupport } from "../migration.js";
import { verifyWrittenPayload } from "../payload.js";
import {
  verifyChecksums,
  verifyNotices,
  verifySbom,
  type SpdxDocument,
} from "../supply-chain.js";
import { reclaimOsTemporaries } from "../temporary-directories.js";
import {
  RELEASE_FILES,
  RELEASE_SCHEMA,
  VULNERABILITY_REPORT_SCHEMA,
  type ReleaseMetadata,
  type VulnerabilityReport,
} from "./metadata.js";
import { isUnqualifiedPayload, RELEASE_QUALIFIED } from "./qualification.js";
import { hash } from "./shared.js";

export interface VerifiedRelease {
  readonly directory: string;
  readonly payload: string;
  readonly metadata: ReleaseMetadata;
  readonly lock: DistributionLock;
  readonly sbom?: SpdxDocument;
  readonly archiveSha256?: string;
  /** Removes the extraction directory when the input was an archive. */
  readonly cleanup: () => void;
}

function fail(message: string, userAction?: string): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Release verification: ${message}`,
    {
      component: "release",
      userAction:
        userAction ??
        "Do not install this artifact; obtain it again from the trusted source",
    },
  );
}

/**
 * Consumer verification of a release directory or archive: archive checksum
 * sidecar, release checksums, every payload file against its inventory, the
 * lock and manifest, metadata consistency, SBOM completeness, notices, and
 * the vulnerability verdict. With `requireTarget`, the payload must match
 * this machine.
 */
export async function verifyRelease(
  input: string,
  options: {
    readonly requireTarget?: boolean;
    readonly expectedSha256?: string;
    readonly extractTo?: string;
    /**
     * The consumer path: archive trust and small metadata, leaving
     * qualification to CI. An archive is read once. Its digest and the
     * SHA-256 of every payload file are computed from the bytes that are
     * written, and checked against `expectedSha256` and the payload inventory
     * that `release.json` binds, before anything is returned.
     */
    readonly fastClient?: boolean;
    /** With `fastClient`: extract only the few metadata files, not the payload (a check that installs nothing). */
    readonly metadataOnly?: boolean;
    /**
     * With `fastClient` and an archive: write the payload directly into this
     * directory (which must not exist), instead of a staging directory the
     * caller would move it from. `release.json` is read from memory. The
     * directory is removed again if anything fails to verify; on success
     * `directory` and `payload` of the result are this directory.
     */
    readonly payloadTo?: string;
    /** Extraction tuning for the `payloadTo` path; defaults apply. Measurement only. */
    readonly tuning?: {
      readonly concurrency?: number;
      readonly bufferedFileMax?: number;
    };
  } = {},
): Promise<VerifiedRelease> {
  const path = resolve(input);
  let directory = path;
  let archiveSha256: string | undefined;
  let writtenFiles: ReadonlyMap<string, string> | undefined;
  let cleanup = () => {};
  if (!statSync(path).isFile() && isUnqualifiedPayload(path))
    throw fail(
      `${path} is an unqualified local build, not a release: it was not audited and has no SBOM, notices, recorded tests, or checksums`,
      "Run piship release <manifest> to build the qualified release",
    );
  if (statSync(path).isFile()) {
    const checkDigest = (actual: string): void =>
      checkArchiveDigest(path, actual, options.expectedSha256);
    if (options.payloadTo !== undefined && options.fastClient)
      return extractVerifiedPayload(path, options.payloadTo, options);
    // The consumer path reads the archive once, and hashes it from that read:
    // a second read could be of other bytes. A full verification checks the
    // digest first, then reads every file.
    archiveSha256 = options.fastClient ? undefined : await sha256File(path);
    if (archiveSha256 !== undefined) checkDigest(archiveSha256);
    // Without `extractTo` the extraction is a directory of this call, owned
    // and removed by it; a caller's `extractTo` is its own staging directory.
    let own: TemporaryDirectory | undefined;
    if (!options.extractTo) {
      reclaimOsTemporaries();
      own = createTemporaryDirectory(tmpdir(), "verify");
    }
    const parent = options.extractTo ?? (own as TemporaryDirectory).path;
    const expectedRoot = basename(path).replace(/\.tar\.gz$/, "");
    const streamed = options.fastClient === true && !options.metadataOnly;
    const extracted = await extractArchive(path, join(parent, "x"), {
      expectedRoot,
      hash: archiveSha256 === undefined,
      digests: streamed,
      ...(options.metadataOnly
        ? {
            mapEntry: (name: string, directory: boolean) => {
              const relative = name.slice(expectedRoot.length + 1);
              return directory ||
                [
                  "release.json",
                  "payload/piship.lock",
                  "payload/piship.yaml",
                  "payload/package-lock.json",
                  "payload/metadata/target.json",
                  "payload/metadata/inventory.json",
                ].includes(relative)
                ? directory
                  ? undefined
                  : name
                : undefined;
            },
          }
        : streamed
          ? {
              // Only what the consumer path needs: the release metadata and
              // the payload, written once.
              mapEntry: (name: string) => {
                const relative = name.slice(expectedRoot.length + 1);
                return relative === "release.json" ||
                  relative === "payload" ||
                  relative.startsWith("payload/")
                  ? name
                  : undefined;
              },
            }
          : {}),
    }).catch((error: Error) => {
      own?.remove();
      throw fail(error.message);
    });
    directory = join(parent, "x", extracted.root);
    writtenFiles = extracted.files;
    cleanup = () =>
      own ? own.remove() : rmSync(parent, { recursive: true, force: true });
    if (archiveSha256 === undefined) {
      archiveSha256 = extracted.sha256 as string;
      try {
        checkDigest(archiveSha256);
      } catch (error) {
        cleanup();
        throw error;
      }
    }
  }
  try {
    const verified = verifyReleaseDirectory(
      directory,
      options.requireTarget,
      options.fastClient,
    );
    if (writtenFiles !== undefined) {
      // The bytes of every payload file, as written, against the inventory
      // whose digest release.json binds (checked above).
      const prefix = `${basename(directory)}/payload/`;
      const inventory = JSON.parse(
        readFileSync(
          join(verified.payload, "metadata", "inventory.json"),
          "utf8",
        ),
      ) as Record<string, string>;
      verifyWrittenPayload(
        new Map(
          [...writtenFiles]
            .filter(([file]) => file.startsWith(prefix))
            .map(([file, digest]) => [file.slice(prefix.length), digest]),
        ),
        inventory,
        verified.payload,
      );
    }
    return {
      ...verified,
      ...(archiveSha256 ? { archiveSha256 } : {}),
      cleanup,
    };
  } catch (error) {
    cleanup();
    throw error;
  }
}

/** The archive's digest against the one expected and the sidecar published beside it. */
function checkArchiveDigest(
  path: string,
  actual: string,
  expectedSha256: string | undefined,
): void {
  if (expectedSha256 && actual !== expectedSha256)
    throw fail(
      `archive SHA-256 ${actual} does not match the expected ${expectedSha256}`,
    );
  const sidecar = `${path}.sha256`;
  if (existsSync(sidecar)) {
    const recorded = readFileSync(sidecar, "utf8").split(/\s+/)[0];
    if (recorded !== actual)
      throw fail(
        `archive SHA-256 ${actual} does not match ${basename(sidecar)}`,
      );
  }
}

/**
 * The consumer path of an archive whose destination is known: one read
 * writes the payload straight into `payloadTo`, hashing the archive and every
 * file as they are written, and keeps `release.json` in memory. Both are
 * checked before anything is returned, and `payloadTo` is removed if they do
 * not hold.
 */
async function extractVerifiedPayload(
  path: string,
  payloadTo: string,
  options: {
    readonly requireTarget?: boolean;
    readonly expectedSha256?: string;
    readonly tuning?: {
      readonly concurrency?: number;
      readonly bufferedFileMax?: number;
    };
  },
): Promise<VerifiedRelease> {
  const root = basename(path).replace(/\.tar\.gz$/, "");
  const releaseKey = `${root}/release.json`;
  const prefix = `${root}/payload/`;
  const extracted = await extractArchive(path, payloadTo, {
    expectedRoot: root,
    digests: true,
    ...options.tuning,
    capture: (key) => key === releaseKey,
    mapEntry: (name) =>
      name.startsWith(prefix) ? name.slice(prefix.length) : undefined,
  }).catch((error: Error) => {
    throw fail(error.message);
  });
  try {
    const archiveSha256 = extracted.sha256 as string;
    checkArchiveDigest(path, archiveSha256, options.expectedSha256);
    const releaseJson = extracted.captured?.get(releaseKey);
    if (releaseJson === undefined) throw fail("release.json is missing");
    const verified = verifyReleaseDirectory(
      payloadTo,
      options.requireTarget,
      true,
      { releaseJson: releaseJson.toString("utf8"), payload: payloadTo },
    );
    verifyWrittenPayload(
      extracted.files as ReadonlyMap<string, string>,
      JSON.parse(
        readFileSync(join(payloadTo, "metadata", "inventory.json"), "utf8"),
      ) as Record<string, string>,
      payloadTo,
    );
    return { ...verified, archiveSha256, cleanup: () => {} };
  } catch (error) {
    rmSync(payloadTo, { recursive: true, force: true });
    throw error;
  }
}

function verifyReleaseDirectory(
  directory: string,
  requireTarget = false,
  fastClient = false,
  source?: ReleaseSource,
): Omit<VerifiedRelease, "cleanup"> {
  try {
    return checkReleaseDirectory(directory, requireTarget, fastClient, source);
  } catch (error) {
    // Malformed metadata is an integrity failure, not a crash.
    if (error instanceof PiShipError) throw error;
    throw fail(`malformed release metadata: ${(error as Error).message}`);
  }
}

/** A release whose `release.json` and payload are not read from `directory`. */
interface ReleaseSource {
  readonly releaseJson: string;
  readonly payload: string;
}

function checkReleaseDirectory(
  directory: string,
  requireTarget: boolean,
  fastClient: boolean,
  source?: ReleaseSource,
): Omit<VerifiedRelease, "cleanup"> {
  if (!fastClient) {
    const checksums = join(directory, "checksums.txt");
    if (!existsSync(checksums)) throw fail("checksums.txt is missing");
    try {
      verifyChecksums(directory, readFileSync(checksums, "utf8"), {
        required: RELEASE_FILES,
      });
    } catch (error) {
      throw fail((error as Error).message);
    }
  }
  const metadata = JSON.parse(
    source?.releaseJson ??
      readFileSync(join(directory, "release.json"), "utf8"),
  ) as ReleaseMetadata;
  if (metadata.schema !== RELEASE_SCHEMA)
    throw fail(`unsupported release metadata ${String(metadata.schema)}`);
  // Releases built before the field existed omit it; anything else must say
  // it was qualified.
  if (
    metadata.qualification !== undefined &&
    metadata.qualification !== RELEASE_QUALIFIED
  )
    throw fail(
      `the release records its qualification as ${JSON.stringify(metadata.qualification)}, not ${RELEASE_QUALIFIED}`,
    );
  const payload = source?.payload ?? join(directory, "payload");
  let lock: DistributionLock;
  try {
    lock = verifyPayloadContents(payload, {
      requireTarget,
      verifyContents: !fastClient,
    });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const inventory = readFileSync(join(payload, "metadata", "inventory.json"));
  const target = JSON.parse(
    readFileSync(join(payload, "metadata", "target.json"), "utf8"),
  ) as { platform: string; arch: string };
  const mismatches = [
    [metadata.distribution.id, lock.app.id, "distribution id"],
    [metadata.distribution.version, lock.app.version, "distribution version"],
    [metadata.distribution.command, lock.app.command, "command"],
    [metadata.pi.version, lock.runtime.version, "Pi version"],
    [metadata.piship.version, lock.runtime.pishipVersion, "PiShip version"],
    [metadata.lockSchema, lock.schema, "lock schema"],
    [
      metadata.lockSha256,
      hash(readFileSync(join(payload, "piship.lock"))),
      "lock digest",
    ],
    [metadata.payload.inventorySha256, hash(inventory), "payload inventory"],
    [metadata.target, `${target.platform}-${target.arch}`, "target"],
  ].filter(([a, b]) => a !== b);
  if (mismatches.length)
    throw fail(
      `release.json does not match the payload: ${mismatches.map((item) => item[2]).join(", ")}`,
    );
  if (fastClient) return { directory, payload, metadata, lock };
  const sbom = JSON.parse(
    readFileSync(join(directory, "sbom.spdx.json"), "utf8"),
  ) as SpdxDocument;
  try {
    verifySbom(payload, sbom);
    verifyNotices(
      sbom,
      JSON.parse(
        readFileSync(join(directory, "licenses", "index.json"), "utf8"),
      ),
    );
  } catch (error) {
    throw fail((error as Error).message);
  }
  const report = JSON.parse(
    readFileSync(join(directory, "vulnerabilities.json"), "utf8"),
  ) as VulnerabilityReport;
  if (
    report.schema !== VULNERABILITY_REPORT_SCHEMA ||
    report.verdict !== "passed"
  )
    throw fail("the recorded vulnerability scan did not pass");
  if (
    metadata.signatures !== undefined &&
    metadata.signatures?.verdict !== "passed" &&
    metadata.signatures?.verdict !== "unavailable"
  )
    throw fail("the recorded registry signature check did not pass");
  if (
    !metadata.tests.length ||
    metadata.tests.some((t) => t.result !== "passed")
  )
    throw fail("required release tests are not recorded as passed");
  return { directory, payload, metadata, lock, sbom };
}

/** Supported state schemas of a payload's PiShip version. */
export function payloadStateSchemas(
  lock: DistributionLock,
): StateSchemaSupport {
  return lock.runtime.stateSchemas ?? LEGACY_STATE_SCHEMAS;
}
