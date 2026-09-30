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
import { hash } from "./shared.js";

export interface VerifiedRelease {
  readonly directory: string;
  readonly payload: string;
  readonly metadata: ReleaseMetadata;
  readonly lock: DistributionLock;
  readonly sbom: SpdxDocument;
  /** Removes the extraction directory when the input was an archive. */
  readonly cleanup: () => void;
}

function fail(message: string): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Release verification: ${message}`,
    {
      component: "release",
      userAction:
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
  } = {},
): Promise<VerifiedRelease> {
  const path = resolve(input);
  let directory = path;
  let cleanup = () => {};
  if (statSync(path).isFile()) {
    const actual = await sha256File(path);
    if (options.expectedSha256 && actual !== options.expectedSha256)
      throw fail(
        `archive SHA-256 ${actual} does not match the expected ${options.expectedSha256}`,
      );
    const sidecar = `${path}.sha256`;
    if (existsSync(sidecar)) {
      const recorded = readFileSync(sidecar, "utf8").split(/\s+/)[0];
      if (recorded !== actual)
        throw fail(
          `archive SHA-256 ${actual} does not match ${basename(sidecar)}`,
        );
    }
    // Without `extractTo` the extraction is a directory of this call, owned
    // and removed by it; a caller's `extractTo` is its own staging directory.
    let own: TemporaryDirectory | undefined;
    if (!options.extractTo) {
      reclaimOsTemporaries();
      own = createTemporaryDirectory(tmpdir(), "verify");
    }
    const parent = options.extractTo ?? (own as TemporaryDirectory).path;
    const expectedRoot = basename(path).replace(/\.tar\.gz$/, "");
    const extracted = await extractArchive(path, join(parent, "x"), {
      expectedRoot,
    }).catch((error: Error) => {
      own?.remove();
      throw fail(error.message);
    });
    directory = join(parent, "x", extracted.root);
    cleanup = () =>
      own ? own.remove() : rmSync(parent, { recursive: true, force: true });
  }
  try {
    const verified = verifyReleaseDirectory(directory, options.requireTarget);
    return { ...verified, cleanup };
  } catch (error) {
    cleanup();
    throw error;
  }
}

function verifyReleaseDirectory(
  directory: string,
  requireTarget = false,
): Omit<VerifiedRelease, "cleanup"> {
  try {
    return checkReleaseDirectory(directory, requireTarget);
  } catch (error) {
    // Malformed metadata is an integrity failure, not a crash.
    if (error instanceof PiShipError) throw error;
    throw fail(`malformed release metadata: ${(error as Error).message}`);
  }
}

function checkReleaseDirectory(
  directory: string,
  requireTarget: boolean,
): Omit<VerifiedRelease, "cleanup"> {
  const checksums = join(directory, "checksums.txt");
  if (!existsSync(checksums)) throw fail("checksums.txt is missing");
  try {
    verifyChecksums(directory, readFileSync(checksums, "utf8"), {
      required: RELEASE_FILES,
    });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const metadata = JSON.parse(
    readFileSync(join(directory, "release.json"), "utf8"),
  ) as ReleaseMetadata;
  if (metadata.schema !== RELEASE_SCHEMA)
    throw fail(`unsupported release metadata ${String(metadata.schema)}`);
  const payload = join(directory, "payload");
  let lock: DistributionLock;
  try {
    lock = verifyPayloadContents(payload, { requireTarget });
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
