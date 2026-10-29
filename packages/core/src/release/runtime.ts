// The distribution-independent runtime release: PiShip, Pi, and the locked
// npm closure with no manifest, lock, resources, or branded command. It reuses
// the release assembly (runtime cache, bundler, scans, SBOM, notices,
// checksums, archive) and the release verification rules.
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import {
  createStageTimer,
  createTemporaryDirectory,
  PiShipError,
} from "@piship/contracts";
import { createArchive, extractArchive, sha256File } from "../archive.js";
import { bundleDistribution } from "../bundle.js";
import { placeRuntime, type RuntimeCacheReport } from "../build.js";
import {
  PI_COMPATIBILITY,
  currentTarget,
  PISHIP_VERSION,
} from "../compatibility.js";
import { STATE_SCHEMAS, type StateSchemaSupport } from "../migration.js";
import { removeTree } from "../parallel-files.js";
import { inventory } from "../payload.js";
import { portableCliSource } from "../launcher-source.js";
import { renameWithRetry } from "../rename-retry.js";
import { runtimeCacheFor } from "../runtime-cache.js";
import { runtimeDependencies } from "../runtime-dependencies.js";
import {
  lockDefaultSearchTools,
  stageSearchTools,
} from "../search-tools/index.js";
import type { LockedSearchTools } from "../lock-schema.js";
import {
  formatChecksums,
  generateNotices,
  generateSbom,
  listPayloadPackages,
  verifyChecksums,
  verifyNotices,
  verifySbom,
  type SpdxDocument,
} from "../supply-chain.js";
import {
  reclaimOsTemporaries,
  sweepOutputStaging,
} from "../temporary-directories.js";
import { prepareAuditDirectory } from "./build.js";
import {
  VULNERABILITY_REPORT_SCHEMA,
  type CommandResult,
  type ReleaseOptions,
  type ReleaseTestResult,
  type RuntimeCacheProvenance,
  type SignatureReport,
  type VulnerabilityReport,
} from "./metadata.js";
import { RELEASE_QUALIFIED } from "./qualification.js";
import {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "./scans.js";
import {
  gate,
  hash,
  outcome,
  runCommand,
  unwrap,
  writeJson,
} from "./shared.js";
import { checkArchiveDigest } from "./verify.js";

export const RUNTIME_SCHEMA = "piship-runtime/v1";

/** The archive name prefix, which is how an input is told to be a runtime release. */
export const RUNTIME_PREFIX = "piship-runtime-";

/** Files every runtime release carries besides the payload, in checksum order. */
export const RUNTIME_FILES = [
  "licenses/THIRD_PARTY_NOTICES.txt",
  "licenses/index.json",
  "payload/metadata/inventory.json",
  "runtime.json",
  "sbom.spdx.json",
  "vulnerabilities.json",
] as const;

/** Files a distribution adds to a payload; a runtime has none of them. */
const DISTRIBUTION_FILES = ["bin", "piship.lock", "piship.yaml", "resources"];

const NODE_MIN = "22.19.0";
const AUDIT_DIRECTORY = ".audit";
const RELEASE_DIRECTORY = ".release";

export interface RuntimeMetadata {
  readonly schema: typeof RUNTIME_SCHEMA;
  readonly pishipVersion: string;
  readonly pi: {
    readonly package: string;
    readonly version: string;
    /** The weakest of the Pi version's recorded compatibility surfaces. */
    readonly compatibility: string;
  };
  /** The digest of the payload's package-lock.json: what a pack's lock must name. */
  readonly npmLockSha256: string;
  readonly target: string;
  readonly nodeMin: string;
  readonly strip: true;
  readonly bundle: true;
  /** Version of each search tool bundled in the payload (`tools/`), pinned in `metadata/search-tools.json`. */
  readonly searchTools: Readonly<Record<string, string>>;
  /** RFC 3339; SOURCE_DATE_EPOCH when set, so rebuilds stay identical. */
  readonly created: string;
  readonly qualification: string;
  readonly inventory: { readonly sha256: string; readonly files: number };
  readonly stateSchemas: StateSchemaSupport;
  readonly tests: readonly ReleaseTestResult[];
  readonly sbom: {
    readonly path: string;
    readonly sha256: string;
    readonly packages: number;
  };
  readonly notices: { readonly path: string; readonly index: string };
  readonly vulnerabilities: {
    readonly path: string;
    readonly failOn: string;
    readonly verdict: "passed";
    readonly counts: Readonly<Record<string, number>>;
  };
  readonly signatures?: SignatureReport;
  readonly attribution: string;
}

export interface RuntimeReleaseOptions
  extends Pick<
    ReleaseOptions,
    | "outputRoot"
    | "scanner"
    | "signatureAuditor"
    | "now"
    | "cache"
    | "reclaimStaging"
    | "abandonedStaging"
  > {
  /** Test seam: runs the payload's `piship.mjs` (defaults to Node). */
  readonly runTest?: (
    payload: string,
    args: readonly string[],
    env: NodeJS.ProcessEnv,
  ) => Promise<CommandResult> | CommandResult;
  /**
   * Test seam: places the search tools in the payload and returns what it
   * pinned (defaults to downloading and placing the catalog versions).
   */
  readonly bundleSearchTools?: (
    payload: string,
    target: string,
  ) => Promise<LockedSearchTools> | LockedSearchTools;
  /** Test seam: completes the payload (tree, npm lock, inventory) instead of installing the runtime. */
  readonly assemble?: (payload: string) => void;
}

export interface BuiltRuntimeRelease {
  readonly name: string;
  readonly directory: string;
  readonly archive: string;
  readonly sha256: string;
  readonly metadata: RuntimeMetadata;
  readonly runtimeCache: RuntimeCacheProvenance;
}

export function runtimeReleaseName(target: string): string {
  return `${RUNTIME_PREFIX}${PISHIP_VERSION}-${target}`;
}

function createdTime(): string {
  const epoch = Number(process.env.SOURCE_DATE_EPOCH);
  const seconds =
    process.env.SOURCE_DATE_EPOCH !== undefined &&
    Number.isSafeInteger(epoch) &&
    epoch >= 0
      ? epoch
      : 0;
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

function compatibility(version: string): string {
  const known = PI_COMPATIBILITY[version];
  const order = ["unsupported", "candidate", "supported"];
  const ranks = (
    ["personal", "managed", "governance", "lifecycle"] as const
  ).map((surface) =>
    Math.max(0, order.indexOf(known?.[surface] ?? "unsupported")),
  );
  return order[Math.min(...ranks)] as string;
}

/**
 * Build a verified runtime release for this machine's target: the runtime
 * tree, dependency scan, registry signature check, SBOM, notices, one launch
 * test, checksums, and a deterministic archive. Any failure removes the
 * partial output.
 */
export async function buildRuntimeRelease(
  options: RuntimeReleaseOptions = {},
): Promise<BuiltRuntimeRelease> {
  const timer = createStageTimer();
  const target = currentTarget();
  const runtime = runtimeDependencies(true);
  const outputRoot = resolve(options.outputRoot ?? "dist", "releases");
  const name = runtimeReleaseName(target);
  const directory = join(outputRoot, name);
  const archive = join(outputRoot, `${name}.tar.gz`);
  mkdirSync(outputRoot, { recursive: true });
  sweepOutputStaging(outputRoot, "release", options);
  const temporary = createTemporaryDirectory(outputRoot, "release", "runtime");
  const stage = temporary.path;
  const inFlight: Promise<unknown>[] = [];
  try {
    const injected = options.assemble !== undefined;
    const runtimeCache =
      injected ||
      options.cache === false ||
      process.env.PISHIP_RELEASE_NO_CACHE === "1"
        ? undefined
        : runtimeCacheFor({ runtime });
    const provenance: {
      -readonly [K in keyof RuntimeCacheProvenance]: RuntimeCacheProvenance[K];
    } = { status: "disabled" };
    const root = join(stage, RELEASE_DIRECTORY);
    const payload = join(root, "payload");
    mkdirSync(payload, { recursive: true });
    const writeFiles = (): void => {
      mkdirSync(join(payload, "metadata"), { recursive: true });
      writeFileSync(
        join(payload, "metadata", "target.json"),
        `${JSON.stringify({ platform: process.platform, arch: process.arch }, null, 2)}\n`,
      );
      writeFileSync(join(payload, "piship.mjs"), portableCliSource());
    };
    let searchTools: LockedSearchTools = {};
    const placeSearchTools = async (): Promise<void> => {
      searchTools = await (
        options.bundleSearchTools ??
        (async (dir, platform) => {
          const locked = await lockDefaultSearchTools(platform);
          stageSearchTools({ searchTools: locked }, dir, platform);
          return locked;
        })
      )(payload, target);
      writeJson(join(payload, "metadata", "search-tools.json"), {
        searchTools,
      });
    };
    if (options.assemble) {
      writeFiles();
      await placeSearchTools();
      options.assemble(payload);
    } else {
      await timer.run("runtime assembly", async () => {
        placeRuntime(payload, {
          cache: runtimeCache,
          strip: true,
          leaveWhole: true,
          progress: undefined,
          found: (found: RuntimeCacheReport) => {
            provenance.status =
              found.status === "unusable" ? "disabled" : found.status;
            if (found.entry) {
              provenance.entry = found.entry;
              provenance.linked = found.linked;
              provenance.copied = found.copied;
            }
            if (found.framework) provenance.framework = found.framework;
            if (found.crossVolume) provenance.crossVolume = true;
          },
          meanwhile: writeFiles,
          overlap: false,
        });
      });
      await timer.run("search tools", placeSearchTools);
    }
    const lockDirectory = join(stage, AUDIT_DIRECTORY);
    prepareAuditDirectory(payload, lockDirectory);
    const now = options.now ?? (() => new Date());
    const vulnerabilityScan = outcome(
      timer.run("npm audit", async () =>
        (options.scanner ?? npmAuditScanner)(lockDirectory),
      ),
    );
    const signatureScan = outcome(
      timer.run("signature audit", async () =>
        (options.signatureAuditor ?? npmSignatureAuditor)(payload),
      ),
    );
    inFlight.push(vulnerabilityScan, signatureScan);
    const created = createdTime();
    const packages = listPayloadPackages(payload);
    const sbom = generateSbom({
      payloadDir: payload,
      distribution: {
        id: "piship-runtime",
        name: "PiShip Runtime",
        version: PISHIP_VERSION,
      },
      target,
      created,
      packages,
      lockPackages: runtime.packages,
    });
    verifySbom(payload, sbom, packages);
    writeJson(join(root, "sbom.spdx.json"), sbom);
    const notices = generateNotices(payload, packages);
    mkdirSync(join(root, "licenses"), { recursive: true });
    writeFileSync(
      join(root, "licenses", "THIRD_PARTY_NOTICES.txt"),
      notices.text,
    );
    writeJson(join(root, "licenses", "index.json"), notices.index);
    // The signature check reads the installed packages that bundling replaces.
    const signatures = evaluateSignatures(unwrap(await signatureScan));
    if (!injected)
      await timer.run("bundle", async () =>
        bundleDistribution(payload, {
          components: packages,
          ...(runtimeCache
            ? {
                cache: runtimeCache,
                onCache: (found: "hit" | "miss") => {
                  provenance.bundle = found;
                },
              }
            : {}),
          strip: true,
        }),
      );
    const tests = await timer.run("smoke tests", async () => {
      reclaimOsTemporaries();
      const env: NodeJS.ProcessEnv = { ...process.env, PISHIP_NO_BROWSER: "1" };
      delete env.PISHIP_BUILD_INPUT;
      const result = await (
        options.runTest ??
        ((dir, args, environment) =>
          runCommand(process.execPath, [join(dir, "piship.mjs"), ...args], {
            env: environment,
            cwd: dir,
            timeout: 300_000,
          }))
      )(payload, ["--version"], env);
      if (result.status !== 0 || result.stdout.trim() !== PISHIP_VERSION)
        throw gate(
          "UPDATE_FAILED",
          "test",
          `required test runtime-version failed: ${(result.stderr || result.stdout).trim().slice(0, 500)}`,
        );
      return [{ name: "runtime-version", result: "passed" as const }];
    });
    const report = evaluateVulnerabilities(
      unwrap(await vulnerabilityScan),
      // The runtime has no release policy of its own: the defaults apply.
      { failOn: "high", allow: [] },
      now(),
    );
    writeJson(join(root, "vulnerabilities.json"), report);
    if (report.verdict !== "passed")
      throw gate(
        "POLICY_DENIED",
        "vulnerability",
        `blocking advisories at or above ${report.failOn}: ${report.findings
          .filter((item) => item.status === "blocking")
          .map((item) => `${item.id} (${item.package}, ${item.severity})`)
          .join(", ")}`,
        "Update the dependency, then build the runtime again",
      );
    const inventoryText = readFileSync(
      join(payload, "metadata", "inventory.json"),
    );
    const metadata: RuntimeMetadata = {
      schema: RUNTIME_SCHEMA,
      pishipVersion: PISHIP_VERSION,
      pi: {
        package: runtime.package,
        version: runtime.version,
        compatibility: compatibility(runtime.version),
      },
      npmLockSha256: runtime.npmLockSha256,
      target,
      nodeMin: NODE_MIN,
      strip: true,
      bundle: true,
      searchTools: Object.fromEntries(
        Object.entries(searchTools).map(([tool, locked]) => [
          tool,
          locked.version,
        ]),
      ),
      created,
      qualification: RELEASE_QUALIFIED,
      inventory: {
        sha256: hash(inventoryText),
        files: Object.keys(JSON.parse(inventoryText.toString())).length + 1,
      },
      stateSchemas: runtime.stateSchemas ?? STATE_SCHEMAS,
      tests,
      sbom: {
        path: "sbom.spdx.json",
        sha256: hash(readFileSync(join(root, "sbom.spdx.json"))),
        packages: packages.length,
      },
      notices: {
        path: "licenses/THIRD_PARTY_NOTICES.txt",
        index: "licenses/index.json",
      },
      vulnerabilities: {
        path: "vulnerabilities.json",
        failOn: report.failOn,
        verdict: "passed",
        counts: report.counts,
      },
      signatures,
      attribution: `PiShip Runtime ${PISHIP_VERSION}, built on Pi ${runtime.version} by Earendil Works`,
    };
    writeJson(join(root, "runtime.json"), metadata);
    writeFileSync(
      join(root, "checksums.txt"),
      formatChecksums(root, [...RUNTIME_FILES]),
    );
    const stagedArchive = join(stage, `${name}.tar.gz`);
    const result = await timer.run("archive", () =>
      createArchive(root, name, stagedArchive),
    );
    removeTree(directory, { attempts: 3 });
    rmSync(archive, { force: true });
    renameWithRetry(root, directory);
    renameWithRetry(stagedArchive, archive);
    writeFileSync(`${archive}.sha256`, `${result.sha256}  ${name}.tar.gz\n`);
    return {
      name,
      directory,
      archive,
      sha256: result.sha256,
      metadata,
      runtimeCache: provenance,
    };
  } finally {
    await Promise.all(inFlight);
    temporary.remove();
    timer.report("runtime release");
  }
}

export interface VerifiedRuntimeRelease {
  readonly directory: string;
  readonly payload: string;
  readonly metadata: RuntimeMetadata;
  readonly archiveSha256?: string;
  /** Removes the extraction directory when the input was an archive. */
  readonly cleanup: () => void;
}

/**
 * Which kind of release `input` is, by its content: `runtime.json` or
 * `release.json` at the root of the directory or archive. Anything else,
 * including a missing input, is left to the release verifier to report.
 */
export async function releaseKind(
  input: string,
): Promise<"runtime" | "release"> {
  const path = resolve(input);
  if (!existsSync(path)) return "release";
  if (!statSync(path).isFile())
    return existsSync(join(path, "runtime.json")) ? "runtime" : "release";
  const root = basename(path).replace(/\.tar\.gz$/, "");
  const own = createTemporaryDirectory(tmpdir(), "verify");
  try {
    const found = await extractArchive(path, join(own.path, "x"), {
      expectedRoot: root,
      hash: false,
      capture: (key) => key === `${root}/runtime.json`,
      mapEntry: () => undefined,
    });
    return found.captured?.has(`${root}/runtime.json`) ? "runtime" : "release";
  } catch {
    return "release";
  } finally {
    own.remove();
  }
}

function fail(message: string): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `Runtime release verification: ${message}`,
    {
      component: "release",
      userAction:
        "Do not use this artifact; obtain it again from the trusted source",
    },
  );
}

/**
 * Consumer verification of a runtime release archive or directory, by the
 * rules of `verifyRelease`: archive digest, checksums, every payload file
 * against its inventory, metadata against the payload, SBOM, notices, and the
 * scan and test verdicts. With `requireTarget`, the runtime must be for this
 * machine.
 */
export async function verifyRuntimeRelease(
  input: string,
  options: {
    readonly requireTarget?: boolean;
    readonly expectedSha256?: string;
  } = {},
): Promise<VerifiedRuntimeRelease> {
  const path = resolve(input);
  let directory = path;
  let archiveSha256: string | undefined;
  let cleanup = () => {};
  if (statSync(path).isFile()) {
    archiveSha256 = await sha256File(path);
    checkArchiveDigest(path, archiveSha256, options.expectedSha256);
    reclaimOsTemporaries();
    const own = createTemporaryDirectory(tmpdir(), "verify");
    const expectedRoot = basename(path).replace(/\.tar\.gz$/, "");
    const extracted = await extractArchive(path, join(own.path, "x"), {
      expectedRoot,
      hash: false,
    }).catch((error: Error) => {
      own.remove();
      throw fail(error.message);
    });
    directory = join(own.path, "x", extracted.root);
    cleanup = () => own.remove();
  }
  try {
    return {
      ...checkRuntimeDirectory(directory, options.requireTarget === true),
      ...(archiveSha256 ? { archiveSha256 } : {}),
      cleanup,
    };
  } catch (error) {
    cleanup();
    if (error instanceof PiShipError) throw error;
    throw fail(`malformed runtime metadata: ${(error as Error).message}`);
  }
}

function checkRuntimeDirectory(
  directory: string,
  requireTarget: boolean,
): Omit<VerifiedRuntimeRelease, "cleanup" | "archiveSha256"> {
  const checksums = join(directory, "checksums.txt");
  if (!existsSync(checksums)) throw fail("checksums.txt is missing");
  try {
    verifyChecksums(directory, readFileSync(checksums, "utf8"), {
      required: RUNTIME_FILES,
    });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const metadata = JSON.parse(
    readFileSync(join(directory, "runtime.json"), "utf8"),
  ) as RuntimeMetadata;
  if (metadata.schema !== RUNTIME_SCHEMA)
    throw fail(`unsupported runtime metadata ${String(metadata.schema)}`);
  if (metadata.qualification !== RELEASE_QUALIFIED)
    throw fail(
      `the runtime records its qualification as ${JSON.stringify(metadata.qualification)}, not ${RELEASE_QUALIFIED}`,
    );
  const unexpected = [
    ...readdirSync(directory).filter(
      (entry) =>
        entry !== "checksums.txt" &&
        !RUNTIME_FILES.some((file) => file.split("/")[0] === entry),
    ),
    ...readdirSync(join(directory, "licenses"))
      .filter((entry) => !RUNTIME_FILES.includes(`licenses/${entry}` as never))
      .map((entry) => `licenses/${entry}`),
  ];
  if (unexpected.length)
    throw fail(
      `unexpected entries in the runtime release: ${unexpected.join(", ")}`,
    );
  const payload = join(directory, "payload");
  const found = DISTRIBUTION_FILES.filter((file) =>
    existsSync(join(payload, file)),
  );
  if (found.length)
    throw fail(
      `the payload holds distribution files (${found.join(", ")}); a runtime has none`,
    );
  const inventoryPath = join(payload, "metadata", "inventory.json");
  const expected = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
    string,
    string
  >;
  const actual = inventory(payload);
  const added = Object.keys(actual).filter((key) => !(key in expected));
  const missing = Object.keys(expected).filter((key) => !(key in actual));
  const modified = Object.keys(actual).filter(
    (key) => key in expected && expected[key] !== actual[key],
  );
  if (added.length || missing.length || modified.length)
    throw fail(
      `the payload does not match its inventory (added: ${added.length}, missing: ${missing.length}, modified: ${modified.length}${modified.length ? `; first: ${modified[0]}` : ""})`,
    );
  const target = JSON.parse(
    readFileSync(join(payload, "metadata", "target.json"), "utf8"),
  ) as { platform: string; arch: string };
  const npmLock = JSON.parse(
    readFileSync(join(payload, "package-lock.json"), "utf8"),
  ) as { packages?: Record<string, { version?: string }> };
  const core = JSON.parse(
    readFileSync(
      join(payload, "node_modules", "@piship", "core", "package.json"),
      "utf8",
    ),
  ) as { version?: string };
  const searchTools =
    (existsSync(join(payload, "metadata", "search-tools.json"))
      ? (
          JSON.parse(
            readFileSync(
              join(payload, "metadata", "search-tools.json"),
              "utf8",
            ),
          ) as { searchTools?: LockedSearchTools }
        ).searchTools
      : undefined) ?? {};
  const mismatches = [
    [metadata.pishipVersion, core.version, "PiShip version"],
    [
      metadata.pi.version,
      npmLock.packages?.[`node_modules/${metadata.pi.package}`]?.version,
      "Pi version",
    ],
    [
      JSON.stringify(metadata.searchTools),
      JSON.stringify(
        Object.fromEntries(
          Object.entries(searchTools).map(([tool, locked]) => [
            tool,
            locked.version,
          ]),
        ),
      ),
      "search tools",
    ],
    [metadata.target, `${target.platform}-${target.arch}`, "target"],
    [
      metadata.npmLockSha256,
      hash(readFileSync(join(payload, "package-lock.json"))),
      "npm lock digest",
    ],
    [metadata.inventory.sha256, hash(readFileSync(inventoryPath)), "inventory"],
  ].filter(([a, b]) => a !== b);
  if (mismatches.length)
    throw fail(
      `runtime.json does not match the payload: ${mismatches.map((item) => item[2]).join(", ")}`,
    );
  if (
    requireTarget &&
    (target.platform !== process.platform || target.arch !== process.arch)
  )
    throw fail(
      `the runtime is for ${metadata.target}, not this machine (${currentTarget()}); use the runtime built for this target`,
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
    metadata.signatures.verdict !== "passed" &&
    metadata.signatures.verdict !== "unavailable"
  )
    throw fail("the recorded registry signature check did not pass");
  if (
    !metadata.tests.length ||
    metadata.tests.some((t) => t.result !== "passed")
  )
    throw fail("required runtime tests are not recorded as passed");
  return { directory, payload, metadata };
}
