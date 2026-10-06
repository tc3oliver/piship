// Production release builds. A release wraps the canonical payload from
// `buildDistribution` unchanged; it never assembles a second runtime,
// resource, or launcher layout.
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createStageTimer, createTemporaryDirectory } from "@piship/contracts";
import {
  RELEASE_CHANNELS,
  type ReleaseManifest,
  type UpdatesManifest,
} from "@piship/schema";
import { bundleDistribution } from "../bundle.js";
import { createArchive } from "../archive.js";
import {
  buildDistribution,
  currentTarget,
  type DistributionLock,
} from "../index.js";
import type { RuntimeCacheReport } from "../build.js";
import { STATE_SCHEMAS } from "../migration.js";
import { removeTree } from "../parallel-files.js";
import { renameWithRetry } from "../rename-retry.js";
import { runtimeCacheFor } from "../runtime-cache.js";
import { downloadLockedSearchTools } from "../search-tools/index.js";
import { workspacePackages } from "../runtime-dependencies.js";
import {
  formatChecksums,
  generateNotices,
  generateSbom,
  listPayloadPackages,
  verifySbom,
} from "../supply-chain.js";
import {
  reclaimOsTemporaries,
  sweepOutputStaging,
} from "../temporary-directories.js";
import {
  checkReleaseInputs,
  piCompatibility,
  piCompatibilitySurfaces,
  releaseName,
} from "./gates.js";
import {
  RELEASE_FILES,
  RELEASE_SCHEMA,
  type BuiltRelease,
  type CommandResult,
  type ReleaseMetadata,
  type ReleaseOptions,
  type RuntimeCacheProvenance,
  type ReleaseTestResult,
  type AsyncReleaseTestRunner,
  BUILD_INFO_SCHEMA,
} from "./metadata.js";
import {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "./scans.js";
import {
  auditPiPackage,
  PI_PACKAGE_VENDOR_DIRECTORY,
} from "../pi-packages/gates.js";
import { RELEASE_QUALIFIED } from "./qualification.js";
import {
  gate,
  hash,
  outcome,
  runCommand,
  unwrap,
  writeJson,
} from "./shared.js";

/**
 * The fixed directories of a release's staging directory. The built payload
 * lands in the same directory as `<id>`, and a distribution ID is lowercase
 * letters, digits, and hyphens, so a name that starts with a dot can never be
 * one (an ID of `release` or `audit` would have collided with plain names).
 */
const RELEASE_DIRECTORY = ".release";
const AUDIT_DIRECTORY = ".audit";

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

/** Default test runner: runs the payload's launcher with Node. */
export function runPayloadCommand(
  payload: string,
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<CommandResult> {
  return runCommand(
    process.execPath,
    [join(payload, "bin", command), ...args],
    {
      env,
      cwd: payload,
      timeout: 300_000,
    },
  );
}

/**
 * Required release tests on the assembled payload, each with its own
 * throwaway state directory so they run side by side: launch and version
 * (integrity, target, Node, pinned Pi); the offline smoke session when the
 * distribution needs no sign-in; and the governance inspection when governed.
 */
async function runReleaseTests(
  payload: string,
  lock: DistributionLock,
  runTest: AsyncReleaseTestRunner,
): Promise<ReleaseTestResult[]> {
  reclaimOsTemporaries();
  const env: NodeJS.ProcessEnv = { ...process.env, PISHIP_NO_BROWSER: "1" };
  delete env.PISHIP_BUILD_INPUT;
  const tests: [string, string[], (out: string) => boolean][] = [
    [
      "launch-version",
      ["version"],
      // The Pi line on its own: "AcmePi 1.0.0" names the app, not Pi 1.0.0.
      (out) =>
        out.includes(`${lock.app.name} ${lock.app.version}`) &&
        out
          .split(/\r?\n/)
          .some(
            (line) =>
              line === `Pi ${lock.runtime.version}` ||
              line.startsWith(`Pi ${lock.runtime.version} `),
          ),
    ],
  ];
  const needsSignIn =
    !!lock.access &&
    (lock.access.identity.mode !== "none" ||
      !["pi-native", "none"].includes(lock.access.credential.provider));
  if (!needsSignIn)
    tests.push([
      "offline-smoke",
      ["--smoke"],
      (out) => out.includes('"initialized":true'),
    ]);
  if (lock.governance)
    tests.push([
      "governance-inspection",
      ["capabilities", "--json"],
      (out) => out.trim().startsWith("["),
    ]);
  const outcomes = await Promise.allSettled(
    tests.map(async ([name, args, accept]) => {
      const state = createTemporaryDirectory(tmpdir(), "release-test");
      try {
        const result = await runTest(payload, lock.app.command, args, {
          ...env,
          PISHIP_STATE_HOME: state.path,
        });
        if (result.status !== 0 || !accept(result.stdout))
          throw gate(
            "UPDATE_FAILED",
            "test",
            `required test ${name} failed: ${(result.stderr || result.stdout).trim().slice(0, 500)}`,
          );
        return { name, result: "passed" as const };
      } finally {
        state.remove();
      }
    }),
  );
  // Every test has finished and removed its state before the first failure,
  // in test order, is reported.
  return outcomes.map((outcome) => {
    if (outcome.status === "rejected") throw outcome.reason;
    return outcome.value;
  });
}

function installScripts(name: string): { sh: string; ps1: string } {
  return {
    sh: `#!/bin/sh
# Installs this release's payload for the current user. The install checks the
# release metadata and this machine's target; it does not hash every payload
# file. Run \`verify-release\` on this directory for the full verification.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }
node "$here/payload/piship.mjs" install "$here" "$@"
echo "Full verification of this release (every payload file, SBOM, notices) is separate: node \\"$here/payload/piship.mjs\\" verify-release \\"$here\\""
`,
    ps1: `# Installs this release's payload for the current user. The install checks the
# release metadata and this machine's target; it does not hash every payload
# file. Run verify-release on this directory for the full verification.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Error 'Node.js 22.19.0 or newer is required. Install Node separately.'; exit 1 }
node "$here\\payload\\piship.mjs" install "$here" @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "Full verification of this release (every payload file, SBOM, notices) is separate: node \`"$here\\payload\\piship.mjs\`" verify-release \`"$here\`""
exit 0
# Release ${name}
`,
  };
}

/**
 * Whether a release builds its runtime cold: `piship release --rebuild`,
 * PISHIP_RELEASE_NO_CACHE=1, or an injected assembler, which has no runtime to
 * cache.
 */
export function runtimeCacheDisabled(
  options: Pick<ReleaseOptions, "cache" | "assemble">,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return (
    options.cache === false ||
    options.assemble !== undefined ||
    env.PISHIP_RELEASE_NO_CACHE === "1"
  );
}

/**
 * Build a verified release: static gates, the canonical payload, required
 * tests, dependency scan, registry signature check, SBOM, notices,
 * metadata, checksums, and a deterministic archive. Any failure removes
 * the partial output.
 */
export async function buildRelease(
  manifestPath: string,
  options: ReleaseOptions = {},
): Promise<BuiltRelease> {
  const timer = createStageTimer();
  const target = options.target ?? currentTarget();
  const inputsChecked = timer.start("release inputs");
  const lock = checkReleaseInputs(manifestPath, target);
  inputsChecked();
  const updates = lock.updates as UpdatesManifest;
  const channel = options.channel ?? updates.channel;
  if (!(RELEASE_CHANNELS as readonly string[]).includes(channel))
    throw gate("CONFIG_INVALID", "channel", `unknown channel ${channel}`);
  const outputRoot = resolve(options.outputRoot ?? "dist", "releases");
  const name = releaseName(lock, target);
  const directory = join(outputRoot, name);
  const archive = join(outputRoot, `${name}.tar.gz`);
  const buildInfo = join(outputRoot, `${name}.build-info.json`);
  mkdirSync(outputRoot, { recursive: true });
  sweepOutputStaging(outputRoot, "release", options);
  // Every character of the staging path counts on Windows, where npm cannot
  // run an install script in a directory longer than 260 characters, and the
  // deepest such directory is inside the build's own staging directory. So
  // this one is named for the distribution, not the release, and the payload
  // is assembled straight into it (as `<stage>/<id>`).
  const temporary = createTemporaryDirectory(
    outputRoot,
    "release",
    lock.app.id,
  );
  const stage = temporary.path;
  const inFlight: Promise<unknown>[] = [];
  try {
    // The pinned search tool archives for this target, checked against the
    // lock, before the payload is assembled from them.
    await timer.run("search tools", () =>
      downloadLockedSearchTools(lock, target),
    );
    // Only runtime bytes come from the cache; every check below runs afresh.
    const runtimeCache = runtimeCacheDisabled(options)
      ? undefined
      : runtimeCacheFor(lock);
    // Reported beside the release, never in it: the release bytes must not
    // depend on the cache.
    const provenance: {
      -readonly [K in keyof RuntimeCacheProvenance]: RuntimeCacheProvenance[K];
    } = { status: "disabled" };
    if (!runtimeCache) timer.start("runtime cache disabled")();
    const assembled = timer.start("runtime assembly");
    const built = options.assemble
      ? options.assemble(manifestPath, stage)
      : buildDistribution(manifestPath, stage, {
          cache: false,
          deferBundle: true,
          ...(runtimeCache
            ? {
                runtimeCache,
                onRuntimeCache: (found: RuntimeCacheReport) => {
                  const detail =
                    found.status === "hit"
                      ? ` (${found.linked} linked, ${found.copied} copied)`
                      : found.crossVolume
                        ? " (entry copied across volumes)"
                        : "";
                  timer.start(`runtime cache ${found.status}${detail}`)();
                  // A cache that could not be used shipped nothing from it.
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
              }
            : {}),
        });
    assembled();
    const payload = join(stage, RELEASE_DIRECTORY, "payload");
    mkdirSync(dirname(payload), { recursive: true });
    renameWithRetry(built, payload);
    const root = dirname(payload);
    const lockDirectory = join(stage, AUDIT_DIRECTORY);
    mkdirSync(lockDirectory);
    copyFileSync(
      join(payload, "package-lock.json"),
      join(lockDirectory, "package-lock.json"),
    );
    const buildInputDirectory = join(
      payload,
      "node_modules",
      "@piship",
      "core",
      "dist",
      "build-input",
    );
    if (existsSync(join(buildInputDirectory, "package.json"))) {
      copyFileSync(
        join(buildInputDirectory, "package.json"),
        join(lockDirectory, "package.json"),
      );
      // npm audit reaches the runtime dependencies only through the
      // workspace packages that declare them. Without their manifests every
      // locked package is unreachable, `--omit=dev` drops it, and the scan
      // passes without checking anything.
      for (const name of workspacePackages) {
        const folder = join(lockDirectory, "packages", name);
        mkdirSync(folder, { recursive: true });
        copyFileSync(
          join(buildInputDirectory, "packages", name, "package.json"),
          join(folder, "package.json"),
        );
      }
    }
    const release = lock.release as ReleaseManifest;
    const now = options.now ?? (() => new Date());
    // The scans wait on the registry, so they start together and run beside
    // the SBOM, notices, bundling, and tests, which do not touch the lock
    // directory. Each Pi package lockfile goes through the same policy,
    // against release.vulnerabilities.registry or the package's own registry.
    // The package files are read now, before bundling rewrites the payload.
    const vulnerabilityScan = outcome(
      timer.run("npm audit", async () =>
        (options.scanner ?? npmAuditScanner)(lockDirectory),
      ),
    );
    const packageScan = outcome(
      timer.run("pi package audits", () =>
        Promise.all(
          (lock.packages ?? []).map(async (entry) => {
            const vendored = join(
              payload,
              PI_PACKAGE_VENDOR_DIRECTORY,
              entry.id,
            );
            const declaration =
              lock.governance?.manifest.resources.packages?.find(
                (item) => item.id === entry.id,
              );
            const registry =
              release.vulnerabilities.registry ??
              (declaration?.source === "npm"
                ? declaration.registry
                : undefined);
            const audit = await auditPiPackage(
              entry.id,
              {
                manifest: readFileSync(join(vendored, "package.json"), "utf8"),
                lockfile: readFileSync(
                  join(vendored, "package-lock.json"),
                  "utf8",
                ),
              },
              release.vulnerabilities,
              {
                mode: lock.deployment.mode,
                ...(registry ? { registry } : {}),
                now: now(),
                ...(options.scanner ? { scanner: options.scanner } : {}),
              },
            );
            return {
              id: audit.id,
              scannedAt: audit.scannedAt,
              ...(audit.report
                ? {
                    verdict: audit.report.verdict,
                    findings: audit.report.findings,
                  }
                : {}),
              ...(audit.warning ? { warning: audit.warning } : {}),
            };
          }),
        ),
      ),
    );
    const signatureScan = outcome(
      timer.run("signature audit", async () =>
        (options.signatureAuditor ?? npmSignatureAuditor)(payload),
      ),
    );
    // Whatever happens next, no scan may still be running in the staging
    // directory when the cleanup removes it.
    inFlight.push(vulnerabilityScan, packageScan, signatureScan);
    const created = createdTime();
    const sbomWritten = timer.start("sbom");
    const packages = listPayloadPackages(payload);
    const sbom = generateSbom({
      payloadDir: payload,
      distribution: lock.app,
      target,
      created,
      packages,
      lockPackages: lock.runtime.packages,
    });
    verifySbom(payload, sbom, packages);
    writeJson(join(root, "sbom.spdx.json"), sbom);
    sbomWritten();
    const noticesWritten = timer.start("notices");
    const notices = generateNotices(payload, packages);
    mkdirSync(join(root, "licenses"), { recursive: true });
    writeFileSync(
      join(root, "licenses", "THIRD_PARTY_NOTICES.txt"),
      notices.text,
    );
    writeJson(join(root, "licenses", "index.json"), notices.index);
    noticesWritten();
    const startTests = () => {
      const run = outcome(
        timer.run("smoke tests", () =>
          runReleaseTests(payload, lock, options.runTest ?? runPayloadCommand),
        ),
      );
      inFlight.push(run);
      return run;
    };
    // Both only read the installed packages, so without bundling the tests
    // run beside the signature check. Bundling replaces those packages: the
    // signature check, which reads them, has to finish first, and the tests
    // run on what bundling leaves.
    const unbundledTests = release.bundle === true ? undefined : startTests();
    const signatures = evaluateSignatures(unwrap(await signatureScan));
    if (release.bundle === true)
      await timer.run("bundle", () =>
        bundleDistribution(payload, {
          // The packages the SBOM and notices were made from.
          components: packages,
          ...(runtimeCache
            ? {
                cache: runtimeCache,
                onCache: (found: "hit" | "miss") => {
                  timer.start(`bundle cache ${found}`)();
                  provenance.bundle = found;
                },
              }
            : {}),
          strip: release.strip === true,
        }),
      );
    const tests = unwrap(await (unbundledTests ?? startTests()));
    const report = evaluateVulnerabilities(
      unwrap(await vulnerabilityScan),
      release.vulnerabilities,
      now(),
    );
    const packageAudits = unwrap(await packageScan);
    writeJson(
      join(root, "vulnerabilities.json"),
      packageAudits.length ? { ...report, packages: packageAudits } : report,
    );
    if (report.verdict !== "passed")
      throw gate(
        "POLICY_DENIED",
        "vulnerability",
        `blocking advisories at or above ${release.vulnerabilities.failOn}: ${report.findings
          .filter((item) => item.status === "blocking")
          .map((item) => `${item.id} (${item.package}, ${item.severity})`)
          .join(", ")}`,
        "Update the dependency, or record a reviewed exception with an expiry in release.vulnerabilities.allow",
      );
    const metadataStarted = timer.start("metadata");
    const scripts = installScripts(name);
    writeFileSync(join(root, "install.sh"), scripts.sh);
    if (process.platform !== "win32")
      chmodSync(join(root, "install.sh"), 0o755);
    writeFileSync(join(root, "install.ps1"), scripts.ps1);
    const inventory = readFileSync(join(payload, "metadata", "inventory.json"));
    const metadata: ReleaseMetadata = {
      schema: RELEASE_SCHEMA,
      distribution: {
        id: lock.app.id,
        name: lock.app.name,
        version: lock.app.version,
        command: lock.app.command,
        mode: lock.deployment.mode,
      },
      piship: { version: lock.runtime.pishipVersion },
      pi: {
        package: lock.runtime.package,
        version: lock.runtime.version,
        compatibility: piCompatibility(lock),
        surfaces: piCompatibilitySurfaces(lock),
      },
      manifestSchema: lock.manifest.schema,
      lockSchema: lock.schema,
      lockSha256: hash(readFileSync(join(payload, "piship.lock"))),
      target,
      channel,
      created,
      qualification: RELEASE_QUALIFIED,
      payload: {
        path: "payload",
        inventorySha256: hash(inventory),
        files: Object.keys(JSON.parse(inventory.toString())).length + 1,
      },
      stateSchemas: lock.runtime.stateSchemas ?? STATE_SCHEMAS,
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
      attribution: `${lock.app.name} ${lock.app.version}, built with PiShip ${lock.runtime.pishipVersion} on Pi ${lock.runtime.version} by Earendil Works`,
    };
    writeJson(join(root, "release.json"), metadata);
    metadataStarted();
    const checksumsWritten = timer.start("checksums");
    writeFileSync(
      join(root, "checksums.txt"),
      formatChecksums(root, [...RELEASE_FILES]),
    );
    checksumsWritten();
    const stagedArchive = join(stage, `${name}.tar.gz`);
    const result = await timer.run("archive", () =>
      createArchive(root, name, stagedArchive, {
        executable: (path) =>
          path === "install.sh" ||
          (path.startsWith("payload/bin/") && !path.endsWith(".cmd")),
      }),
    );
    const published = timer.start("publish");
    // The previous release's files are removed by several threads, each
    // retried where Windows still holds one open (a scanner, an indexer).
    removeTree(directory, { attempts: 3 });
    rmSync(archive, { force: true });
    rmSync(buildInfo, { force: true });
    renameWithRetry(root, directory);
    renameWithRetry(stagedArchive, archive);
    writeFileSync(`${archive}.sha256`, `${result.sha256}  ${name}.tar.gz\n`);
    // Beside the archive and outside what it, checksums.txt, and release.json
    // cover, replaced with the release it describes.
    writeJson(buildInfo, {
      schema: BUILD_INFO_SCHEMA,
      runtimeCache: provenance,
    });
    published();
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
    const cleaned = timer.start("staging cleanup");
    temporary.remove();
    cleaned();
    timer.report("release");
  }
}
