// Production release builds. A release wraps the canonical payload from
// `buildDistribution` unchanged; it never assembles a second runtime,
// resource, or launcher layout.
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createTemporaryDirectory } from "@piship/contracts";
import {
  RELEASE_CHANNELS,
  type ReleaseManifest,
  type UpdatesManifest,
} from "@piship/schema";
import { createArchive } from "../archive.js";
import {
  buildDistribution,
  currentTarget,
  type DistributionLock,
} from "../index.js";
import { STATE_SCHEMAS } from "../migration.js";
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
  type ReleaseTestResult,
  type ReleaseTestRunner,
} from "./metadata.js";
import {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "./scans.js";
import { gate, hash, writeJson } from "./shared.js";

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
): CommandResult {
  const result = spawnSync(
    process.execPath,
    [join(payload, "bin", command), ...args],
    { encoding: "utf8", env, cwd: payload, timeout: 300_000 },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
}

/**
 * Required release tests on the assembled payload, with a throwaway state
 * directory: launch and version (integrity, target, Node, pinned Pi); the
 * offline smoke session when the distribution needs no sign-in; and the
 * governance inspection when governed.
 */
function runReleaseTests(
  payload: string,
  lock: DistributionLock,
  runTest: ReleaseTestRunner,
): ReleaseTestResult[] {
  reclaimOsTemporaries();
  const state = createTemporaryDirectory(tmpdir(), "release-test");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PISHIP_STATE_HOME: state.path,
    PISHIP_NO_BROWSER: "1",
  };
  delete env.PISHIP_BUILD_INPUT;
  const tests: [string, string[], (out: string) => boolean][] = [
    [
      "launch-version",
      ["version"],
      (out) =>
        out.includes(`${lock.app.name} ${lock.app.version}`) &&
        out.includes(`Pi ${lock.runtime.version}`),
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
  try {
    return tests.map(([name, args, accept]) => {
      const result = runTest(payload, lock.app.command, args, env);
      if (result.status !== 0 || !accept(result.stdout))
        throw gate(
          "UPDATE_FAILED",
          "test",
          `required test ${name} failed: ${(result.stderr || result.stdout).trim().slice(0, 500)}`,
        );
      return { name, result: "passed" as const };
    });
  } finally {
    state.remove();
  }
}

function installScripts(name: string): { sh: string; ps1: string } {
  return {
    sh: `#!/bin/sh
# Verifies this release, then installs its payload for the current user.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v node >/dev/null 2>&1 || { echo 'Node.js 22.19.0 or newer is required. Install Node separately.' >&2; exit 1; }
node "$here/payload/piship.mjs" verify-release "$here"
node "$here/payload/piship.mjs" install "$here" "$@"
`,
    ps1: `# Verifies this release, then installs its payload for the current user.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Error 'Node.js 22.19.0 or newer is required. Install Node separately.'; exit 1 }
node "$here\\payload\\piship.mjs" verify-release "$here"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node "$here\\payload\\piship.mjs" install "$here" @args
exit $LASTEXITCODE
# Release ${name}
`,
  };
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
  const target = options.target ?? currentTarget();
  const lock = checkReleaseInputs(manifestPath, target);
  const updates = lock.updates as UpdatesManifest;
  const channel = options.channel ?? updates.channel;
  if (!(RELEASE_CHANNELS as readonly string[]).includes(channel))
    throw gate("CONFIG_INVALID", "channel", `unknown channel ${channel}`);
  const outputRoot = resolve(options.outputRoot ?? "dist", "releases");
  const name = releaseName(lock, target);
  const directory = join(outputRoot, name);
  const archive = join(outputRoot, `${name}.tar.gz`);
  mkdirSync(outputRoot, { recursive: true });
  sweepOutputStaging(outputRoot, "release", options);
  const temporary = createTemporaryDirectory(outputRoot, "release", name);
  const stage = temporary.path;
  try {
    const built = (options.assemble ?? buildDistribution)(
      manifestPath,
      join(stage, "build"),
    );
    const payload = join(stage, "release", "payload");
    mkdirSync(dirname(payload), { recursive: true });
    renameSync(built, payload);
    const root = dirname(payload);
    const tests = runReleaseTests(
      payload,
      lock,
      options.runTest ?? runPayloadCommand,
    );
    const lockDirectory = join(stage, "audit");
    mkdirSync(lockDirectory);
    copyFileSync(
      join(payload, "package-lock.json"),
      join(lockDirectory, "package-lock.json"),
    );
    const buildInputPackage = join(
      payload,
      "node_modules",
      "@piship",
      "core",
      "dist",
      "build-input",
      "package.json",
    );
    if (existsSync(buildInputPackage))
      copyFileSync(buildInputPackage, join(lockDirectory, "package.json"));
    const release = lock.release as ReleaseManifest;
    const report = evaluateVulnerabilities(
      await (options.scanner ?? npmAuditScanner)(lockDirectory),
      release.vulnerabilities,
      (options.now ?? (() => new Date()))(),
    );
    writeJson(join(root, "vulnerabilities.json"), report);
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
    const signatures = evaluateSignatures(
      await (options.signatureAuditor ?? npmSignatureAuditor)(payload),
    );
    const created = createdTime();
    const packages = listPayloadPackages(payload);
    const sbom = generateSbom({
      payloadDir: payload,
      distribution: lock.app,
      target,
      created,
      lockPackages: lock.runtime.packages,
    });
    verifySbom(payload, sbom);
    writeJson(join(root, "sbom.spdx.json"), sbom);
    const notices = generateNotices(payload, packages);
    mkdirSync(join(root, "licenses"), { recursive: true });
    writeFileSync(
      join(root, "licenses", "THIRD_PARTY_NOTICES.txt"),
      notices.text,
    );
    writeJson(join(root, "licenses", "index.json"), notices.index);
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
    writeFileSync(
      join(root, "checksums.txt"),
      formatChecksums(root, [...RELEASE_FILES]),
    );
    const stagedArchive = join(stage, `${name}.tar.gz`);
    const result = await createArchive(root, name, stagedArchive, {
      executable: (path) =>
        path === "install.sh" ||
        (path.startsWith("payload/bin/") && !path.endsWith(".cmd")),
    });
    rmSync(directory, { recursive: true, force: true });
    rmSync(archive, { force: true });
    renameSync(root, directory);
    renameSync(stagedArchive, archive);
    writeFileSync(`${archive}.sha256`, `${result.sha256}  ${name}.tar.gz\n`);
    return { name, directory, archive, sha256: result.sha256, metadata };
  } finally {
    temporary.remove();
  }
}
