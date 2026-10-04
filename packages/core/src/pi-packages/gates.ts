// Package supply-chain gates (spec §§9, 17). Package closures go through the
// existing release gates (`release.sources`, the install-script review, and
// `release.vulnerabilities`), never a parallel set.
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReleaseManifest } from "@piship/schema";
import { REVIEWED_INSTALL_SCRIPTS } from "../compatibility.js";
import { checkLockedPackageSources } from "../release/sources.js";
import type { VulnerabilityReport } from "../release/metadata.js";
import { evaluateVulnerabilities, npmAuditScanner } from "../release/scans.js";
import { gate } from "../release/shared.js";
import { checkLockfileClosure, packageError } from "./refs.js";
import type {
  DeclaredPackage,
  DeploymentMode,
  LockedPiPackage,
  PackageDependency,
  PackageTrustConfig,
} from "./types.js";

/** Payload directory vendored packages live in: `<dir>/<id>/…`. */
export const PI_PACKAGE_VENDOR_DIRECTORY = "pi-packages";

/**
 * The payload path the install-script review keys a package dependency by:
 * `pi-packages/<id>/node_modules/<name>@<version>`.
 */
export function piPackageDependencyPath(
  id: string,
  dependency: Pick<PackageDependency, "path">,
): string {
  return `${PI_PACKAGE_VENDOR_DIRECTORY}/${id}/${dependency.path}`;
}

/**
 * The `source` and `install-script` gates over one package closure. A
 * binding.gyp counts as an install script (the vendoring step marks it).
 */
export function checkPiPackageSources(
  id: string,
  dependencies: readonly PackageDependency[],
  sources: readonly string[],
  stage: "Release" | "Build" = "Release",
  reviewed: readonly string[] = REVIEWED_INSTALL_SCRIPTS,
): void {
  checkLockedPackageSources(
    dependencies.map((item) => ({
      path: piPackageDependencyPath(id, item),
      version: item.version,
      integrity: item.integrity,
      resolved: item.resolved,
      ...(item.installScript ? { installScript: true as const } : {}),
    })),
    sources,
    stage,
    reviewed,
  );
}

/**
 * The `install-script` gate alone, which applies with or without a
 * `lifecycle.release` (spec §8.2 step 6): every closure entry with an npm
 * lifecycle script or a binding.gyp, and a git or local package's own root
 * with one (`ownInstallScript`, `package@<commit or tree>`), must be reviewed.
 */
export function checkPiPackageInstallScripts(
  id: string,
  dependencies: readonly PackageDependency[],
  ownInstallScript: string | undefined,
  stage: "Release" | "Build" = "Release",
  reviewed: readonly string[] = REVIEWED_INSTALL_SCRIPTS,
): void {
  const scripts = [
    ...(ownInstallScript
      ? [`${PI_PACKAGE_VENDOR_DIRECTORY}/${id}/${ownInstallScript}`]
      : []),
    ...dependencies
      .filter((item) => item.installScript)
      .map((item) => `${piPackageDependencyPath(id, item)}@${item.version}`),
  ];
  for (const script of scripts)
    if (!reviewed.includes(script))
      throw gate(
        "POLICY_DENIED",
        "install-script",
        `${script} runs npm lifecycle scripts that were not reviewed for this PiShip version`,
        undefined,
        stage,
      );
}

/**
 * A certified package's review evidence must describe what was locked: its
 * `integrity` is the locked tree digest (or, for npm, the registry
 * integrity), and for npm its `version` is the locked version. Evidence
 * versions are SemVer, so a git commit is bound through the tree digest of
 * its content instead, as a local package is.
 */
export function checkCertifiedPackage(
  declaration: Pick<DeclaredPackage, "id" | "class" | "certified">,
  locked: LockedPiPackage,
): void {
  if (declaration.class !== "certified") return;
  const evidence = declaration.certified;
  if (!evidence)
    throw packageError(
      "POLICY_DENIED",
      declaration.id,
      "the package is certified without certification evidence",
    );
  if (locked.version !== undefined && evidence.version !== locked.version)
    throw packageError(
      "INTEGRITY_FAILED",
      declaration.id,
      `certified evidence is for version ${evidence.version}, but the lock resolved ${locked.version}`,
      "Review the resolved package and update its certified evidence, or pin the reviewed version",
    );
  if (
    evidence.integrity !== locked.tree &&
    (!locked.integrity || evidence.integrity !== locked.integrity)
  )
    throw packageError(
      "INTEGRITY_FAILED",
      declaration.id,
      "the locked package does not match its certified integrity",
      "Review the resolved package and update its certified evidence",
    );
}

/**
 * Static release check of a locked package without the network: the stored
 * lockfile matches its sha256, its closure has only immutable sources, and
 * the source and install-script gates pass. Returns the closure.
 */
export function checkLockedPiPackage(
  locked: LockedPiPackage,
  lockfile: string,
  options: {
    readonly trust: Pick<PackageTrustConfig, "npm">;
    readonly sources: readonly string[];
    readonly stage?: "Release" | "Build";
    readonly reviewed?: readonly string[];
  },
): PackageDependency[] {
  if (
    createHash("sha256").update(lockfile).digest("hex") !==
    locked.lockfileSha256
  )
    throw packageError(
      "LOCK_INVALID",
      locked.id,
      "the package npm lockfile does not match its sha256 in the lock",
      "Run piship lock again and review the package changes",
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockfile);
  } catch {
    throw packageError(
      "LOCK_INVALID",
      locked.id,
      "the package npm lockfile is not JSON",
    );
  }
  const closure = checkLockfileClosure(
    locked.id,
    parsed as Parameters<typeof checkLockfileClosure>[1],
    options.trust,
  );
  checkPiPackageSources(
    locked.id,
    closure,
    options.sources,
    options.stage,
    options.reviewed,
  );
  return closure;
}

export interface PackageAuditResult {
  readonly id: string;
  /** When the scan ran; npm exposes no advisory-database timestamp. */
  readonly scannedAt: string;
  readonly report?: VulnerabilityReport;
  /** Personal only: why no audit endpoint answered. */
  readonly warning?: string;
}

/**
 * `npm audit` against one package lockfile under the release vulnerability
 * policy, using `registry` (the package's, or
 * `release.vulnerabilities.registry`). An unreachable audit endpoint fails a
 * managed release and is a warning for a personal one; a blocking advisory
 * fails both.
 */
export async function auditPiPackage(
  id: string,
  files: { readonly manifest: string; readonly lockfile: string },
  policy: ReleaseManifest["vulnerabilities"],
  options: {
    readonly mode: DeploymentMode;
    readonly registry?: string;
    readonly now?: Date;
    readonly scanner?: (
      directory: string,
      registry?: string,
    ) => Promise<unknown> | unknown;
  },
): Promise<PackageAuditResult> {
  const now = options.now ?? new Date();
  const directory = mkdtempSync(join(tmpdir(), "piship-package-audit-"));
  let audit: unknown;
  try {
    writeFileSync(join(directory, "package.json"), files.manifest);
    writeFileSync(join(directory, "package-lock.json"), files.lockfile);
    try {
      audit = await (options.scanner ?? npmAuditScanner)(
        directory,
        options.registry,
      );
    } catch (error) {
      if (options.mode === "managed") throw error;
      return {
        id,
        scannedAt: now.toISOString(),
        warning: `package ${id} was not scanned: ${(error as Error).message}`,
      };
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const report = evaluateVulnerabilities(audit, policy, now);
  if (report.verdict !== "passed")
    throw packageError(
      "POLICY_DENIED",
      id,
      `blocking advisories at or above ${policy.failOn}: ${report.findings
        .filter((item) => item.status === "blocking")
        .map((item) => `${item.id} (${item.package}, ${item.severity})`)
        .join(", ")}`,
      "Update the dependency, or record a reviewed exception with an expiry in release.vulnerabilities.allow",
    );
  return { id, scannedAt: now.toISOString(), report };
}
