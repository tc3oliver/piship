// packageTrust defaults (spec §9). It constrains package *sources*; trust
// classes stay with resourceTrust.
import { PiShipError } from "@piship/contracts";
import { type Manifest, ManifestError } from "@piship/schema";
import type { DeploymentMode, PackageTrustConfig } from "./types.js";

/**
 * Semantic validation of `packageTrust`, run by `piship validate` and
 * `piship lock` (through the governance checks): a managed distribution
 * cannot turn off npm integrity or full commit SHAs.
 */
export function checkPackageTrust(manifest: Manifest): void {
  if (manifest.deployment.mode !== "managed") return;
  const trust = manifest.governance?.packageTrust;
  if (trust?.npm.requireIntegrity === false)
    throw new ManifestError(
      "invalid field",
      "packageTrust.npm.requireIntegrity",
      "A managed distribution requires npm integrity for every package",
    );
  if (trust?.git.requireCommitSha === false)
    throw new ManifestError(
      "invalid field",
      "packageTrust.git.requireCommitSha",
      "A managed distribution requires a full commit SHA for every git package",
    );
}

/**
 * The packageTrust a distribution resolves packages under. Managed defaults
 * are `requireIntegrity: true`, `requireCommitSha: true`, and no local paths;
 * a managed manifest cannot turn either requirement off. Personal requires
 * integrity unless it opts out and accepts any local path inside the
 * distribution directory.
 */
export function effectivePackageTrust(
  trust: PackageTrustConfig | undefined,
  mode: DeploymentMode,
): PackageTrustConfig {
  const managed = mode === "managed";
  if (
    managed &&
    (trust?.npm?.requireIntegrity === false ||
      trust?.git?.requireCommitSha === false)
  )
    throw new PiShipError(
      "CONFIG_INVALID",
      "packageTrust: a managed distribution cannot turn off requireIntegrity or requireCommitSha",
      { component: "packages" },
    );
  const hosts = trust?.git?.hosts;
  const paths = trust?.local?.paths ?? (managed ? [] : undefined);
  return {
    npm: { requireIntegrity: trust?.npm?.requireIntegrity ?? true },
    git: {
      ...(hosts ? { hosts } : {}),
      requireCommitSha: trust?.git?.requireCommitSha ?? managed,
    },
    local: paths ? { paths } : {},
  };
}
