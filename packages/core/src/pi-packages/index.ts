// Pi packages (spec v0.9.0 §§8, 9): PiShip resolves, vendors, and expands
// them; Pi never installs one. Exported as `@piship/core/pi-packages`, not
// from the core root, so the root keeps no import edge into the release gates.
export { type CommandRunner, runCommand } from "./command.js";
export { expandPackageResources } from "./expand.js";
export {
  auditPiPackage,
  checkCertifiedPackage,
  checkLockedPiPackage,
  checkPiPackageInstallScripts,
  checkPiPackageSources,
  PI_PACKAGE_VENDOR_DIRECTORY,
  type PackageAuditResult,
  piPackageDependencyPath,
} from "./gates.js";
export {
  checkGitDeclaration,
  checkLocalDeclaration,
  checkLockfileClosure,
  checkNpmDeclaration,
  checkRegistrySpecs,
  isHostProvided,
  optionalDependenciesFor,
} from "./refs.js";
export {
  currentPiPackages,
  declaredPackages,
  lockPiPackages,
  PACKAGE_LOCK_DIRECTORY,
  packageContext,
  packageLockFiles,
  reviewedInstallScripts,
  vendorPiPackages,
} from "./lock.js";
export {
  type PackageContext,
  packageTreeDigest,
  type ResolvedPiPackage,
  resolvePiPackage,
  type VendoredPiPackage,
  vendorPiPackage,
} from "./resolve.js";
export { effectivePackageTrust } from "./trust.js";
export type * from "./types.js";
export { PACKAGE_RESOURCE_KINDS } from "./types.js";
