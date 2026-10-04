// Types of Pi package resolution (spec v0.9.0 §§8, 9). Declarations,
// packageTrust, and lock entries are the piship/v1alpha6 shapes from
// @piship/schema and the core lock schema; only the dependency closure read
// from a per-package npm lockfile is local to this module.
export type {
  DeclaredPackage,
  DeploymentMode,
  GitPackage,
  LocalPackage,
  NpmPackage,
  PackageFilters,
  PackageResourceKind,
  PackageTrustConfig,
} from "@piship/schema";
export { PACKAGE_RESOURCE_KINDS } from "@piship/schema";
export type {
  LockedPackageResource,
  LockedPiPackage,
} from "../lock-schema.js";

/** A dependency of the package closure, as the per-package npm lockfile records it. */
export interface PackageDependency {
  /** Lockfile key, such as `node_modules/@scope/x`. */
  readonly path: string;
  readonly name: string;
  readonly version: string;
  readonly integrity: string;
  readonly resolved: string;
  readonly installScript?: true;
  readonly optional?: true;
}
