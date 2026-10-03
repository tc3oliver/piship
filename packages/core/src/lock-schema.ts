import type {
  AccessManifest,
  Manifest,
  PishipSchemaVersion,
  ReleaseManifest,
  UpdatesManifest,
} from "@piship/schema";
import type { PI_PACKAGE } from "./compatibility.js";
import type { StateSchemaSupport } from "./migration.js";
import type { GovernanceLock } from "./trust.js";

export interface DistributionId {
  readonly value: string;
}
export interface ResolvedDistribution {
  readonly id: DistributionId;
  readonly schema: PishipSchemaVersion;
  readonly piVersion: string;
}
export const LOCK_SCHEMA_VERSION = "piship-lock/v1alpha1";
/** Lock schema for piship/v1alpha2 manifests; adds the static access envelope. */
export const LOCK_SCHEMA_V1ALPHA2 = "piship-lock/v1alpha2";
/** Lock schema for piship/v1alpha3 manifests; adds trust classes and governance. */
export const LOCK_SCHEMA_V1ALPHA3 = "piship-lock/v1alpha3";
/**
 * Lock schema for piship/v1alpha4 manifests: package sources and install
 * scripts, static digests, update and release inputs, and state schemas.
 */
export const LOCK_SCHEMA_V1ALPHA4 = "piship-lock/v1alpha4";
/**
 * Lock schema for piship/v1alpha5 manifests: v1alpha4 with the canonical
 * manifest digest (`sha256-<hex>` of canonical JSON) and the validated
 * update bootstrap root in `updates.trust.bootstrap`.
 */
export const LOCK_SCHEMA_V1ALPHA5 = "piship-lock/v1alpha5";
export type LockSchemaVersion =
  | typeof LOCK_SCHEMA_VERSION
  | typeof LOCK_SCHEMA_V1ALPHA2
  | typeof LOCK_SCHEMA_V1ALPHA3
  | typeof LOCK_SCHEMA_V1ALPHA4
  | typeof LOCK_SCHEMA_V1ALPHA5;

export interface LockedResource {
  readonly kind:
    | "instructions"
    | "skills"
    | "extensions"
    | "prompts"
    | "themes"
    | "adapters"
    | "providers";
  readonly path: string;
  readonly sha256: string;
  /** v1alpha3 only: the declared trust class (`certified`, `company`, or `user`). */
  readonly class?: string;
}
export interface LockedPackage {
  readonly path: string;
  readonly version: string;
  readonly integrity: string;
  /** v1alpha4: the package-lock `resolved` source URL. */
  readonly resolved?: string;
  /** v1alpha4: npm reports lifecycle scripts for this package. */
  readonly installScript?: true;
}
/** v1alpha4 static digests (`sha256-<hex>` of canonical JSON). */
export interface LockDigests {
  readonly resources: string;
  readonly policy: string;
  readonly capabilities: string;
  readonly mcp: string;
  readonly sandbox: string;
  readonly audit: string;
  readonly access: string;
}
export interface DistributionLock {
  readonly schema: LockSchemaVersion;
  readonly manifest: {
    readonly schema: PishipSchemaVersion;
    /**
     * Digest of the parsed manifest: `sha256-<64 lowercase hex>` of its
     * canonical JSON from lock v1alpha5, bare hex of its JSON before.
     */
    readonly sha256: string;
  };
  readonly app: Manifest["app"];
  readonly deployment: Manifest["deployment"];
  readonly runtime: {
    readonly package: typeof PI_PACKAGE;
    readonly version: string;
    readonly pishipVersion: string;
    readonly npmLockSha256: string;
    readonly packages: readonly LockedPackage[];
    /** v1alpha4: state file schemas this PiShip version reads. */
    readonly stateSchemas?: StateSchemaSupport;
  };
  readonly resources: readonly LockedResource[];
  readonly declared: Manifest["resources"];
  /**
   * Static access intent for v1alpha2: unresolved `${NAME}` templates, provider
   * modes, and the model catalog. Never tokens, credentials, or resolved
   * machine-specific values.
   */
  readonly access?: AccessManifest;
  /**
   * v1alpha3 governance intent plus static trust evidence: certified tree
   * digests and exact provider/contract versions.
   */
  readonly governance?: GovernanceLock;
  /** v1alpha4: digests of the static policy bundle and capability graph. */
  readonly digests?: LockDigests;
  /**
   * v1alpha4: channel policy and trusted release keys (`trust.keys`);
   * v1alpha5: the exact validated bootstrap root (`trust.bootstrap`).
   */
  readonly updates?: UpdatesManifest;
  /** v1alpha4: release targets, approved sources, and vulnerability policy. */
  readonly release?: ReleaseManifest;
}
