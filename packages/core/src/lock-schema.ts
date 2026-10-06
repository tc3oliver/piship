import type {
  EnforcementStatus,
  PolicyAction,
  RuntimeSeamKind,
  SessionExportResource,
} from "@piship/contracts";
import type {
  AccessManifest,
  AgentFileMode,
  CacheWarmingConfig,
  DATA_CONTRACT_VERSION,
  DataManifest,
  DeclarableResourceClass,
  Manifest,
  PackageEnvironmentValue,
  PackageResourceKind,
  PackageSourceKind,
  PishipSchemaVersion,
  ReleaseManifest,
  RuntimeToolsConfig,
  SearchTool,
  ToolExposure,
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
/**
 * Lock schema for piship/v1alpha6 manifests: v1alpha5 plus what is
 * installed (resolved Pi packages), which tools are visible, which physical
 * models can receive requests, which policies are actually enforced, and
 * where every package came from.
 */
export const LOCK_SCHEMA_V1ALPHA6 = "piship-lock/v1alpha6";
/**
 * Lock schema for piship/v1 manifests: the v1alpha6 lock, frozen. Every key
 * keeps its v1alpha6 meaning; a backward-compatible addition is an optional
 * key and keeps this version, a breaking change needs a new major
 * (docs/manifest.md, "Lock stability").
 */
export const LOCK_SCHEMA_V1 = "piship-lock/v1";
export type LockSchemaVersion =
  | typeof LOCK_SCHEMA_VERSION
  | typeof LOCK_SCHEMA_V1ALPHA2
  | typeof LOCK_SCHEMA_V1ALPHA3
  | typeof LOCK_SCHEMA_V1ALPHA4
  | typeof LOCK_SCHEMA_V1ALPHA5
  | typeof LOCK_SCHEMA_V1ALPHA6
  | typeof LOCK_SCHEMA_V1;

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
/** v1alpha6: one file a Pi package contributes, after its filters. */
export interface LockedPackageResource {
  readonly kind: PackageResourceKind;
  /** Path inside the package. */
  readonly path: string;
  readonly sha256: string;
}
/**
 * v1alpha6: a configuration file the launch writes into Pi's agent
 * directory for a package, with the digest of the exact bytes it writes (the
 * declared JSON in its declared key order: an extension may read its rules in
 * order). The content itself is in `governance.manifest`.
 */
export interface LockedAgentFile {
  /** Relative to the agent directory: `extensions/[<name>/]<file>.json`. */
  readonly path: string;
  readonly mode: AgentFileMode;
  /** `sha256-<hex>` of the written bytes. */
  readonly sha256: string;
}
/**
 * v1alpha6: a Pi package resolved to an immutable identity. The full
 * `node_modules` file list is not recorded: the tree digest and file count
 * bound it.
 */
export interface LockedPiPackage {
  readonly id: string;
  readonly source: PackageSourceKind;
  readonly class: DeclarableResourceClass;
  /** Canonical source URL with any userinfo stripped (npm and git). */
  readonly url?: string;
  /** npm: the exact resolved version. */
  readonly version?: string;
  /** git: the full commit SHA. */
  readonly commit?: string;
  /** npm: the registry `dist.integrity`. */
  readonly integrity?: string;
  /** `sha256-<hex>` over the vendored tree. */
  readonly tree: string;
  readonly files: number;
  /** sha256 of the per-package npm lockfile stored beside the lock. */
  readonly lockfileSha256?: string;
  readonly resources: readonly LockedPackageResource[];
  /** Optional dependencies installed per target (`<platform>-<arch>`). */
  readonly optionalDependencies?: Readonly<Record<string, readonly string[]>>;
  /** The environment the launch sets for the package; absent when none. */
  readonly environment?: Readonly<Record<string, PackageEnvironmentValue>>;
  /** Configuration files written into the agent directory; absent when none. */
  readonly agentFiles?: readonly LockedAgentFile[];
}
/**
 * v1alpha6: where a locked tool came from. Only tools known without running
 * extension code are locked: PiShip's own tools and declared MCP rules.
 * Extension and package tools register themselves at runtime, so their
 * exposure is enforced and audited at launch, never locked.
 */
export const LOCKED_TOOL_ORIGINS = ["piship", "mcp"] as const;
export type LockedToolOrigin = (typeof LOCKED_TOOL_ORIGINS)[number];
/** v1alpha6: one tool's resolved exposure. */
export interface LockedToolExposure {
  readonly tool: string;
  readonly origin: LockedToolOrigin;
  readonly exposure: ToolExposure;
}
/** v1alpha6: a virtual model and the closed set of its physical routes. */
export interface LockedVirtualModel {
  readonly id: string;
  readonly router: string;
  readonly routes: readonly string[];
}
/** v1alpha6: the runtime seam evidence enforcement claims are based on. */
export interface LockedEnforcement {
  /** The Pi version the seam table was proven against. */
  readonly pi: string;
  readonly seams: Readonly<Record<PolicyAction, RuntimeSeamKind>>;
  /** `sha256-<hex>` of the canonical seam table. */
  readonly digest: string;
}
/** v1alpha6: the data lifecycle contract the lock was written for. */
export interface LockedDataContract {
  readonly contract: typeof DATA_CONTRACT_VERSION;
  /**
   * The manifest's `data` section (retention, purge, export), which the
   * launch and logout sweeps and the session export status read. Absent when
   * the manifest has none: no retention sweep runs.
   */
  readonly declared?: DataManifest;
}
/** v1alpha6: the exact Pi sibling package versions (`name` -> version). */
export type LockedPiSiblings = Readonly<Record<string, string>>;

/**
 * v1alpha6: one release target's upstream archive of a bundled search tool
 * and the executable PiShip takes from it.
 */
export interface LockedSearchToolTarget {
  /** The official upstream release archive. */
  readonly url: string;
  /** `sha256-<hex>` of the archive as downloaded. */
  readonly archive: string;
  /** The executable's path inside the archive. */
  readonly entry: string;
  /** `sha256-<hex>` of the executable. */
  readonly binary: string;
  readonly size: number;
}
/** v1alpha6: a bundled search tool at one upstream version. */
export interface LockedSearchTool {
  readonly version: string;
  /** The upstream repository URL. */
  readonly source: string;
  /** Every release target the distribution builds for. */
  readonly targets: Readonly<Record<string, LockedSearchToolTarget>>;
}
/** v1alpha6 `runtime.searchTools`, as locked. */
export type LockedSearchTools = Readonly<
  Partial<Record<SearchTool, LockedSearchTool>>
>;

/** v1alpha4 static digests (`sha256-<hex>` of canonical JSON). */
export interface LockDigests {
  readonly resources: string;
  /** v1alpha6: the locked Pi packages, when the manifest declares any. */
  readonly packages?: string;
  /** v1alpha6: the locked search tools, when the manifest bundles them. */
  readonly searchTools?: string;
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
  /** v1alpha6: resolved Pi packages, their integrity, and inventories. */
  readonly packages?: readonly LockedPiPackage[];
  /** v1alpha6: the resolved exposure of PiShip tools and declared MCP rules. */
  readonly tools?: readonly LockedToolExposure[];
  /**
   * v1alpha6: `runtime.tools` as resolved (defaults applied): the Codemode
   * and tool search modes and the exposure rules a launch applies.
   */
  readonly runtimeTools?: RuntimeToolsConfig;
  /**
   * v1alpha6: `runtime.cacheWarming` as parsed. Absent: `off`, and enforced
   * only for a managed distribution.
   */
  readonly cacheWarming?: CacheWarmingConfig;
  /**
   * v1alpha6: `runtime.verifyAtLaunch` when the manifest declares it. Absent
   * or false: a launch hashes only this lock, against the digest recorded
   * when the release was installed, trusts the rest of the payload as
   * installed (it was verified then, and `doctor` verifies it again), reads
   * the resources it loads without hashing them, and may keep a V8 code cache
   * of a bundled payload. True: a launch verifies the whole payload, its
   * inventory included, hashes each resource against this lock, and keeps no
   * code cache, since a cache in state is not verified.
   */
  readonly verifyAtLaunch?: boolean;
  /** v1alpha6: virtual models and their physical routes. */
  readonly virtualModels?: readonly LockedVirtualModel[];
  /** v1alpha6: the runtime seam evidence. */
  readonly enforcement?: LockedEnforcement;
  /** v1alpha6: the data lifecycle contract version. */
  readonly data?: LockedDataContract;
  /** v1alpha6: the enforcement status of each session export resource. */
  readonly sessionExportStatus?: Readonly<
    Record<SessionExportResource, EnforcementStatus>
  >;
  /** v1alpha6: `fd` and `rg` bundled into the payload, when declared. */
  readonly searchTools?: LockedSearchTools;
  /** v1alpha6: the pinned Pi sibling package tree. */
  readonly piSiblings?: LockedPiSiblings;
}
