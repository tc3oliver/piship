// Release, vulnerability, and reproducibility schemas and the release metadata
// and option types shared by the release modules.
import type { StateSchemaSupport } from "../migration.js";

export const RELEASE_SCHEMA = "piship-release/v1";
export const CHANNEL_SCHEMA = "piship-channel/v1";
export const VULNERABILITY_REPORT_SCHEMA = "piship-vulnerabilities/v1";
export const REPRODUCIBILITY_SCHEMA = "piship-reproducibility/v1";

/** Files every release carries besides the payload, in checksum order. */
export const RELEASE_FILES = [
  "install.ps1",
  "install.sh",
  "licenses/THIRD_PARTY_NOTICES.txt",
  "licenses/index.json",
  "payload/metadata/inventory.json",
  "release.json",
  "sbom.spdx.json",
  "vulnerabilities.json",
] as const;

export interface ReleaseTestResult {
  readonly name: string;
  readonly result: "passed";
}

export interface ReleaseMetadata {
  readonly schema: typeof RELEASE_SCHEMA;
  readonly distribution: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly command: string;
    readonly mode: string;
  };
  readonly piship: { readonly version: string };
  readonly pi: {
    readonly package: string;
    readonly version: string;
    /**
     * Compatibility status of this Pi version for the release: the weakest of
     * the distribution's deployment surface, the `governance` surface when it
     * declares governance, and the `lifecycle` surface.
     */
    readonly compatibility: string;
    /** Per-surface statuses behind `compatibility` (absent in older releases). */
    readonly surfaces?: Readonly<Record<string, string>>;
  };
  readonly manifestSchema: string;
  readonly lockSchema: string;
  readonly lockSha256: string;
  readonly target: string;
  readonly channel: string;
  /** RFC 3339; SOURCE_DATE_EPOCH when set, so rebuilds stay identical. */
  readonly created: string;
  readonly payload: {
    readonly path: "payload";
    readonly inventorySha256: string;
    readonly files: number;
  };
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
  /** Registry signature check of the payload packages (absent in older releases). */
  readonly signatures?: SignatureReport;
  readonly attribution: string;
}

/**
 * Result of `npm audit signatures` over the installed payload packages.
 * `passed`: no invalid signature or attestation (packages without a registry
 * signature are listed in `missing`). `unavailable`: the check could not run,
 * for example because the Sigstore trust root or the registry keys could not
 * be fetched; `reason` says why. Invalid signatures never produce a release.
 */
export interface SignatureReport {
  readonly tool: string;
  readonly verdict: "passed" | "unavailable";
  /** `name@version` of packages without a registry signature. */
  readonly missing: readonly string[];
  readonly reason?: string;
}

/** Runs the registry signature check in the payload directory. */
export type SignatureAuditor = (
  payloadDirectory: string,
) => Promise<CommandResult> | CommandResult;

export interface VulnerabilityFinding {
  readonly id: string;
  readonly package: string;
  readonly severity: string;
  readonly title: string;
  readonly url: string | null;
  /** `blocking`, `allowed` (reviewed exception), or `below-threshold`. */
  readonly status: "blocking" | "allowed" | "below-threshold";
}

export interface VulnerabilityReport {
  readonly schema: typeof VULNERABILITY_REPORT_SCHEMA;
  readonly scanner: string;
  readonly failOn: string;
  readonly verdict: "passed" | "failed";
  readonly counts: Readonly<Record<string, number>>;
  readonly findings: readonly VulnerabilityFinding[];
}

/** Returns npm-audit-v2-shaped JSON for the given npm lock directory. */
export type VulnerabilityScanner = (
  lockDirectory: string,
) => Promise<unknown> | unknown;

export interface CommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** Runs a payload command (`version`, `--smoke`, ...) for the release tests. */
export type ReleaseTestRunner = (
  payload: string,
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
) => CommandResult;

export interface ReleaseOptions {
  /** Output root; the release lands in `<outputRoot>/releases/`. */
  readonly outputRoot?: string;
  readonly channel?: string;
  /** Build target; defaults to this machine. Cross-target builds are refused. */
  readonly target?: string;
  readonly scanner?: VulnerabilityScanner;
  /** Registry signature check (defaults to `npm audit signatures`). */
  readonly signatureAuditor?: SignatureAuditor;
  readonly runTest?: ReleaseTestRunner;
  /** Injectable clock for vulnerability exception expiry. */
  readonly now?: () => Date;
  /** Test seam: assembles the canonical payload (defaults to buildDistribution). */
  readonly assemble?: (manifestPath: string, outputRoot: string) => string;
}

export interface BuiltRelease {
  readonly name: string;
  readonly directory: string;
  readonly archive: string;
  readonly sha256: string;
  readonly metadata: ReleaseMetadata;
}
