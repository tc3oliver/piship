import type { DistributionLock } from "../index.js";

export type DiffRisk = "low" | "medium" | "high";

/** Report areas in display order. */
export const DIFF_AREAS = [
  "distribution",
  "schema",
  "pi",
  "piship",
  "packages",
  "resources",
  "extensions",
  "providers",
  "capabilities",
  "policy",
  "enforcement",
  "tools",
  "mcp",
  "sandbox",
  "audit",
  "data",
  "access",
  "models",
  "network",
  "updates",
  "release",
] as const;
export type DiffArea = (typeof DIFF_AREAS)[number];

export interface DiffChange {
  readonly area: DiffArea;
  readonly kind: "added" | "removed" | "changed";
  /** Stable identifier, such as `node_modules/foo` or `policy rule acme.shell`. */
  readonly item: string;
  readonly before?: string;
  readonly after?: string;
  readonly risk: DiffRisk;
  readonly reason: string;
}

export interface DiffSide {
  readonly id: string;
  readonly version: string;
  readonly pi: string;
  readonly piship: string;
  readonly lockSchema: string;
}

export interface DiffReport {
  readonly schema: "piship-diff/v1";
  readonly before: DiffSide;
  readonly after: DiffSide;
  readonly risk: DiffRisk | "none";
  readonly changes: readonly DiffChange[];
  readonly requiredTests: readonly string[];
}

/** Test and review names `requiredTests` draws from. */
export const DIFF_TESTS = {
  check: "npm run check",
  compatibility: "Pi compatibility suite (npm run test:compatibility)",
  installed: "installed lifecycle E2E on every advertised target",
  governance: "governance E2E and policy explain review",
  sandbox: "sandbox boundary tests on Linux and macOS",
  managed: "managed E2E (identity, credentials, inference)",
  release: "release verification and update/rollback E2E",
  migration: "manifest and lock migration review",
} as const;

// Optional v1alpha4 lock fields, typed loosely so older locks compare too.
interface LockedPackage {
  readonly path: string;
  readonly version: string;
  readonly integrity: string;
  readonly resolved?: string;
  readonly installScript?: true;
}
interface UpdatesLock {
  readonly channel?: string;
  readonly channels?: readonly string[];
  readonly source?: string;
  /** v1alpha5 `https` or `http-allowed`; absent means https. */
  readonly transport?: string;
  readonly rollback?: boolean;
  readonly trust?: {
    readonly keys?: readonly TrustKeyLock[];
    /** v1alpha5 bootstrap update root. */
    readonly bootstrap?: {
      readonly version?: number;
      readonly expires?: string;
      readonly keys?: readonly TrustKeyLock[];
      readonly roles?: Readonly<
        Record<
          string,
          { readonly keyIds?: readonly string[]; readonly threshold?: number }
        >
      >;
    };
  };
}
interface TrustKeyLock {
  readonly id: string;
  readonly publicKey: string;
}
interface ReleaseLock {
  readonly targets?: readonly string[];
  readonly sources?: readonly string[];
  readonly vulnerabilities?: {
    readonly failOn?: string;
    readonly allow?: readonly {
      readonly id: string;
      readonly reason: string;
      readonly expires: string;
    }[];
  };
}
export interface AnyLock
  extends Omit<
    DistributionLock,
    "schema" | "runtime" | "digests" | "updates" | "release"
  > {
  readonly schema: string;
  readonly runtime: Omit<DistributionLock["runtime"], "packages"> & {
    readonly packages: readonly LockedPackage[];
  };
  readonly digests?: Readonly<Record<string, string>>;
  readonly updates?: UpdatesLock;
  readonly release?: ReleaseLock;
}

export type Verdict = readonly [DiffRisk, string];
export type Kind = DiffChange["kind"];
