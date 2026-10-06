// The footprint of the vendored Pi packages in a payload: which closures were
// bundled, which keep their vendored files and why, and which dependencies are
// shared. The decisions are made here, in this order: a bundle-safe closure is
// bundled first (it removes its own duplicates along with the rest), then the
// dependencies the remaining closures hold identical copies of are shared.
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import {
  analyzeClosures,
  bundleClosure,
  type ClosureAnalysis,
  type ClosureOptions,
  type FallbackFinding,
} from "./closure.js";
import {
  type DedupeReport,
  dedupePiPackages,
  type RetainedReason,
} from "./dedupe.js";
import type { EsbuildApi } from "./module-scan.js";

export { type EsbuildApi, loadEsbuild } from "./module-scan.js";
import type { LockedPackageResource } from "./types.js";

export const FOOTPRINT_FILE = "metadata/pi-package-footprint.json";
export const FOOTPRINT_SCHEMA = "piship-pi-package-footprint/v1";
const VENDOR = "pi-packages";

export interface FootprintInput {
  /** One entry per vendored package: its directory and its own root inside it. */
  readonly packages: readonly {
    readonly id: string;
    /** `<payload>/pi-packages/<id>`. */
    readonly directory: string;
    /** `node_modules/<name>` or `package` below it, as an absolute path. */
    readonly packageRoot: string;
    readonly resources: readonly LockedPackageResource[];
  }[];
  readonly esbuild: EsbuildApi;
  /** Bundle bundle-safe closures. Dependency sharing runs either way. */
  readonly bundle: boolean;
}

export interface PackageClosureDecision {
  readonly id: string;
  /** `bundled`, or `vendored` with the findings that decided it. */
  readonly closure: "bundled" | "vendored";
  readonly replaced?: number;
  readonly bundledFiles?: number;
  readonly findings?: readonly FallbackFinding[];
}

export interface PackageFootprint {
  readonly schema: typeof FOOTPRINT_SCHEMA;
  readonly closures: readonly PackageClosureDecision[];
  readonly shared: DedupeReport["shared"];
  /** How many dependency places keep their copy, by reason. */
  readonly retained: Readonly<Partial<Record<RetainedReason, number>>>;
  readonly files: {
    /** Files under `pi-packages` before bundling and sharing, and after. */
    readonly before: number;
    readonly after: number;
  };
}

const posix = (path: string) => path.split(sep).join("/");

/**
 * Bundle what is bundle-safe, share what is identical, write the decisions to
 * `metadata/pi-package-footprint.json` of `payload`, and return them.
 */
export function optimizePiPackages(
  payload: string,
  input: FootprintInput,
): PackageFootprint {
  const closures: PackageClosureDecision[] = [];
  const before = filesUnder(join(payload, VENDOR));
  const ordered = input.bundle
    ? [...input.packages].sort((a, b) =>
        a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
      )
    : [];
  const options = ordered.map((item) => ({
    root: item.directory,
    packagePath: posix(relative(item.directory, item.packageRoot)),
    resources: item.resources,
    esbuild: input.esbuild,
  }));
  // Every closure is read first, together, then the safe ones are bundled.
  const analyses = analyzeClosures(options, input.esbuild);
  ordered.forEach((item, index) => {
    const analysis = analyses[index] as ClosureAnalysis;
    if (!analysis.safe) {
      closures.push({
        id: item.id,
        closure: "vendored",
        findings: analysis.findings.slice(0, 8),
      });
      return;
    }
    const result = bundleClosure(
      options[index] as ClosureOptions,
      analysis.plan,
    );
    closures.push({
      id: item.id,
      closure: "bundled",
      replaced: result.replaced,
      bundledFiles: result.inlined,
    });
  });
  const deduped = dedupePiPackages(join(payload, VENDOR), {
    keep: input.packages.map((item) => item.packageRoot),
    esbuild: input.esbuild,
  });
  const retained: Partial<Record<RetainedReason, number>> = {};
  for (const item of deduped.retained)
    retained[item.reason] = (retained[item.reason] ?? 0) + 1;
  const footprint: PackageFootprint = {
    schema: FOOTPRINT_SCHEMA,
    closures,
    shared: deduped.shared,
    retained: Object.fromEntries(Object.entries(retained).sort()),
    files: { before, after: deduped.filesAfter },
  };
  const file = join(payload, ...FOOTPRINT_FILE.split("/"));
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(footprint, null, 2)}\n`);
  return footprint;
}

/** The report a build wrote into a payload, or undefined when it has none. */
export function readFootprint(payload: string): PackageFootprint | undefined {
  try {
    const value = JSON.parse(
      readFileSync(join(payload, ...FOOTPRINT_FILE.split("/")), "utf8"),
    ) as PackageFootprint;
    return value.schema === FOOTPRINT_SCHEMA ? value : undefined;
  } catch {
    return undefined;
  }
}

function filesUnder(directory: string): number {
  let total = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true }))
    total += entry.isDirectory() ? filesUnder(join(directory, entry.name)) : 1;
  return total;
}

/** What a build tells its user about the footprint: one line each for closures and dependencies. */
export function describeFootprint(footprint: PackageFootprint): string[] {
  const bundled = footprint.closures.filter(
    (item) => item.closure === "bundled",
  );
  const kept = footprint.closures.filter((item) => item.closure === "vendored");
  const lines = [
    `Pi package closures: ${bundled.length} of ${footprint.closures.length} bundled${
      kept.length
        ? `; vendored: ${kept
            .map((item) => {
              const reasons = [
                ...new Set(
                  (item.findings ?? []).map((finding) => finding.reason),
                ),
              ];
              return `${item.id} (${reasons.slice(0, 3).join(", ")})`;
            })
            .join("; ")}`
        : ""
    }`,
  ];
  const saved = footprint.shared.reduce((total, item) => total + item.saved, 0);
  const reasons = Object.entries(footprint.retained)
    .sort(([, a], [, b]) => (b ?? 0) - (a ?? 0))
    .map(([reason, count]) => `${reason} ${count}`);
  lines.push(
    `Pi package dependencies: ${footprint.shared.length} shared (${saved} fewer files); copies kept: ${reasons.join(", ") || "none"}`,
  );
  return lines;
}
