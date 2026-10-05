// Release-impact comparison of two locks for `piship diff`. Works across lock
// schemas: every field newer than piship-lock/v1alpha1 is treated as optional.
// Display values are versions, ids, effects, templates, and shortened hashes;
// secret-bearing values (env values, settings text, key material) are never shown.
import type { DistributionLock } from "../index.js";
import { access } from "./areas/access.js";
import { distribution } from "./areas/distribution.js";
import { governance } from "./areas/governance.js";
import { packages } from "./areas/packages.js";
import { release } from "./areas/release.js";
import { resources } from "./areas/resources.js";
import { searchTools } from "./areas/search-tools.js";
import {
  cacheWarming,
  dataLifecycle,
  enforcement,
  piPackages,
  runtimeTools,
  virtualModels,
} from "./areas/runtime-governance.js";
import { updates } from "./areas/updates.js";
import { Collector, compare, RISK_RANK, side } from "./collector.js";
import {
  type AnyLock,
  DIFF_AREAS,
  DIFF_TESTS,
  type DiffChange,
  type DiffReport,
  type DiffRisk,
} from "./types.js";

export { display } from "./collector.js";
export {
  DIFF_AREAS,
  DIFF_TESTS,
  type DiffArea,
  type DiffChange,
  type DiffReport,
  type DiffRisk,
  type DiffSide,
} from "./types.js";

function requiredTests(changes: readonly DiffChange[]): string[] {
  const tests = new Set<string>();
  for (const change of changes) {
    tests.add(DIFF_TESTS.check);
    switch (change.area) {
      case "pi":
      case "piship":
      case "packages":
        tests.add(DIFF_TESTS.compatibility);
        tests.add(DIFF_TESTS.installed);
        break;
      case "distribution":
      case "resources":
        tests.add(DIFF_TESTS.installed);
        break;
      case "schema":
        tests.add(DIFF_TESTS.migration);
        break;
      case "extensions":
      case "providers":
      case "capabilities":
        tests.add(DIFF_TESTS.installed);
        tests.add(DIFF_TESTS.governance);
        break;
      case "policy":
      case "tools":
      case "mcp":
      case "audit":
      case "data":
        tests.add(DIFF_TESTS.governance);
        break;
      case "enforcement":
        tests.add(DIFF_TESTS.governance);
        tests.add(DIFF_TESTS.compatibility);
        break;
      case "sandbox":
        tests.add(DIFF_TESTS.governance);
        tests.add(DIFF_TESTS.sandbox);
        break;
      case "access":
      case "models":
      case "network":
        tests.add(DIFF_TESTS.managed);
        break;
      case "updates":
      case "release":
        tests.add(DIFF_TESTS.release);
        break;
    }
  }
  return [...tests].sort(compare);
}

/** Compare two locks and classify every release-impact change by risk. */
export function diffLocks(
  before: DistributionLock,
  after: DistributionLock,
): DiffReport {
  const b = before as unknown as AnyLock;
  const a = after as unknown as AnyLock;
  const out = new Collector();
  distribution(out, b, a);
  packages(out, b, a);
  piPackages(out, b, a);
  searchTools(out, b, a);
  resources(out, b, a);
  governance(out, b, a);
  runtimeTools(out, b, a);
  enforcement(out, b, a);
  dataLifecycle(out, b, a);
  access(out, b, a);
  virtualModels(out, b, a);
  cacheWarming(out, b, a);
  updates(out, b, a);
  release(out, b, a);
  const changes = out.changes.sort(
    (x, y) =>
      DIFF_AREAS.indexOf(x.area) - DIFF_AREAS.indexOf(y.area) ||
      compare(x.item, y.item) ||
      compare(x.kind, y.kind) ||
      compare(x.reason, y.reason),
  );
  const risk = changes.reduce<DiffRisk | "none">(
    (max, change) =>
      max === "none" || RISK_RANK[change.risk] > RISK_RANK[max]
        ? change.risk
        : max,
    "none",
  );
  return {
    schema: "piship-diff/v1",
    before: side(b),
    after: side(a),
    risk,
    changes,
    requiredTests: requiredTests(changes),
  };
}

function transition(before: string, after: string): string {
  return before === after ? before : `${before} -> ${after}`;
}

/** Deterministic plain-text rendering of a diff report. */
export function formatDiff(report: DiffReport): string {
  const lines = [
    `${report.after.id} ${report.before.version} -> ${report.after.version} (risk: ${report.risk})`,
    `Pi ${transition(report.before.pi, report.after.pi)}, PiShip ${transition(report.before.piship, report.after.piship)}`,
  ];
  if (report.changes.length === 0) lines.push("No release-impact changes.");
  else {
    lines.push("Changes:");
    for (const change of report.changes) {
      const values =
        change.before !== undefined && change.after !== undefined
          ? ` (${change.before} -> ${change.after})`
          : change.before !== undefined || change.after !== undefined
            ? ` (${change.before ?? change.after})`
            : "";
      lines.push(
        `  [${change.risk}] ${change.area}: ${change.kind} ${change.item}${values}: ${change.reason}`,
      );
    }
  }
  if (report.requiredTests.length) {
    lines.push("Required tests:");
    for (const test of report.requiredTests) lines.push(`  - ${test}`);
  }
  return `${lines.join("\n")}\n`;
}
