// Local data classes and the non-mutating migration check used by update,
// rollback, and `piship migrate-check`. Credentials are never part of a
// migration plan or snapshot: an incompatible credential class is cleared and
// reacquired, never copied.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { auditLogFiles } from "@piship/audit";

/**
 * State marker naming the release that last used this state; written at
 * update and rollback activation and repaired before either compares state.
 */
export const STATE_MARKER_SCHEMA = "piship-state/v1";
export const STATE_MARKER_FILE = "state.json";

/** State file schemas one PiShip version reads, recorded in `piship.lock`. */
export interface StateSchemaSupport {
  readonly state: readonly string[];
  readonly identity: readonly string[];
  readonly credential: readonly string[];
  readonly preferences: readonly string[];
  readonly metrics: readonly string[];
  readonly audit: readonly string[];
}

/** What this PiShip version reads and writes. */
export const STATE_SCHEMAS: StateSchemaSupport = Object.freeze({
  state: [STATE_MARKER_SCHEMA],
  identity: ["piship-identity-metadata/v1"],
  credential: ["piship-credential-metadata/v1"],
  preferences: ["piship-preferences/v1"],
  metrics: ["piship-metrics/v1"],
  audit: ["piship-audit/v1"],
});

/**
 * What a payload built before lock v1alpha4 reads. Those releases never read
 * the state marker, so it cannot confuse them.
 */
export const LEGACY_STATE_SCHEMAS: StateSchemaSupport = Object.freeze({
  state: [],
  identity: ["piship-identity-metadata/v1"],
  credential: ["piship-credential-metadata/v1"],
  preferences: ["piship-preferences/v1"],
  metrics: ["piship-metrics/v1"],
  audit: ["piship-audit/v1"],
});

export type DataSensitivity = "secret-reference" | "private" | "metadata";

/** One documented local data class (location, scope, retention, clearing, migration). */
export interface DataClass {
  readonly name: string;
  /** Path relative to the distribution state directory, `/` separated. */
  readonly path: string;
  readonly kind: "file" | "directory";
  readonly scope: string;
  readonly sensitivity: DataSensitivity;
  readonly retention: string;
  readonly clear: string;
  readonly migration: string;
  /** Key into StateSchemaSupport for classes with a versioned JSON schema. */
  readonly schema?: keyof StateSchemaSupport;
  /** Credential classes are cleared and reacquired, never migrated or restored. */
  readonly credential?: boolean;
}

export const STATE_DATA_CLASSES: readonly DataClass[] = Object.freeze([
  {
    name: "state marker",
    path: STATE_MARKER_FILE,
    kind: "file",
    scope: "distribution",
    sensitivity: "metadata",
    retention: "kept by uninstall",
    clear: "purge",
    migration: "rewritten at every activation",
    schema: "state",
  },
  {
    name: "identity session",
    path: "identity/session.json",
    kind: "file",
    scope: "user",
    sensitivity: "secret-reference",
    retention: "until logout",
    clear: "logout, purge",
    migration:
      "never copied; cleared and reacquired by login when the target cannot read it",
    schema: "identity",
    credential: true,
  },
  {
    name: "runtime credential metadata",
    path: "credentials-metadata/inference.json",
    kind: "file",
    scope: "user",
    sensitivity: "secret-reference",
    retention: "until logout or expiry",
    clear: "logout, purge",
    migration:
      "never copied; cleared and reacquired when the target cannot read it",
    schema: "credential",
    credential: true,
  },
  {
    name: "file secret fallback",
    path: "secrets",
    kind: "directory",
    scope: "user",
    sensitivity: "secret-reference",
    retention: "until logout",
    clear: "logout, purge",
    migration: "never copied, snapshotted, or restored",
    credential: true,
  },
  {
    name: "preferences",
    path: "config/preferences.json",
    kind: "file",
    scope: "user",
    sensitivity: "metadata",
    retention: "kept by uninstall and logout",
    clear: "purge",
    migration: "kept in place; included in the pre-upgrade snapshot",
    schema: "preferences",
  },
  {
    name: "user policy rules",
    path: "config/policy.json",
    kind: "file",
    scope: "user",
    sensitivity: "metadata",
    retention: "kept by uninstall and logout",
    clear: "purge",
    migration: "kept in place; included in the pre-upgrade snapshot",
  },
  {
    name: "Pi agent configuration",
    path: "agent",
    kind: "directory",
    scope: "user",
    sensitivity: "private",
    retention: "kept by uninstall",
    clear: "purge",
    migration:
      "owned by Pi; kept in place. Pi-native auth.json is a credential and is never snapshotted",
    credential: true,
  },
  {
    name: "sessions",
    path: "sessions",
    kind: "directory",
    scope: "user",
    sensitivity: "private",
    retention: "kept by uninstall and logout",
    clear: "purge",
    migration:
      "owned by Pi; kept in place. Pi migrates older sessions forward; a target with an older Pi needs review",
  },
  {
    name: "audit and metrics logs",
    path: "logs",
    kind: "directory",
    scope: "distribution",
    sensitivity: "private",
    retention: "kept by uninstall",
    clear: "purge",
    migration: "kept in place; append-only",
    schema: "audit",
  },
  {
    name: "cache",
    path: "cache",
    kind: "directory",
    scope: "distribution",
    sensitivity: "metadata",
    retention: "kept by uninstall",
    clear: "purge; safe to delete",
    migration: "not migrated; may be discarded",
  },
  {
    name: "runtime data",
    path: "data",
    kind: "directory",
    scope: "distribution",
    sensitivity: "private",
    retention: "kept by uninstall",
    clear: "purge",
    migration: "kept in place",
  },
  {
    name: "migration snapshots",
    path: "migration",
    kind: "directory",
    scope: "distribution",
    sensitivity: "metadata",
    retention: "last 3 snapshots",
    clear: "purge",
    migration:
      "non-secret pre-upgrade copies of preferences and user policy; never credentials",
  },
]);

export type MigrationVerdict = "safe" | "requires-review" | "unsupported";

export interface MigrationItem {
  readonly name: string;
  readonly path: string;
  readonly current: string | null;
  readonly verdict: MigrationVerdict;
  /** `keep`, `clear-and-reacquire`, `review`, or `refuse`. */
  readonly action: "keep" | "clear-and-reacquire" | "review" | "refuse";
  readonly reason: string;
}

export interface MigrationReport {
  readonly verdict: MigrationVerdict;
  readonly from: {
    readonly version: string | null;
    readonly pi: string | null;
  };
  readonly to: { readonly version: string; readonly pi: string };
  readonly items: readonly MigrationItem[];
}

export interface MigrationTarget {
  readonly version: string;
  readonly pi: string;
  readonly schemas: StateSchemaSupport;
}

export interface StateMarker {
  readonly schema: string;
  readonly distribution: string;
  readonly version: string;
  readonly pi: string;
  readonly piship: string;
}

const NUMBER = "(0|[1-9]\\d*)";
const PRERELEASE = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
const BUILD = "[0-9A-Za-z-]+";
const VERSION = new RegExp(
  `^${NUMBER}\\.${NUMBER}\\.${NUMBER}(?:-(${PRERELEASE}(?:\\.${PRERELEASE})*))?(?:\\+${BUILD}(?:\\.${BUILD})*)?$`,
);

/** SemVer 2.0 precedence; throws on a malformed version. */
export function compareVersions(a: string, b: string): number {
  const left = VERSION.exec(a);
  const right = VERSION.exec(b);
  if (!left || !right)
    throw new Error(`Not a semantic version: ${left ? b : a}`);
  for (let index = 1; index <= 3; index += 1) {
    const difference = Number(left[index]) - Number(right[index]);
    if (difference) return Math.sign(difference);
  }
  const leftPre = left[4]?.split(".");
  const rightPre = right[4]?.split(".");
  if (!leftPre || !rightPre) return leftPre ? -1 : rightPre ? 1 : 0;
  for (
    let index = 0;
    index < Math.max(leftPre.length, rightPre.length);
    index += 1
  ) {
    const x = leftPre[index];
    const y = rightPre[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    if (xNumeric && yNumeric) {
      const difference = Number(x) - Number(y);
      if (difference) return Math.sign(difference);
    } else if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function readSchema(path: string): string | null | "unreadable" {
  if (!existsSync(path)) return null;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as {
      schema?: unknown;
    };
    return typeof value.schema === "string" ? value.schema : "unreadable";
  } catch {
    return "unreadable";
  }
}

/** The state marker, or null when absent. An unknown schema is returned as is. */
export function readStateMarker(stateDir: string): StateMarker | null {
  const path = join(stateDir, STATE_MARKER_FILE);
  if (!existsSync(path)) return null;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as StateMarker;
    return value && typeof value.schema === "string" ? value : null;
  } catch {
    return null;
  }
}

function newestAuditSchema(stateDir: string): string | null | "unreadable" {
  // Right after a size rotation the newest events are in `audit.jsonl.1`.
  for (const path of auditLogFiles(stateDir)) {
    const last = readFileSync(path, "utf8").trimEnd().split("\n").at(-1);
    if (!last) continue;
    try {
      const value = JSON.parse(last) as { schema?: unknown };
      return typeof value.schema === "string" ? value.schema : "unreadable";
    } catch {
      return "unreadable";
    }
  }
  return null;
}

function worst(verdicts: readonly MigrationVerdict[]): MigrationVerdict {
  if (verdicts.includes("unsupported")) return "unsupported";
  if (verdicts.includes("requires-review")) return "requires-review";
  return "safe";
}

/**
 * Report whether each local data class can move to `target` without reading
 * or writing anything outside plain reads. Never mutates the state directory.
 */
export function checkStateMigration(
  stateDir: string,
  target: MigrationTarget,
  current: { readonly version: string | null; readonly pi: string | null },
): MigrationReport {
  const items: MigrationItem[] = [];
  const marker = readStateMarker(stateDir);
  const fromPi = marker?.pi ?? current.pi;
  const fromVersion = marker?.version ?? current.version;
  for (const dataClass of STATE_DATA_CLASSES) {
    const path = join(stateDir, ...dataClass.path.split("/"));
    const present = existsSync(path);
    if (!dataClass.schema) {
      if (dataClass.name === "sessions" && present) {
        const hasSessions = readdirSync(path).length > 0;
        const older = !!fromPi && compareVersions(target.pi, fromPi) < 0;
        items.push({
          name: dataClass.name,
          path: dataClass.path,
          current: fromPi ? `Pi ${fromPi}` : null,
          verdict: hasSessions && older ? "requires-review" : "safe",
          action: hasSessions && older ? "review" : "keep",
          reason:
            hasSessions && older
              ? `Sessions were written by Pi ${fromPi}; the target runs the older Pi ${target.pi}, which may not read newer session entries`
              : "Kept in place; Pi reads and migrates its own session files forward",
        });
      } else
        items.push({
          name: dataClass.name,
          path: dataClass.path,
          current: null,
          verdict: "safe",
          action: "keep",
          reason: present
            ? dataClass.credential
              ? "Kept in place and never copied into a snapshot"
              : "Kept in place"
            : "Not present",
        });
      continue;
    }
    const schema =
      dataClass.schema === "audit"
        ? newestAuditSchema(stateDir)
        : dataClass.schema === "state"
          ? marker
            ? marker.schema
            : existsSync(path)
              ? "unreadable"
              : null
          : readSchema(path);
    const supported = target.schemas[dataClass.schema];
    if (schema === null) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: null,
        verdict: "safe",
        action: "keep",
        reason: "Not present",
      });
      continue;
    }
    // A release that never reads the marker is unaffected by it.
    if (dataClass.schema === "state" && supported.length === 0) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: schema,
        verdict: "safe",
        action: "keep",
        reason: "The target does not read the state marker",
      });
      continue;
    }
    if (schema !== "unreadable" && supported.includes(schema)) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: schema,
        verdict: "safe",
        action: "keep",
        reason: `${schema} is readable by the target`,
      });
      continue;
    }
    if (dataClass.credential) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: schema,
        verdict: "safe",
        action: "clear-and-reacquire",
        reason: `The target cannot read ${schema}; it is cleared and the target signs in or reacquires the credential`,
      });
      continue;
    }
    items.push({
      name: dataClass.name,
      path: dataClass.path,
      current: schema,
      verdict: "unsupported",
      action: "refuse",
      reason: `The target reads ${supported.join(", ") || "no version"} of this file, not ${schema}; it would be reinterpreted`,
    });
  }
  return {
    verdict: worst(items.map((item) => item.verdict)),
    from: { version: fromVersion, pi: fromPi },
    to: { version: target.version, pi: target.pi },
    items,
  };
}

/** Plain-text rendering for CLI output. */
export function formatMigrationReport(report: MigrationReport): string {
  const lines = [
    `Migration check ${report.from.version ?? "unknown"} -> ${report.to.version} (Pi ${report.from.pi ?? "unknown"} -> ${report.to.pi}): ${report.verdict}`,
  ];
  for (const item of report.items)
    lines.push(
      `  ${item.verdict === "safe" ? "✓" : item.verdict === "requires-review" ? "!" : "✗"} ${item.name.padEnd(28)} ${item.action.padEnd(19)} ${item.reason}`,
    );
  return lines.join("\n");
}
