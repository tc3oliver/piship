// The piship/v1alpha6 `data` section: retention per data class, purge on
// logout and uninstall, and session export. Parse level only: the sweep and
// the export enforcement live in the runtime.
import {
  type PolicyEffect,
  SESSION_EXPORT_RESOURCES,
  type SessionExportResource,
} from "@piship/contracts";
import {
  fail,
  list,
  oneOf,
  optionalRecord,
  record,
} from "./governance/fields.js";

/** The version of the data lifecycle contract a lock records. */
export const DATA_CONTRACT_VERSION = "piship-data/v1" as const;

/**
 * Data classes with a retention: `sessions` (including Codemode store
 * entries), rotated `audit` logs, the runtime `cache`, and PiShip `temp`
 * files. Credential metadata has no retention: only logout and purge remove
 * it.
 */
export const DATA_CLASSES = ["sessions", "audit", "cache", "temp"] as const;
export type DataClass = (typeof DATA_CLASSES)[number];

/**
 * How the distribution's retention bounds a user's: a `maximum` may be
 * shortened, a `minimum` (audit) may be lengthened.
 */
export const DATA_RETENTION_BOUNDS: Readonly<
  Record<DataClass, "minimum" | "maximum">
> = {
  sessions: "maximum",
  audit: "minimum",
  cache: "maximum",
  temp: "maximum",
};

export const DATA_UNINSTALL_PURGE = ["none", "all"] as const;
export type DataUninstallPurge = (typeof DATA_UNINSTALL_PURGE)[number];

export interface DataRetention {
  /** The declared retention (`30d`, `12h`) in seconds. */
  readonly retentionSeconds: number;
}

export interface DataManifest {
  /** Declared classes only; an absent class is not swept. */
  readonly retention: Readonly<Partial<Record<DataClass, DataRetention>>>;
  readonly purge: {
    readonly onLogout: readonly DataClass[];
    readonly onUninstall: DataUninstallPurge;
  };
  /**
   * `data.export.<resource>`: sugar for a distribution-enforced
   * `session.export` rule on that resource. Declared resources only.
   */
  readonly export: Readonly<
    Partial<Record<SessionExportResource, PolicyEffect>>
  >;
}

/** Top-level manifest sections added by piship/v1alpha6 outside governance. */
export const DATA_KEYS = ["data"] as const;

const EFFECTS: readonly PolicyEffect[] = ["allow", "ask", "deny"];

/** A retention such as `30d` or `12h`, in seconds. */
function retention(value: unknown, path: string): number {
  if (typeof value !== "string")
    fail(path, "Expected a retention such as 30d or 12h");
  const match = /^([1-9]\d{0,4})(d|h)$/.exec(value);
  if (!match) fail(path, "Expected a retention such as 30d or 12h");
  return Number(match[1]) * (match[2] === "d" ? 86_400 : 3_600);
}

/** Parse `data`; undefined when the manifest has no `data` section. */
export function parseData(value: unknown): DataManifest | undefined {
  if (value === undefined) return undefined;
  const data = record(value, "data", [...DATA_CLASSES, "purge", "export"]);
  const retentionOf: Partial<Record<DataClass, DataRetention>> = {};
  for (const name of DATA_CLASSES) {
    if (data[name] === undefined) continue;
    const item = record(data[name], `data.${name}`, ["retention"]);
    retentionOf[name] = {
      retentionSeconds: retention(item.retention, `data.${name}.retention`),
    };
  }
  const purge = optionalRecord(data.purge, "data.purge", [
    "onLogout",
    "onUninstall",
  ]);
  const exports = optionalRecord(
    data.export,
    "data.export",
    SESSION_EXPORT_RESOURCES,
  );
  const exportOf: Partial<Record<SessionExportResource, PolicyEffect>> = {};
  for (const resource of SESSION_EXPORT_RESOURCES)
    if (exports[resource] !== undefined)
      exportOf[resource] = oneOf(
        exports[resource],
        `data.export.${resource}`,
        EFFECTS,
      );
  return {
    retention: retentionOf,
    purge: {
      onLogout: list(purge.onLogout, "data.purge.onLogout", (entry, at) =>
        oneOf(entry, at, DATA_CLASSES),
      ),
      onUninstall: oneOf(
        purge.onUninstall,
        "data.purge.onUninstall",
        DATA_UNINSTALL_PURGE,
        "none",
      ),
    },
    export: exportOf,
  };
}
