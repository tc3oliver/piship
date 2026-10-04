// The `data` lifecycle contract (spec v0.9 §13): retention of the swept data
// classes, the sweep that enforces it at launch and logout, and the logout
// purge.
//
// What the sweep may touch, and nothing else:
//
// - sessions: `*.jsonl` files under `<state>/sessions` (Pi's session files,
//   including their `codemode-store` entries). A session held by a live owner
//   record (packages/pi `SessionOwnership`) is skipped.
// - audit: the rotated `logs/audit.jsonl.N` files only, never the live
//   `audit.jsonl` (there is no forward spool: the HTTP queue is in memory).
// - cache: regular files under `<state>/cache`.
//
// Credential metadata, the secret fallback, the Pi agent directory,
// preferences, and every other class of STATE_DATA_CLASSES are never swept.
// `temp` has a retention but no files here: PiShip temporaries are removed by
// the launch sweep of abandoned temporaries (temporary-directories.ts), and a
// live one belongs to a running process.
//
// The sweep never follows a symbolic link, deletes only regular files, judges
// age by mtime, and writes one `data.swept` audit event per class before it
// deletes anything of that class. A class whose event cannot be recorded is
// left as it is.
import { lstatSync, readdirSync, type Stats, unlinkSync } from "node:fs";
import { join } from "node:path";
import { AUDIT_ROTATION, type AuditRotation } from "@piship/audit";
import type { AuditEventType } from "@piship/contracts";
import {
  DATA_CLASSES,
  DATA_RETENTION_BOUNDS,
  type DataClass,
  type DataManifest,
} from "@piship/schema";

/** A data class with a retention in the `data` contract. */
export type RetainedDataClass = DataClass;

/** A class the sweep deletes files of; `temp` is the temporaries sweep's. */
export type SweptDataClass = Exclude<RetainedDataClass, "temp">;

/** Retention per class, in milliseconds; an absent class is not swept. */
export type RetentionMs = Partial<Record<RetainedDataClass, number>>;

/** The audit event a sweep writes before it deletes a class's files. */
export interface DataSweptEvent {
  readonly event: Extract<AuditEventType, "data.swept">;
  /** The data class, never a path: session paths name the user's projects. */
  readonly resource: SweptDataClass;
  readonly detail: {
    readonly class: SweptDataClass;
    readonly trigger: DataSweepTrigger;
    /** The retention applied, in seconds (0 for a logout purge). */
    readonly retentionSeconds: number;
    /** Files older than this were selected. */
    readonly cutoff: string;
    /** Files about to be deleted. */
    readonly files: number;
    /** Sessions old enough but held by a live owner, and kept. */
    readonly held?: number;
  };
}

/** The declared retention of each class of a `data` section, in milliseconds. */
export function declaredRetention(data: DataManifest): RetentionMs {
  const result: RetentionMs = {};
  for (const dataClass of DATA_CLASSES) {
    const declared = data.retention[dataClass];
    if (declared) result[dataClass] = declared.retentionSeconds * 1000;
  }
  return result;
}

/**
 * The retention applied to one class, from the distribution's and the
 * user's value: for `audit` the distribution's is a minimum (a user may
 * lengthen it, never shorten it), for every other class a maximum (a user may
 * shorten it). Without a distribution value the user's applies; without
 * either the class is not swept.
 */
export function effectiveRetention(
  dataClass: RetainedDataClass,
  enforced: number | undefined,
  user: number | undefined,
): number | undefined {
  if (enforced === undefined) return user;
  if (user === undefined) return enforced;
  return DATA_RETENTION_BOUNDS[dataClass] === "minimum"
    ? Math.max(enforced, user)
    : Math.min(enforced, user);
}

/** Effective retention for every class, from the enforced and the user's values. */
export function effectiveRetentions(
  enforced: RetentionMs,
  user: RetentionMs = {},
): RetentionMs {
  const result: RetentionMs = {};
  for (const dataClass of DATA_CLASSES) {
    const value = effectiveRetention(
      dataClass,
      enforced[dataClass],
      user[dataClass],
    );
    if (value !== undefined) result[dataClass] = value;
  }
  return result;
}

export interface DataLifecycleIssue {
  readonly level: "error";
  readonly path: string;
  readonly message: string;
}

/**
 * Semantic checks of the `data` section that parsing leaves: the audit
 * retention is a minimum, so logout may not purge it.
 */
export function dataLifecycleIssues(data: DataManifest): DataLifecycleIssue[] {
  return data.purge.onLogout.includes("audit")
    ? [
        {
          level: "error",
          path: "data.purge.onLogout",
          message:
            "audit retention is a minimum, so logout cannot purge it; remove audit from onLogout",
        },
      ]
    : [];
}

export type DataSweepTrigger = "launch" | "logout";

/**
 * The retention a sweep applies: at launch the effective retention, at
 * logout also 0 for every class in `purge.onLogout` (audit never, whatever
 * the contract says).
 */
export function sweepRetention(
  trigger: DataSweepTrigger,
  retention: RetentionMs,
  onLogout: readonly RetainedDataClass[] = [],
): Partial<Record<SweptDataClass, number>> {
  const result: Partial<Record<SweptDataClass, number>> = {};
  for (const dataClass of ["sessions", "audit", "cache"] as const) {
    const value = retention[dataClass];
    if (value !== undefined) result[dataClass] = value;
    if (
      trigger === "logout" &&
      dataClass !== "audit" &&
      onLogout.includes(dataClass)
    )
      result[dataClass] = 0;
  }
  return result;
}

export interface DataSweepOptions {
  /** The distribution state directory. */
  readonly stateDir: string;
  readonly trigger: DataSweepTrigger;
  /** Per class, in milliseconds; see `sweepRetention`. */
  readonly retention: Partial<Record<SweptDataClass, number>>;
  /**
   * Records the `data.swept` event; the sweep deletes a class's files only
   * once this has resolved for it. A rejection leaves the class as it is.
   */
  readonly record: (event: DataSweptEvent) => void | Promise<void>;
  /**
   * Whether a session file is held by a live runtime. Defaults to "has any
   * owner record" (`sessionHasOwnerRecord`), which never deletes a held
   * session but keeps one whose owner died until a launch clears its record.
   */
  readonly sessionHeld?: (sessionFile: string) => boolean;
  /** Wall clock in milliseconds; tests pass a fixed one. */
  readonly now?: number;
}

export interface DataSweepClassResult {
  readonly class: SweptDataClass;
  readonly removed: number;
  /** Old enough, but held by a live runtime. */
  readonly held: number;
  /** Selected, but found changed or held again just before deletion. */
  readonly kept: number;
  readonly failed: number;
  /** Set when the `data.swept` event could not be recorded; nothing was deleted. */
  readonly unrecorded?: true;
}

export interface DataSweepResult {
  readonly classes: readonly DataSweepClassResult[];
}

/** Pi's owner records beside session files; never session files themselves. */
const OWNER_DIRECTORY = ".piship-owners";
/** `audit.jsonl.1` and up: rotated files only. */
const ROTATED_AUDIT = /^audit\.jsonl\.[1-9]\d*$/;
/** Bound on directory nesting walked under `sessions` and `cache`. */
const MAX_DEPTH = 8;

function lstat(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function entries(directory: string): string[] {
  try {
    return readdirSync(directory);
  } catch {
    return [];
  }
}

/**
 * Whether any owner record names the session file, live or not. The
 * conservative default of `sessionHeld`: packages/pi's `liveOwner` also
 * removes the records of owners that are gone.
 */
export function sessionHasOwnerRecord(sessionFile: string): boolean {
  const slash = Math.max(
    sessionFile.lastIndexOf("/"),
    sessionFile.lastIndexOf("\\"),
  );
  const directory = join(sessionFile.slice(0, slash), OWNER_DIRECTORY);
  const session = sessionFile.slice(slash + 1);
  return entries(directory).some(
    (name) => name.startsWith(`${session}.`) && name.endsWith(".json"),
  );
}

/** Regular files under `root`, without following a link, that `accept` takes. */
function walk(
  root: string,
  accept: (name: string) => boolean,
  skipDirectory: (name: string) => boolean = () => false,
): string[] {
  const rootStats = lstat(root);
  if (!rootStats?.isDirectory()) return [];
  const found: string[] = [];
  const visit = (directory: string, depth: number) => {
    for (const name of entries(directory)) {
      const path = join(directory, name);
      const stats = lstat(path);
      if (!stats) continue;
      if (stats.isDirectory()) {
        if (depth < MAX_DEPTH && !skipDirectory(name)) visit(path, depth + 1);
      } else if (stats.isFile() && accept(name)) found.push(path);
    }
  };
  visit(root, 0);
  return found;
}

function candidates(stateDir: string, dataClass: SweptDataClass): string[] {
  switch (dataClass) {
    case "sessions":
      return walk(
        join(stateDir, "sessions"),
        (name) => name.endsWith(".jsonl"),
        (name) => name === OWNER_DIRECTORY,
      );
    case "audit": {
      const logs = join(stateDir, "logs");
      if (!lstat(logs)?.isDirectory()) return [];
      return entries(logs)
        .filter((name) => ROTATED_AUDIT.test(name))
        .map((name) => join(logs, name))
        .filter((path) => lstat(path)?.isFile() === true);
    }
    case "cache":
      return walk(join(stateDir, "cache"), () => true);
  }
}

/**
 * Delete what the retention no longer keeps, class by class: sessions, then
 * rotated audit files, then cache. Best effort: a file that cannot be removed
 * is counted, not thrown. Classes without a retention are not swept.
 */
export async function sweepData(
  options: DataSweepOptions,
): Promise<DataSweepResult> {
  const now = options.now ?? Date.now();
  const held = options.sessionHeld ?? sessionHasOwnerRecord;
  const classes: DataSweepClassResult[] = [];
  for (const dataClass of ["sessions", "audit", "cache"] as const) {
    const retention = options.retention[dataClass];
    if (retention === undefined || !(retention >= 0)) continue;
    const cutoff = now - retention;
    // A logout purge (retention 0) takes everything that exists now.
    const old = (path: string) => {
      const stats = lstat(path);
      return (
        stats?.isFile() === true && (retention === 0 || stats.mtimeMs < cutoff)
      );
    };
    const isHeld = (path: string) =>
      dataClass === "sessions" && safeHeld(held, path);
    const selected: string[] = [];
    let heldCount = 0;
    for (const path of candidates(options.stateDir, dataClass)) {
      if (!old(path)) continue;
      if (isHeld(path)) heldCount += 1;
      else selected.push(path);
    }
    if (selected.length === 0) {
      if (heldCount > 0)
        classes.push({
          class: dataClass,
          removed: 0,
          held: heldCount,
          kept: 0,
          failed: 0,
        });
      continue;
    }
    try {
      await options.record({
        event: "data.swept",
        resource: dataClass,
        detail: {
          class: dataClass,
          trigger: options.trigger,
          retentionSeconds: Math.floor(retention / 1000),
          cutoff: new Date(cutoff).toISOString(),
          files: selected.length,
          ...(dataClass === "sessions" ? { held: heldCount } : {}),
        },
      });
    } catch {
      classes.push({
        class: dataClass,
        removed: 0,
        held: heldCount,
        kept: selected.length,
        failed: 0,
        unrecorded: true,
      });
      continue;
    }
    let removed = 0;
    let kept = 0;
    let failed = 0;
    for (const path of selected) {
      // Checked again: a session resumed, or a file written, since it was
      // selected stays.
      if (!old(path) || isHeld(path)) {
        kept += 1;
        continue;
      }
      try {
        unlinkSync(path);
        removed += 1;
      } catch {
        failed += 1;
      }
    }
    classes.push({
      class: dataClass,
      removed,
      held: heldCount,
      kept,
      failed,
    });
  }
  return { classes };
}

/** A predicate that throws holds the session: wrongly kept is harmless. */
function safeHeld(held: (path: string) => boolean, path: string): boolean {
  try {
    return held(path);
  } catch {
    return true;
  }
}

/**
 * The file sink rotation of a distribution: the fixed size limits, and the
 * declared audit retention as the minimum rotation never deletes before.
 */
export function auditRotation(lock: {
  readonly data?: { readonly declared?: DataManifest };
}): AuditRotation {
  const audit = lock.data?.declared?.retention.audit;
  return audit
    ? { ...AUDIT_ROTATION, minimumRetentionMs: audit.retentionSeconds * 1000 }
    : AUDIT_ROTATION;
}
