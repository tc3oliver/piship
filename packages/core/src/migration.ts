// Local data classes and the non-mutating migration check used by update,
// rollback, and `piship migrate-check`. Credentials are never part of a
// migration plan or snapshot: an incompatible credential class is cleared and
// reacquired, never copied.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { auditLogFiles } from "@piship/audit";
import type { SecretStoreProvider } from "@piship/credentials";
import {
  applySecretLayoutTransition,
  applyStorageTransition,
} from "./storage-transition.js";

export {
  applySecretLayoutTransition,
  applyStorageTransition,
  storageOf,
  storageTransition,
} from "./storage-transition.js";

/**
 * State marker naming the release that last used this state; written at
 * update and rollback activation and repaired before either compares state.
 */
export const STATE_MARKER_SCHEMA = "piship-state/v1";
export const STATE_MARKER_FILE = "state.json";

/**
 * State file schemas one PiShip version reads, recorded in `piship.lock`. A
 * key added after a release is absent from that release's lock: the release
 * reads none of that class's schemas.
 */
export interface StateSchemaSupport {
  readonly state: readonly string[];
  readonly identity: readonly string[];
  readonly credential: readonly string[];
  readonly preferences: readonly string[];
  readonly metrics: readonly string[];
  readonly audit: readonly string[];
  readonly sandboxCredential?: readonly string[];
  readonly credentialIssuance?: readonly string[];
}

/** What this PiShip version reads and writes. */
export const STATE_SCHEMAS: StateSchemaSupport = Object.freeze({
  state: [STATE_MARKER_SCHEMA],
  identity: ["piship-identity-metadata/v1"],
  credential: ["piship-credential-metadata/v1"],
  preferences: ["piship-preferences/v1"],
  metrics: ["piship-metrics/v1"],
  audit: ["piship-audit/v1"],
  sandboxCredential: ["piship-sandbox-credential-metadata/v1"],
  credentialIssuance: ["piship-credential-issuance/v1"],
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
    // Also the identity discarded marker (piship-identity-discarded/v1) left
    // when a signed-out or replaced session's tokens could not be deleted:
    // only the references still to delete, no claim. No release restores it
    // as a session, and every command retries the deletion first.
    name: "identity session",
    path: "identity/session.json",
    kind: "file",
    scope: "user",
    sensitivity: "secret-reference",
    retention:
      "until logout; a session whose tokens cannot be deleted is replaced by a discarded marker that keeps them tracked and is never used",
    clear: "logout (also without the runtime variables), purge",
    migration:
      "never copied; when the target cannot read it, its secrets are deleted and the deletion confirmed before the switch, and login reacquires it. A secret that cannot be deleted stops the switch",
    schema: "identity",
    credential: true,
  },
  {
    // Also the discarded marker (piship-credential-discarded/v1) left when a
    // secret could not be deleted: no release reads it, so every switch
    // clears it.
    name: "runtime credential metadata",
    path: "credentials-metadata/inference.json",
    kind: "file",
    scope: "user",
    sensitivity: "secret-reference",
    retention: "until logout or expiry",
    clear:
      "logout (also without the runtime variables), change of principal, purge",
    migration:
      "never copied; when the target cannot read it (always for a discarded marker), its secrets are deleted and the deletion confirmed before the switch, and it is reacquired. A secret that cannot be deleted stops the switch",
    schema: "credential",
    credential: true,
  },
  {
    // Also the discarded marker (piship-credential-discarded/v1) left when a
    // secret could not be deleted: no release reads it as a credential.
    name: "sandbox credential metadata",
    path: "credentials-metadata/sandbox.json",
    kind: "file",
    scope: "user, bound to the principal that stored it",
    sensitivity: "secret-reference",
    retention:
      "until sandbox logout, logout, a change of principal, or purge; never the secret, which is in the secret store",
    clear:
      "sandbox logout, logout (also without the runtime variables), change of principal (at login, and at launch for one bound to another principal), purge",
    migration:
      "never copied; when the target cannot read it (every release before it, and always for a discarded marker), its secrets are deleted and the deletion confirmed before the switch, and the user runs sandbox login again. A secret that cannot be deleted stops the switch",
    schema: "sandboxCredential",
    credential: true,
  },
  {
    // Only the idempotency key of an acquire or renewal whose answer was
    // lost, bound to the principal and to the credential it renews. A
    // credential class, so a release that does not know it (every release
    // before it) has it cleared at the switch instead of leaving a file its
    // logout would not remove.
    name: "pending credential issuance",
    path: "credentials-metadata/pending-issuance.json",
    kind: "file",
    scope: "user, bound to the principal that sent the request",
    sensitivity: "metadata",
    retention:
      "from before an acquire or renewal is sent until it is resolved: its credential committed, the broker's final refusal, 24 hours, or a change of principal",
    clear:
      "commit of the credential, logout (also without the runtime variables), change of principal, purge; a login of the same principal keeps it",
    migration:
      "never copied or snapshotted; cleared when the target cannot read it (every release before it) or when the runtime credential is cleared",
    schema: "credentialIssuance",
    credential: true,
  },
  {
    name: "principal binding",
    path: "identity/principal.json",
    kind: "file",
    scope: "user",
    sensitivity: "private",
    retention:
      "kept by logout; replaced when another principal (issuer and subject) signs in",
    clear: "purge",
    migration:
      "kept in place; no secret. An unreadable record counts as a change of principal, and so does a missing one unless the stored session is the signing-in principal's (a signed-in user upgrading from a release without it keeps the model selection, and the record is created)",
  },
  {
    name: "pending revocations",
    path: "credentials-metadata/revocation-retry.json",
    kind: "file",
    scope: "user",
    sensitivity: "metadata",
    retention:
      "until the credential expires; written when a revocation fails or cannot be sent (logout without the runtime variables); at most 20 entries, older ones dropped and counted; checked at every login and reported by doctor",
    clear: "login once the credential expired, purge",
    migration:
      "kept in place; credential IDs and times only, never a secret, so nothing can be revoked or restored from it",
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
    name: "user auto mode",
    path: "config/auto.json",
    kind: "file",
    scope: "user, bound to the principal binding it was switched on under",
    sensitivity: "metadata",
    retention:
      "kept by uninstall and logout; off once another principal binds the state",
    clear: "auto off, purge",
    migration:
      "kept in place, never snapshotted; it applies only while the running release allows policy.userAuto",
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
    migration: "kept in place; audit.jsonl is rotated by size, never rewritten",
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
  /** Set when the class is cleared because the secret store changes. */
  readonly storageTransition?: {
    readonly from: SecretStoreProvider;
    readonly to: SecretStoreProvider;
  };
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
  /** The target's `credential.storage.provider`; see `current.storage`. */
  readonly storage?: SecretStoreProvider;
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

/**
 * The schema of the newest audit event, or null when there is none. A line
 * that is not an event (one cut short by a crash or a full disk) is skipped:
 * no release reads it as an event, and the log is never rewritten, so it is
 * kept in place and named in `damaged`.
 */
function newestAuditSchema(stateDir: string): {
  schema: string | null;
  damaged: string | null;
} {
  let damaged: string | null = null;
  // Right after a size rotation the newest events are in `audit.jsonl.1`.
  for (const path of auditLogFiles(stateDir)) {
    const lines = readFileSync(path, "utf8").split("\n");
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      const line = (lines[index] as string).trim();
      if (!line) continue;
      try {
        const value = JSON.parse(line) as { schema?: unknown } | null;
        if (typeof value?.schema === "string")
          return { schema: value.schema, damaged };
      } catch {
        // Not an event; see below.
      }
      damaged ??= path;
    }
  }
  return { schema: null, damaged };
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
  current: {
    readonly version: string | null;
    readonly pi: string | null;
    /**
     * The active release's `credential.storage.provider`. When it differs
     * from the target's, identity and credential state is cleared from the
     * active store and reacquired (see `applyStorageTransition`).
     */
    readonly storage?: SecretStoreProvider;
    /** Defaults to `process.platform`; see `applySecretLayoutTransition`. */
    readonly platform?: NodeJS.Platform;
  },
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
    // A marker that cannot be read counts as absent: it only repeats the
    // active release's lock, and update and rollback rewrite it.
    if (dataClass.schema === "state" && !marker && present) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: "unreadable",
        verdict: "safe",
        action: "keep",
        reason: `${path} cannot be read, so it counts as absent; it is rewritten for the active release`,
      });
      continue;
    }
    const audit =
      dataClass.schema === "audit" ? newestAuditSchema(stateDir) : null;
    const schema = audit
      ? audit.schema
      : dataClass.schema === "state"
        ? (marker?.schema ?? null)
        : readSchema(path);
    // A target whose lock predates this schema key reads none of the class.
    const supported = target.schemas[dataClass.schema] ?? [];
    if (schema === null) {
      items.push({
        name: dataClass.name,
        path: dataClass.path,
        current: null,
        verdict: "safe",
        action: "keep",
        reason: audit?.damaged
          ? `Kept in place; ${audit.damaged} holds only a line cut short, which no release reads as an event`
          : "Not present",
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
      // Damaged user data is never rebuilt or deleted here: the user moves
      // it aside, and the target then starts without it.
      reason:
        schema === "unreadable"
          ? `${path} is empty, cut short, or not a ${dataClass.name} file, so no release can read it; move it aside (for example to ${path}.damaged) and run the command again, which then starts without it`
          : `The target reads ${supported.join(", ") || "no version"} of this file, not ${schema}; it would be reinterpreted`,
    });
  }
  const checked = applyStorageTransition(
    applySecretLayoutTransition(
      items,
      current.storage,
      target.schemas,
      current.platform,
    ),
    current.storage,
    target.storage,
  );
  return {
    verdict: worst(checked.map((item) => item.verdict)),
    from: { version: fromVersion, pi: fromPi },
    to: { version: target.version, pi: target.pi },
    items: checked,
  };
}

function migrationHeader(report: MigrationReport): string {
  return `Migration check ${report.from.version ?? "unknown"} -> ${report.to.version} (Pi ${report.from.pi ?? "unknown"} -> ${report.to.pi}): ${report.verdict}`;
}

function migrationLine(item: MigrationReport["items"][number]): string {
  return `  ${item.verdict === "safe" ? "✓" : item.verdict === "requires-review" ? "!" : "✗"} ${item.name.padEnd(28)} ${item.action.padEnd(19)} ${item.reason}`;
}

/** Plain-text rendering for CLI output. */
export function formatMigrationReport(report: MigrationReport): string {
  return [migrationHeader(report), ...report.items.map(migrationLine)].join(
    "\n",
  );
}

/**
 * The report without the state items that are kept unchanged, for update:
 * one line when nothing in the state changes.
 */
export function formatMigrationSummary(report: MigrationReport): string {
  const changed = report.items.filter(
    (item) => item.verdict !== "safe" || item.action !== "keep",
  );
  const kept = report.items.length - changed.length;
  if (!changed.length)
    return `${migrationHeader(report)}; every state item (${kept}) is kept unchanged.`;
  return [
    migrationHeader(report),
    ...changed.map(migrationLine),
    ...(kept
      ? [
          `  ${kept} other state item(s) are kept unchanged; piship migrate-check prints them all.`,
        ]
      : []),
  ].join("\n");
}
