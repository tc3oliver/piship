import { readFileSync } from "node:fs";
import { join } from "node:path";
import { systemError } from "@piship/contracts";
import { type Document, LineCounter, parseDocument } from "yaml";
import { valid as validSemver } from "semver";
import {
  AccessFieldError,
  parseAccess,
  parseVariables,
  type AccessManifest,
  type DeploymentMode,
} from "./access.js";
import { type DataManifest, DATA_KEYS, parseData } from "./data.js";
import type {
  CacheWarmingConfig,
  GovernanceManifest,
  RuntimeToolsConfig,
  SearchToolsConfig,
} from "./governance.js";
import { assertLaunchable } from "./launch.js";
import { locateErrors } from "./locate.js";
import { unknownFieldMessage } from "./suggest.js";
import {
  GOVERNANCE_KEYS,
  governanceReferences,
  parseCacheWarming,
  parseGovernance,
  parseRuntimeTools,
  parseSearchTools,
  V1ALPHA6_GOVERNANCE_KEYS,
} from "./governance-parse.js";
import {
  LIFECYCLE_KEYS,
  lifecycleReferences,
  parseLifecycle,
  type LifecycleManifest,
} from "./lifecycle.js";
import { migrationPath } from "./migrations/index.js";
import {
  LATEST_SCHEMA,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA6,
  PISHIP_SCHEMA_VERSION,
  type PishipSchemaVersion,
  SUPPORTED_SCHEMAS,
} from "./versions.js";

export * from "./access.js";
export * from "./variables.js";
export * from "./governance.js";
export * from "./governance-parse.js";
export * from "./lifecycle.js";
export * from "./launch.js";
export * from "./http-transport.js";
export * from "./data.js";
export * from "./versions.js";
export { nearestField } from "./suggest.js";
export {
  MANIFEST_MIGRATIONS,
  MIGRATED_BOOTSTRAP_EXPIRES,
  type ManifestMigration,
  type MigrationContext,
  type MigrationStepResult,
  manifestMigration,
  migrationPath,
} from "./migrations/index.js";

export interface ValidationDiagnostic {
  readonly path: string;
  readonly message: string;
}
export interface ManifestHeader {
  readonly schema: PishipSchemaVersion;
}
export interface LockfileHeader {
  readonly schema: string;
}
export interface Manifest {
  readonly schema: PishipSchemaVersion;
  readonly app: {
    readonly id: string;
    readonly name: string;
    readonly command: string;
    readonly version: string;
    readonly banner?: string;
    readonly theme?: string;
  };
  readonly runtime: {
    /**
     * The Pi version the manifest asks for. Omitted, the build uses the Pi
     * it pins; stated, it must equal that pin.
     */
    readonly pi?: string;
    /** Present for piship/v1alpha6 and later, including piship/v1 (defaults applied). */
    readonly tools?: RuntimeToolsConfig;
    /** Present for piship/v1alpha6 and later; an omitted mode is `off`. */
    readonly cacheWarming?: CacheWarmingConfig;
    /** piship/v1alpha6: bundled `fd` and `rg`; absent unless declared. */
    readonly searchTools?: SearchToolsConfig;
    /**
     * piship/v1alpha6, locked as declared. Absent or false: startup hashes
     * only the lock, against the digest recorded at install, never scans the
     * payload, reads the resources it loads without hashing them, and may
     * keep a V8 code cache of a bundled payload. True: startup verifies the
     * whole payload, its inventory included, and keeps no code cache.
     */
    readonly verifyAtLaunch?: boolean;
  };
  readonly deployment: { readonly mode: DeploymentMode };
  readonly resources: {
    readonly instructions: readonly string[];
    readonly skills: readonly string[];
    readonly extensions: readonly string[];
    readonly prompts: readonly string[];
    readonly themes: readonly string[];
  };
  /** Present for piship/v1alpha2 and later manifests. */
  readonly access?: AccessManifest;
  /** Present for piship/v1alpha3 and later manifests. */
  readonly governance?: GovernanceManifest;
  /** Present for piship/v1alpha4 and later manifests (release defaults applied). */
  readonly lifecycle?: LifecycleManifest;
  /**
   * piship/v1alpha6: the data lifecycle. Absent when the manifest has no
   * `data` section, which runs no retention sweep.
   */
  readonly data?: DataManifest;
}
/** A place in the manifest source; both numbers start at 1. */
export interface SourcePosition {
  readonly line: number;
  readonly column: number;
}
export class ManifestError extends Error {
  /**
   * Every problem found in one pass, this one first. A parse reports all it
   * can find, so one run shows what to fix instead of one error per run.
   */
  errors: readonly ManifestError[] = [this];
  constructor(
    readonly kind:
      | "file not found"
      | "YAML parse failure"
      | "schema mismatch"
      | "invalid field"
      | "missing resource"
      | "unsafe path/name"
      | "conflict",
    readonly field: string,
    /** What is wrong, before the secret-field rewrite. */
    readonly reason: string,
    /** Where it is in the YAML source, when the source is known. */
    public position?: SourcePosition,
  ) {
    const unknownSecret =
      reason.startsWith("Unknown field") &&
      SECRET_FIELD_NAME.test(lastSegment(field));
    const text = unknownSecret
      ? "Unknown field; secrets are not allowed in piship.yaml"
      : reason;
    const where = position
      ? `line ${position.line}, column ${position.column}`
      : undefined;
    // Diagnostic redaction treats `<secret-like key>: <word>` as a secret
    // assignment; keep such field paths readable by not following them with
    // a colon. Values are never part of the message.
    super(
      REDACTION_KEY.test(field)
        ? `${kind} at ${field} (${where ? `${where}; ` : ""}${text})`
        : `${kind} at ${field}${where ? ` (${where})` : ""}: ${text}`,
    );
    this.name = "ManifestError";
  }
  /** This problem with a source position (and optionally a better reason). */
  locatedAt(position: SourcePosition, reason = this.reason): ManifestError {
    return new ManifestError(this.kind, this.field, reason, position);
  }
  /** One error for several: the first one's kind and field, every message. */
  static combine(errors: readonly ManifestError[]): ManifestError {
    const [first] = errors;
    if (!first) throw new Error("combine needs at least one error");
    if (errors.length === 1) return first;
    const combined = new ManifestError(
      first.kind,
      first.field,
      first.reason,
      first.position,
    );
    combined.message = `Manifest has ${errors.length} problems:\n${errors
      .map((error) => `  - ${error.message}`)
      .join("\n")}`;
    combined.errors = errors;
    return combined;
  }
}
/** Field names that indicate secret material; never valid manifest keys. */
const SECRET_FIELD_NAME =
  /(secret|token|password|passwd|api_?key|private_?key|client_?key|bearer|authorization|cookie|credentials)/i;
/**
 * Key endings that diagnostic redaction treats as a secret assignment or a
 * credential header (`redact` in `@piship/contracts`).
 */
const REDACTION_KEY =
  /(?:token|secret|passw(?:or)?d|credentials?|(?:api|access|secret|private)[-_]?key|authorization|cookie)"?$/i;
function lastSegment(field: string): string {
  return field.slice(
    Math.max(field.lastIndexOf("."), field.lastIndexOf("]")) + 1,
  );
}
/**
 * Common secret value shapes. A static manifest never carries these, so every
 * string scalar (and mapping key) is checked. Equivalent to the MCP value
 * check in governance/fields, narrowed so ordinary names stay valid: the
 * `Bearer`/`Basic` prefix needs a credential-shaped token ("Basic Agent" is
 * display text), and an `sk-` key needs 16+ characters including a digit
 * (`sk-helper` is a distribution id).
 */
export const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  /^(?:bearer|basic)\s+(?=\S*[0-9+/=._~-])[A-Za-z0-9._~+/=-]{8,}\s*$/i,
  /\bsk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{16,}/,
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\./,
  /\b(?:ghp|gho|ghs|ghu|github_pat|glpat|xox[abpsr])[-_][A-Za-z0-9_-]{8,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
export function looksLikeSecretValue(value: string): boolean {
  return SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}
/**
 * Reject secret-looking values anywhere in a manifest document. The error
 * names the field path and never echoes the value.
 */
export function assertNoSecretValues(value: unknown, path = "manifest"): void {
  if (typeof value === "string") {
    if (looksLikeSecretValue(value))
      throw new ManifestError(
        "invalid field",
        path,
        "Value looks like secret material. Secrets are never declared in piship.yaml",
      );
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertNoSecretValues(item, `${path}[${index}]`);
    });
    return;
  }
  if (isRecord(value))
    for (const [key, item] of Object.entries(value)) {
      if (looksLikeSecretValue(key))
        throw new ManifestError(
          "invalid field",
          path,
          "A key looks like secret material. Secrets are never declared in piship.yaml",
        );
      assertNoSecretValues(item, path === "manifest" ? key : `${path}.${key}`);
    }
}
export function parseManifestHeader(
  value: unknown,
): ManifestHeader | ValidationDiagnostic {
  if (!isRecord(value) || !("schema" in value))
    return { path: "schema", message: "Missing manifest schema" };
  if (!(SUPPORTED_SCHEMAS as readonly unknown[]).includes(value.schema))
    return {
      path: "schema",
      message: schemaProblem(value.schema),
    };
  return { schema: value.schema as PishipSchemaVersion };
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function record(
  value: unknown,
  path: string,
  allowed: readonly string[],
  /** Where to put unknown fields; without it the first is thrown. */
  problems?: ManifestError[],
): Record<string, unknown> {
  if (!isRecord(value))
    throw new ManifestError(
      "invalid field",
      path,
      value === undefined
        ? "Expected an object; this required section is missing"
        : "Expected an object",
    );
  const unknown = Object.keys(value)
    .filter((key) => !allowed.includes(key))
    .map(
      (key) =>
        new ManifestError(
          "invalid field",
          `${path}.${key}`,
          unknownFieldMessage(key, allowed),
        ),
    );
  if (problems) problems.push(...unknown);
  else if (unknown.length) throw ManifestError.combine(unknown);
  return value;
}
function string(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "")
    throw new ManifestError(
      "invalid field",
      path,
      "Expected a non-empty string",
    );
  if (/\$\{/.test(value))
    throw new ManifestError(
      "invalid field",
      path,
      "Environment substitutions are not allowed in this alpha manifest",
    );
  return value;
}
function name(value: unknown, path: string): string {
  const result = string(value, path);
  if (
    !/^[a-z][a-z0-9-]*$/.test(result) ||
    result.endsWith("-") ||
    result.includes("--")
  )
    throw new ManifestError(
      "unsafe path/name",
      path,
      "Use lowercase letters, digits, and single hyphens; start with a letter",
    );
  return result;
}
function displayText(value: unknown, path: string): string {
  const result = string(value, path);
  if (
    result.length > 120 ||
    [...result].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new ManifestError(
      "invalid field",
      path,
      "Use a single display line of at most 120 characters",
    );
  return result;
}
function paths(value: unknown, path: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value))
    throw new ManifestError(
      "invalid field",
      path,
      "Expected a list of relative paths",
    );
  return value.map((entry, index) => {
    const item = string(entry, `${path}[${index}]`);
    const segments = item.slice(2).split("/");
    if (
      !item.startsWith("./") ||
      item.includes("\\") ||
      segments.some(
        (segment) => !segment || segment === "." || segment === "..",
      )
    )
      throw new ManifestError(
        "unsafe path/name",
        `${path}[${index}]`,
        "Use a ./ relative path without traversal",
      );
    return item;
  });
}
const V1ALPHA2_KEYS = [
  "identity",
  "credential",
  "inference",
  "models",
  "config",
  "network",
  "variables",
];
/**
 * The message of a schema that is not supported: a `piship/v<n>` string
 * names the current schema, so a manifest written for a later or earlier
 * major says what to write instead.
 */
function schemaProblem(schema: unknown): string {
  const accepted = `Accepted: ${SUPPORTED_SCHEMAS.join(", ")}`;
  if (schema === undefined)
    return `Missing schema; start the manifest with schema: ${LATEST_SCHEMA}`;
  if (typeof schema === "string" && /^piship\/v\d/.test(schema))
    return `Unsupported schema ${schema}; the current schema is ${LATEST_SCHEMA}, so write schema: ${LATEST_SCHEMA}. ${accepted}`;
  return `Expected schema: ${LATEST_SCHEMA}. ${accepted}`;
}
/** The exact Pi version a manifest may state; omit it for the pinned Pi. */
function piVersion(value: unknown): string {
  const pi = string(value, "runtime.pi");
  if (!/^\d+\.\d+\.\d+$/.test(pi))
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      "Expected an exact Pi version such as 1.2.3; or remove the field to use the Pi version this PiShip pins",
    );
  return pi;
}
export function parseManifest(value: unknown): Manifest {
  assertNoSecretValues(value);
  const schema = isRecord(value) ? value.schema : undefined;
  if (!(SUPPORTED_SCHEMAS as readonly unknown[]).includes(schema)) {
    if (!isRecord(value))
      throw new ManifestError(
        "invalid field",
        "manifest",
        "Expected an object",
      );
    throw new ManifestError("schema mismatch", "schema", schemaProblem(schema));
  }
  // v1 carries the v1alpha6 semantics, so every v6 rule holds from v1alpha6 on.
  const v6 = schema === PISHIP_SCHEMA_V1ALPHA6 || schema === PISHIP_SCHEMA_V1;
  const v5 = schema === PISHIP_SCHEMA_V1ALPHA5 || v6;
  const v4 = schema === PISHIP_SCHEMA_V1ALPHA4 || v5;
  const v3 = schema === PISHIP_SCHEMA_V1ALPHA3 || v4;
  const v2 = schema === PISHIP_SCHEMA_V1ALPHA2 || v3;
  // Every problem the structure lets it find, reported together: a field
  // that fails is skipped, the others are still checked.
  const problems: ManifestError[] = [];
  const attempt = <T>(run: () => T): T | undefined => {
    try {
      return run();
    } catch (error) {
      if (error instanceof ManifestError) problems.push(...error.errors);
      else if (error instanceof AccessFieldError)
        for (const item of [error, ...error.more])
          problems.push(new ManifestError(item.kind, item.field, item.message));
      else throw error;
      return undefined;
    }
  };
  const root = attempt(() =>
    record(
      value,
      "manifest",
      [
        "schema",
        "app",
        "runtime",
        "deployment",
        "resources",
        ...(v2 ? V1ALPHA2_KEYS : []),
        ...(v3 ? GOVERNANCE_KEYS : []),
        ...(v4 ? LIFECYCLE_KEYS : []),
        ...(v6 ? [...V1ALPHA6_GOVERNANCE_KEYS, ...DATA_KEYS] : []),
      ],
      problems,
    ),
  );
  if (!root) throw ManifestError.combine(problems);
  const app = attempt(() =>
    record(
      root.app,
      "app",
      ["id", "name", "command", "version", "banner", "theme"],
      problems,
    ),
  );
  const runtime = attempt(() =>
    root.runtime === undefined
      ? {}
      : record(
          root.runtime,
          "runtime",
          v6
            ? ["pi", "tools", "cacheWarming", "searchTools", "verifyAtLaunch"]
            : ["pi"],
          problems,
        ),
  );
  const deployment = attempt(() =>
    record(root.deployment, "deployment", ["mode"], problems),
  );
  const resources = v3
    ? {}
    : attempt(() =>
        record(
          root.resources ?? {},
          "resources",
          ["instructions", "skills", "extensions", "prompts", "themes"],
          problems,
        ),
      );
  const mode = deployment?.mode;
  let modeKnown = false;
  if (deployment) {
    if (mode === "managed" && !v2)
      problems.push(
        new ManifestError(
          "invalid field",
          "deployment.mode",
          "managed requires schema piship/v1alpha2, piship/v1alpha3, piship/v1alpha4, piship/v1alpha5, piship/v1alpha6, or piship/v1 with identity, credential, inference, and models sections; piship/v1alpha1 is the personal alpha (see docs/manifest.md)",
        ),
      );
    else if (mode !== "personal" && mode !== "managed")
      problems.push(
        new ManifestError(
          "invalid field",
          "deployment.mode",
          v2 ? "Expected personal or managed" : "Expected personal",
        ),
      );
    else modeKnown = true;
  }
  let access: AccessManifest | undefined;
  let governance: GovernanceManifest | undefined;
  let lifecycle: LifecycleManifest | undefined;
  let v6Runtime: Pick<
    Manifest["runtime"],
    "tools" | "cacheWarming" | "searchTools" | "verifyAtLaunch"
  > = {};
  let data: DataManifest | undefined;
  // The access, governance, lifecycle and data sections depend on each other
  // and on the mode, and each parser stops at its first problem.
  if (v2 && modeKnown && runtime)
    attempt(() => {
      const deploymentMode = mode as DeploymentMode;
      if (v3) {
        const variables = parseVariables(root.variables);
        governance = parseGovernance(
          root,
          deploymentMode,
          variables,
          { id: name(app?.id, "app.id") },
          v5,
          v6,
        );
        if (v4) lifecycle = parseLifecycle(root, variables, v5, v6);
        if (v6) {
          let verifyAtLaunch: boolean | undefined;
          if (runtime.verifyAtLaunch !== undefined) {
            if (typeof runtime.verifyAtLaunch !== "boolean")
              throw new ManifestError(
                "invalid field",
                "runtime.verifyAtLaunch",
                "Expected true or false",
              );
            verifyAtLaunch = runtime.verifyAtLaunch;
          }
          v6Runtime = {
            tools: parseRuntimeTools(runtime.tools),
            cacheWarming: parseCacheWarming(runtime.cacheWarming),
            ...(runtime.searchTools === undefined
              ? {}
              : { searchTools: parseSearchTools(runtime.searchTools) }),
            ...(verifyAtLaunch === undefined ? {} : { verifyAtLaunch }),
          };
          data = parseData(root.data);
        }
      }
      access = parseAccess(root, deploymentMode, { v6 });
      assertLaunchable({ mode: deploymentMode, access, governance });
    });
  const pi =
    runtime?.pi === undefined
      ? undefined
      : attempt(() => piVersion(runtime.pi));
  const appFields = app
    ? {
        id: attempt(() => name(app.id, "app.id")),
        name: attempt(() => displayText(app.name, "app.name")),
        command: attempt(() => name(app.command, "app.command")),
        version: attempt(() => {
          const version = string(app.version, "app.version");
          if (!/^[0-9]/.test(version) || validSemver(version) === null)
            throw new ManifestError(
              "invalid field",
              "app.version",
              "Expected a distribution semver version",
            );
          return version;
        }),
        banner:
          app.banner === undefined
            ? undefined
            : attempt(() => displayText(app.banner, "app.banner")),
        theme:
          app.theme === undefined
            ? undefined
            : attempt(() => name(app.theme, "app.theme")),
      }
    : undefined;
  const declared = resources
    ? (["instructions", "skills", "extensions", "prompts", "themes"] as const)
    : [];
  const flat = Object.fromEntries(
    declared.map((kind) => [
      kind,
      attempt(() => paths(resources?.[kind], `resources.${kind}`)),
    ]),
  ) as Partial<Record<(typeof declared)[number], string[]>>;
  // One problem can surface twice (the app id is read by the governance
  // parser and again here); report it once.
  const seen = new Set<string>();
  const unique = problems.filter((problem) => {
    if (seen.has(problem.message)) return false;
    seen.add(problem.message);
    return true;
  });
  if (unique.length) throw ManifestError.combine(unique);
  const fields = appFields as NonNullable<typeof appFields>;
  return {
    schema:
      schema === PISHIP_SCHEMA_V1
        ? PISHIP_SCHEMA_V1
        : v6
          ? PISHIP_SCHEMA_V1ALPHA6
          : v5
            ? PISHIP_SCHEMA_V1ALPHA5
            : v4
              ? PISHIP_SCHEMA_V1ALPHA4
              : v3
                ? PISHIP_SCHEMA_V1ALPHA3
                : v2
                  ? PISHIP_SCHEMA_V1ALPHA2
                  : PISHIP_SCHEMA_VERSION,
    app: {
      id: fields.id as string,
      name: fields.name as string,
      command: fields.command as string,
      version: fields.version as string,
      ...(fields.banner === undefined ? {} : { banner: fields.banner }),
      ...(fields.theme === undefined ? {} : { theme: fields.theme }),
    },
    runtime: { ...(pi === undefined ? {} : { pi }), ...v6Runtime },
    deployment: { mode: mode as DeploymentMode },
    resources: governance
      ? flatResources(governance)
      : {
          instructions: flat.instructions ?? [],
          skills: flat.skills ?? [],
          extensions: flat.extensions ?? [],
          prompts: flat.prompts ?? [],
          themes: flat.themes ?? [],
        },
    ...(access ? { access } : {}),
    ...(governance ? { governance } : {}),
    ...(lifecycle ? { lifecycle } : {}),
    ...(data ? { data } : {}),
  };
}
/** Declared paths per kind in certified, company, user order. */
function flatResources(governance: GovernanceManifest): Manifest["resources"] {
  const of = (kind: string) =>
    governance.resources.declared
      .filter((entry) => entry.kind === kind)
      .map((entry) => entry.path);
  return {
    instructions: of("instructions"),
    skills: of("skills"),
    extensions: of("extensions"),
    prompts: of("prompts"),
    themes: of("themes"),
  };
}
export function readManifest(path: string): Manifest {
  return parseManifestSource(readManifestSource(path), path);
}
/**
 * Parse manifest text. A problem carries the line and column of its field,
 * and every YAML syntax error is reported, not only the first.
 */
function parseManifestSource(source: string, label: string): Manifest {
  const lineCounter = new LineCounter();
  const document = parseDocument(source, { uniqueKeys: true, lineCounter });
  yamlProblems(document, label);
  try {
    return parseManifest(document.toJS() as unknown);
  } catch (error) {
    throw error instanceof ManifestError
      ? locateErrors(error, document, lineCounter)
      : error;
  }
}
/** Throw every syntax error of a YAML document as one ManifestError. */
function yamlProblems(document: Document, label: string): void {
  if (!document.errors.length) return;
  throw ManifestError.combine(
    document.errors.map((item) => {
      const problem = new ManifestError(
        "YAML parse failure",
        label,
        item.message,
      );
      const start = item.linePos?.[0];
      if (start) problem.position = { line: start.line, column: start.col };
      return problem;
    }),
  );
}
/**
 * The text of a manifest file. A missing file is a ManifestError; a
 * directory or another file system failure is a PiShip error that names the
 * path and what to pass instead.
 */
export function readManifestSource(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      throw new ManifestError(
        "file not found",
        path,
        "Manifest does not exist",
      );
    throw (
      systemError(
        error,
        path,
        (error as NodeJS.ErrnoException).code === "EISDIR"
          ? `Pass the manifest file, such as ${join(path, "piship.yaml")}`
          : undefined,
      ) ?? error
    );
  }
}
/** Read and parse YAML without schema validation (used by migration). */
export function readManifestDocument(path: string): unknown {
  const document = parseDocument(readManifestSource(path), {
    uniqueKeys: true,
  });
  yamlProblems(document, path);
  return document.toJS() as unknown;
}

export interface MigrationPlan {
  readonly from: PishipSchemaVersion;
  readonly to: PishipSchemaVersion;
  /** Every change, one warning line each. */
  readonly changes: readonly string[];
  /**
   * The changes that alter an effective decision; `piship migrate --check`
   * fails when there is any.
   */
  readonly effective: readonly string[];
  /**
   * Configuration left as written because only the owner can decide it;
   * `piship migrate --check` reports "requires review" when there is any.
   */
  readonly review: readonly string[];
  readonly source: string;
}

/**
 * Versioned, step-wise migration through the registered steps. The default
 * target is the latest schema; pass `to` to stop at an earlier one (for
 * example piship/v1alpha2). Each step is deterministic, never broadens what
 * the distribution allows, and keeps comments.
 */
export function migrateManifestSource(
  source: string,
  to: PishipSchemaVersion = LATEST_SCHEMA,
): MigrationPlan {
  const lineCounter = new LineCounter();
  const document = parseDocument(source, { uniqueKeys: true, lineCounter });
  yamlProblems(document, "manifest");
  const current = (() => {
    try {
      return parseManifest(document.toJS() as unknown);
    } catch (error) {
      throw error instanceof ManifestError
        ? locateErrors(error, document, lineCounter)
        : error;
    }
  })();
  const from = current.schema;
  if (SUPPORTED_SCHEMAS.indexOf(from) > SUPPORTED_SCHEMAS.indexOf(to))
    throw new ManifestError(
      "schema mismatch",
      "schema",
      `Cannot migrate ${from} back to ${to}; downgrades are not supported`,
    );
  if (from === to)
    return { from, to, changes: [], effective: [], review: [], source };
  const changes: string[] = [];
  const effective: string[] = [];
  const review: string[] = [];
  const context = {
    mode: current.deployment.mode,
    parse: () => parseManifest(document.toJS() as unknown),
  };
  for (const step of migrationPath(from, to)) {
    const result = step.migrate(document, context);
    changes.push(...result.changes);
    effective.push(...result.effective);
    review.push(...(result.review ?? []));
  }
  const migrated = document.toString();
  parseManifest(parseDocument(migrated).toJS() as unknown);
  changes.push("Regenerate piship.lock with piship lock, then rebuild");
  return { from, to, changes, effective, review, source: migrated };
}

/**
 * The outcome of `piship migrate --check`. `migratable`: the migration
 * changes no effective decision and leaves nothing for the owner to decide.
 * `requires review`: it can run, but an effective decision changes or a value
 * needs the owner's judgment, and it lists each. `cannot migrate`: a step
 * refused the manifest, or it does not parse, and `reason` says why.
 */
export type MigrationVerdict =
  | "migratable"
  | "requires review"
  | "cannot migrate";

export interface MigrationCheck {
  readonly verdict: MigrationVerdict;
  readonly from?: PishipSchemaVersion;
  readonly to: PishipSchemaVersion;
  readonly changes: readonly string[];
  /** Effective changes first, then the owner decisions. */
  readonly review: readonly string[];
  readonly reason?: string;
}

/**
 * Classify a migration without producing or writing anything: it takes the
 * manifest text and returns a verdict. A manifest that is already `to`
 * is `migratable` with no changes.
 */
export function checkManifestMigration(
  source: string,
  to: PishipSchemaVersion = LATEST_SCHEMA,
): MigrationCheck {
  try {
    const plan = migrateManifestSource(source, to);
    const review = [...plan.effective, ...plan.review];
    return {
      verdict: review.length ? "requires review" : "migratable",
      from: plan.from,
      to,
      changes: plan.changes,
      review,
    };
  } catch (error) {
    return {
      verdict: "cannot migrate",
      to,
      changes: [],
      review: [],
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}
