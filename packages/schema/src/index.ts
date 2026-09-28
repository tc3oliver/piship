import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";
import { valid as validSemver } from "semver";
import {
  AccessFieldError,
  parseAccess,
  parseVariables,
  type AccessManifest,
  type DeploymentMode,
} from "./access.js";
import type { GovernanceManifest } from "./governance.js";
import {
  GOVERNANCE_KEYS,
  governanceReferences,
  parseGovernance,
} from "./governance-parse.js";
import {
  DEFAULT_PACKAGE_SOURCES,
  DEFAULT_RELEASE_TARGETS,
  LIFECYCLE_KEYS,
  lifecycleReferences,
  parseLifecycle,
  type LifecycleManifest,
} from "./lifecycle.js";

export * from "./access.js";
export * from "./variables.js";
export * from "./governance.js";
export * from "./governance-parse.js";
export * from "./lifecycle.js";

/** The v0.1 personal alpha schema; still accepted for personal pi-native distributions. */
export const PISHIP_SCHEMA_VERSION = "piship/v1alpha1" as const;
/** The v0.2 alpha schema with managed and personal access configuration. */
export const PISHIP_SCHEMA_V1ALPHA2 = "piship/v1alpha2" as const;
/** The v0.3 alpha schema: v1alpha2 access plus governance sections. */
export const PISHIP_SCHEMA_V1ALPHA3 = "piship/v1alpha3" as const;
/** The v0.4 alpha schema: v1alpha3 plus update channels and release policy. */
export const PISHIP_SCHEMA_V1ALPHA4 = "piship/v1alpha4" as const;
export const SUPPORTED_SCHEMAS = [
  PISHIP_SCHEMA_VERSION,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
] as const;
/** The newest schema; `migrateManifestSource` targets it by default. */
export const LATEST_SCHEMA = PISHIP_SCHEMA_V1ALPHA4;
export type PishipSchemaVersion = (typeof SUPPORTED_SCHEMAS)[number];
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
  readonly runtime: { readonly pi: string };
  readonly deployment: { readonly mode: DeploymentMode };
  readonly resources: {
    readonly instructions: readonly string[];
    readonly skills: readonly string[];
    readonly extensions: readonly string[];
    readonly prompts: readonly string[];
    readonly themes: readonly string[];
  };
  /** Present for piship/v1alpha2, piship/v1alpha3, and piship/v1alpha4 manifests. */
  readonly access?: AccessManifest;
  /** Present for piship/v1alpha3 and piship/v1alpha4 manifests. */
  readonly governance?: GovernanceManifest;
  /** Present exactly for piship/v1alpha4 manifests (release defaults applied). */
  readonly lifecycle?: LifecycleManifest;
}
export class ManifestError extends Error {
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
    message: string,
  ) {
    const unknownSecret =
      message === "Unknown field" && SECRET_FIELD_NAME.test(lastSegment(field));
    const text = unknownSecret
      ? "Unknown field; secrets are not allowed in piship.yaml"
      : message;
    // Diagnostic redaction treats `<secret-like key>: <word>` as a secret
    // assignment; keep such field paths readable by not following them with
    // a colon. Values are never part of the message.
    super(
      REDACTION_KEY.test(field)
        ? `${kind} at ${field} (${text})`
        : `${kind} at ${field}: ${text}`,
    );
    this.name = "ManifestError";
  }
}
/** Field names that indicate secret material; never valid manifest keys. */
const SECRET_FIELD_NAME =
  /(secret|token|password|passwd|api_?key|private_?key|client_?key|bearer|authorization|cookie|credentials)/i;
/** Key endings that diagnostic redaction treats as a secret assignment. */
const REDACTION_KEY =
  /(?:access_token|refresh_token|id_token|credential|api_?key|client_secret|password|secret)"?$/i;
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
      message: `Expected ${SUPPORTED_SCHEMAS.join(" or ")}`,
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
): Record<string, unknown> {
  if (!isRecord(value))
    throw new ManifestError("invalid field", path, "Expected an object");
  for (const key of Object.keys(value))
    if (!allowed.includes(key))
      throw new ManifestError(
        "invalid field",
        `${path}.${key}`,
        "Unknown field",
      );
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
    throw new ManifestError(
      "schema mismatch",
      "schema",
      `Expected ${SUPPORTED_SCHEMAS.join(" or ")}`,
    );
  }
  const v4 = schema === PISHIP_SCHEMA_V1ALPHA4;
  const v3 = schema === PISHIP_SCHEMA_V1ALPHA3 || v4;
  const v2 = schema === PISHIP_SCHEMA_V1ALPHA2 || v3;
  const root = record(value, "manifest", [
    "schema",
    "app",
    "runtime",
    "deployment",
    "resources",
    ...(v2 ? V1ALPHA2_KEYS : []),
    ...(v3 ? GOVERNANCE_KEYS : []),
    ...(v4 ? LIFECYCLE_KEYS : []),
  ]);
  const app = record(root.app, "app", [
    "id",
    "name",
    "command",
    "version",
    "banner",
    "theme",
  ]);
  const runtime = record(root.runtime, "runtime", ["pi"]);
  const deployment = record(root.deployment, "deployment", ["mode"]);
  const resources = v3
    ? {}
    : record(root.resources ?? {}, "resources", [
        "instructions",
        "skills",
        "extensions",
        "prompts",
        "themes",
      ]);
  const mode = deployment.mode;
  if (mode === "managed" && !v2)
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      "managed requires schema piship/v1alpha2, piship/v1alpha3, or piship/v1alpha4 with identity, credential, inference, and models sections; piship/v1alpha1 is the personal alpha (see docs/manifest.md)",
    );
  if (mode !== "personal" && mode !== "managed")
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      v2 ? "Expected personal or managed" : "Expected personal",
    );
  let access: AccessManifest | undefined;
  let governance: GovernanceManifest | undefined;
  let lifecycle: LifecycleManifest | undefined;
  if (v2)
    try {
      if (v3) {
        const variables = parseVariables(root.variables);
        governance = parseGovernance(root, mode, variables, {
          id: name(app.id, "app.id"),
        });
        if (v4) lifecycle = parseLifecycle(root, variables);
      }
      access = parseAccess(root, mode, [
        ...(governance ? governanceReferences(governance) : []),
        ...(lifecycle ? lifecycleReferences(lifecycle) : []),
      ]);
    } catch (error) {
      if (error instanceof AccessFieldError)
        throw new ManifestError(error.kind, error.field, error.message);
      throw error;
    }
  const pi = string(runtime.pi, "runtime.pi");
  if (!/^\d+\.\d+\.\d+$/.test(pi))
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      "Expected an exact Pi version",
    );
  return {
    schema: v4
      ? PISHIP_SCHEMA_V1ALPHA4
      : v3
        ? PISHIP_SCHEMA_V1ALPHA3
        : v2
          ? PISHIP_SCHEMA_V1ALPHA2
          : PISHIP_SCHEMA_VERSION,
    app: {
      id: name(app.id, "app.id"),
      name: displayText(app.name, "app.name"),
      command: name(app.command, "app.command"),
      version: (() => {
        const version = string(app.version, "app.version");
        if (!/^[0-9]/.test(version) || validSemver(version) === null)
          throw new ManifestError(
            "invalid field",
            "app.version",
            "Expected a distribution semver version",
          );
        return version;
      })(),
      ...(app.banner === undefined
        ? {}
        : { banner: displayText(app.banner, "app.banner") }),
      ...(app.theme === undefined
        ? {}
        : { theme: name(app.theme, "app.theme") }),
    },
    runtime: { pi },
    deployment: { mode },
    resources: governance
      ? flatResources(governance)
      : {
          instructions: paths(resources.instructions, "resources.instructions"),
          skills: paths(resources.skills, "resources.skills"),
          extensions: paths(resources.extensions, "resources.extensions"),
          prompts: paths(resources.prompts, "resources.prompts"),
          themes: paths(resources.themes, "resources.themes"),
        },
    ...(access ? { access } : {}),
    ...(governance ? { governance } : {}),
    ...(lifecycle ? { lifecycle } : {}),
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
  return parseManifest(readManifestDocument(path));
}
/** Read and parse YAML without schema validation (used by migration). */
export function readManifestDocument(path: string): unknown {
  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      throw new ManifestError(
        "file not found",
        path,
        "Manifest does not exist",
      );
    throw error;
  }
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length)
    throw new ManifestError(
      "YAML parse failure",
      path,
      document.errors[0]?.message ?? "Invalid YAML",
    );
  return document.toJS() as unknown;
}

export interface MigrationPlan {
  readonly from: PishipSchemaVersion;
  readonly to: PishipSchemaVersion;
  readonly changes: readonly string[];
  readonly source: string;
}
type YamlDocument = ReturnType<typeof parseDocument>;
const SCHEMA_ORDER: readonly PishipSchemaVersion[] = SUPPORTED_SCHEMAS;
const RESOURCE_KIND_KEYS = [
  "instructions",
  "skills",
  "extensions",
  "prompts",
  "themes",
] as const;

/**
 * v1alpha1 -> v1alpha2: an equivalent personal profile with no identity,
 * explicit Pi-native credential delegation, and Pi-native inference.
 */
function migrateToV1alpha2(document: YamlDocument): string[] {
  document.set("schema", PISHIP_SCHEMA_V1ALPHA2);
  document.set("identity", document.createNode({ mode: "none" }));
  document.set("credential", document.createNode({ provider: "pi-native" }));
  document.set("inference", document.createNode({ provider: "pi-native" }));
  return [
    "schema: piship/v1alpha1 -> piship/v1alpha2",
    "identity.mode: none (unchanged behavior: no enterprise identity)",
    "credential.provider: pi-native (explicit delegation to Pi auth in isolated state)",
    "inference.provider: pi-native (Pi model catalog, as in v0.1)",
  ];
}

/**
 * v1alpha2 -> v1alpha3: flat resource lists gain a trust class, and the new
 * governance sections are written with values that keep v1alpha2 behavior
 * (no tool policy, no sandbox, no audit, no MCP).
 */
function migrateToV1alpha3(
  document: YamlDocument,
  mode: DeploymentMode,
): string[] {
  const trust = mode === "managed" ? "company" : "user";
  const changes = ["schema: piship/v1alpha2 -> piship/v1alpha3"];
  document.set("schema", PISHIP_SCHEMA_V1ALPHA3);
  for (const kind of RESOURCE_KIND_KEYS) {
    const node = document.getIn(["resources", kind], true);
    if (node === undefined || node === null) continue;
    document.setIn(["resources", kind], document.createNode({ [trust]: node }));
    changes.push(
      `resources.${kind}: flat list -> ${trust} trust class (${mode} distribution resources)`,
    );
  }
  // v1alpha2 never loaded project resources, not even themes (its resource
  // loader ran with noThemes against the distribution directory); only tool
  // access to project files.
  const closed = {
    passiveContext: "deny",
    instructions: "deny",
    skills: "deny",
    agents: "deny",
    hooks: "deny",
    extensions: "deny",
    mcp: "deny",
    providers: "deny",
  };
  document.set(
    "policy",
    document.createNode({
      default: "allow",
      projectTrust: {
        company: closed,
        external: closed,
        unknown: closed,
      },
    }),
  );
  document.set("sandbox", document.createNode({ required: false }));
  document.set("audit", document.createNode({ enabled: false }));
  document.set("mcp", document.createNode({ mode: "off" }));
  changes.push(
    "policy.default: allow (v1alpha2 had no tool policy)",
    "policy.projectTrust: project files stay tool-readable; project instructions, skills, extensions, themes, and MCP stay unloaded (as in v1alpha2)",
    "sandbox.required: false (v1alpha2 had no OS sandbox)",
    "audit.enabled: false (v1alpha2 had no audit log)",
    "mcp.mode: off (v1alpha2 had no MCP servers)",
    `Review the new governance defaults for ${mode} mode: resource, provider, and project trust (policy.resourceTrust, policy.providerTrust, policy.projectTrust) and capabilities now apply`,
  );
  return changes;
}

/**
 * v1alpha3 -> v1alpha4: adds the required update channel section with no
 * trust keys and no source, so updates stay disabled; release policy defaults.
 */
function migrateToV1alpha4(document: YamlDocument): string[] {
  document.set("schema", PISHIP_SCHEMA_V1ALPHA4);
  document.set(
    "updates",
    document.createNode({
      channel: "stable",
      channels: ["stable"],
      rollback: true,
    }),
  );
  return [
    "schema: piship/v1alpha3 -> piship/v1alpha4",
    "updates.channel: stable, updates.channels: [stable], updates.rollback: true",
    "Updates stay disabled until updates.trust.keys and updates.source are configured",
    `release defaults apply: targets ${DEFAULT_RELEASE_TARGETS.join(", ")}; package sources ${DEFAULT_PACKAGE_SOURCES.join(", ")}; vulnerabilities.failOn high`,
  ];
}

/**
 * Versioned, step-wise migration. The default target is the latest schema;
 * pass `to` to stop at an earlier one (for example piship/v1alpha2). Each
 * step is behavior-preserving and comments are kept.
 */
export function migrateManifestSource(
  source: string,
  to: PishipSchemaVersion = LATEST_SCHEMA,
): MigrationPlan {
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length)
    throw new ManifestError(
      "YAML parse failure",
      "manifest",
      document.errors[0]?.message ?? "Invalid YAML",
    );
  const current = parseManifest(document.toJS() as unknown);
  const from = current.schema;
  if (SCHEMA_ORDER.indexOf(from) > SCHEMA_ORDER.indexOf(to))
    throw new ManifestError(
      "schema mismatch",
      "schema",
      `Cannot migrate ${from} back to ${to}; downgrades are not supported`,
    );
  if (from === to) return { from, to, changes: [], source };
  const changes: string[] = [];
  const steps = (target: PishipSchemaVersion) =>
    SCHEMA_ORDER.indexOf(from) < SCHEMA_ORDER.indexOf(target) &&
    SCHEMA_ORDER.indexOf(target) <= SCHEMA_ORDER.indexOf(to);
  if (steps(PISHIP_SCHEMA_V1ALPHA2))
    changes.push(...migrateToV1alpha2(document));
  if (steps(PISHIP_SCHEMA_V1ALPHA3))
    changes.push(...migrateToV1alpha3(document, current.deployment.mode));
  if (steps(PISHIP_SCHEMA_V1ALPHA4))
    changes.push(...migrateToV1alpha4(document));
  const migrated = document.toString();
  parseManifest(parseDocument(migrated).toJS() as unknown);
  changes.push("Regenerate piship.lock with piship lock, then rebuild");
  return { from, to, changes, source: migrated };
}
