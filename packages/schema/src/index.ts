import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";
import { valid as validSemver } from "semver";
import {
  AccessFieldError,
  parseAccess,
  type AccessManifest,
  type DeploymentMode,
} from "./access.js";

export * from "./access.js";
export * from "./variables.js";

/** The v0.1 personal alpha schema; still accepted for personal pi-native distributions. */
export const PISHIP_SCHEMA_VERSION = "piship/v1alpha1" as const;
/** The v0.2 alpha schema with managed and personal access configuration. */
export const PISHIP_SCHEMA_V1ALPHA2 = "piship/v1alpha2" as const;
export const SUPPORTED_SCHEMAS = [
  PISHIP_SCHEMA_VERSION,
  PISHIP_SCHEMA_V1ALPHA2,
] as const;
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
  /** Present only for piship/v1alpha2 manifests. */
  readonly access?: AccessManifest;
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
    super(`${kind} at ${field}: ${message}`);
    this.name = "ManifestError";
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
  const v2 = schema === PISHIP_SCHEMA_V1ALPHA2;
  const root = record(value, "manifest", [
    "schema",
    "app",
    "runtime",
    "deployment",
    "resources",
    ...(v2 ? V1ALPHA2_KEYS : []),
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
  const resources = record(root.resources ?? {}, "resources", [
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
      "managed requires schema piship/v1alpha2 with identity, credential, inference, and models sections; piship/v1alpha1 is the personal alpha (see docs/manifest.md)",
    );
  if (mode !== "personal" && mode !== "managed")
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      v2 ? "Expected personal or managed" : "Expected personal",
    );
  let access: AccessManifest | undefined;
  if (v2)
    try {
      access = parseAccess(root, mode);
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
    schema: v2 ? PISHIP_SCHEMA_V1ALPHA2 : PISHIP_SCHEMA_VERSION,
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
    resources: {
      instructions: paths(resources.instructions, "resources.instructions"),
      skills: paths(resources.skills, "resources.skills"),
      extensions: paths(resources.extensions, "resources.extensions"),
      prompts: paths(resources.prompts, "resources.prompts"),
      themes: paths(resources.themes, "resources.themes"),
    },
    ...(access ? { access } : {}),
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
/**
 * Versioned migration from the v0.1 personal alpha to piship/v1alpha2. The
 * migrated profile is behaviorally equivalent: no identity, explicit Pi-native
 * credential delegation, and Pi-native inference inside isolated state.
 */
export function migrateManifestSource(source: string): MigrationPlan {
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length)
    throw new ManifestError(
      "YAML parse failure",
      "manifest",
      document.errors[0]?.message ?? "Invalid YAML",
    );
  const current = parseManifest(document.toJS() as unknown);
  if (current.schema === PISHIP_SCHEMA_V1ALPHA2)
    return {
      from: current.schema,
      to: current.schema,
      changes: [],
      source,
    };
  document.set("schema", PISHIP_SCHEMA_V1ALPHA2);
  document.set("identity", document.createNode({ mode: "none" }));
  document.set("credential", document.createNode({ provider: "pi-native" }));
  document.set("inference", document.createNode({ provider: "pi-native" }));
  const migrated = document.toString();
  parseManifest(parseDocument(migrated).toJS() as unknown);
  return {
    from: PISHIP_SCHEMA_VERSION,
    to: PISHIP_SCHEMA_V1ALPHA2,
    changes: [
      "schema: piship/v1alpha1 -> piship/v1alpha2",
      "identity.mode: none (unchanged behavior: no enterprise identity)",
      "credential.provider: pi-native (explicit delegation to Pi auth in isolated state)",
      "inference.provider: pi-native (Pi model catalog, as in v0.1)",
      "Regenerate piship.lock with piship lock, then rebuild",
    ],
    source: migrated,
  };
}
