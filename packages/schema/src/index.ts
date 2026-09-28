import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";
import { valid as validSemver } from "semver";

export const PISHIP_SCHEMA_VERSION = "piship/v1alpha1" as const;
export type PishipSchemaVersion = typeof PISHIP_SCHEMA_VERSION;
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
  readonly deployment: { readonly mode: "personal" };
  readonly resources: {
    readonly instructions: readonly string[];
    readonly skills: readonly string[];
    readonly extensions: readonly string[];
    readonly prompts: readonly string[];
    readonly themes: readonly string[];
  };
}
export class ManifestError extends Error {
  constructor(
    readonly kind:
      | "file not found"
      | "YAML parse failure"
      | "schema mismatch"
      | "invalid field"
      | "missing resource"
      | "unsafe path/name",
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
  if (value.schema !== PISHIP_SCHEMA_VERSION)
    return { path: "schema", message: `Expected ${PISHIP_SCHEMA_VERSION}` };
  return { schema: PISHIP_SCHEMA_VERSION };
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
export function parseManifest(value: unknown): Manifest {
  const root = record(value, "manifest", [
    "schema",
    "app",
    "runtime",
    "deployment",
    "resources",
  ]);
  if (root.schema !== PISHIP_SCHEMA_VERSION)
    throw new ManifestError(
      "schema mismatch",
      "schema",
      `Expected ${PISHIP_SCHEMA_VERSION}`,
    );
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
  if (mode === "managed")
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      "managed is not runnable in PiShip v1alpha1 yet. Managed access is planned for a later milestone",
    );
  if (mode !== "personal")
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      "Expected personal",
    );
  const pi = string(runtime.pi, "runtime.pi");
  if (!/^\d+\.\d+\.\d+$/.test(pi))
    throw new ManifestError(
      "invalid field",
      "runtime.pi",
      "Expected an exact Pi version",
    );
  return {
    schema: PISHIP_SCHEMA_VERSION,
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
  };
}
export function readManifest(path: string): Manifest {
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
  return parseManifest(document.toJS() as unknown);
}
