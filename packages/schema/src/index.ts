import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

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
  };
  readonly runtime: { readonly pi: string };
  readonly deployment: { readonly mode: "personal" | "managed" };
  readonly resources: {
    readonly instructions: readonly string[];
    readonly skills: readonly string[];
    readonly extensions: readonly string[];
    readonly prompts: readonly string[];
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
  if (
    /\$\{|(?:api[_-]?key|access[_-]?token|password|secret|credential)/i.test(
      value,
    )
  )
    throw new ManifestError(
      "invalid field",
      path,
      "Secret values and environment substitutions are not allowed in this alpha manifest",
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
  const app = record(root.app, "app", ["id", "name", "command"]);
  const runtime = record(root.runtime, "runtime", ["pi"]);
  const deployment = record(root.deployment, "deployment", ["mode"]);
  const resources = record(root.resources ?? {}, "resources", [
    "instructions",
    "skills",
    "extensions",
    "prompts",
  ]);
  const mode = deployment.mode;
  if (mode !== "personal" && mode !== "managed")
    throw new ManifestError(
      "invalid field",
      "deployment.mode",
      "Expected personal or managed",
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
      name: string(app.name, "app.name"),
      command: name(app.command, "app.command"),
    },
    runtime: { pi },
    deployment: { mode },
    resources: {
      instructions: paths(resources.instructions, "resources.instructions"),
      skills: paths(resources.skills, "resources.skills"),
      extensions: paths(resources.extensions, "resources.extensions"),
      prompts: paths(resources.prompts, "resources.prompts"),
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
