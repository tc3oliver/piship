/**
 * Runtime references: `${NAME}` may appear only in allowlisted non-secret
 * endpoint, identifier, and path fields. The manifest and lock keep the
 * unresolved template, so a lock is not machine-specific; values are resolved
 * from the launch environment at runtime and never written back.
 */
export const RUNTIME_REFERENCE_FIELDS = [
  "identity.oidc.issuer",
  "identity.oidc.clientId",
  "identity.oidc.audience",
  "credential.broker.endpoint",
  "credential.broker.revokeEndpoint",
  "inference.baseUrl",
  "network.tls.additionalCA",
] as const;
export type RuntimeReferenceField = (typeof RUNTIME_REFERENCE_FIELDS)[number];

const REFERENCE = /\$\{([^}]*)\}/g;
const VARIABLE_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
/** Names that indicate secret material can never be runtime references. */
const SECRET_NAME =
  /(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|SESSION)/;

export interface ReferenceProblem {
  readonly message: string;
}

export function referencedVariables(value: string): string[] {
  return [...value.matchAll(REFERENCE)].map((match) => match[1] ?? "");
}

export function hasRuntimeReference(value: string): boolean {
  return /\$\{/.test(value);
}

export function checkVariableName(name: string): ReferenceProblem | undefined {
  if (!VARIABLE_NAME.test(name))
    return {
      message: `Runtime variable ${JSON.stringify(name)} must use uppercase letters, digits, and underscores`,
    };
  if (SECRET_NAME.test(name))
    return {
      message: `Runtime variable ${name} looks like secret material; secrets are never interpolated into the manifest`,
    };
  return undefined;
}

/** Validate template syntax without resolving it. */
export function checkTemplate(
  value: string,
  declared: readonly string[],
): ReferenceProblem | undefined {
  const stripped = value.replace(REFERENCE, "");
  if (stripped.includes(`\${`) || stripped.includes("$"))
    return { message: `Malformed runtime reference; use \${NAME}` };
  for (const name of referencedVariables(value)) {
    const problem = checkVariableName(name);
    if (problem) return problem;
    if (!declared.includes(name))
      return {
        message: `Runtime variable ${name} is not declared in variables`,
      };
  }
  return undefined;
}

export class RuntimeReferenceError extends Error {
  constructor(
    readonly field: string,
    readonly variable: string | undefined,
    message: string,
  ) {
    super(message);
    this.name = "RuntimeReferenceError";
  }
}

/**
 * Resolve a template from an environment. Missing or empty variables fail;
 * resolved values may not contain a further `${...}` (no recursive expansion)
 * or control characters.
 */
export function resolveTemplate(
  field: string,
  value: string,
  declared: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
): string {
  const problem = checkTemplate(value, declared);
  if (problem)
    throw new RuntimeReferenceError(field, undefined, problem.message);
  return value.replace(REFERENCE, (_match, name: string) => {
    const resolved = env[name];
    if (resolved === undefined || resolved.trim() === "")
      throw new RuntimeReferenceError(
        field,
        name,
        `Runtime variable ${name} for ${field} is not set`,
      );
    if (
      resolved.includes(`\${`) ||
      [...resolved].some((character) => {
        const code = character.charCodeAt(0);
        return code < 32 || code === 127;
      })
    )
      throw new RuntimeReferenceError(
        field,
        name,
        `Runtime variable ${name} for ${field} contains a reference or control character`,
      );
    return resolved.trim();
  });
}
