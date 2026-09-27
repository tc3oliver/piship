/** Experimental manifest version. The complete manifest is not implemented. */
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

/** Checks only the alpha schema marker; it does not validate a manifest. */
export function parseManifestHeader(
  value: unknown,
): ManifestHeader | ValidationDiagnostic {
  if (typeof value !== "object" || value === null || !("schema" in value)) {
    return { path: "schema", message: "Missing manifest schema" };
  }
  if (value.schema !== PISHIP_SCHEMA_VERSION) {
    return { path: "schema", message: `Expected ${PISHIP_SCHEMA_VERSION}` };
  }
  return { schema: PISHIP_SCHEMA_VERSION };
}
