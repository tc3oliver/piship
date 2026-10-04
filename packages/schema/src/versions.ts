// Manifest schema versions. Kept apart from the parser so the migration
// registry can name them without importing the parser.

/** The v0.1 personal alpha schema; still accepted for personal pi-native distributions. */
export const PISHIP_SCHEMA_VERSION = "piship/v1alpha1" as const;
/** The v0.2 alpha schema with managed and personal access configuration. */
export const PISHIP_SCHEMA_V1ALPHA2 = "piship/v1alpha2" as const;
/** The v0.3 alpha schema: v1alpha2 access plus governance sections. */
export const PISHIP_SCHEMA_V1ALPHA3 = "piship/v1alpha3" as const;
/** The v0.4 alpha schema: v1alpha3 plus update channels and release policy. */
export const PISHIP_SCHEMA_V1ALPHA4 = "piship/v1alpha4" as const;
/**
 * The v0.8 alpha schema: v1alpha4 with `updates.trust.bootstrap` (a versioned
 * update root with root and channel roles) replacing `updates.trust.keys`.
 */
export const PISHIP_SCHEMA_V1ALPHA5 = "piship/v1alpha5" as const;
/**
 * The v0.9 alpha schema: v1alpha5 plus Pi packages and `packageTrust`, tool
 * exposure, Codemode and tool search, MCP server trust class and exposure,
 * model types and virtual models, cache warming, the data lifecycle and
 * session export, `policy.acknowledgeUnenforced`, and
 * `release.vulnerabilities.registry`.
 */
export const PISHIP_SCHEMA_V1ALPHA6 = "piship/v1alpha6" as const;
export const SUPPORTED_SCHEMAS = [
  PISHIP_SCHEMA_VERSION,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
] as const;
/** The newest schema; `migrateManifestSource` targets it by default. */
export const LATEST_SCHEMA = PISHIP_SCHEMA_V1ALPHA6;
export type PishipSchemaVersion = (typeof SUPPORTED_SCHEMAS)[number];

/** True when `schema` is `at` or a later schema. */
export function schemaAtLeast(
  schema: PishipSchemaVersion,
  at: PishipSchemaVersion,
): boolean {
  return SUPPORTED_SCHEMAS.indexOf(schema) >= SUPPORTED_SCHEMAS.indexOf(at);
}
