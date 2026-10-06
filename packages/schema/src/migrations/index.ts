// The manifest migration registry, keyed by (from, to). Each step moves one
// schema version forward; `migrateManifestSource` chains them. A later
// schema adds its step here with a fixture.
import {
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA2,
  PISHIP_SCHEMA_V1ALPHA3,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  PISHIP_SCHEMA_VERSION,
  type PishipSchemaVersion,
  SUPPORTED_SCHEMAS,
} from "../versions.js";
import {
  migrateToV1alpha2,
  migrateToV1alpha3,
  migrateToV1alpha4,
  migrateToV1alpha5,
} from "./legacy.js";
import type { ManifestMigration } from "./types.js";
import { migrateToV1 } from "./v1.js";
import { migrateToV1alpha6 } from "./v1alpha6.js";

export type {
  ManifestMigration,
  MigrationContext,
  MigrationStepResult,
} from "./types.js";
export { MIGRATED_BOOTSTRAP_EXPIRES } from "./legacy.js";

/** Steps up to v1alpha5 preserve behavior by construction. */
export const MANIFEST_MIGRATIONS: readonly ManifestMigration[] = [
  {
    from: PISHIP_SCHEMA_VERSION,
    to: PISHIP_SCHEMA_V1ALPHA2,
    migrate: (document) => ({
      changes: migrateToV1alpha2(document),
      effective: [],
    }),
  },
  {
    from: PISHIP_SCHEMA_V1ALPHA2,
    to: PISHIP_SCHEMA_V1ALPHA3,
    migrate: (document, { mode }) => ({
      changes: migrateToV1alpha3(document, mode),
      effective: [],
    }),
  },
  {
    from: PISHIP_SCHEMA_V1ALPHA3,
    to: PISHIP_SCHEMA_V1ALPHA4,
    migrate: (document) => ({
      changes: migrateToV1alpha4(document),
      effective: [],
    }),
  },
  {
    from: PISHIP_SCHEMA_V1ALPHA4,
    to: PISHIP_SCHEMA_V1ALPHA5,
    migrate: (document, { mode }) => ({
      changes: migrateToV1alpha5(document, mode),
      effective: [],
    }),
  },
  {
    from: PISHIP_SCHEMA_V1ALPHA5,
    to: PISHIP_SCHEMA_V1ALPHA6,
    migrate: migrateToV1alpha6,
  },
  {
    from: PISHIP_SCHEMA_V1ALPHA6,
    to: PISHIP_SCHEMA_V1,
    migrate: migrateToV1,
  },
];

/** The registered step from `from` to `to`, if there is one. */
export function manifestMigration(
  from: PishipSchemaVersion,
  to: PishipSchemaVersion,
): ManifestMigration | undefined {
  return MANIFEST_MIGRATIONS.find(
    (step) => step.from === from && step.to === to,
  );
}

/**
 * The steps from `from` to `to`, in order. Throws when a step is missing,
 * so a new schema cannot be added without its migration.
 */
export function migrationPath(
  from: PishipSchemaVersion,
  to: PishipSchemaVersion,
): ManifestMigration[] {
  const steps: ManifestMigration[] = [];
  for (
    let index = SUPPORTED_SCHEMAS.indexOf(from);
    index < SUPPORTED_SCHEMAS.indexOf(to);
    index += 1
  ) {
    const stepFrom = SUPPORTED_SCHEMAS[index] as PishipSchemaVersion;
    const stepTo = SUPPORTED_SCHEMAS[index + 1] as PishipSchemaVersion;
    const step = manifestMigration(stepFrom, stepTo);
    if (!step)
      throw new Error(`No manifest migration from ${stepFrom} to ${stepTo}`);
    steps.push(step);
  }
  return steps;
}
