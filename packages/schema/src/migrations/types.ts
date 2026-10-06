import type { parseDocument } from "yaml";
import type { DeploymentMode } from "../access.js";
import type { Manifest } from "../index.js";
import type { PishipSchemaVersion } from "../versions.js";

export type YamlDocument = ReturnType<typeof parseDocument>;

export interface MigrationContext {
  /** The deployment mode of the manifest being migrated. */
  readonly mode: DeploymentMode;
  /** Parse the document as it is now; a step calls it before it changes the schema. */
  readonly parse: () => Manifest;
}

export interface MigrationStepResult {
  /** One line per change, printed as a warning. */
  readonly changes: readonly string[];
  /**
   * The changes that alter an effective decision (what loads, starts, runs,
   * or is sent). `piship migrate --check` fails when any step reports one.
   */
  readonly effective: readonly string[];
  /**
   * Configuration the step left as written because only the owner can say
   * what it should be. `piship migrate --check` reports "requires review"
   * for any of these, with no change to a decision.
   */
  readonly review?: readonly string[];
}

/**
 * One deterministic migration step. It edits the YAML document in place, so
 * comments are kept, and it never broadens what the distribution allows.
 */
export interface ManifestMigration {
  readonly from: PishipSchemaVersion;
  readonly to: PishipSchemaVersion;
  readonly migrate: (
    document: YamlDocument,
    context: MigrationContext,
  ) => MigrationStepResult;
}
