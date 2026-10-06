// piship/v1alpha6 -> piship/v1. piship/v1 freezes the v1alpha6 semantics, so
// the step changes the schema id and nothing else: no field is renamed,
// added, or removed, and no default moves. It never rewrites configuration
// that needs an owner's judgment; it reports it as a review item instead.
import { sharedRoleKeyIds } from "../lifecycle.js";
import { PISHIP_SCHEMA_V1 } from "../versions.js";
import { MIGRATED_BOOTSTRAP_EXPIRES } from "./legacy.js";
import type {
  MigrationContext,
  MigrationStepResult,
  YamlDocument,
} from "./types.js";

export function migrateToV1(
  document: YamlDocument,
  context: MigrationContext,
): MigrationStepResult {
  const review: string[] = [];
  const trust = context.parse().lifecycle?.updates.trust;
  const bootstrap = trust && "bootstrap" in trust ? trust.bootstrap : undefined;
  if (bootstrap?.expires === MIGRATED_BOOTSTRAP_EXPIRES)
    review.push(
      `updates.trust.bootstrap.expires is ${MIGRATED_BOOTSTRAP_EXPIRES}, the fixed value an earlier migration wrote, not a date you chose; set the real expiry before you rely on it`,
    );
  const shared = bootstrap ? sharedRoleKeyIds(bootstrap) : [];
  if (context.mode === "managed" && shared.length)
    review.push(
      `updates.trust.bootstrap: the root and channel roles share ${shared.join(", ")}; a managed release needs an offline root key separate from the channel release key (piship release refuses this distribution until the roles are split)`,
    );
  document.set("schema", PISHIP_SCHEMA_V1);
  return {
    changes: [
      "schema: piship/v1alpha6 -> piship/v1",
      "no field, default, or rule changes: piship/v1 freezes the piship/v1alpha6 semantics",
    ],
    effective: [],
    review,
  };
}
