// The manifest-level checks of the `data` contract and session export, run by
// both `piship validate` and `piship lock`.
import { type Manifest, ManifestError } from "@piship/schema";
import { dataLifecycleIssues } from "./lifecycle.js";
import { assertRadiusClosed } from "./session-export.js";

/**
 * Throw what the data contract cannot accept: audit in `purge.onLogout`, and
 * a gateway distribution whose provider id would open Pi's Radius `/share`.
 * A `data.export` deny or ask on an unsupported resource is the seam
 * table's POLICY_UNENFORCEABLE (checkEnforceability).
 */
export function checkDataContract(manifest: Manifest): void {
  const issue = manifest.data ? dataLifecycleIssues(manifest.data)[0] : null;
  if (issue)
    throw new ManifestError("invalid field", issue.path, issue.message);
  assertRadiusClosed(manifest.app.id, manifest.access);
}
