import { LocalMetrics } from "@piship/audit";
import type { DistributionLock } from "@piship/core";

/**
 * The local metrics of one launch, stamped with the running versions. Access
 * and the governed session record into this one instance, so neither save
 * overwrites the other's counts. A plain personal Pi distribution (no access,
 * no governance) keeps no metrics.
 */
export function launchMetrics(
  metadata: Pick<DistributionLock, "app" | "runtime" | "access" | "governance">,
  stateDir: string,
  piVersion: string,
): LocalMetrics | undefined {
  if (!metadata.access && !metadata.governance) return undefined;
  const metrics = LocalMetrics.load(stateDir);
  metrics.recordVersions({
    distribution: metadata.app.version,
    piship: metadata.runtime.pishipVersion,
    pi: piVersion,
    node: process.versions.node,
  });
  return metrics;
}

/** Local metrics never block a launch or a command. */
export function saveMetrics(metrics: LocalMetrics | undefined): void {
  try {
    metrics?.save();
  } catch {
    // Best effort.
  }
}
