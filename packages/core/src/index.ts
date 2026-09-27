import type { PishipSchemaVersion } from "@piship/schema";

export interface DistributionId {
  readonly value: string;
}

export interface ResolvedDistribution {
  readonly id: DistributionId;
  readonly schema: PishipSchemaVersion;
  readonly piVersion: string;
}

/** Runtime state is kept separate from source manifests and lockfiles. */
export function distributionStateDirectory(id: DistributionId): string {
  if (!/^[a-z][a-z0-9-]*$/.test(id.value)) {
    throw new Error(
      "Distribution id must contain lowercase letters, digits or hyphens",
    );
  }
  return `.piship/${id.value}`;
}
