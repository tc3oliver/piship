// Installed release ownership: the receipt, install, uninstall, purge, and
// status.
export { installDistribution, type InstallChecks } from "./install.js";
export {
  inspectInstalledLauncher,
  installedLauncherPath,
  refreshInstalledLauncher,
  type InstalledLauncher,
} from "./launcher.js";
export { purgeDistributionState, type PurgeResult } from "./purge.js";
export {
  RECEIPT_SCHEMA,
  readInstallReceipt,
  recoverInstallation,
  type InstallReceipt,
  type InstalledRelease,
  type LifecycleOptions,
  type LifecyclePhase,
  type RetiredKey,
} from "./receipt.js";
export { lifecycleStatus, type LifecycleStatus } from "./status.js";
export {
  LEGACY_ROOT_EXPIRES,
  TRUST_STATE_SCHEMA,
  readTrustState,
  trustStatePath,
  type RemovedTrustKey,
  type UpdateTrustState,
} from "./trust-state.js";
export { sweepStateTemporaries } from "./temporaries.js";
export {
  describeReclaimed,
  reclaimObsoleteVersions,
  type ReclaimedVersions,
  type ReclaimOptions,
} from "./reclaim.js";
export {
  uninstallAndPurgeDistribution,
  uninstallDistribution,
  type UninstallOptions,
} from "./uninstall.js";
export {
  holdRuntimeLease,
  runtimeLeases,
  type RuntimeLeaseStatus,
} from "./runtime-lease.js";
