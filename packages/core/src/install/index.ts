// Installed release ownership: the receipt, install, uninstall, purge, and
// status.
export { installDistribution } from "./install.js";
export { purgeDistributionState, type PurgeResult } from "./purge.js";
export {
  RECEIPT_SCHEMA,
  readInstallReceipt,
  recoverInstallation,
  type InstallReceipt,
  type InstalledRelease,
  type LifecycleOptions,
  type LifecyclePhase,
} from "./receipt.js";
export { lifecycleStatus, type LifecycleStatus } from "./status.js";
export { sweepStateTemporaries } from "./temporaries.js";
export {
  uninstallAndPurgeDistribution,
  uninstallDistribution,
} from "./uninstall.js";
export {
  holdRuntimeLease,
  runtimeLeases,
  type RuntimeLeaseStatus,
} from "./runtime-lease.js";
