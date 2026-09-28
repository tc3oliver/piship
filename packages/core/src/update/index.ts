// Verified update and rollback of an installed distribution.
export { rollbackDistribution, type RollbackResult } from "./rollback.js";
export { SNAPSHOT_SCHEMA } from "./state.js";
export {
  selectChannel,
  updateDistribution,
  type ChannelSelection,
  type UpdateOptions,
  type UpdateResult,
} from "./update.js";
