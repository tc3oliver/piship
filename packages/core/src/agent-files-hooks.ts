// Test seams of the agent-files lock: the file operations it goes through and
// three points inside it, for a test to inject a failure or an interleaving.
// Empty in production. Not exported from the package index: tests import it
// from here, and nothing outside @piship/core can reach it.
export const agentFilesLockHooks: {
  rename?: (from: string, to: string) => void;
  rm?: (path: string) => void;
  /** After a taker read the owner it is about to discard. */
  afterOwnerRead?: () => void;
  /** After the taker decided the owner is dead, before it takes the lock down. */
  afterHolderCheck?: () => void;
  /** Before the holder releases its lock. */
  beforeRelease?: () => void;
} = {};
