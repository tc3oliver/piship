// The Windows rename retry lives in @piship/credentials, the lowest package
// that renames files; core re-exports it unchanged.
export {
  RENAME_DELAYS_MS,
  type RenameRetryOptions,
  renameWithRetry,
  TRANSIENT_ATTEMPTS,
  TRANSIENT_RETRY_MS,
} from "@piship/credentials";
