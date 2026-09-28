export {
  activateSandbox,
  type ActivationContext,
  type ActiveSandbox,
  type ContainmentLevel,
  type ContainmentReport,
  type ContainmentVerification,
  describeContainment,
  HOST_BOUND_VARIABLES,
  INJECTED_VARIABLES,
  platformInjectedVariables,
  SANDBOX_READY_MARKER,
  type SandboxExecOptions,
} from "./activate.js";
export {
  type AdapterAvailability,
  findExecutable,
  SANDBOX_ADAPTER_IDS,
  type SandboxAdapter,
  type SandboxAdapterId,
  type SandboxCommand,
  type WrappedCommand,
} from "./adapter.js";
export {
  capabilityMismatch,
  claimedGuarantees,
  enforcesPathPolicy,
  HOST_FILESYSTEM_ISOLATION,
  isBackendId,
  PATH_POLICY_PLANES,
  requiredPlanes,
  SANDBOX_GUARANTEES,
  SANDBOX_PROVIDERS,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxGuarantee,
  type SandboxInstance,
  type SandboxPrepareRequest,
  type SandboxProvider,
} from "./backend.js";
export {
  BubblewrapAdapter,
  type BubblewrapFeatures,
  bubblewrapArgs,
  hostEscapePaths,
  MODERN_BUBBLEWRAP,
} from "./bubblewrap.js";
export {
  filterEnvironment,
  isCredentialName,
  looksLikeSecret,
  STDERR_TRUNCATION_MARKER,
  sanitizeStderr,
  stripCredentials,
} from "./environment.js";
export { NativeBackend } from "./native.js";
export {
  CONTAINMENT_PLANES,
  type ContainmentPlane,
  type ProbeOptions,
  type ProbeResult,
  type ProbeTarget,
  probeSandbox,
} from "./probe.js";
export {
  killAllManaged,
  type ManagedExit,
  type ManagedProcess,
  type ManagedSpawnOptions,
  type SandboxWrapper,
  spawnManaged,
} from "./process.js";
export {
  expandPathToken,
  isWithin,
  type ProfileContext,
  type ProtectedPaths,
  realpathNearest,
  resolveProfile,
  type SandboxPolicy,
  type SandboxProfile,
} from "./profile.js";
export {
  SANDBOX_EXEC,
  SeatbeltAdapter,
  sbplString,
  seatbeltProfile,
} from "./seatbelt.js";
export {
  ADAPTER_OVERRIDE_VARIABLE,
  adapterIdFor,
  selectAdapter,
  UnsupportedAdapter,
} from "./select.js";
export { type CustomBackendContext, customBackend } from "./custom.js";
export {
  connectEnvelope,
  E2bCompatibleBackend,
  type E2bCompatibleOptions,
  EnvelopeReader,
} from "./remote/e2b.js";
export type { RemoteBackendOptions } from "./remote/http.js";
export {
  KubernetesAgentSandboxBackend,
  type KubernetesAgentSandboxOptions,
  runtimeCommand,
} from "./remote/kubernetes.js";
