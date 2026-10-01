// The supported surface for writing PiShip adapters. Everything here is a
// curated re-export of a public PiShip package or a thin wrapper around one;
// an adapter imports nothing else from PiShip. A name is added here only on
// purpose: `index.test.ts` pins the exact list.

/** The adapter kinds a distribution can supply, and the conformance kits cover. */
export const ADAPTER_KINDS = [
  "identity",
  "credential",
  "sandbox",
  "audit-sink",
] as const;
export type AdapterKind = (typeof ADAPTER_KINDS)[number];

export {
  type AdapterFactory,
  defineAuditSink,
  defineCredentialAdapter,
  defineIdentityAdapter,
  defineSandboxAdapter,
  type SandboxAdapterFactory,
  type SandboxBackendDefinition,
  withTimeout,
} from "./define.js";

// Contracts: the adapter context, identity and the principal, credentials,
// audit, secrets, redaction, the managed fetch, and error normalization.
export {
  type AdapterContext,
  AUDIT_BATCH_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  type AuditBatch,
  type AuditEvent,
  type AuditEventType,
  type AuditSink,
  type CredentialContext,
  type CredentialMode,
  type CredentialProvider,
  formatError,
  type IdentityCallContext,
  type IdentityProvider,
  type IdentitySession,
  isPiShipError,
  isSecretValue,
  type LoginContext,
  type ManagedFetch,
  PISHIP_ERROR_CODES,
  PiShipError,
  type PiShipErrorCode,
  type PiShipErrorOptions,
  type PrincipalKey,
  parseRetryAfter,
  principalKey,
  REDACTED_TEXT,
  RETAINED_CLAIMS,
  type ResolvedEndpoints,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  redact,
  redactValue,
  SecretValue,
  samePrincipal,
  type WorkloadIdentityProvider,
} from "@piship/contracts";

// Sandbox backends: the contract a custom backend implements and the
// capabilities it declares.
export {
  type AdapterAvailability,
  type CustomBackendContext,
  HOST_FILESYSTEM_ISOLATION,
  SANDBOX_GUARANTEES,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxCommand,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxGuarantee,
  type SandboxInstance,
  type SandboxNetworkProbe,
  type SandboxPrepareRequest,
  type SandboxProfile,
  type WrappedCommand,
} from "@piship/sandbox";
