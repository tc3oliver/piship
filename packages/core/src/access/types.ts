import type {
  IdentitySession,
  ModelDefinition,
  RuntimeProviderConfiguration,
  SecretStore,
} from "@piship/contracts";
import type {
  ActiveCredential,
  CredentialEvent,
  CredentialPhase,
  SecretStoreResolver,
} from "@piship/credentials";
import type {
  AccessManifest,
  CapabilityConfig,
  Manifest,
} from "@piship/schema";
import type { EffectiveConfig } from "../config.js";
import type { AccessMetrics } from "./metrics.js";

/**
 * Metadata-only access lifecycle event, emitted as it happens. Details never
 * contain token or credential text.
 */
export interface AccessEvent {
  readonly event:
    | CredentialEvent["event"]
    | "identity.login"
    | "identity.refresh"
    | "identity.logout";
  readonly detail: Readonly<Record<string, string | number | boolean | null>>;
}

/**
 * Points of sign-in, sign-out, and activation a test can stop or hold at,
 * besides the credential manager's own (`CredentialPhase`).
 * - `login-locked`: login holds the credential lock, nothing is changed yet.
 * - `credential-cleared`: the previous runtime credential is gone.
 * - `sandbox-credential-cleared`: another principal's stored sandbox
 *   credential is gone.
 * - `principal-bound`: the principal binding names the new principal.
 * - `identity-cleared`: another principal's identity session is gone.
 * - `identity-stored`: the new identity is stored (or held, for a workload).
 * - `identity-resolved`: activation has its identity, before the credential.
 * - `credential-rejected`: activation recorded a gateway rejection, before
 *   the renewal.
 */
export type AccessPhase =
  | CredentialPhase
  | "login-locked"
  | "credential-cleared"
  | "sandbox-credential-cleared"
  | "principal-bound"
  | "identity-cleared"
  | "identity-stored"
  | "identity-resolved"
  | "credential-rejected";

export interface AccessOptions {
  readonly app: Manifest["app"];
  readonly mode: "personal" | "managed";
  /** undefined for piship/v1alpha1 (personal, pi-native, no identity). */
  readonly access: AccessManifest | undefined;
  readonly stateDir: string;
  readonly distributionDir: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Tests may inject a store; production selects from the manifest. */
  readonly secretStore?: SecretStore;
  /**
   * The store of the other storage provider, for deleting what state
   * recorded for it after `credential.storage.provider` changed. Production
   * creates it; with an injected `secretStore` and no resolver, it is
   * unavailable (tests never reach a real platform store by accident).
   */
  readonly secretStoreFor?: SecretStoreResolver;
  readonly now?: () => number;
  /** Declared capabilities; model requirements of enabled ones are checked at launch. */
  readonly capabilities?: readonly CapabilityConfig[];
  /** Receives identity and credential lifecycle events; failures are ignored. */
  readonly onEvent?: (event: AccessEvent) => void;
  /** Local operational metrics; recorder failures are ignored. */
  readonly metrics?: AccessMetrics;
  /**
   * Fault injection for crash-safety and concurrency tests: a hook that
   * throws stops the operation there, as a crash would, and one that waits
   * holds it there (with its locks). Never set in production.
   */
  readonly onPhase?: (phase: AccessPhase) => void | Promise<void>;
  /**
   * How long one call into an identity or credential adapter may take,
   * interactive ones included. Tests shorten it; production leaves it unset
   * for `ADAPTER_CALL_TIMEOUT_MS` and `ADAPTER_INTERACTIVE_TIMEOUT_MS`.
   */
  readonly adapterTimeoutMs?: number;
  /**
   * Signs the user in where a launch finds no usable sign-in (`activate`
   * would fail with IDENTITY_REQUIRED or IDENTITY_EXPIRED): it runs once and
   * the identity is read again. Only an interactive launch supplies it; its
   * own error is the launch's error. A workload identity never uses it.
   */
  readonly loginInline?: () => Promise<void>;
}

export interface ActivatedAccess {
  readonly identity: IdentitySession | null;
  readonly credential: ActiveCredential;
  readonly models: readonly ModelDefinition[];
  readonly runtime: RuntimeProviderConfiguration;
  readonly config: EffectiveConfig;
  readonly selectedModel: string | undefined;
  /**
   * Allowed models that do not meet an enabled capability's requirements,
   * by model ID; they are not offered for selection.
   */
  readonly incompatibleModels: Readonly<Record<string, string>>;
  readonly notices: readonly string[];
}
