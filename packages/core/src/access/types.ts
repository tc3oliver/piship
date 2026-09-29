import type {
  IdentitySession,
  ModelDefinition,
  RuntimeProviderConfiguration,
  SecretStore,
} from "@piship/contracts";
import type { ActiveCredential, CredentialEvent } from "@piship/credentials";
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
  readonly now?: () => number;
  /** Declared capabilities; model requirements of enabled ones are checked at launch. */
  readonly capabilities?: readonly CapabilityConfig[];
  /** Receives identity and credential lifecycle events; failures are ignored. */
  readonly onEvent?: (event: AccessEvent) => void;
  /** Local operational metrics; recorder failures are ignored. */
  readonly metrics?: AccessMetrics;
  /** Fault injection for crash-safety tests of login. */
  readonly onPhase?: (phase: "credential-cleared" | "identity-stored") => void;
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
