import type { SecretValue } from "./secret.js";

/*
 * Identity, credential, secret storage, and inference are separate contracts.
 * Nothing here combines them: identity may be absent, a credential provider
 * receives an identity only as input, and inference receives only a credential
 * reference plus a short-lived request-time secret accessor.
 */

// ---------------------------------------------------------------- identity

export interface LoginContext {
  /** Present the authorization URL to the user (open a browser or print it). */
  readonly openUrl: (url: string) => void | Promise<void>;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export interface IdentitySession {
  readonly subject: string;
  readonly issuer: string;
  readonly displayName?: string;
  readonly email?: string;
  readonly accessToken?: SecretValue;
  readonly idToken?: SecretValue;
  readonly refreshToken?: SecretValue;
  readonly expiresAt?: Date;
  /** Non-secret claims only; token strings never appear here. */
  readonly claims?: Record<string, unknown>;
}

export interface IdentityProvider {
  readonly kind: string;
  login(ctx: LoginContext): Promise<IdentitySession>;
  refresh?(session: IdentitySession): Promise<IdentitySession>;
  logout?(session: IdentitySession): Promise<void>;
}

// -------------------------------------------------------------- credentials

export type RuntimeCredentialKind = "api_key" | "bearer" | "opaque";

export interface RuntimeCredential {
  readonly kind: RuntimeCredentialKind;
  readonly secret: SecretValue;
  readonly expiresAt?: Date;
  readonly credentialId?: string;
  readonly metadata?: {
    readonly models?: readonly string[];
    readonly scopes?: readonly string[];
    readonly teamId?: string;
    readonly baseUrl?: string;
    readonly [key: string]: unknown;
  };
}

export interface CredentialContext {
  readonly distributionId: string;
  /**
   * Cancels the operation. It composes with the provider's own request
   * timeout and never replaces it.
   */
  readonly signal?: AbortSignal;
  /** Interactive input for user-owned secrets; absent in headless flows. */
  readonly readSecret?: (prompt: string) => Promise<string>;
}

export type CredentialMode =
  | "http-broker"
  | "local-secret"
  | "pi-native"
  | "none"
  | "adapter";

export interface CredentialProvider {
  readonly mode: CredentialMode;
  /** Whether acquire needs an identity session. */
  readonly requiresIdentity: boolean;
  acquire(
    identity: IdentitySession | null,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential | null>;
  refresh?(
    identity: IdentitySession | null,
    current: RuntimeCredential,
    ctx: CredentialContext,
  ): Promise<RuntimeCredential>;
  revoke?(credential: RuntimeCredential, ctx: CredentialContext): Promise<void>;
}

/** Non-secret reference that inference receives in place of a secret. */
export interface CredentialRef {
  readonly ref: string;
  readonly mode: CredentialMode;
  readonly kind?: RuntimeCredentialKind;
  readonly credentialId?: string;
  readonly expiresAt?: Date;
  readonly models?: readonly string[];
}

// ------------------------------------------------------------ secret store

export interface SecretStore {
  readonly kind: string;
  /** Human-readable security level for diagnostics. */
  readonly description: string;
  put(ref: string, value: SecretValue): Promise<void>;
  get(ref: string): Promise<SecretValue | null>;
  delete(ref: string): Promise<void>;
}

// --------------------------------------------------------------- inference

/** Verified model metadata. An absent field is unknown, never assumed. */
export interface ModelCapabilities {
  readonly input?: readonly string[];
  readonly reasoning?: boolean;
  readonly tools?: boolean;
  readonly streaming?: boolean;
  readonly structuredOutput?: boolean;
  readonly contextWindow?: number;
  readonly maxOutputTokens?: number;
}

export interface ModelDefinition {
  readonly id: string;
  readonly name: string;
  readonly provider: string;
  readonly capabilities: ModelCapabilities;
  readonly policyTags: readonly string[];
  readonly availability: {
    readonly available: boolean;
    readonly reason?: string;
  };
}

export interface InferenceContext {
  readonly models: readonly ModelDefinition[];
  readonly allowed: readonly string[];
  readonly defaultModel?: string;
}

export interface ResolvedModel {
  readonly model: ModelDefinition;
  readonly source: string;
}

export interface RuntimeConfigurationContext {
  readonly providerId: string;
  readonly credential: CredentialRef | null;
  readonly models: readonly ModelDefinition[];
}

export interface RuntimeProviderConfiguration {
  /** "managed" binds an explicit endpoint; "pi-native" delegates to Pi auth. */
  readonly kind: "managed-endpoint" | "pi-native";
  readonly providerId: string;
  readonly baseUrl?: string;
  readonly api?: "openai-completions" | "openai-responses";
  readonly models: readonly ModelDefinition[];
  readonly requiresCredential: boolean;
}

export interface InferenceProvider {
  readonly kind: string;
  listModels(
    identity: IdentitySession | null,
    credential: CredentialRef | null,
  ): Promise<ModelDefinition[]>;
  resolveModel(
    requested: string,
    ctx: InferenceContext,
  ): Promise<ResolvedModel>;
  configureRuntime(
    ctx: RuntimeConfigurationContext,
  ): Promise<RuntimeProviderConfiguration>;
}

// ------------------------------------------------ extension-facing context

/** Frozen, token-free context exposed to approved distribution extensions. */
export interface EnterpriseContext {
  readonly version: 1;
  readonly distribution: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly mode: "personal" | "managed";
  };
  readonly identity: {
    readonly subject: string;
    readonly issuer: string;
    readonly displayName?: string;
    readonly email?: string;
  } | null;
  readonly credential: {
    readonly mode: CredentialMode;
    readonly credentialId?: string;
    readonly expiresAt?: string;
  };
  readonly inference: {
    readonly provider: string;
    readonly models: readonly {
      readonly id: string;
      readonly name: string;
      readonly policyTags: readonly string[];
    }[];
    readonly defaultModel?: string;
    readonly selectedModel?: string;
  };
  readonly config: Readonly<
    Record<string, { readonly value: unknown; readonly source: string }>
  >;
}

export const ENTERPRISE_CONTEXT_SYMBOL = Symbol.for(
  "piship.enterprise-context/v1",
);
