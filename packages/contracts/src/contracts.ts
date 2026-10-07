import { createHash } from "node:crypto";
import { PiShipError } from "./errors.js";
import type { ManagedFetch } from "./network.js";
import type { SecretValue } from "./secret.js";

/*
 * Identity, credential, secret storage, and inference are separate contracts.
 * Nothing here combines them: identity may be absent, a credential provider
 * receives an identity only as input, and inference receives only a credential
 * reference plus a short-lived request-time secret accessor.
 */

// ---------------------------------------------------------------- identity

/**
 * What a person needs to finish an RFC 8628 device sign-in on any browser.
 * The user code is a short-lived one-time code, not a secret, but it is shown
 * to the person only and kept out of persistent state.
 */
export interface DeviceCodePrompt {
  readonly verificationUri: string;
  readonly userCode: string;
  /** The verification URI with the code in it, when the provider gives one. */
  readonly verificationUriComplete?: string;
  /** How long the sign-in waits for the code to be entered. */
  readonly expiresInSeconds: number;
}

export interface LoginContext {
  /** Present the authorization URL to the user (open a browser or print it). */
  readonly openUrl: (url: string) => void | Promise<void>;
  /**
   * Present a device code and where to enter it. Only the built-in OIDC
   * `device_code` flow calls it; an adapter never needs it, and a context
   * without it cannot run that flow.
   */
  readonly presentDeviceCode?: (
    prompt: DeviceCodePrompt,
  ) => void | Promise<void>;
  /**
   * Cancels the sign-in. An identity adapter's `login()` receives one that
   * also aborts at PiShip's deadline for the call.
   */
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

/**
 * The normalized principal: the stable identity key `(iss, sub)`. PiShip binds
 * user-scoped state (runtime credential, entitlement, model selection) to it.
 * Both parts are compared as exact strings, as OIDC compares them; email,
 * display name, and username are attributes and never part of the key.
 */
export interface PrincipalKey {
  readonly issuer: string;
  readonly subject: string;
}

/**
 * The principal of an identity session or of stored metadata. Throws
 * `IDENTITY_INVALID` when the issuer or subject is missing or not a string.
 */
export function principalKey(value: {
  readonly issuer?: unknown;
  readonly subject?: unknown;
}): PrincipalKey {
  const { issuer, subject } = value ?? {};
  if (typeof issuer !== "string" || !issuer)
    throw new PiShipError("IDENTITY_INVALID", "The identity has no issuer", {
      component: "identity",
    });
  if (typeof subject !== "string" || !subject)
    throw new PiShipError("IDENTITY_INVALID", "The identity has no subject", {
      component: "identity",
    });
  return { issuer, subject };
}

/**
 * Whether two principals are the same `(iss, sub)`. `null` stands for "no
 * identity" and equals only `null`; a malformed principal equals nothing.
 */
export function samePrincipal(
  a: PrincipalKey | null | undefined,
  b: PrincipalKey | null | undefined,
): boolean {
  if (!a || !b) return !a && !b;
  return (
    typeof a.issuer === "string" &&
    typeof a.subject === "string" &&
    !!a.issuer &&
    !!a.subject &&
    a.issuer === b.issuer &&
    a.subject === b.subject
  );
}

/**
 * The principal as one string, for audit attribution: the issuer, `#`, then
 * the subject. `%` and `#` in the issuer are percent-encoded, so the first
 * `#` always ends the issuer and two principals never share a string. An OIDC
 * issuer is an URL without a fragment and reads unchanged.
 */
export function principalId(key: PrincipalKey): string {
  return `${key.issuer.replace(/%/g, "%25").replace(/#/g, "%23")}#${key.subject}`;
}

/**
 * A fixed-length, filesystem-safe name for per-principal directories: 32 hex
 * characters of SHA-256 over the principal. It reveals neither part.
 */
export function principalDigest(key: PrincipalKey): string {
  return createHash("sha256")
    .update(JSON.stringify([key.issuer, key.subject]))
    .digest("hex")
    .slice(0, 32);
}

/** What PiShip passes to an identity adapter's `refresh` and `logout`. */
export interface IdentityCallContext {
  /**
   * Aborts when PiShip stops waiting for the call: at its deadline or on
   * cancellation. Optional to honor; PiShip stops waiting either way.
   */
  readonly signal?: AbortSignal;
}

export interface IdentityProvider {
  readonly kind: string;
  login(ctx: LoginContext): Promise<IdentitySession>;
  refresh?(
    session: IdentitySession,
    ctx?: IdentityCallContext,
  ): Promise<IdentitySession>;
  logout?(session: IdentitySession, ctx?: IdentityCallContext): Promise<void>;
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
  /**
   * Names one logical acquire or renewal, so a broker that honors it answers
   * a repeated request with the credential it already issued instead of a new
   * one. Random and not secret; never derived from the identity or a token.
   * `CredentialManager` generates one per logical acquire or renewal (or
   * takes the caller's), records it before the request is sent, and passes
   * the same key to every later attempt of that request, in any process,
   * until the credential is committed or the provider gives a final answer.
   */
  readonly idempotencyKey?: string;
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
  /** Extra headers every inference request carries, such as `PiShip-Client`. */
  readonly headers?: Readonly<Record<string, string>>;
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

// --------------------------------------------------- adapter-facing context

/** Endpoints of a distribution's access configuration, with runtime references resolved. */
export interface ResolvedEndpoints {
  readonly issuer?: string;
  readonly clientId?: string;
  readonly audience?: string;
  readonly brokerEndpoint?: string;
  readonly brokerRevokeEndpoint?: string;
  readonly baseUrl?: string;
  readonly additionalCA: readonly string[];
}

/** What an identity or credential adapter module's default-export factory receives. */
export interface AdapterContext {
  readonly distributionId: string;
  /** PiShip's managed fetch: proxy, CA, and private-only policy applied. */
  readonly fetch: ManagedFetch;
  readonly endpoints: ResolvedEndpoints;
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
