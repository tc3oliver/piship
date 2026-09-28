import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  DEFAULT_NETWORK_POLICY,
  type EnterpriseContext,
  type IdentityProvider,
  type IdentitySession,
  type InferenceProvider,
  type LoginContext,
  type ManagedFetch,
  type ModelDefinition,
  type NetworkPolicy,
  PiShipError,
  type RuntimeProviderConfiguration,
  type SecretStore,
  type SecretValue,
  createManagedFetch,
  redact,
} from "@piship/contracts";
import {
  type ActiveCredential,
  CredentialManager,
  type CredentialStatus,
  HttpBrokerCredentialProvider,
  LocalSecretCredentialProvider,
  NoCredentialProvider,
  PiNativeCredentialProvider,
  createSecretStore,
} from "@piship/credentials";
import {
  type IdentityMetadata,
  OidcPkceIdentityProvider,
  identityMetadata,
  identitySecret,
  parseIdentityMetadata,
  restoreIdentitySession,
} from "@piship/identity";
import {
  OpenAICompatibleInferenceProvider,
  PiNativeInferenceProvider,
  resolveRequestedModel,
} from "@piship/inference";
import {
  type AccessManifest,
  type Manifest,
  RuntimeReferenceError,
  checkUrl,
  resolveTemplate,
} from "@piship/schema";
import {
  type EffectiveConfig,
  readPreferences,
  resolveEffectiveConfig,
} from "./config.js";

export interface ResolvedEndpoints {
  readonly issuer?: string;
  readonly clientId?: string;
  readonly audience?: string;
  readonly brokerEndpoint?: string;
  readonly brokerRevokeEndpoint?: string;
  readonly baseUrl?: string;
  readonly additionalCA: readonly string[];
}

/** Resolve allowlisted `${NAME}` references from the launch environment. */
export function resolveRuntimeReferences(
  access: AccessManifest,
  env: Readonly<Record<string, string | undefined>> = process.env,
): ResolvedEndpoints {
  const variables = access.variables;
  const one = (field: string, value: string | undefined, url: boolean) => {
    if (value === undefined) return undefined;
    let resolved: string;
    try {
      resolved = resolveTemplate(field, value, variables, env);
    } catch (error) {
      if (error instanceof RuntimeReferenceError)
        throw new PiShipError("CONFIG_UNAVAILABLE", error.message, {
          component: "config",
          userAction: error.variable
            ? `Set ${error.variable} in the launch environment (see the distribution documentation)`
            : "Fix the runtime reference in piship.yaml",
        });
      throw error;
    }
    if (url)
      try {
        checkUrl(resolved, field);
      } catch (error) {
        throw new PiShipError(
          "CONFIG_INVALID",
          `${field} resolved to an unacceptable URL: ${(error as Error).message}`,
          {
            component: "config",
          },
        );
      }
    return resolved;
  };
  const identity =
    access.identity.mode === "oidc" ? access.identity.oidc : undefined;
  const values = {
    issuer: one("identity.oidc.issuer", identity?.issuer, true),
    clientId: one("identity.oidc.clientId", identity?.clientId, false),
    audience: one("identity.oidc.audience", identity?.audience, false),
    brokerEndpoint: one(
      "credential.broker.endpoint",
      access.credential.broker?.endpoint,
      true,
    ),
    brokerRevokeEndpoint: one(
      "credential.broker.revokeEndpoint",
      access.credential.broker?.revokeEndpoint,
      true,
    ),
    baseUrl: one("inference.baseUrl", access.inference.baseUrl, true),
  };
  const output: Record<string, unknown> = {
    additionalCA: access.network.tls.additionalCA.map((path, index) =>
      one(`network.tls.additionalCA[${index}]`, path, false),
    ),
  };
  for (const [key, value] of Object.entries(values))
    if (value !== undefined) output[key] = value;
  return output as unknown as ResolvedEndpoints;
}

export function networkPolicyFor(
  access: AccessManifest | undefined,
  endpoints?: ResolvedEndpoints,
): NetworkPolicy {
  if (!access) return DEFAULT_NETWORK_POLICY;
  const hosts = new Set(access.network.allowHosts);
  for (const url of [
    endpoints?.issuer,
    endpoints?.brokerEndpoint,
    endpoints?.brokerRevokeEndpoint,
    endpoints?.baseUrl,
  ])
    if (url) hosts.add(new URL(url).hostname.toLowerCase());
  return {
    inheritProxyEnvironment: access.network.proxy.inheritEnvironment,
    additionalCA: endpoints?.additionalCA ?? [],
    privateOnly: access.network.privateOnly,
    allowHosts: [...hosts].sort(),
  };
}

export interface AccessStatePaths {
  readonly identity: string;
  readonly credential: string;
  readonly preferences: string;
  readonly secrets: string;
}

export function accessStatePaths(stateDir: string): AccessStatePaths {
  return {
    identity: join(stateDir, "identity", "session.json"),
    credential: join(stateDir, "credentials-metadata", "inference.json"),
    preferences: join(stateDir, "config", "preferences.json"),
    secrets: join(stateDir, "secrets"),
  };
}

export interface AdapterContext {
  readonly distributionId: string;
  readonly fetch: ManagedFetch;
  readonly endpoints: ResolvedEndpoints;
}

async function loadAdapter<T>(
  distributionDir: string,
  path: string,
  kind: string,
  context: AdapterContext,
): Promise<T> {
  const base = resolve(distributionDir, "resources");
  const absolute = resolve(base, ...path.slice(2).split("/"));
  if (!absolute.startsWith(`${base}${sep}`) || !existsSync(absolute))
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter is missing from the verified payload: ${path}`,
      {
        component: kind,
      },
    );
  const module = (await import(pathToFileURL(absolute).href)) as {
    default?: unknown;
  };
  if (typeof module.default !== "function")
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter must default-export a factory function`,
      {
        component: kind,
      },
    );
  const instance = await (
    module.default as (context: AdapterContext) => unknown
  )(context);
  if (!instance || typeof instance !== "object")
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter factory returned no provider`,
      { component: kind },
    );
  return instance as T;
}

function writeJsonAtomic(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  renameSync(temporary, path);
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
}

export interface ActivatedAccess {
  readonly identity: IdentitySession | null;
  readonly credential: ActiveCredential;
  readonly models: readonly ModelDefinition[];
  readonly runtime: RuntimeProviderConfiguration;
  readonly config: EffectiveConfig;
  readonly selectedModel: string | undefined;
  readonly notices: readonly string[];
}

/**
 * Orchestrates Identity → Credential → Inference for one distribution without
 * merging them: each provider is constructed separately from the manifest and
 * connected only through IdentitySession, CredentialRef, and ModelDefinition.
 */
export class DistributionAccess {
  readonly endpoints: ResolvedEndpoints;
  readonly network: NetworkPolicy;
  readonly paths: AccessStatePaths;
  readonly store: SecretStore | null;
  readonly #fetch: ManagedFetch;
  #identity: IdentityProvider | null | undefined;
  #credential: CredentialManager | undefined;
  #secret: SecretValue | null = null;
  readonly #now: () => number;

  private constructor(readonly options: AccessOptions) {
    const env = options.env ?? process.env;
    this.#now = options.now ?? Date.now;
    this.endpoints = options.access
      ? resolveRuntimeReferences(options.access, env)
      : { additionalCA: [] };
    this.network = networkPolicyFor(options.access, this.endpoints);
    this.#fetch = createManagedFetch(this.network, "access");
    this.paths = accessStatePaths(options.stateDir);
    const needsStore =
      !!options.access &&
      (options.access.identity.mode !== "none" ||
        !["pi-native", "none"].includes(options.access.credential.provider));
    this.store = needsStore
      ? (options.secretStore ??
        createSecretStore({
          provider: options.access?.credential.storage.provider ?? "system",
          fileDirectory: this.paths.secrets,
        }))
      : null;
  }

  static open(options: AccessOptions): DistributionAccess {
    return new DistributionAccess(options);
  }

  get access(): AccessManifest | undefined {
    return this.options.access;
  }
  get providerId(): string {
    return this.options.app.id;
  }
  get credentialMode(): CredentialProvider["mode"] {
    return this.options.access?.credential.provider ?? "pi-native";
  }
  get identityMode(): "none" | "oidc" | "adapter" {
    return this.options.access?.identity.mode ?? "none";
  }

  #context(): AdapterContext {
    return {
      distributionId: this.options.app.id,
      fetch: this.#fetch,
      endpoints: this.endpoints,
    };
  }

  async identityProvider(): Promise<IdentityProvider | null> {
    if (this.#identity !== undefined) return this.#identity;
    const identity = this.options.access?.identity;
    if (!identity || identity.mode === "none") this.#identity = null;
    else if (identity.mode === "adapter")
      this.#identity = await loadAdapter<IdentityProvider>(
        this.options.distributionDir,
        identity.adapter,
        "identity",
        this.#context(),
      );
    else
      this.#identity = new OidcPkceIdentityProvider({
        issuer: this.endpoints.issuer ?? "",
        clientId: this.endpoints.clientId ?? "",
        scopes: identity.oidc.scopes,
        ...(this.endpoints.audience
          ? { audience: this.endpoints.audience }
          : {}),
        redirectUri: identity.oidc.redirectUri,
        fetch: this.#fetch,
      });
    return this.#identity;
  }

  async credentialManager(): Promise<CredentialManager> {
    if (this.#credential) return this.#credential;
    const access = this.options.access;
    const mode = this.credentialMode;
    let provider: CredentialProvider;
    if (mode === "http-broker")
      provider = new HttpBrokerCredentialProvider({
        endpoint: this.endpoints.brokerEndpoint ?? "",
        ...(this.endpoints.brokerRevokeEndpoint
          ? { revokeEndpoint: this.endpoints.brokerRevokeEndpoint }
          : {}),
        ...(this.endpoints.baseUrl
          ? { expectedBaseUrl: this.endpoints.baseUrl }
          : {}),
        fetch: this.#fetch,
      });
    else if (mode === "local-secret")
      provider = new LocalSecretCredentialProvider();
    else if (mode === "none") provider = new NoCredentialProvider();
    else if (mode === "adapter")
      provider = await loadAdapter<CredentialProvider>(
        this.options.distributionDir,
        access?.credential.adapter ?? "",
        "credential",
        this.#context(),
      );
    else provider = new PiNativeCredentialProvider();
    this.#credential = new CredentialManager({
      distributionId: this.options.app.id,
      provider,
      store: this.store,
      metadataPath: this.paths.credential,
      beforeExpirySeconds:
        access?.credential.refresh.beforeExpirySeconds ?? 300,
      now: this.#now,
    });
    return this.#credential;
  }

  inferenceProvider(userAllowed?: readonly string[]): InferenceProvider {
    const access = this.options.access;
    if (!access || access.inference.provider === "pi-native")
      return new PiNativeInferenceProvider(access?.models.allowed ?? []);
    return new OpenAICompatibleInferenceProvider({
      providerId: this.providerId,
      baseUrl: this.endpoints.baseUrl ?? "",
      api: access.inference.api ?? "openai-completions",
      catalog: access.models.catalog,
      allowed: access.models.allowed,
      ...(userAllowed ? { userAllowed } : {}),
      liveCatalog: access.inference.liveCatalog,
      fetch: this.#fetch,
      secret: () => this.#secret,
    });
  }

  // ------------------------------------------------------------- identity state

  readIdentityMetadata(): IdentityMetadata | null {
    if (!existsSync(this.paths.identity)) return null;
    try {
      return parseIdentityMetadata(
        JSON.parse(readFileSync(this.paths.identity, "utf8")),
      );
    } catch {
      return null;
    }
  }

  async #storeIdentity(session: IdentitySession): Promise<void> {
    if (!this.store)
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "No secret store is configured",
        { component: "identity" },
      );
    const previous = this.readIdentityMetadata();
    const generation = previous
      ? Number(previous.secretRef.split("#")[1] ?? 0) + 1
      : 1;
    const ref = `piship:${this.options.app.id}:identity#${generation}`;
    await this.store.put(ref, identitySecret(session));
    writeJsonAtomic(this.paths.identity, identityMetadata(session, ref));
    if (previous && previous.secretRef !== ref)
      await this.store.delete(previous.secretRef).catch(() => {});
  }

  /** Load the identity session, refreshing it when it is expiring. */
  async currentIdentity(options: {
    required: boolean;
  }): Promise<IdentitySession | null> {
    const provider = await this.identityProvider();
    if (!provider) return null;
    const metadata = this.readIdentityMetadata();
    if (!metadata) {
      if (existsSync(this.paths.identity))
        rmSync(this.paths.identity, { force: true });
      if (!options.required) return null;
      throw new PiShipError("IDENTITY_REQUIRED", "You are not signed in", {
        component: "identity",
        userAction: `Run ${this.options.app.command} login`,
      });
    }
    const secret = await this.store?.get(metadata.secretRef);
    let session = restoreIdentitySession(metadata, secret ?? null);
    if (!session.accessToken) {
      if (!options.required) return null;
      throw new PiShipError(
        "IDENTITY_REQUIRED",
        "The stored identity session has no token material",
        {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        },
      );
    }
    const expiring =
      session.expiresAt && session.expiresAt.getTime() - this.#now() < 60_000;
    if (expiring) {
      if (!provider.refresh || !session.refreshToken)
        throw new PiShipError(
          "IDENTITY_EXPIRED",
          "The identity session expired",
          {
            component: "identity",
            userAction: `Run ${this.options.app.command} login`,
          },
        );
      session = await provider.refresh(session);
      await this.#storeIdentity(session);
    }
    return session;
  }

  // -------------------------------------------------------------- operations

  #credentialContext(
    readSecret?: (prompt: string) => Promise<string>,
  ): CredentialContext {
    return {
      distributionId: this.options.app.id,
      ...(readSecret ? { readSecret } : {}),
    };
  }

  /** Interactive login: identity (when configured), then the runtime credential. */
  async login(ctx: {
    openUrl: LoginContext["openUrl"];
    readSecret?: (prompt: string) => Promise<string>;
    signal?: AbortSignal;
  }): Promise<{
    identity: IdentitySession | null;
    credential: CredentialStatus;
    notices: string[];
  }> {
    const provider = await this.identityProvider();
    let identity: IdentitySession | null = null;
    if (provider) {
      identity = await provider.login({
        openUrl: ctx.openUrl,
        ...(ctx.signal ? { signal: ctx.signal } : {}),
      });
      await this.#storeIdentity(identity);
    }
    const manager = await this.credentialManager();
    const notices: string[] = [];
    if (manager.storesSecrets) {
      // A fresh login always replaces the runtime credential.
      await manager.logout(this.#credentialContext()).catch(() => []);
      const active = await manager.ensure(
        identity,
        this.#credentialContext(ctx.readSecret),
        { allowAcquire: true },
      );
      this.#secret = active.secret;
      notices.push(...active.notices);
    }
    return { identity, credential: manager.status(), notices };
  }

  /** Revoke and clear runtime and identity credentials; sessions are preserved. */
  async logout(): Promise<string[]> {
    const problems: string[] = [];
    const manager = await this.credentialManager();
    problems.push(...(await manager.logout(this.#credentialContext())));
    const provider = await this.identityProvider().catch(() => null);
    const metadata = this.readIdentityMetadata();
    if (metadata && this.store) {
      const secret = await this.store.get(metadata.secretRef).catch(() => null);
      if (provider?.logout && secret)
        try {
          await provider.logout(restoreIdentitySession(metadata, secret));
        } catch (error) {
          problems.push(
            `identity revocation: ${redact((error as Error).message)}`,
          );
        }
      for (const ref of [
        metadata.secretRef,
        `${metadata.secretRef.split("#")[0]}#${Number(metadata.secretRef.split("#")[1] ?? 0) + 1}`,
      ])
        await this.store
          .delete(ref)
          .catch((error: Error) =>
            problems.push(`identity secret: ${redact(error.message)}`),
          );
    }
    rmSync(this.paths.identity, { force: true });
    this.#secret = null;
    return problems;
  }

  /**
   * Launch-time resolution: identity, credential, catalog, and effective model
   * selection. Fails closed with the error contract when anything required is
   * missing; never falls back to personal providers.
   */
  async activate(
    options: { requestedModel?: string } = {},
  ): Promise<ActivatedAccess> {
    const notices: string[] = [];
    const access = this.options.access;
    const preferences = readPreferences(this.paths.preferences);
    const manager = await this.credentialManager();
    const identityRequired =
      manager.options.provider.requiresIdentity || this.identityMode !== "none";
    const identity = await this.currentIdentity({ required: identityRequired });
    let credential: ActiveCredential;
    try {
      credential = await manager.ensure(identity, this.#credentialContext(), {
        allowAcquire:
          this.credentialMode === "http-broker" ||
          this.credentialMode === "adapter",
      });
    } catch (error) {
      if (
        error instanceof PiShipError &&
        error.code === "IDENTITY_EXPIRED" &&
        identity
      ) {
        const refreshed = await this.#refreshIdentity(identity);
        credential = await manager.ensure(
          refreshed,
          this.#credentialContext(),
          { allowAcquire: true },
        );
      } else throw error;
    }
    this.#secret = credential.secret;
    notices.push(...credential.notices);
    let config = resolveEffectiveConfig(
      access,
      this.options.app.theme,
      preferences,
      credential.ref?.models,
    );
    const inference = this.inferenceProvider(preferences.modelsAllowed);
    let models: ModelDefinition[];
    try {
      models = await inference.listModels(identity, credential.ref);
    } catch (error) {
      // A gateway rejection of a stored credential gets one automatic renewal.
      if (
        !(error instanceof PiShipError) ||
        error.code !== "CREDENTIAL_REVOKED" ||
        !manager.storesSecrets
      )
        throw error;
      manager.markRejected();
      await this.requestSecret({ force: true });
      notices.push(
        "The gateway rejected the stored credential; a new credential was acquired",
      );
      const renewed = manager.readMetadata();
      credential = {
        ...credential,
        secret: this.#secret,
        ref: renewed
          ? {
              ref: renewed.credential_ref,
              mode: renewed.mode,
              kind: renewed.kind,
              ...(renewed.credential_id
                ? { credentialId: renewed.credential_id }
                : {}),
              ...(renewed.expires_at
                ? { expiresAt: new Date(renewed.expires_at) }
                : {}),
              ...(renewed.models ? { models: renewed.models } : {}),
            }
          : credential.ref,
      };
      models = await inference.listModels(identity, credential.ref);
    }
    config = resolveEffectiveConfig(
      access,
      this.options.app.theme,
      preferences,
      credential.ref?.models,
    );
    notices.push(...config.notices);
    const runtimeConfig = await inference.configureRuntime({
      providerId: this.providerId,
      credential:
        credential.ref && this.credentialMode !== "none"
          ? credential.ref
          : null,
      models,
    });
    let selectedModel: string | undefined;
    const requested = options.requestedModel ?? config.values.model;
    if (runtimeConfig.kind === "managed-endpoint") {
      const allowed = config.allowedModels.filter((id) =>
        models.some((model) => model.id === id && model.availability.available),
      );
      if (!allowed.length)
        throw new PiShipError(
          "MODEL_UNAVAILABLE",
          "No allowed model is currently available",
          {
            component: "inference",
            sanitizedDetail: {
              models: models.map((model) => ({
                id: model.id,
                ...model.availability,
              })),
            },
          },
        );
      if (!requested)
        throw new PiShipError(
          "MODEL_DENIED",
          "No default model is configured",
          { component: "inference" },
        );
      selectedModel = (
        await inference.resolveModel(requested, { models, allowed })
      ).model.id;
    } else if (requested) {
      await inference.resolveModel(requested, {
        models: [],
        allowed: config.allowedModels,
      });
      selectedModel = requested;
    }
    return {
      identity,
      credential,
      models,
      runtime: runtimeConfig,
      config,
      selectedModel,
      notices,
    };
  }

  async #refreshIdentity(identity: IdentitySession): Promise<IdentitySession> {
    const provider = await this.identityProvider();
    if (!provider?.refresh)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The identity session expired",
        {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        },
      );
    const refreshed = await provider.refresh(identity);
    await this.#storeIdentity(refreshed);
    return refreshed;
  }

  /**
   * Request-time secret for the managed provider. Refreshes before expiry and,
   * after a gateway rejection, re-acquires once (force) before failing.
   */
  async requestSecret(
    options: { force?: boolean } = {},
  ): Promise<SecretValue | null> {
    const manager = await this.credentialManager();
    if (!manager.storesSecrets) return null;
    const status = manager.status();
    if (!options.force && status.state === "valid" && this.#secret)
      return this.#secret;
    const identity = await this.currentIdentity({
      required: manager.options.provider.requiresIdentity,
    });
    try {
      const active = await manager.ensure(identity, this.#credentialContext(), {
        allowAcquire:
          this.credentialMode === "http-broker" ||
          this.credentialMode === "adapter",
        ...(options.force ? { forceRefresh: true } : {}),
      });
      this.#secret = active.secret;
    } catch (error) {
      if (
        error instanceof PiShipError &&
        error.code === "IDENTITY_EXPIRED" &&
        identity
      ) {
        const refreshed = await this.#refreshIdentity(identity);
        const active = await manager.ensure(
          refreshed,
          this.#credentialContext(),
          {
            allowAcquire: true,
            ...(options.force ? { forceRefresh: true } : {}),
          },
        );
        this.#secret = active.secret;
      } else throw error;
    }
    return this.#secret;
  }

  /** Persist a gateway rejection of the current runtime credential. */
  async markCredentialRejected(): Promise<void> {
    (await this.credentialManager()).markRejected();
  }

  /** Token-free context for approved extensions. */
  enterpriseContext(
    activated: ActivatedAccess,
    selectedModel?: string,
  ): EnterpriseContext {
    const credential = activated.credential.ref;
    const chosen = selectedModel ?? activated.selectedModel;
    return deepFreeze({
      version: 1,
      distribution: {
        id: this.options.app.id,
        name: this.options.app.name,
        version: this.options.app.version,
        mode: this.options.mode,
      },
      identity: activated.identity
        ? {
            subject: activated.identity.subject,
            issuer: activated.identity.issuer,
            ...(activated.identity.displayName
              ? { displayName: activated.identity.displayName }
              : {}),
            ...(activated.identity.email
              ? { email: activated.identity.email }
              : {}),
          }
        : null,
      credential: {
        mode: this.credentialMode,
        ...(credential?.credentialId
          ? { credentialId: credential.credentialId }
          : {}),
        ...(credential?.expiresAt
          ? { expiresAt: credential.expiresAt.toISOString() }
          : {}),
      },
      inference: {
        provider:
          activated.runtime.kind === "pi-native"
            ? "pi-native"
            : (this.options.access?.inference.provider ?? "pi-native"),
        models: activated.models
          .filter(
            (model) =>
              model.availability.available &&
              activated.config.allowedModels.includes(model.id),
          )
          .map((model) => ({
            id: model.id,
            name: model.name,
            policyTags: [...model.policyTags],
          })),
        ...(this.options.access?.models.default
          ? { defaultModel: this.options.access.models.default }
          : {}),
        ...(chosen ? { selectedModel: chosen } : {}),
      },
      config: Object.fromEntries(
        activated.config.entries.map((entry) => [
          entry.key,
          { value: entry.value, source: entry.source },
        ]),
      ),
    } satisfies EnterpriseContext);
  }

  /** Non-secret status used by doctor and config explain. */
  async status(): Promise<{
    identity: IdentityMetadata | null;
    credential: CredentialStatus;
    store: string;
    refs: CredentialRef | null;
  }> {
    const manager = await this.credentialManager();
    const credential = manager.status();
    return {
      identity: this.readIdentityMetadata(),
      credential,
      store: this.store
        ? `${this.store.kind} (${this.store.description})`
        : "not used",
      refs: credential.metadata
        ? {
            ref: credential.metadata.credential_ref,
            mode: credential.metadata.mode,
            kind: credential.metadata.kind,
            ...(credential.metadata.credential_id
              ? { credentialId: credential.metadata.credential_id }
              : {}),
          }
        : null,
    };
  }

  /** Validate the requested model against the activated catalog (later selection). */
  static checkSelection(activated: ActivatedAccess, requested: string): void {
    if (activated.runtime.kind !== "managed-endpoint") return;
    resolveRequestedModel(requested, {
      models: activated.models,
      allowed: activated.config.allowedModels,
    });
  }
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>))
      deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

export interface ExplainRow {
  readonly key: string;
  readonly value: unknown;
  readonly source: string;
  readonly overridable: boolean;
  readonly note?: string;
}

/**
 * Explain every effective value and its source without secrets. Runtime
 * references show the template and whether it currently resolves; credential
 * state shows only references, identifiers, and expiry.
 */
export async function explainConfiguration(
  options: AccessOptions,
): Promise<ExplainRow[]> {
  const access = options.access;
  const env = options.env ?? process.env;
  const rows: ExplainRow[] = [
    {
      key: "schema",
      value: access ? "piship/v1alpha2" : "piship/v1alpha1",
      source: "manifest",
      overridable: false,
    },
    {
      key: "deployment.mode",
      value: options.mode,
      source: "distribution-enforced",
      overridable: false,
    },
  ];
  const reference = (key: string, template: string | undefined) => {
    if (template === undefined) return;
    let note: string;
    let value: unknown = template;
    try {
      const resolved = resolveTemplate(
        key,
        template,
        access?.variables ?? [],
        env,
      );
      note =
        resolved === template ? "static" : `resolves at runtime to ${resolved}`;
    } catch (error) {
      note = `unresolved: ${(error as Error).message}`;
      value = template;
    }
    rows.push({
      key,
      value,
      source: "distribution-enforced",
      overridable: false,
      note,
    });
  };
  if (!access) {
    rows.push(
      {
        key: "identity.mode",
        value: "none",
        source: "builtin-default",
        overridable: false,
      },
      {
        key: "credential.provider",
        value: "pi-native",
        source: "builtin-default",
        overridable: false,
        note: "Pi auth in isolated state",
      },
      {
        key: "inference.provider",
        value: "pi-native",
        source: "builtin-default",
        overridable: false,
      },
    );
  } else {
    rows.push({
      key: "identity.mode",
      value: access.identity.mode,
      source: "distribution-enforced",
      overridable: false,
    });
    if (access.identity.mode === "oidc") {
      reference("identity.oidc.issuer", access.identity.oidc.issuer);
      reference("identity.oidc.clientId", access.identity.oidc.clientId);
      reference("identity.oidc.audience", access.identity.oidc.audience);
      rows.push(
        {
          key: "identity.oidc.flow",
          value: "authorization_code_pkce (S256)",
          source: "distribution-enforced",
          overridable: false,
        },
        {
          key: "identity.oidc.redirectUri",
          value: access.identity.oidc.redirectUri,
          source: "distribution-enforced",
          overridable: false,
        },
        {
          key: "identity.oidc.scopes",
          value: access.identity.oidc.scopes,
          source: "distribution-enforced",
          overridable: false,
        },
      );
    }
    if (access.identity.mode === "adapter")
      rows.push({
        key: "identity.adapter",
        value: access.identity.adapter,
        source: "distribution-enforced",
        overridable: false,
      });
    rows.push({
      key: "credential.provider",
      value: access.credential.provider,
      source: "distribution-enforced",
      overridable: false,
    });
    reference("credential.broker.endpoint", access.credential.broker?.endpoint);
    reference(
      "credential.broker.revokeEndpoint",
      access.credential.broker?.revokeEndpoint,
    );
    if (!["pi-native", "none"].includes(access.credential.provider))
      rows.push(
        {
          key: "credential.storage",
          value: access.credential.storage.provider,
          source: "distribution-enforced",
          overridable: false,
          ...(access.credential.storage.provider === "file"
            ? {
                note: "plaintext fallback, explicitly opted in; not equivalent to platform secure storage",
              }
            : {}),
        },
        {
          key: "credential.refresh.beforeExpiry",
          value: `${access.credential.refresh.beforeExpirySeconds}s`,
          source: "distribution-enforced",
          overridable: false,
        },
      );
    rows.push({
      key: "inference.provider",
      value: access.inference.provider,
      source: "distribution-enforced",
      overridable: false,
    });
    reference("inference.baseUrl", access.inference.baseUrl);
    if (access.models.catalog.length)
      rows.push({
        key: "models.catalog",
        value: access.models.catalog.map(
          (model) =>
            `${model.id} (${model.name}; ctx ${model.contextWindow}; tags ${model.policyTags.join("|") || "-"})`,
        ),
        source: "distribution-enforced",
        overridable: false,
      });
    rows.push(
      {
        key: "network.publicFallback",
        value: access.network.publicFallback,
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.privateOnly",
        value: access.network.privateOnly,
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.proxy.inheritEnvironment",
        value: access.network.proxy.inheritEnvironment,
        source: "distribution-enforced",
        overridable: false,
      },
      {
        key: "network.tls.verification",
        value: "always on",
        source: "builtin-default",
        overridable: false,
      },
    );
    for (const [index, path] of access.network.tls.additionalCA.entries())
      reference(`network.tls.additionalCA[${index}]`, path);
  }
  const paths = accessStatePaths(options.stateDir);
  let preferences: ReturnType<typeof readPreferences> = {
    schema: "piship-preferences/v1",
    values: {},
  };
  let credentialModels: readonly string[] | undefined;
  try {
    const status = await DistributionAccess.open(options).status();
    credentialModels = status.credential.metadata?.models;
    rows.push({
      key: "identity.session",
      value: status.identity
        ? {
            subject: status.identity.subject,
            issuer: status.identity.issuer,
            expiresAt: status.identity.expiresAt ?? null,
          }
        : null,
      source: "runtime-state",
      overridable: false,
    });
    rows.push({
      key: "credential.state",
      value: {
        state: status.credential.state,
        ref: status.refs?.ref ?? null,
        credentialId: status.refs?.credentialId ?? null,
        expiresAt: status.credential.metadata?.expires_at ?? null,
        store: status.store,
      },
      source: "runtime-state",
      overridable: false,
      ...(status.credential.notice ? { note: status.credential.notice } : {}),
    });
  } catch (error) {
    rows.push({
      key: "credential.state",
      value: null,
      source: "runtime-state",
      overridable: false,
      note: redact((error as Error).message),
    });
  }
  try {
    preferences = readPreferences(paths.preferences);
  } catch (error) {
    rows.push({
      key: "preferences",
      value: null,
      source: "user-preference",
      overridable: false,
      note: redact((error as Error).message),
    });
  }
  const effective = resolveEffectiveConfig(
    access,
    options.app.theme,
    preferences,
    credentialModels,
  );
  for (const entry of effective.entries) rows.push(entry);
  for (const notice of effective.notices)
    rows.push({
      key: "notice",
      value: notice,
      source: "user-preference",
      overridable: false,
    });
  return rows;
}

/** Render explanation rows for a terminal, redacted. */
export function formatExplanation(
  appName: string,
  rows: readonly ExplainRow[],
): string {
  return [
    `${appName} configuration (Distribution Enforced > Distribution Defaults > User Preferences; enforced values cannot be overridden, permitted user preferences replace defaults)`,
    ...rows.map((row) =>
      redact(
        `${row.key.padEnd(34)} ${JSON.stringify(row.value)}  [${row.source}${row.overridable ? ", user-overridable" : ""}]${row.note ? ` — ${row.note}` : ""}`,
      ),
    ),
  ].join("\n");
}
