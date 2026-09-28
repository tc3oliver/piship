import { existsSync, readFileSync, rmSync } from "node:fs";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  createManagedFetch,
  type EnterpriseContext,
  type IdentityProvider,
  type IdentitySession,
  type InferenceProvider,
  type LoginContext,
  type ManagedFetch,
  type ModelDefinition,
  type NetworkPolicy,
  PiShipError,
  redact,
  type SecretStore,
  type SecretValue,
} from "@piship/contracts";
import {
  type ActiveCredential,
  type CredentialEvent,
  CredentialManager,
  type CredentialStatus,
  createSecretStore,
  HttpBrokerCredentialProvider,
  LocalSecretCredentialProvider,
  metadataSecretRefs,
  NoCredentialProvider,
  PiNativeCredentialProvider,
  type RevocationOutcome,
  withFileLock,
} from "@piship/credentials";
import {
  type IdentityMetadata,
  identityMetadata,
  identitySecret,
  normalizedIdentityProvider,
  OidcPkceIdentityProvider,
  parseIdentityMetadata,
  restoreIdentitySession,
} from "@piship/identity";
import {
  OpenAICompatibleInferenceProvider,
  PiNativeInferenceProvider,
  resolveRequestedModel,
} from "@piship/inference";
import { incompatibleCapabilities } from "@piship/policy";
import type { AccessManifest } from "@piship/schema";
import { readPreferences, resolveEffectiveConfig } from "../config.js";
import { type AdapterContext, loadAdapter } from "./adapters.js";
import { type AccessMetrics, recordGatewayResult } from "./metrics.js";
import { modelIncompatible } from "./models.js";
import {
  networkPolicyFor,
  type ResolvedEndpoints,
  resolveRuntimeReferences,
} from "./network.js";
import {
  type AccessStatePaths,
  accessStatePaths,
  writeJsonAtomic,
} from "./state.js";
import type { AccessEvent, AccessOptions, ActivatedAccess } from "./types.js";

function rejectedUserSecret(command: string): PiShipError {
  return new PiShipError(
    "CREDENTIAL_REVOKED",
    "The gateway rejected the stored secret",
    {
      component: "credential",
      userAction: `Check the key, then run ${command} login to replace it if it is no longer valid`,
    },
  );
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
  /** The last acquire or refresh the credential manager reported. */
  #credentialChange: CredentialEvent["event"] | undefined;
  /** Whether this instance already recorded gateway reachability. */
  #gatewayRecorded = false;
  readonly #now: () => number;

  private constructor(readonly options: AccessOptions) {
    const env = options.env ?? process.env;
    this.#now = options.now ?? Date.now;
    this.endpoints = options.access
      ? resolveRuntimeReferences(options.access, env)
      : { additionalCA: [] };
    this.network = networkPolicyFor(
      options.access,
      this.endpoints,
      options.mode,
    );
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

  #emit(event: AccessEvent["event"], detail: AccessEvent["detail"]): void {
    try {
      this.options.onEvent?.({ event, detail });
    } catch {
      // Event consumers never break sign-in, launch, or sign-out.
    }
  }

  #metric(record: (metrics: AccessMetrics) => void): void {
    const metrics = this.options.metrics;
    if (!metrics) return;
    try {
      record(metrics);
    } catch {
      // Metrics never break sign-in, launch, or sign-out.
    }
  }

  /** Load an identity or credential adapter, counting a failure by its code. */
  async #loadAdapter<T>(path: string, kind: string): Promise<T> {
    try {
      return await loadAdapter<T>(
        this.options.distributionDir,
        path,
        kind,
        this.#context(),
      );
    } catch (error) {
      this.#metric((metrics) =>
        metrics.recordLoadFailure(
          "provider",
          error instanceof PiShipError ? error.code : "UNKNOWN",
        ),
      );
      throw error;
    }
  }

  /** Time an identity sign-in or session check that produced a session. */
  async #timedIdentity<T>(task: () => Promise<T>): Promise<T> {
    const started = this.#now();
    const result = await task();
    if (result)
      this.#metric((metrics) =>
        metrics.recordIdentityLatency(this.#now() - started),
      );
    return result;
  }

  /**
   * Ensure the runtime credential and, when that acquired or refreshed an
   * organization-issued credential, record how long it took. Reusing a stored
   * credential is not an acquisition, and a user-entered secret measures the
   * person, not the system, so neither is recorded.
   */
  async #ensureCredential(
    manager: CredentialManager,
    identity: IdentitySession | null,
    ctx: CredentialContext,
    options: { allowAcquire: boolean; forceRefresh?: boolean },
  ): Promise<ActiveCredential> {
    const started = this.#now();
    this.#credentialChange = undefined;
    const active = await manager.ensure(identity, ctx, options);
    const change = this.#credentialChange;
    this.#credentialChange = undefined;
    if (
      manager.renewable &&
      (change === "credential.acquire" || change === "credential.refresh")
    )
      this.#metric((metrics) =>
        metrics.recordCredentialLatency(
          change === "credential.acquire" ? "acquire" : "refresh",
          this.#now() - started,
        ),
      );
    return active;
  }

  /**
   * List the catalog. A live catalog is fetched from the gateway, so its
   * result is also the gateway's reachability and a catalog fetch.
   */
  async #listModels(
    inference: InferenceProvider,
    identity: IdentitySession | null,
    credential: CredentialRef | null,
  ): Promise<ModelDefinition[]> {
    const live =
      inference.kind === "openai-compatible" &&
      !!this.options.access?.inference.liveCatalog;
    try {
      const models = await inference.listModels(identity, credential);
      if (live) {
        this.#gatewayRecorded = true;
        recordGatewayResult(this.options.metrics);
        this.#metric((metrics) =>
          metrics.recordModelCatalogFetch(models.length),
        );
      }
      return models;
    } catch (error) {
      if (live) {
        this.#gatewayRecorded = true;
        recordGatewayResult(this.options.metrics, error);
      }
      throw error;
    }
  }

  /**
   * GET the gateway model list (doctor). Undefined when inference is not an
   * OpenAI-compatible endpoint. Reachability is recorded once per access
   * instance: when activation already fetched the live catalog, the probe
   * does not count the same gateway again.
   */
  async probeGateway(): Promise<string[] | undefined> {
    const inference = this.inferenceProvider();
    if (!(inference instanceof OpenAICompatibleInferenceProvider))
      return undefined;
    const record = !this.#gatewayRecorded;
    this.#gatewayRecorded = true;
    try {
      const listed = await inference.probe();
      if (record) recordGatewayResult(this.options.metrics);
      return listed;
    } catch (error) {
      if (record) recordGatewayResult(this.options.metrics, error);
      throw error;
    }
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
      this.#identity = normalizedIdentityProvider(
        await this.#loadAdapter<IdentityProvider>(identity.adapter, "identity"),
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
      provider = await this.#loadAdapter<CredentialProvider>(
        access?.credential.adapter ?? "",
        "credential",
      );
    else provider = new PiNativeCredentialProvider();
    if (provider.requiresIdentity && this.identityMode === "none")
      throw new PiShipError(
        "CONFIG_INVALID",
        `The ${mode} credential provider requires a signed-in identity, but identity.mode is none`,
        {
          component: "credential",
          userAction:
            "Configure identity.mode (oidc or adapter), or use a credential provider that does not require identity",
        },
      );
    this.#credential = new CredentialManager({
      distributionId: this.options.app.id,
      provider,
      store: this.store,
      metadataPath: this.paths.credential,
      beforeExpirySeconds:
        access?.credential.refresh.beforeExpirySeconds ?? 300,
      now: this.#now,
      onEvent: (event) => {
        if (event.event !== "credential.revoke")
          this.#credentialChange = event.event;
        this.#emit(event.event, event.detail);
      },
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
    return this.#timedIdentity(() => this.#checkIdentity(provider, options));
  }

  async #checkIdentity(
    provider: IdentityProvider,
    options: { required: boolean },
  ): Promise<IdentitySession | null> {
    const metadata = this.readIdentityMetadata();
    if (!metadata) {
      if (existsSync(this.paths.identity)) {
        // Delete the token bundle unusable metadata may still reference.
        let stale: unknown;
        try {
          stale = JSON.parse(readFileSync(this.paths.identity, "utf8"));
        } catch {
          stale = null;
        }
        const ref = (stale as { secretRef?: unknown } | null)?.secretRef;
        if (
          typeof ref === "string" &&
          ref.startsWith(`piship:${this.options.app.id}:identity#`)
        )
          await this.store?.delete(ref).catch(() => {});
        rmSync(this.paths.identity, { force: true });
      }
      if (!options.required) return null;
      throw new PiShipError("IDENTITY_REQUIRED", "You are not signed in", {
        component: "identity",
        userAction: `Run ${this.options.app.command} login`,
      });
    }
    const secret = await this.store?.get(metadata.secretRef);
    const session = restoreIdentitySession(metadata, secret ?? null);
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
      return this.#refreshShared(provider, session, "expiring");
    }
    return session;
  }

  /** Reload the stored identity session, or null when there is none. */
  async #storedIdentity(): Promise<IdentitySession | null> {
    const metadata = this.readIdentityMetadata();
    if (!metadata) return null;
    const secret = await this.store?.get(metadata.secretRef);
    const session = restoreIdentitySession(metadata, secret ?? null);
    return session.accessToken ? session : null;
  }

  /**
   * Refresh the identity session once across processes. Refresh tokens may
   * rotate on use, so concurrent launches share a lock beside the session
   * metadata; a caller that finds a session another process already
   * refreshed uses it instead of spending the old refresh token.
   */
  async #refreshShared(
    provider: IdentityProvider,
    observed: IdentitySession,
    reason: "expiring" | "rejected",
  ): Promise<IdentitySession> {
    const refresh = provider.refresh?.bind(provider);
    if (!refresh)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The identity session expired",
        {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        },
      );
    return withFileLock(this.paths.identity, async () => {
      const stored = await this.#storedIdentity();
      if (
        stored &&
        stored.subject === observed.subject &&
        !stored.accessToken?.equals(observed.accessToken)
      )
        return stored;
      const refreshed = await refresh(stored ?? observed);
      await this.#storeIdentity(refreshed);
      this.#emit("identity.refresh", {
        reason,
        expiresAt: refreshed.expiresAt?.toISOString() ?? null,
      });
      return refreshed;
    });
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
      identity = await this.#timedIdentity(() =>
        provider.login({
          openUrl: ctx.openUrl,
          ...(ctx.signal ? { signal: ctx.signal } : {}),
        }),
      );
      await this.#storeIdentity(identity);
      this.#emit("identity.login", {
        expiresAt: identity.expiresAt?.toISOString() ?? null,
      });
    }
    const manager = await this.credentialManager();
    const notices: string[] = [];
    if (manager.storesSecrets) {
      // A fresh login always replaces the runtime credential, revoking the
      // previous one where supported (audited as credential.revoke).
      const problems = await manager
        .logout(this.#credentialContext(), { reason: "replace" })
        .catch((error: Error) => [redact(error.message)]);
      for (const problem of problems)
        notices.push(
          `The previous credential was not fully cleared: ${problem}`,
        );
      const active = await this.#ensureCredential(
        manager,
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
      let revocation: "completed" | "failed" | "unsupported" | "skipped" =
        provider?.logout ? "skipped" : "unsupported";
      if (provider?.logout && secret)
        try {
          await provider.logout(restoreIdentitySession(metadata, secret));
          revocation = "completed";
        } catch (error) {
          revocation = "failed";
          problems.push(
            `identity revocation: ${redact((error as Error).message)}`,
          );
        }
      for (const ref of metadataSecretRefs(metadata, this.options.app.id))
        await this.store
          .delete(ref)
          .catch((error: Error) =>
            problems.push(`identity secret: ${redact(error.message)}`),
          );
      this.#emit("identity.logout", { revocation });
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
      credential = await this.#ensureCredential(
        manager,
        identity,
        this.#credentialContext(),
        {
          allowAcquire:
            this.credentialMode === "http-broker" ||
            this.credentialMode === "adapter",
        },
      );
    } catch (error) {
      if (
        error instanceof PiShipError &&
        error.code === "IDENTITY_EXPIRED" &&
        identity
      ) {
        const refreshed = await this.#refreshIdentity(identity);
        credential = await this.#ensureCredential(
          manager,
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
      models = await this.#listModels(inference, identity, credential.ref);
    } catch (error) {
      // A gateway rejection of a stored credential gets one automatic renewal.
      if (
        !(error instanceof PiShipError) ||
        error.code !== "CREDENTIAL_REVOKED" ||
        !manager.storesSecrets
      )
        throw error;
      // A user-owned secret cannot be renewed automatically; leave it in
      // place (the rejection may be transient) and ask for a new one.
      if (!manager.renewable)
        throw rejectedUserSecret(this.options.app.command);
      await manager.markRejected();
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
      models = await this.#listModels(inference, identity, credential.ref);
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
    let incompatibleModels: Record<string, string> = {};
    const capabilities = this.options.capabilities ?? [];
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
      const resolved = (
        await inference.resolveModel(requested, { models, allowed })
      ).model;
      selectedModel = resolved.id;
      const incompatible: Record<string, string> = {};
      for (const id of allowed) {
        const gaps = incompatibleCapabilities(
          models.find((model) => model.id === id),
          capabilities,
        );
        if (gaps.length)
          incompatible[id] = gaps
            .map((gap) => `${gap.capability}: ${gap.reasons.join("; ")}`)
            .join(", ");
      }
      incompatibleModels = incompatible;
      const gaps = incompatibleCapabilities(resolved, capabilities);
      if (gaps.length)
        throw modelIncompatible(
          `${this.providerId}/${resolved.id}`,
          gaps,
          allowed.filter((id) => !incompatible[id]),
        );
    } else if (requested) {
      if (config.modelsRestricted && !config.allowedModels.includes(requested))
        throw new PiShipError(
          "MODEL_DENIED",
          `Model ${requested} is not allowed by this distribution`,
          { component: "inference" },
        );
      const resolved = await inference.resolveModel(requested, {
        models: [],
        allowed: config.allowedModels,
      });
      selectedModel = requested;
      const gaps = incompatibleCapabilities(resolved.model, capabilities);
      if (gaps.length) throw modelIncompatible(requested, gaps, []);
    } else {
      // Pi chooses the model and PiShip has no verified metadata for it.
      const gaps = incompatibleCapabilities(undefined, capabilities);
      if (gaps.length) throw modelIncompatible("(selected by Pi)", gaps, []);
    }
    return {
      identity,
      credential,
      models,
      runtime: runtimeConfig,
      config,
      selectedModel,
      incompatibleModels,
      notices,
    };
  }

  async #refreshIdentity(identity: IdentitySession): Promise<IdentitySession> {
    const provider = await this.identityProvider();
    if (!provider)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The identity session expired",
        {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        },
      );
    return this.#timedIdentity(() =>
      this.#refreshShared(provider, identity, "rejected"),
    );
  }

  /**
   * Best-effort remote revocation of the current runtime credential before
   * an update, rollback, or migration clears it. Local clearing is the
   * caller's job and happens whatever the outcome.
   */
  async revokeCredential(): Promise<{
    readonly outcome: RevocationOutcome | "absent";
    readonly problem?: string;
  }> {
    const manager = await this.credentialManager();
    return manager.revoke(this.#credentialContext(), "lifecycle");
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
    if (options.force && !manager.renewable)
      throw rejectedUserSecret(this.options.app.command);
    const status = manager.status();
    if (!options.force && status.state === "valid" && this.#secret)
      return this.#secret;
    const identity = await this.currentIdentity({
      required: manager.options.provider.requiresIdentity,
    });
    try {
      const active = await this.#ensureCredential(
        manager,
        identity,
        this.#credentialContext(),
        {
          allowAcquire:
            this.credentialMode === "http-broker" ||
            this.credentialMode === "adapter",
          ...(options.force ? { forceRefresh: true } : {}),
        },
      );
      this.#secret = active.secret;
    } catch (error) {
      if (
        error instanceof PiShipError &&
        error.code === "IDENTITY_EXPIRED" &&
        identity
      ) {
        const refreshed = await this.#refreshIdentity(identity);
        const active = await this.#ensureCredential(
          manager,
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
    await (await this.credentialManager()).markRejected();
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
    const reason = activated.incompatibleModels[requested];
    if (reason)
      throw new PiShipError(
        "MODEL_INCOMPATIBLE",
        `Model ${requested} does not meet capability model requirements (${reason})`,
        { component: "inference", retryable: false },
      );
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
