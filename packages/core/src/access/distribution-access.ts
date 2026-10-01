import { existsSync, readFileSync, rmSync } from "node:fs";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  createManagedFetch,
  type EnterpriseContext,
  type IdentityProvider,
  type IdentitySession,
  formatError,
  type InferenceProvider,
  type LoginContext,
  type ManagedFetch,
  type ModelDefinition,
  type NetworkPolicy,
  PiShipError,
  type PrincipalKey,
  principalKey,
  redact,
  type SecretStore,
  type SecretValue,
  samePrincipal,
} from "@piship/contracts";
import {
  type ActiveCredential,
  type CredentialEvent,
  CredentialManager,
  type CredentialStatus,
  createSecretStore,
  deleteSecretsVerified,
  deletionFailure,
  HttpBrokerCredentialProvider,
  LocalSecretCredentialProvider,
  metadataFileSecretRefs,
  metadataSecretRefs,
  NoCredentialProvider,
  metadataFileSecretStore,
  type PendingRevocations,
  PiNativeCredentialProvider,
  readPendingRevocations,
  type RevocationOutcome,
  type SecretStoreProvider,
  type SecretStoreResolver,
  storeForRecorded,
  withFileLock,
} from "@piship/credentials";
import {
  type IdentityMetadata,
  identityMetadata,
  identitySecret,
  isWorkloadIdentityProvider,
  normalizedIdentityProvider,
  assertSamePrincipal,
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
import { SandboxCredential, type SignedInGuard } from "./sandbox-credential.js";
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
 * A refused model selection with the recovery for where the model came from:
 * a stale user preference is removed with `config unset model`; another model
 * is chosen with `--model`. An enforced model has no user recovery.
 */
function withModelRecovery(
  error: unknown,
  command: string,
  source: string | undefined,
): unknown {
  if (
    !(error instanceof PiShipError) ||
    (error.code !== "MODEL_UNAVAILABLE" && error.code !== "MODEL_DENIED") ||
    !(
      source === "flag" ||
      source === "user-preference" ||
      source === "distribution-default"
    )
  )
    return error;
  const recovery =
    source === "user-preference"
      ? `Run ${command} config unset model to remove the model preference, or start ${command} --model <model>`
      : `Start ${command} --model <model>`;
  return new PiShipError(error.code, error.message, {
    component: error.component ?? "inference",
    userAction: `${error.userAction ? `${error.userAction}. ` : ""}${recovery}; ${command} models lists the models`,
    ...(error.sanitizedDetail
      ? { sanitizedDetail: error.sanitizedDetail }
      : {}),
  });
}

/** What activation and renewal ask of `CredentialManager.ensure`. */
type CredentialEnsureOptions = Omit<
  Parameters<CredentialManager["ensure"]>[2],
  "guard"
>;

const PRINCIPAL_BINDING_SCHEMA = "piship-principal-binding/v1";
/**
 * What `identity/session.json` becomes when the token bundles of a signed-out
 * or replaced identity session could not all be deleted: only the references
 * still to delete, with no token, subject, or claim. No release restores it
 * as a session (older ones see an incompatible schema), and every command
 * that reads the identity retries the deletion first and fails closed while
 * it cannot.
 */
const IDENTITY_DISCARDED_SCHEMA = "piship-identity-discarded/v1";

/**
 * Leave a discarded marker in place of identity metadata whose token bundles
 * could not all be deleted: it names the orphans so they stay tracked and is
 * never restored as a session.
 */
export function writeIdentityDiscardedMarker(
  path: string,
  orphans: string[],
  now: Date = new Date(),
  /** The secret store that holds the orphans, when it is known. */
  store?: SecretStoreProvider,
): void {
  writeJsonAtomic(path, {
    schema: IDENTITY_DISCARDED_SCHEMA,
    orphans: [...orphans].sort(),
    ...(store ? { secret_store: store } : {}),
    discarded_at: now.toISOString(),
  });
}
/** How long a workload identity adapter's `login()` may take. */
const WORKLOAD_LOGIN_TIMEOUT_MS = 30_000;
/**
 * A workload session is obtained again after this long even when it is
 * valid for longer, so a token the platform rotated is picked up.
 */
const WORKLOAD_SESSION_MAX_AGE_MS = 5 * 60_000;

/**
 * The refusal a workload identity adapter gets for `openUrl`. A workload
 * never has a person to send to a browser, so asking for one fails the run.
 */
function browserRefused(): PiShipError {
  return new PiShipError(
    "IDENTITY_INVALID",
    "A non-interactive identity adapter tried to open a browser",
    {
      component: "identity",
      userAction:
        "A workload identity adapter must obtain its session without a person; fix the adapter or declare it interactive",
    },
  );
}

/** A running session whose signed-in user is no longer the one it started with. */
function principalChanged(command: string, signedOut = false): PiShipError {
  return new PiShipError(
    "IDENTITY_REQUIRED",
    signedOut
      ? "You signed out in another session; restart the session"
      : "The signed-in user changed; restart the session",
    {
      component: "identity",
      userAction: signedOut
        ? `Run ${command} login, then start ${command} again`
        : `Start ${command} again to continue as the signed-in user`,
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
  /** The configured `credential.storage.provider`, recorded in metadata. */
  readonly storeProvider: SecretStoreProvider;
  readonly #fetch: ManagedFetch;
  #identity: IdentityProvider | null | undefined;
  #credential: CredentialManager | undefined;
  #secret: SecretValue | null = null;
  /** The credential generation `#secret` belongs to. */
  #secretRef: string | undefined;
  #secretAcquiredAt: string | undefined;
  /**
   * The principal this instance serves, pinned by its first `activate()` or
   * `login()` (null without identity). A running session never switches
   * users: once pinned, another principal is refused, and only `login()`,
   * which is the switch, pins again.
   */
  #principal: PrincipalKey | null | undefined;
  /** A workload identity session, held for this process only and never stored. */
  #workload: IdentitySession | null = null;
  /** When `#workload` was obtained (the injected clock). */
  #workloadAt = 0;
  /** The workload `login()` in flight, shared by concurrent callers. */
  #workloadPending: Promise<IdentitySession> | null = null;
  /** The credential (reference and acquisition time) a model denial re-read. */
  #entitlementReread: string | undefined;
  /** Notices from obtaining a workload identity, reported by the next activation. */
  #identityNotices: string[] = [];
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
    this.storeProvider =
      options.access?.credential.storage.provider ?? "system";
    this.store = needsStore
      ? (options.secretStore ??
        createSecretStore({
          provider: this.storeProvider,
          fileDirectory: this.paths.secrets,
        }))
      : null;
  }

  /**
   * The store of another provider than the configured one, holding what
   * state recorded for it before `credential.storage.provider` changed.
   */
  readonly #storeFor: SecretStoreResolver = (provider) =>
    this.options.secretStoreFor
      ? this.options.secretStoreFor(provider)
      : this.options.secretStore
        ? null
        : createSecretStore({ provider, fileDirectory: this.paths.secrets });

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
    options: CredentialEnsureOptions,
    underLock?: () => void,
  ): Promise<ActiveCredential> {
    const started = this.#now();
    this.#credentialChange = undefined;
    const active = await manager.ensure(identity, ctx, {
      ...options,
      guard: () => {
        this.#assertSignedIn(identity);
        underLock?.();
      },
    });
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

  /**
   * The stored sandbox credential slot, in the distribution's configured
   * store, for `principal`. Login clears it when another principal signs in,
   * and logout clears it.
   */
  sandboxCredential(principal: PrincipalKey | null = null): SandboxCredential {
    const store = this.store ?? this.options.secretStore;
    return new SandboxCredential({
      distributionId: this.options.app.id,
      command: this.options.app.command,
      stateDir: this.options.stateDir,
      ...(this.options.access
        ? { storage: this.options.access.credential.storage }
        : {}),
      ...(store ? { secretStore: store } : {}),
      // Always this access's rule for the other store, the one the runtime
      // credential and the identity follow, not the slot's own default (which
      // opens it for any injected store that is not in memory).
      secretStoreFor: this.#storeFor,
      principal,
      onEvent: (event) => this.#emit(event.event, event.detail),
      ...(this.options.onPhase ? { onPhase: this.options.onPhase } : {}),
      now: this.#now,
    });
  }

  // ------------------------------------------------------------ principal pin

  /**
   * Pin this instance to `identity`'s principal, or confirm it is the pinned
   * one. Another principal means the user changed under a running session:
   * the cached secret is dropped and the call fails.
   */
  #pin(identity: IdentitySession | null): void {
    const principal = identity ? principalKey(identity) : null;
    if (this.#principal === undefined) {
      this.#principal = principal;
      return;
    }
    if (samePrincipal(this.#principal, principal)) return;
    this.#forgetSecret();
    throw principalChanged(this.options.app.command);
  }

  #forgetSecret(): void {
    this.#secret = null;
    this.#secretRef = undefined;
    this.#secretAcquiredAt = undefined;
  }

  #hold(active: ActiveCredential): void {
    this.#secret = active.secret;
    this.#secretRef = active.ref?.ref;
    this.#secretAcquiredAt = active.acquiredAt;
  }

  /**
   * Under the credential lock, before a credential is read, used, or
   * acquired for `identity`: a person's session must still be the stored
   * one. Another process may have signed another user in (or signed out)
   * after `identity` was read; acting on it then would discard the new
   * user's credential and store one issued to the previous user. A workload
   * session is never stored; it is pinned to its process instead.
   */
  #assertSignedIn(identity: IdentitySession | null): void {
    const provider = this.#identity;
    if (!identity || !provider || isWorkloadIdentityProvider(provider)) return;
    const stored = this.readIdentityMetadata();
    if (stored && samePrincipal(stored, principalKey(identity))) return;
    this.#forgetSecret();
    throw principalChanged(this.options.app.command, !stored);
  }

  /**
   * For something bound to `principal` (the stored sandbox credential): runs
   * a task holding the identity lock after checking that `principal` is still
   * the signed-in user, and throws, running nothing, when it is not. Undefined
   * when there is no stored interactive identity to check (no identity, or a
   * workload identity, whose principal comes from the workload).
   */
  async signedInGuard(
    principal: PrincipalKey | null,
  ): Promise<SignedInGuard | undefined> {
    if (
      !principal ||
      this.identityMode === "none" ||
      (await this.usesWorkloadIdentity())
    )
      return undefined;
    return (task) =>
      withFileLock(this.paths.identity, async () => {
        const stored = this.readIdentityMetadata();
        if (!stored || !samePrincipal(stored, principal))
          throw principalChanged(this.options.app.command, !stored);
        return task();
      });
  }

  /** Whether the identity provider is a workload identity adapter. */
  async usesWorkloadIdentity(): Promise<boolean> {
    const provider = await this.identityProvider();
    return !!provider && isWorkloadIdentityProvider(provider);
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
      revocationRetryPath: this.paths.revocationRetry,
      issuancePath: this.paths.credentialIssuance,
      // An adapter's requests go where its module and the resolved
      // endpoints send them; a broker's to its endpoint (the default).
      ...(mode === "adapter"
        ? {
            issuanceTarget: `adapter ${access?.credential.adapter ?? ""} ${JSON.stringify(this.endpoints)}`,
          }
        : {}),
      storeProvider: this.storeProvider,
      storeFor: this.#storeFor,
      ...(this.options.onPhase ? { onPhase: this.options.onPhase } : {}),
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

  /**
   * The stored identity session's metadata, or null when there is none it
   * can be restored from: a discarded marker, an incompatible or damaged
   * file, or a session whose tokens another secret store holds than the
   * configured one (the storage provider changed), which is never looked up
   * in this store.
   */
  readIdentityMetadata(): IdentityMetadata | null {
    if (!existsSync(this.paths.identity)) return null;
    try {
      const raw = JSON.parse(readFileSync(this.paths.identity, "utf8")) as {
        secret_store?: unknown;
      };
      if (
        raw?.secret_store !== undefined &&
        raw.secret_store !== this.storeProvider
      )
        return null;
      return parseIdentityMetadata(raw);
    } catch {
      return null;
    }
  }

  /**
   * The principal that owns this state's user-scoped PiShip data (credential,
   * entitlement, model selection). Kept by logout, so the next sign-in knows
   * whether the user changed. `undefined` when the record is unreadable.
   */
  readPrincipalBinding(): PrincipalKey | null | undefined {
    if (!existsSync(this.paths.principal)) return null;
    try {
      const value = JSON.parse(readFileSync(this.paths.principal, "utf8")) as {
        schema?: unknown;
      };
      if (value.schema !== PRINCIPAL_BINDING_SCHEMA) return undefined;
      return principalKey(value as { issuer?: unknown; subject?: unknown });
    } catch {
      return undefined;
    }
  }

  #writePrincipalBinding(principal: PrincipalKey): void {
    writeJsonAtomic(this.paths.principal, {
      schema: PRINCIPAL_BINDING_SCHEMA,
      issuer: principal.issuer,
      subject: principal.subject,
      bound_at: new Date(this.#now()).toISOString(),
    });
  }

  /**
   * Drop the model selection (`model` and the `modelsAllowed` narrowing) from
   * the user preferences: it was made by another principal from that
   * principal's entitlement. Other preferences stay. Unreadable preferences
   * are left for launch to refuse.
   */
  #clearModelSelection(): boolean {
    let value: Record<string, unknown>;
    try {
      value = JSON.parse(readFileSync(this.paths.preferences, "utf8"));
    } catch {
      return false;
    }
    if (!value || typeof value !== "object") return false;
    const values =
      value.values && typeof value.values === "object"
        ? { ...(value.values as Record<string, unknown>) }
        : undefined;
    if (!values?.model && !("modelsAllowed" in value)) return false;
    if (values) delete values.model;
    const { modelsAllowed: _dropped, ...rest } = value;
    writeJsonAtomic(this.paths.preferences, {
      ...rest,
      ...(values ? { values } : {}),
    });
    return true;
  }

  /**
   * Bind the state to `principal`. When another principal owned it, the model
   * selection is invalidated first; the credential is bound and checked on
   * its own. A missing or unreadable binding may have been anyone's (state
   * from before bindings existed, where the previous user signed out), so it
   * counts as a change unless the stored session is this principal's.
   * Returns whether the principal changed, whether a previous principal was
   * known to differ, and whether a model selection was cleared.
   */
  #bindPrincipal(principal: PrincipalKey): {
    changed: boolean;
    known: boolean;
    cleared: boolean;
  } {
    const bound = this.readPrincipalBinding();
    const stored = this.readIdentityMetadata();
    const known =
      bound === undefined ||
      [bound, stored].some(
        (previous) => !!previous && !samePrincipal(previous, principal),
      );
    const changed =
      known ||
      (bound === null && !(stored && samePrincipal(stored, principal)));
    const cleared = changed && this.#clearModelSelection();
    if (!bound || !samePrincipal(bound, principal))
      this.#writePrincipalBinding(principal);
    return { changed, known, cleared };
  }

  /** The stored identity file as JSON, whatever its schema; null when unreadable. */
  #readIdentityRaw(): unknown {
    try {
      return JSON.parse(readFileSync(this.paths.identity, "utf8"));
    } catch {
      return null;
    }
  }

  /**
   * Delete every token bundle `raw` (identity metadata or a discarded
   * marker) references, and every one the file names in its text (so a
   * damaged file that is no longer JSON is not taken to name nothing),
   * confirming each deletion, then the file. What cannot be deleted is kept
   * in a discarded marker in its place, so it stays tracked and is never
   * restored as a session; the failures are returned. The caller holds the
   * identity lock.
   */
  async #discardIdentity(
    raw: unknown,
  ): Promise<{ ref: string; problem: string }[]> {
    const refs = [
      ...new Set([
        ...metadataSecretRefs(raw, this.options.app.id),
        ...metadataFileSecretRefs(
          this.paths.identity,
          this.options.app.id,
          "identity",
        ),
      ]),
    ].sort();
    // Deleted from the store that holds them: after a storage provider
    // change, the one the file records, never looked up in this one.
    const recorded =
      metadataFileSecretStore(this.paths.identity) ?? this.storeProvider;
    const store = storeForRecorded(
      this.store,
      this.storeProvider,
      recorded,
      this.#storeFor,
    );
    const failed = store
      ? await deleteSecretsVerified(store, refs)
      : refs.map((ref) => ({
          ref,
          problem:
            recorded === this.storeProvider
              ? "no secret store is configured"
              : `the ${recorded} secret store that holds it is not available`,
        }));
    if (!failed.length) rmSync(this.paths.identity, { force: true });
    else
      writeIdentityDiscardedMarker(
        this.paths.identity,
        failed.map((item) => item.ref),
        new Date(this.#now()),
        recorded,
      );
    return failed;
  }

  /**
   * Clear an identity file no session can be restored from (a discarded
   * marker, metadata of an incompatible version, or a damaged file), deleting
   * the token bundles it names first. Fails closed while one cannot be
   * deleted; the marker keeps it tracked for the next command.
   */
  async #clearUnusableIdentity(): Promise<void> {
    if (!existsSync(this.paths.identity) || this.readIdentityMetadata()) return;
    await withFileLock(this.paths.identity, async () => {
      if (!existsSync(this.paths.identity) || this.readIdentityMetadata())
        return;
      const failed = await this.#discardIdentity(this.#readIdentityRaw());
      if (failed.length) throw deletionFailure(failed);
    });
  }

  /**
   * Clear another principal's identity session before a new one is stored:
   * revoke its tokens at the provider (best effort, a failure is a notice;
   * never through a workload adapter, which has no person's tokens to
   * revoke), delete every token generation and confirm it, then the
   * metadata. A deletion that cannot be confirmed fails closed and leaves a
   * discarded marker, so the tokens stay tracked and are never used. The
   * caller holds the identity lock.
   */
  async #clearPreviousIdentity(
    metadata: IdentityMetadata,
    provider: IdentityProvider,
    notices: string[],
  ): Promise<void> {
    const store = this.store;
    if (!store) return;
    if (provider.logout && !isWorkloadIdentityProvider(provider)) {
      const secret = await store.get(metadata.secretRef).catch(() => null);
      if (secret)
        try {
          await provider.logout(restoreIdentitySession(metadata, secret));
        } catch (error) {
          notices.push(
            `The previous identity session could not be revoked at the identity provider: ${redact((error as Error).message)}`,
          );
        }
    }
    const failed = await this.#discardIdentity(metadata);
    if (failed.length) throw deletionFailure(failed);
  }

  /**
   * Store `session` as the next generation. Replaced generations are deleted
   * and the deletion confirmed; one that fails stays listed in the metadata's
   * `orphans`, so the next store or the logout retries it, and is reported.
   * Only a session of the stored principal replaces it, under the identity
   * lock, so two writers never interleave.
   */
  async #storeIdentity(
    session: IdentitySession,
    options: { replace?: boolean } = {},
  ): Promise<void> {
    const store = this.store;
    if (!store)
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "No secret store is configured",
        { component: "identity" },
      );
    await withFileLock(this.paths.identity, async () => {
      const previous = this.readIdentityMetadata();
      // A refresh only replaces a session that is still stored: one signed
      // out in the meantime is not brought back.
      if (options.replace && !previous)
        throw new PiShipError("IDENTITY_REQUIRED", "You are not signed in", {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        });
      // Another principal's session, or an unusable file, is cleared
      // (verified) before a new one is stored; this never replaces it.
      if (
        (!previous && existsSync(this.paths.identity)) ||
        (previous && !samePrincipal(previous, principalKey(session)))
      )
        throw new PiShipError(
          "IDENTITY_INVALID",
          "Another identity is still stored; it must be cleared first",
          { component: "identity" },
        );
      const generation = previous
        ? Number(previous.secretRef.split("#")[1] ?? 0) + 1
        : 1;
      const ref = `piship:${this.options.app.id}:identity#${generation}`;
      // Without metadata nothing would name the new token bundle if the
      // process stopped before the metadata commit: a discarded marker names
      // it first, so the next command deletes it and never restores it.
      if (!previous)
        writeIdentityDiscardedMarker(
          this.paths.identity,
          [ref],
          new Date(this.#now()),
          this.storeProvider,
        );
      await store.put(ref, identitySecret(session));
      const metadata = {
        ...identityMetadata(session, ref),
        secret_store: this.storeProvider,
      };
      const stale = previous
        ? [
            previous.secretRef,
            ...metadataSecretRefs(
              { orphans: (previous as { orphans?: unknown }).orphans },
              this.options.app.id,
            ),
          ].filter(
            (item, index, all) => item !== ref && all.indexOf(item) === index,
          )
        : [];
      // Listed before they are deleted, so a crash leaves them tracked.
      writeJsonAtomic(
        this.paths.identity,
        stale.length ? { ...metadata, orphans: stale } : metadata,
      );
      if (!stale.length) return;
      const failed = await deleteSecretsVerified(store, stale);
      writeJsonAtomic(
        this.paths.identity,
        failed.length
          ? { ...metadata, orphans: failed.map((item) => item.ref) }
          : metadata,
      );
      for (const item of failed)
        this.#identityNotices.push(
          `A replaced identity token bundle could not be deleted from the secret store (${item.ref}: ${item.problem}); it is not used, and the deletion is retried`,
        );
    });
  }

  /** Load the identity session, refreshing it when it is expiring. */
  async currentIdentity(options: {
    required: boolean;
  }): Promise<IdentitySession | null> {
    const provider = await this.identityProvider();
    if (!provider) return null;
    if (isWorkloadIdentityProvider(provider))
      return this.#timedIdentity(() => this.#workloadIdentity(provider, null));
    return this.#timedIdentity(() => this.#checkIdentity(provider, options));
  }

  #expiring(session: IdentitySession): boolean {
    return (
      !!session.expiresAt && session.expiresAt.getTime() - this.#now() < 60_000
    );
  }

  /**
   * Obtain a session from a workload identity adapter. It receives an
   * `openUrl` that fails, so no browser is ever involved; an adapter that
   * asked for one fails even if it caught the refusal. The call has 30 s
   * (and the caller's signal), and whatever the adapter throws becomes a
   * coded error without its message, which may quote the token source. Only
   * a session with an expiry that has not passed is accepted.
   */
  async #obtainWorkload(
    provider: IdentityProvider,
    signal?: AbortSignal,
  ): Promise<IdentitySession> {
    let asked = false;
    const openUrl = (): never => {
      asked = true;
      throw browserRefused();
    };
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), WORKLOAD_LOGIN_TIMEOUT_MS);
    const combined = signal
      ? AbortSignal.any([signal, deadline.signal])
      : deadline.signal;
    const stopped = (): PiShipError =>
      signal?.aborted
        ? new PiShipError("IDENTITY_REQUIRED", "Sign-in was cancelled", {
            component: "identity",
          })
        : new PiShipError(
            "GATEWAY_UNREACHABLE",
            "The workload identity adapter did not answer",
            {
              component: "identity",
              retryable: true,
              userAction: `Check the workload's identity source; the adapter's login() has ${WORKLOAD_LOGIN_TIMEOUT_MS / 1000} s`,
            },
          );
    let session: IdentitySession;
    let onAbort: (() => void) | undefined;
    try {
      session = await new Promise<IdentitySession>((resolve, reject) => {
        onAbort = () => reject(stopped());
        if (combined.aborted) return onAbort();
        combined.addEventListener("abort", onAbort, { once: true });
        provider.login({ openUrl, signal: combined }).then(resolve, reject);
      });
    } catch (error) {
      if (asked) throw browserRefused();
      // PiShip's own errors (the managed fetch's network codes, a session
      // that fails normalization) are coded and carry no adapter text.
      if (error instanceof PiShipError) throw error;
      throw new PiShipError(
        "IDENTITY_INVALID",
        "The workload identity adapter could not obtain a session",
        {
          component: "identity",
          userAction:
            "Check that the workload's identity source (a token file or platform endpoint) is present and current",
        },
      );
    } finally {
      clearTimeout(timer);
      if (onAbort) combined.removeEventListener("abort", onAbort);
    }
    if (asked) throw browserRefused();
    if (!session.expiresAt)
      throw new PiShipError(
        "IDENTITY_INVALID",
        "The workload identity adapter returned a session without an expiry",
        {
          component: "identity",
          userAction:
            "Return expiresAt from the adapter's login(): the time the workload token expires",
        },
      );
    if (session.expiresAt.getTime() <= this.#now())
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The workload identity adapter returned an expired session",
        {
          component: "identity",
          userAction:
            "Check that the workload's identity source (a token file or platform endpoint) is current",
        },
      );
    return session;
  }

  /**
   * The workload identity session: obtained from the adapter without a
   * person or a stored login, held in memory for this process, and never
   * stored. It is obtained again when it expires within 60 s, when it is
   * five minutes old, or after the broker rejected it (`renew: "rejected"`),
   * and must then name the same principal: a process never switches
   * principals. Concurrent callers share one adapter call. The first session
   * of a process may name another principal than the previous run; a stored
   * identity session of that other principal (or one that cannot be read) is
   * cleared (verified) before anything else, and activation then clears its
   * model selection and the credential manager discards its credential.
   */
  async #workloadIdentity(
    provider: IdentityProvider,
    renew: "rejected" | null,
  ): Promise<IdentitySession> {
    const current = this.#workload;
    if (
      current &&
      !renew &&
      !this.#expiring(current) &&
      this.#now() - this.#workloadAt < WORKLOAD_SESSION_MAX_AGE_MS
    )
      return current;
    let pending = this.#workloadPending;
    if (!pending) {
      const started = this.#renewWorkload(provider, renew);
      pending = started;
      this.#workloadPending = started;
      void started
        .finally(() => {
          if (this.#workloadPending === started) this.#workloadPending = null;
        })
        .catch(() => {});
    }
    return pending;
  }

  async #renewWorkload(
    provider: IdentityProvider,
    renew: "rejected" | null,
  ): Promise<IdentitySession> {
    const current = this.#workload;
    const session = await this.#obtainWorkload(provider);
    if (current)
      assertSamePrincipal(session, current, {
        message:
          "The workload identity adapter returned another principal than this run started with",
        userAction:
          "A run never switches workload principals; start a new run for the other principal",
      });
    else {
      await this.#clearUnusableIdentity();
      await withFileLock(this.paths.identity, async () => {
        const stored = this.readIdentityMetadata();
        if (stored && !samePrincipal(stored, principalKey(session)))
          await this.#clearPreviousIdentity(
            stored,
            provider,
            this.#identityNotices,
          );
      });
    }
    this.#workload = session;
    this.#workloadAt = this.#now();
    const expiresAt = session.expiresAt?.toISOString() ?? null;
    if (current)
      this.#emit("identity.refresh", {
        reason: renew ?? (this.#expiring(current) ? "expiring" : "age"),
        expiresAt,
        workload: true,
      });
    else this.#emit("identity.login", { expiresAt, workload: true });
    return session;
  }

  async #checkIdentity(
    provider: IdentityProvider,
    options: { required: boolean },
  ): Promise<IdentitySession | null> {
    const metadata = this.readIdentityMetadata();
    if (!metadata) {
      // Delete the token bundles unusable metadata or a discarded marker
      // still references; fails closed while that is not possible.
      await this.#clearUnusableIdentity();
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
   * refreshed uses it instead of spending the old refresh token. A stored
   * session of another principal (someone else signed in meanwhile) is never
   * refreshed or returned, and neither is a session that was signed out.
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
      if (!stored)
        throw new PiShipError("IDENTITY_REQUIRED", "You are not signed in", {
          component: "identity",
          userAction: `Run ${this.options.app.command} login`,
        });
      if (!samePrincipal(principalKey(stored), principalKey(observed)))
        throw new PiShipError(
          "IDENTITY_INVALID",
          "Another identity signed in; run login again",
          {
            component: "identity",
            userAction: `Run ${this.options.app.command} login, then start ${this.options.app.command} again`,
          },
        );
      if (!stored.accessToken?.equals(observed.accessToken)) return stored;
      // A refresh never switches the principal, whatever the provider does.
      const refreshed = assertSamePrincipal(await refresh(stored), observed);
      await this.#storeIdentity(refreshed, { replace: true });
      this.#emit("identity.refresh", {
        reason,
        expiresAt: refreshed.expiresAt?.toISOString() ?? null,
      });
      return refreshed;
    });
  }

  // -------------------------------------------------------------- operations

  /**
   * With identity configured every credential is bound to the signed-in
   * principal, so none is used without one.
   */
  #identityRequired(manager: CredentialManager): boolean {
    return (
      manager.options.provider.requiresIdentity || this.identityMode !== "none"
    );
  }

  #credentialContext(
    readSecret?: (prompt: string) => Promise<string>,
  ): CredentialContext {
    return {
      distributionId: this.options.app.id,
      ...(readSecret ? { readSecret } : {}),
    };
  }

  /**
   * Interactive login: identity (when configured), then the runtime
   * credential. The previous runtime credential is revoked where supported
   * and deleted, and its deletion confirmed, before the new identity is
   * stored, so no state ever pairs a new identity with an old credential.
   * When the principal changes, the previous identity session and the model
   * selection are cleared as well. A deletion that cannot be confirmed fails
   * the login before the new identity is stored; a failed remote revocation
   * does not: it is a notice, an audited `credential.revoke`, and a pending
   * revocation record.
   *
   * A workload identity adapter never gets `ctx.openUrl`, and its session is
   * held for this process only, never stored; everything else is the same.
   */
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
    const workload = !!provider && isWorkloadIdentityProvider(provider);
    let identity: IdentitySession | null = null;
    if (provider)
      identity = await this.#timedIdentity(() =>
        workload
          ? this.#obtainWorkload(provider, ctx.signal)
          : provider.login({
              openUrl: ctx.openUrl,
              ...(ctx.signal ? { signal: ctx.signal } : {}),
            }),
      );
    const principal = identity ? principalKey(identity) : null;
    const manager = await this.credentialManager();
    const notices: string[] = [];
    this.#forgetSecret();
    // Everything from clearing the previous credential to acquiring the new
    // one runs under the credential lock: no launch, refresh, or other login
    // interleaves with it (they wait), so none can act on an identity this
    // login is replacing. The browser part above runs before the lock.
    const signIn = async (): Promise<void> => {
      await this.options.onPhase?.("login-locked");
      if (manager.storesSecrets) {
        // Earlier revocation failures stay visible at every login.
        try {
          notices.push(...manager.checkPendingRevocations());
        } catch (error) {
          notices.push(
            `Pending revocations could not be checked: ${redact((error as Error).message)}`,
          );
        }
        // A fresh login always replaces the runtime credential, revoking the
        // previous one where supported (audited as credential.revoke). A
        // request of the signing-in principal whose answer was lost stays
        // pending, so the acquire below repeats its idempotency key.
        const problems = (
          await manager.logout(this.#credentialContext(), {
            reason: "replace",
            keepIssuanceFor: principal,
          })
        ).map((problem) => redact(problem));
        if (manager.hasStoredCredential())
          throw new PiShipError(
            "SECRET_STORE_UNAVAILABLE",
            `The previous credential could not be deleted from the secret store, so sign-in stopped before ${provider ? "storing the new identity" : "acquiring a new credential"}: ${problems.join("; ")}`,
            {
              component: "credential",
              userAction:
                "Unlock or repair the secret store, then run login again",
            },
          );
        for (const problem of problems)
          notices.push(
            `The previous credential was deleted locally but not revoked: ${problem}`,
          );
      }
      await this.options.onPhase?.("credential-cleared");
      // Another principal's sandbox credential goes too, its deletion
      // confirmed, before the new identity is stored: the stored sandbox
      // credential is never usable by anyone but the one who stored it.
      await this.sandboxCredential().clearUnlessBoundTo(principal);
      await this.options.onPhase?.("sandbox-credential-cleared");
      if (provider && identity && principal) {
        const binding = this.#bindPrincipal(principal);
        await this.options.onPhase?.("principal-bound");
        await withFileLock(this.paths.identity, async () => {
          // A discarded marker or unreadable metadata may name token bundles
          // of anyone: they are deleted before anything is stored.
          await this.#clearUnusableIdentity();
          const stored = this.readIdentityMetadata();
          if (stored && !samePrincipal(stored, principal))
            await this.#clearPreviousIdentity(stored, provider, notices);
          await this.options.onPhase?.("identity-cleared");
          if (workload) {
            this.#workload = identity;
            this.#workloadAt = this.#now();
          } else await this.#storeIdentity(identity);
        });
        // A `sandbox login` of the previous user that checked the signed-in
        // user before the identity was replaced stored its credential after
        // the first clear: clear it again now that the identity is stored,
        // after which the guard refuses any later one.
        await this.sandboxCredential().clearUnlessBoundTo(principal);
        this.#emit("identity.login", {
          expiresAt: identity.expiresAt?.toISOString() ?? null,
          ...(binding.known ? { principalChange: true } : {}),
          ...(workload ? { workload: true } : {}),
        });
      }
      // Signing in is the one way an instance changes users.
      this.#principal = principal;
      await this.options.onPhase?.("identity-stored");
      if (manager.storesSecrets) {
        const active = await this.#ensureCredential(
          manager,
          identity,
          this.#credentialContext(ctx.readSecret),
          { allowAcquire: true },
        );
        this.#hold(active);
        notices.push(...active.notices);
      }
      notices.push(...this.#identityNotices.splice(0));
    };
    if (manager.storesSecrets) await manager.exclusive(signIn);
    else await signIn();
    return { identity, credential: manager.status(), notices };
  }

  /**
   * Revoke and clear runtime and identity credentials and delete the stored
   * sandbox credential; sessions, preferences, and the principal binding are
   * kept. Runs under the credential lock, then the sandbox credential lock,
   * then the identity lock, like a login. Every problem is returned: a failed
   * revocation, and a secret that cannot be deleted. Credential secrets that
   * could not be deleted stay tracked by the credential's discarded marker.
   * Identity token bundles that could not be deleted leave an identity
   * discarded marker in place of the session, so the session is signed out
   * all the same: nothing restores it, every later command retries the
   * deletion first and fails closed while it cannot, and no launch runs on
   * it. A caller that must report what was found even when a lock wait
   * runs out (and this throws) passes the list the problems are added to.
   */
  async logout(problems: string[] = []): Promise<string[]> {
    const manager = await this.credentialManager();
    let providerError: unknown;
    const provider = await this.identityProvider().catch((error: unknown) => {
      providerError = error;
      return null;
    });
    const signOut = async (): Promise<void> => {
      problems.push(
        ...(await manager.logout(this.#credentialContext())).map((problem) =>
          redact(problem),
        ),
      );
      this.#forgetSecret();
      this.#workload = null;
      const clearSandbox = async (): Promise<void> => {
        // What cannot be deleted stays tracked by its discarded marker.
        problems.push(
          ...(await this.sandboxCredential().clear()).map(
            (problem) => `sandbox credential: ${problem}`,
          ),
        );
      };
      if (!existsSync(this.paths.identity)) return clearSandbox();
      await withFileLock(this.paths.identity, async () => {
        const metadata = this.readIdentityMetadata();
        // A workload adapter never receives a person's tokens.
        const revocable =
          !!provider?.logout && !isWorkloadIdentityProvider(provider);
        let revocation: "completed" | "failed" | "unsupported" | "skipped" =
          revocable ? "skipped" : "unsupported";
        // An adapter that could not be loaded may have had tokens to
        // revoke: that is a failure to revoke, not an unsupported one.
        if (metadata && providerError !== undefined) {
          revocation = "failed";
          problems.push(
            `identity revocation: not attempted: ${redact(formatError(providerError))}`,
          );
        }
        if (metadata && revocable && this.store) {
          const secret = await this.store
            .get(metadata.secretRef)
            .catch(() => null);
          if (secret)
            try {
              await provider?.logout?.(
                restoreIdentitySession(metadata, secret),
              );
              revocation = "completed";
            } catch (error) {
              revocation = "failed";
              problems.push(
                `identity revocation: ${redact((error as Error).message)}`,
              );
            }
        }
        const failed = await this.#discardIdentity(
          metadata ?? this.#readIdentityRaw(),
        );
        for (const item of failed)
          problems.push(
            `identity secret ${item.ref}: ${item.problem}; the session is signed out and never used, and the deletion is retried by the next command`,
          );
        if (metadata) this.#emit("identity.logout", { revocation });
      });
      // After the identity, so a `sandbox login` that checked the signed-in
      // user before this took the identity lock has stored its secret by
      // now and is cleared here, and one that checks later finds no user.
      await clearSandbox();
    };
    if (manager.storesSecrets) await manager.exclusive(signOut);
    else await signOut();
    return problems;
  }

  /** Revocations that failed and may still be live remotely (no secrets). */
  pendingRevocations(): PendingRevocations {
    return readPendingRevocations(this.paths.revocationRetry, this.#now());
  }

  /**
   * Launch-time resolution: identity, credential, catalog, and effective model
   * selection. Fails closed with the error contract when anything required is
   * missing; never falls back to personal providers. `listOnly` (the models
   * listing) leaves an unavailable requested model unselected instead.
   */
  async activate(
    options: { requestedModel?: string; listOnly?: boolean } = {},
  ): Promise<ActivatedAccess> {
    const notices: string[] = [];
    const access = this.options.access;
    let preferences = readPreferences(this.paths.preferences);
    const manager = await this.credentialManager();
    const identity = await this.currentIdentity({
      required: this.#identityRequired(manager),
    });
    this.#pin(identity);
    notices.push(...this.#identityNotices.splice(0));
    await this.options.onPhase?.("identity-resolved");
    // State another principal left behind (from an interrupted switch or an
    // older release) loses its model selection before anything uses it. With
    // a stored credential this runs under the credential lock, after the
    // identity was confirmed there, so it never rebinds the state to a user
    // another process just replaced.
    let cleared = false;
    const bind = () => {
      if (identity && this.#bindPrincipal(principalKey(identity)).cleared)
        cleared = true;
    };
    if (!manager.storesSecrets) bind();
    let credential = await this.#activeCredential(
      manager,
      identity,
      {
        allowAcquire:
          this.credentialMode === "http-broker" ||
          this.credentialMode === "adapter",
      },
      manager.storesSecrets ? bind : undefined,
    );
    if (cleared) {
      preferences = readPreferences(this.paths.preferences);
      notices.push(
        "The model selection of a previously signed-in identity was cleared",
      );
    }
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
      await manager.markRejected(
        credential.ref && this.#principal !== undefined
          ? {
              ref: credential.ref.ref,
              acquiredAt: credential.acquiredAt,
              principal: this.#principal,
            }
          : undefined,
      );
      await this.options.onPhase?.("credential-rejected");
      // The renewal is checked against the pinned principal like any other,
      // and its entitlement is what it returned under the lock. Only the
      // rejected generation is renewed: one another process already replaced
      // is adopted instead of issuing a second credential.
      credential = await this.#renewCredential(
        manager,
        true,
        credential.ref?.ref,
      );
      notices.push(
        "The gateway rejected the stored credential; a new credential was acquired",
        ...credential.notices,
      );
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
      let resolved: ModelDefinition | undefined;
      try {
        resolved = (
          await inference.resolveModel(requested, { models, allowed })
        ).model;
      } catch (error) {
        // Listing never uses the selection, so a stale one does not block it.
        if (!options.listOnly)
          throw withModelRecovery(
            error,
            this.options.app.command,
            options.requestedModel
              ? "flag"
              : config.entries.find((entry) => entry.key === "model")?.source,
          );
      }
      selectedModel = resolved?.id;
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
      const gaps = resolved
        ? incompatibleCapabilities(resolved, capabilities)
        : [];
      if (resolved && gaps.length)
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
    if (isWorkloadIdentityProvider(provider))
      return this.#timedIdentity(() =>
        this.#workloadIdentity(provider, "rejected"),
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
   * after a gateway rejection, re-acquires once (force) before failing. The
   * cached secret is served only while the stored credential is still the
   * generation it belongs to and bound to this instance's pinned principal;
   * otherwise the credential is resolved again for that principal, and a
   * different signed-in user fails the call.
   */
  async requestSecret(
    options: { force?: boolean } = {},
  ): Promise<SecretValue | null> {
    const manager = await this.credentialManager();
    if (!manager.storesSecrets) return null;
    if (options.force && !manager.renewable)
      throw rejectedUserSecret(this.options.app.command);
    if (!options.force && this.#cachedSecretValid(manager)) return this.#secret;
    // A forced renewal is about the generation this session sent, not
    // whatever another process stored since.
    return (
      await this.#renewCredential(
        manager,
        !!options.force,
        options.force ? this.#secretRef : undefined,
      )
    ).secret;
  }

  #cachedSecretValid(manager: CredentialManager): boolean {
    if (!this.#secret || this.#principal === undefined) return false;
    const { state, metadata } = manager.status();
    return (
      state === "valid" &&
      !!metadata &&
      metadata.credential_ref === this.#secretRef &&
      metadata.acquired_at === this.#secretAcquiredAt &&
      samePrincipal(metadata.principal ?? null, this.#principal)
    );
  }

  /**
   * Resolve the credential again for the current identity, which must be the
   * pinned principal (`force`: renew it even when it looks valid).
   */
  async #renewCredential(
    manager: CredentialManager,
    force: boolean | "entitlement",
    observed?: string,
  ): Promise<ActiveCredential> {
    const identity = await this.currentIdentity({
      required: this.#identityRequired(manager),
    });
    this.#pin(identity);
    return this.#activeCredential(manager, identity, {
      allowAcquire:
        this.credentialMode === "http-broker" ||
        this.credentialMode === "adapter",
      ...(force ? { forceRefresh: force } : {}),
      ...(observed ? { observed } : {}),
    });
  }

  /**
   * Ensure the credential for `identity` and cache its secret. When the
   * broker rejects the identity token, the identity is refreshed once (it
   * must stay the pinned principal) and the credential ensured again.
   */
  async #activeCredential(
    manager: CredentialManager,
    identity: IdentitySession | null,
    options: CredentialEnsureOptions,
    underLock?: () => void,
  ): Promise<ActiveCredential> {
    let active: ActiveCredential;
    try {
      active = await this.#ensureCredential(
        manager,
        identity,
        this.#credentialContext(),
        options,
        underLock,
      );
    } catch (error) {
      if (
        !(error instanceof PiShipError) ||
        error.code !== "IDENTITY_EXPIRED" ||
        !identity
      )
        throw error;
      const refreshed = await this.#refreshIdentity(identity);
      this.#pin(refreshed);
      active = await this.#ensureCredential(
        manager,
        refreshed,
        this.#credentialContext(),
        { ...options, allowAcquire: true },
        underLock,
      );
    }
    this.#hold(active);
    return active;
  }

  /** Persist a gateway rejection of the current runtime credential. */
  async markCredentialRejected(): Promise<void> {
    // Only what this session used, issued to the principal it is pinned to:
    // a request that was in flight while another user signed in must not
    // mark that user's credential.
    if (this.#secretRef === undefined || this.#principal === undefined) return;
    await (await this.credentialManager()).markRejected({
      ref: this.#secretRef,
      acquiredAt: this.#secretAcquiredAt,
      principal: this.#principal,
    });
  }

  /**
   * Re-read the credential entitlement after the gateway denied a model (403
   * `MODEL_DENIED` on a request). A credential without `expires_at` is never
   * renewed otherwise, so its entitlement would stay as issued until the next
   * login. The re-read is one forced renewal through the refresh path, at
   * most once per credential generation: a denial of the renewed credential
   * is the organization's current answer. A failed renewal keeps the current
   * credential and throws. The entitlement only narrows the distribution
   * allowlist at the next activation, never widens it. Returns whether the
   * entitlement was re-read.
   */
  async refreshEntitlement(): Promise<boolean> {
    const manager = await this.credentialManager();
    const current = manager.renewable ? manager.readMetadata() : null;
    // Generations restart after a logout, so the reference alone does not
    // identify a credential; its acquisition time does.
    const key = (metadata: typeof current) =>
      metadata ? `${metadata.credential_ref}@${metadata.acquired_at}` : "";
    if (!current || key(current) === this.#entitlementReread) return false;
    await this.#renewCredential(manager, "entitlement", current.credential_ref);
    this.#entitlementReread = key(manager.readMetadata());
    return true;
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

  /**
   * Non-secret status used by doctor and config explain. A stored credential
   * bound to another principal than the current one is shown as absent,
   * never as usable, and without its ID: it belongs to someone else and the
   * next launch or login discards it.
   */
  async status(): Promise<{
    identity: IdentityMetadata | null;
    credential: CredentialStatus;
    store: string;
    refs: CredentialRef | null;
  }> {
    const manager = await this.credentialManager();
    let credential = manager.status();
    const identity = this.readIdentityMetadata();
    if (
      credential.metadata &&
      !samePrincipal(
        credential.metadata.principal ?? null,
        await this.#statusPrincipal(identity),
      )
    )
      credential = {
        state: "absent",
        metadata: null,
        notice:
          "The stored credential was not issued to the signed-in identity; it is never used, and the next launch or login discards it",
      };
    return {
      identity,
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

  /**
   * Whom a stored credential must belong to for `status()`: the pinned
   * principal once this instance activated or signed in; otherwise the
   * stored session's, or for a workload identity (never stored) the
   * principal binding the last run recorded; nobody without identity.
   */
  async #statusPrincipal(
    identity: IdentityMetadata | null,
  ): Promise<PrincipalKey | null> {
    if (this.#principal !== undefined) return this.#principal;
    if (this.identityMode === "none") return null;
    const provider = await this.identityProvider().catch(() => null);
    if (provider && isWorkloadIdentityProvider(provider))
      return this.readPrincipalBinding() ?? null;
    try {
      return identity ? principalKey(identity) : null;
    } catch {
      return null;
    }
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
