// The stored sandbox credential: an API key or token a person enters with
// `<command> sandbox login` for a remote sandbox backend that declares
// `sandbox.credential: stored`. It lives in the secret store like the runtime
// credential, bound to the principal that stored it and to the origins of the
// endpoint (and, for Kubernetes, the router) it was stored for. It is used
// only by that principal and only for those origins; anything else is
// refused before the secret is read, and a credential of another principal
// is deleted (the deletion confirmed) and never used.
import { randomUUID } from "node:crypto";
import {
  type CredentialProvider,
  type IdentitySession,
  PiShipError,
  type PrincipalKey,
  principalKey,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  redact,
  type SandboxCredentialAccess,
  type SandboxCredentialKind,
  type SecretStore,
  type SecretValue,
  samePrincipal,
} from "@piship/contracts";
import {
  type CredentialEvent,
  CredentialManager,
  type CredentialMetadata,
  type CredentialPhase,
  type CredentialRevokeReason,
  createSecretStore,
  LocalSecretCredentialProvider,
  normalizeCredential,
  type RejectedCredential,
  type SecretStoreResolver,
} from "@piship/credentials";
import { accessStatePaths } from "./state.js";

/** The remote sandbox providers a stored credential is declared for. */
export type SandboxCredentialProvider =
  | "custom"
  | "e2b-compatible"
  | "kubernetes-agent-sandbox";

/** Longest sandbox secret accepted. */
export const SANDBOX_SECRET_MAX_LENGTH = 4096;

/**
 * Runs a task holding the identity lock, after checking that the principal
 * the credential is used or stored for is still the signed-in user; throws
 * (and runs nothing) when it is not. Only an interactive identity has stored
 * state to check.
 */
export type SignedInGuard = <T>(task: () => Promise<T>) => Promise<T>;

export interface SandboxCredentialOptions {
  readonly distributionId: string;
  /** The branded command, for the user actions of errors. */
  readonly command: string;
  readonly stateDir: string;
  /**
   * The backend it is stored for, which sets the prompt and the kind (API
   * key or bearer token). Not needed to clear or read the credential.
   */
  readonly provider?: SandboxCredentialProvider;
  /**
   * The distribution's configured store: `access.credential.storage` when the
   * manifest has one, else the platform (`system`) store. There is no other
   * fallback.
   */
  readonly storage?: { readonly provider: "system" | "file" };
  /** A store to use instead of the configured one (shared or a test's). */
  readonly secretStore?: SecretStore;
  /**
   * The store of another provider, for deleting references that metadata
   * recorded for it (`credential.storage.provider` changed since). By default
   * it is the other provider's store beside the state, except with an
   * injected in-memory `secretStore`, which has none. Without one, such
   * references stay tracked and fail closed.
   */
  readonly secretStoreFor?: SecretStoreResolver;
  /** The principal the credential is used by or stored for; null without identity. */
  readonly principal: PrincipalKey | null;
  /**
   * Given for an interactive identity. `save` and the deletion of another
   * user's credential run inside it, so a session or a `sandbox login` of a
   * user who is no longer signed in stores and deletes nothing.
   */
  readonly signedIn?: SignedInGuard;
  /**
   * The resolved URLs the backend sends the credential to: the endpoint and,
   * for Kubernetes, the router. Not needed to clear the credential.
   */
  readonly targets?: readonly string[];
  /** Receives `credential.acquire` and `credential.revoke` (purpose sandbox). */
  readonly onEvent?: (event: CredentialEvent) => void;
  /** Crash-safety tests: a hook that throws stops the operation there. */
  readonly onPhase?: (phase: CredentialPhase) => void | Promise<void>;
  readonly now?: () => number;
}

export type SandboxCredentialState =
  | "absent"
  | "valid"
  | "rejected"
  | "principal-mismatch"
  | "origin-mismatch";

/** Non-secret status for doctor: never the value, the reference, or the origins. */
export interface SandboxCredentialStatus {
  readonly state: SandboxCredentialState;
  readonly source: "stored";
  readonly kind?: SandboxCredentialKind;
  /** The secret store's kind and description. */
  readonly store: string;
  /** Whether it is bound to the current principal (absent when there is none). */
  readonly boundToPrincipal?: boolean;
  /** Whether its recorded origins cover every configured target. */
  readonly originMatches?: boolean;
  readonly notice?: string;
}

const PROMPTS: Readonly<
  Record<
    SandboxCredentialProvider,
    { label: string; kind: SandboxCredentialKind }
  >
> = {
  "e2b-compatible": { label: "Sandbox API key", kind: "api_key" },
  "kubernetes-agent-sandbox": { label: "Sandbox token", kind: "bearer" },
  custom: { label: "Sandbox credential", kind: "api_key" },
};

/** The origin (scheme://host:port) of an http(s) URL, or undefined. */
export function sandboxOrigin(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:")
      return undefined;
    return parsed.origin;
  } catch {
    return undefined;
  }
}

/** Which stored secret metadata describes: its reference and random ID. */
/** The one issuance of a stored credential, for a rejection to name. */
function issuance(
  metadata: CredentialMetadata,
  principal: PrincipalKey | null,
): RejectedCredential {
  return {
    ref: metadata.credential_ref,
    acquiredAt: metadata.acquired_at,
    credentialId: metadata.credential_id,
    principal,
  };
}

function identify(metadata: CredentialMetadata): string {
  return `${metadata.credential_ref} ${metadata.credential_id ?? ""} ${metadata.acquired_at}`;
}

function sandboxKind(kind: RuntimeCredentialKind): SandboxCredentialKind {
  return kind === "bearer" ? "bearer" : "api_key";
}

/**
 * One distribution's sandbox credential slot for one principal. Operations
 * run under the slot's own lock (beside its metadata). Lock order across the
 * slots: the runtime credential lock, then this one, then the identity lock.
 */
export class SandboxCredential {
  readonly store: SecretStore;
  readonly #options: SandboxCredentialOptions;
  readonly #metadataPath: string;
  readonly #revocationRetryPath: string;
  readonly #storeFor: SecretStoreResolver = (provider) =>
    this.#options.secretStoreFor
      ? this.#options.secretStoreFor(provider)
      : this.store.kind === "memory"
        ? null
        : createSecretStore({
            provider,
            fileDirectory: accessStatePaths(this.#options.stateDir).secrets,
          });

  constructor(options: SandboxCredentialOptions) {
    this.#options = options;
    const paths = accessStatePaths(options.stateDir);
    this.#metadataPath = paths.sandboxCredential;
    this.#revocationRetryPath = paths.revocationRetry;
    this.store =
      options.secretStore ??
      createSecretStore({
        provider: options.storage?.provider ?? "system",
        fileDirectory: paths.secrets,
      });
  }

  #unavailable(message: string, userAction?: string): PiShipError {
    return new PiShipError("SANDBOX_UNAVAILABLE", message, {
      component: "sandbox",
      userAction:
        userAction ??
        `Run ${this.#options.command} sandbox login to store the sandbox credential`,
    });
  }

  /**
   * A manager for the slot. Only `save` passes what it stores and the
   * origins it is bound to; every other operation reads or deletes.
   */
  #manager(
    stored?: {
      readonly kind: RuntimeCredentialKind;
      readonly secret: SecretValue;
      readonly credentialId: string;
    },
    origins?: readonly string[],
  ): CredentialManager {
    return new CredentialManager({
      distributionId: this.#options.distributionId,
      slot: "sandbox",
      provider: {
        mode: "local-secret",
        requiresIdentity: false,
        // Only `store` acquires, with the value it read and checked before
        // taking the lock; nothing else ever asks for a new one.
        acquire: async () => {
          if (!stored)
            throw this.#unavailable("No sandbox credential is stored");
          return stored;
        },
      },
      store: this.store,
      // What the configured store is, and how to reach the one that state
      // recorded before the provider changed.
      ...(this.#options.storage
        ? { storeProvider: this.#options.storage.provider }
        : {}),
      storeFor: this.#storeFor,
      metadataPath: this.#metadataPath,
      revocationRetryPath: this.#revocationRetryPath,
      beforeExpirySeconds: 0,
      ...(origins ? { origins } : {}),
      ...(this.#options.onEvent ? { onEvent: this.#options.onEvent } : {}),
      ...(this.#options.onPhase ? { onPhase: this.#options.onPhase } : {}),
      ...(this.#options.now ? { now: this.#options.now } : {}),
    });
  }

  /**
   * The origins of the configured targets. Every target must be a valid
   * http(s) URL, and there must be one: a stored credential is never sent
   * without an origin to bind it to.
   */
  #resolvedOrigins(): string[] {
    const targets = this.#options.targets ?? [];
    const origins = targets.map(sandboxOrigin);
    if (!origins.length || origins.some((origin) => origin === undefined))
      throw this.#unavailable(
        "sandbox.credential is stored, but the sandbox endpoint is missing or not an http(s) URL",
        "Declare sandbox.endpoint (and, for Kubernetes, sandbox.router) and set its runtime variables",
      );
    return [...new Set(origins as string[])].sort();
  }

  /** Whether anything is left in the slot, including a discarded marker. */
  present(): boolean {
    return this.#manager().hasStoredCredential();
  }

  /**
   * Read, check, and store a new sandbox secret for the principal, replacing
   * any previous one (whoever it belonged to), whose deletion is confirmed
   * first. The secret is read and checked before anything is deleted or the
   * lock is taken, so a malformed entry changes nothing and a person typing
   * never holds the lock. The service is not contacted: the next launch
   * proves the secret.
   */
  async save(
    readSecret: (prompt: string) => Promise<string>,
  ): Promise<{ readonly kind: SandboxCredentialKind; readonly store: string }> {
    const origins = this.#resolvedOrigins();
    const prompt = PROMPTS[this.#options.provider ?? "custom"];
    const entered = await new LocalSecretCredentialProvider({
      label: prompt.label,
      kind: prompt.kind,
      maxLength: SANDBOX_SECRET_MAX_LENGTH,
      userAction: `Run ${this.#options.command} sandbox login and enter the sandbox credential`,
    }).acquire(null, {
      distributionId: this.#options.distributionId,
      readSecret,
    });
    // A random, non-secret ID per stored secret: generations restart after a
    // replacement, so a running session tells secrets apart by this.
    const manager = this.#manager(
      { ...entered, credentialId: randomUUID() },
      origins,
    );
    const principal = this.#options.principal;
    const guard = this.#options.signedIn ?? ((task) => task());
    // The sandbox lock, then the identity lock, and the user is checked under
    // both: a `logout` or another user's `login` that came first is seen
    // here, and one that comes after clears what is stored now.
    await manager.exclusive(() =>
      guard(async () => {
        const problems = await manager.logout(
          { distributionId: this.#options.distributionId },
          { reason: "replace" },
        );
        if (manager.hasStoredCredential())
          throw new PiShipError(
            "SECRET_STORE_UNAVAILABLE",
            `The previous sandbox credential could not be deleted from the secret store, so the new one was not stored: ${problems.map((problem) => redact(problem)).join("; ")}`,
            {
              component: "credential",
              userAction: `Unlock or repair the secret store, then run ${this.#options.command} sandbox login again`,
            },
          );
        await manager.ensure(
          principal
            ? ({
                issuer: principal.issuer,
                subject: principal.subject,
              } satisfies IdentitySession)
            : null,
          { distributionId: this.#options.distributionId },
          { allowAcquire: true },
        );
      }),
    );
    return {
      kind: prompt.kind,
      store: `${this.store.kind} (${this.store.description})`,
    };
  }

  /**
   * Delete the sandbox credential: every secret its metadata may reference
   * (current, orphaned, and pending generations), each deletion confirmed,
   * then the metadata. A stored credential has no remote revocation. Returns
   * the problems; what could not be deleted stays tracked by a discarded
   * marker that is never used (see `present()`).
   */
  async clear(reason: CredentialRevokeReason = "logout"): Promise<string[]> {
    const manager = this.#manager();
    if (!manager.hasStoredCredential()) return [];
    return (
      await manager.logout(
        { distributionId: this.#options.distributionId },
        { reason },
      )
    ).map((problem) => redact(problem));
  }

  /**
   * Delete the sandbox credential unless it is bound to `principal`, which
   * is about to sign in. A deletion that cannot be confirmed fails closed,
   * before the new identity is stored.
   */
  async clearUnlessBoundTo(principal: PrincipalKey | null): Promise<void> {
    const manager = this.#manager();
    if (!manager.hasStoredCredential()) return;
    await manager.exclusive(async () => {
      if (!manager.hasStoredCredential()) return;
      const metadata = manager.readMetadata();
      if (metadata && samePrincipal(metadata.principal ?? null, principal))
        return;
      const problems = await this.clear(
        metadata && !metadata.principal && principal
          ? "unbound"
          : "principal-change",
      );
      if (manager.hasStoredCredential())
        throw new PiShipError(
          "SECRET_STORE_UNAVAILABLE",
          `The previous user's sandbox credential could not be deleted from the secret store, so sign-in stopped before storing the new identity: ${problems.join("; ")}`,
          {
            component: "credential",
            userAction: `Unlock or repair the secret store, then run ${this.#options.command} login again`,
          },
        );
    });
  }

  /** Clear what must never be used, failing closed when a deletion fails. */
  async #discard(
    manager: CredentialManager,
    reason: CredentialRevokeReason,
  ): Promise<void> {
    const problems = await this.clear(reason);
    if (manager.hasStoredCredential())
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        `A sandbox credential that must not be used could not be deleted from the secret store (${problems.join("; ")}); it is not used, and the deletion is retried by the next launch, sandbox login, or logout`,
        {
          component: "credential",
          userAction: `Unlock or repair the secret store, then run ${this.#options.command} again`,
        },
      );
  }

  /** Why `metadata` cannot be sent to the configured targets, if it cannot. */
  #originProblem(
    metadata: CredentialMetadata,
    resolved: readonly string[],
  ): string | undefined {
    const recorded = new Set(metadata.origins ?? []);
    return resolved.every((origin) => recorded.has(origin))
      ? undefined
      : "The stored sandbox credential was stored for another sandbox endpoint than the one configured now, so it is not sent";
  }

  /**
   * The credential for one session of the principal. Before the secret is
   * read: a credential of another principal (or from before an identity was
   * configured) is deleted, its deletion confirmed, and refused; a rejected
   * one is refused; and every configured target must be an origin it was
   * stored for. The returned accessor re-checks the metadata before each
   * request and never deletes anything: a principal change under a running
   * session only stops it.
   */
  async access(): Promise<SandboxCredentialAccess> {
    const resolved = this.#resolvedOrigins();
    const manager = this.#manager();
    const principal = this.#options.principal;
    const store = this.store;
    let held:
      | {
          id: string;
          issuance: RejectedCredential;
          secret: SecretValue;
          kind: SandboxCredentialKind;
        }
      | undefined = await manager.exclusive(async () => {
      if (!manager.hasStoredCredential())
        throw this.#unavailable("No sandbox credential is stored");
      const metadata = manager.readMetadata();
      if (!metadata) {
        // A discarded marker or metadata of an incompatible version.
        await this.#discard(manager, "lifecycle");
        throw this.#unavailable("No usable sandbox credential is stored");
      }
      if (!samePrincipal(metadata.principal ?? null, principal)) {
        // Only the signed-in user's launch deletes: a session of a user who
        // was signed out or replaced meanwhile must not delete the new
        // user's credential.
        const guard = this.#options.signedIn ?? ((task) => task());
        await guard(() =>
          this.#discard(
            manager,
            !metadata.principal && principal ? "unbound" : "principal-change",
          ),
        );
        throw this.#unavailable(
          "The stored sandbox credential belonged to another user; it was deleted",
        );
      }
      if (metadata.rejected_at)
        throw this.#unavailable(
          "The sandbox service rejected the stored sandbox credential",
          `Run ${this.#options.command} sandbox login to store a new one`,
        );
      const problem = this.#originProblem(metadata, resolved);
      if (problem)
        throw this.#unavailable(
          problem,
          `Check the sandbox endpoint's runtime variables, or run ${this.#options.command} sandbox login to store a credential for this endpoint`,
        );
      const secret = await store.get(metadata.credential_ref);
      if (!secret) {
        await this.#discard(manager, "lifecycle");
        throw this.#unavailable(
          "The stored sandbox credential had no matching secret and was cleared",
        );
      }
      return {
        id: identify(metadata),
        issuance: issuance(metadata, principal),
        secret,
        kind: sandboxKind(metadata.kind),
      };
    });
    const kind = held.kind;
    const changed = () => {
      held = undefined;
      return this.#unavailable(
        "The stored sandbox credential changed under this session",
        `Start ${this.#options.command} again`,
      );
    };
    return {
      source: "stored",
      kind,
      origins: resolved,
      secret: async () => {
        const metadata = manager.readMetadata();
        if (!metadata || !samePrincipal(metadata.principal ?? null, principal))
          throw changed();
        if (metadata.rejected_at) {
          held = undefined;
          throw this.#unavailable(
            "The sandbox service rejected the stored sandbox credential",
            `Run ${this.#options.command} sandbox login to store a new one`,
          );
        }
        if (this.#originProblem(metadata, resolved)) throw changed();
        if (held?.id !== identify(metadata)) {
          // The same principal stored a new one: use it from now on.
          const secret = await store.get(metadata.credential_ref);
          if (!secret) throw changed();
          held = {
            id: identify(metadata),
            issuance: issuance(metadata, principal),
            secret,
            kind,
          };
        }
        return held.secret;
      },
      rejected: async () => {
        const used = held?.issuance;
        held = undefined;
        // Only the secret that was rejected is marked, never a newer one:
        // the comparison is made under the lock, since generations restart
        // and a login may have stored another secret under the same reference.
        if (used) await manager.markRejected(used);
      },
    };
  }

  /** Non-secret status; reads no secret and changes nothing. */
  status(): SandboxCredentialStatus {
    const manager = this.#manager();
    const store = `${this.store.kind} (${this.store.description})`;
    if (!manager.hasStoredCredential())
      return { state: "absent", source: "stored", store };
    const metadata = manager.readMetadata();
    if (!metadata)
      return {
        state: "absent",
        source: "stored",
        store,
        notice:
          "A discarded or unreadable sandbox credential is still to be deleted from the secret store; it is never used",
      };
    const kind = sandboxKind(metadata.kind);
    const bound = samePrincipal(
      metadata.principal ?? null,
      this.#options.principal,
    );
    let originMatches: boolean | undefined;
    try {
      originMatches = !this.#originProblem(metadata, this.#resolvedOrigins());
    } catch {
      originMatches = undefined;
    }
    const base = {
      source: "stored" as const,
      kind,
      store,
      boundToPrincipal: bound,
      ...(originMatches === undefined ? {} : { originMatches }),
    };
    if (!bound)
      return {
        ...base,
        state: "principal-mismatch",
        notice:
          "The stored sandbox credential belongs to another user; it is never used, and the next launch deletes it",
      };
    if (metadata.rejected_at)
      return {
        ...base,
        state: "rejected",
        notice: `The sandbox service rejected it; run ${this.#options.command} sandbox login`,
      };
    if (originMatches === false)
      return {
        ...base,
        state: "origin-mismatch",
        notice:
          "It was stored for another sandbox endpoint than the one configured now; it is not sent",
      };
    return { ...base, state: "valid" };
  }
}

export function openSandboxCredential(
  options: SandboxCredentialOptions,
): SandboxCredential {
  return new SandboxCredential(options);
}

export interface AdapterSandboxCredentialOptions {
  readonly distributionId: string;
  /** The branded command, for the user actions of errors. */
  readonly command: string;
  /** A custom sandbox adapter module's `sandboxCredential` export. */
  readonly provider: unknown;
  /**
   * The signed-in identity, passed to the provider; it must stay the
   * launch's principal. Null without identity.
   */
  readonly identity: () => Promise<IdentitySession | null>;
  readonly principal: PrincipalKey | null;
  /** The origins the credential is sent to (the declared endpoint's). */
  readonly origins: readonly string[];
  /** Receives acquire, refresh, and revoke (purpose sandbox, source adapter). */
  readonly onEvent?: (event: CredentialEvent) => void;
  readonly now?: () => number;
}

/** Renew this long before the adapter credential's expiry. */
const ADAPTER_RENEW_BEFORE_MS = 60_000;

/**
 * A custom sandbox adapter's own credential (`sandboxCredential`, a
 * `CredentialProvider`): acquired for the launch's principal, held in this
 * process's memory only, renewed before it expires and once after a
 * rejection, and revoked (best effort) when the session ends. It never
 * reaches the secret store, state, snapshots, or migration, so it cannot
 * outlive the process or its principal.
 */
export class AdapterSandboxCredential {
  readonly #options: AdapterSandboxCredentialOptions;
  readonly #provider: CredentialProvider;
  readonly #now: () => number;
  #current: RuntimeCredential | null = null;
  #pending: Promise<RuntimeCredential> | null = null;
  #revoked = false;

  constructor(options: AdapterSandboxCredentialOptions) {
    const provider = options.provider as Partial<CredentialProvider> | null;
    if (
      !provider ||
      typeof provider !== "object" ||
      typeof provider.acquire !== "function" ||
      (provider.refresh !== undefined &&
        typeof provider.refresh !== "function") ||
      (provider.revoke !== undefined && typeof provider.revoke !== "function")
    )
      throw new PiShipError(
        "SANDBOX_UNAVAILABLE",
        "The custom sandbox adapter's sandboxCredential export is not a credential provider (acquire, optional refresh and revoke)",
        { component: "sandbox" },
      );
    this.#options = options;
    this.#provider = provider as CredentialProvider;
    this.#now = options.now ?? Date.now;
  }

  #unavailable(message: string): PiShipError {
    return new PiShipError("SANDBOX_UNAVAILABLE", message, {
      component: "sandbox",
      userAction: `Check the custom sandbox adapter's credential source, then start ${this.#options.command} again`,
    });
  }

  #emit(
    event: CredentialEvent["event"],
    detail: Record<string, string | number | boolean | null>,
  ): void {
    try {
      this.#options.onEvent?.({
        event,
        detail: { purpose: "sandbox", source: "adapter", ...detail },
      });
    } catch {
      // Event consumers never break the session.
    }
  }

  /** The identity for the provider, which must still be the launch's principal. */
  async #identity(): Promise<IdentitySession | null> {
    const identity = await this.#options.identity();
    const principal = identity ? principalKey(identity) : null;
    if (!samePrincipal(principal, this.#options.principal))
      throw this.#unavailable(
        "The signed-in user changed; the sandbox credential is not obtained for another user",
      );
    return identity;
  }

  async #obtain(
    reason: "acquire" | "expiring" | "rejected",
  ): Promise<RuntimeCredential> {
    const identity = await this.#identity();
    const ctx = { distributionId: this.#options.distributionId };
    const current = this.#current;
    let returned: unknown;
    try {
      returned =
        current && this.#provider.refresh
          ? await this.#provider.refresh(identity, current, ctx)
          : await this.#provider.acquire(identity, ctx);
    } catch (error) {
      // The adapter's own text may quote its token source: only a code.
      throw this.#unavailable(
        `The custom sandbox adapter could not provide its credential (${error instanceof PiShipError ? error.code : "adapter error"})`,
      );
    }
    let credential: RuntimeCredential;
    try {
      credential = normalizeCredential(returned);
    } catch (error) {
      throw this.#unavailable(
        `The custom sandbox adapter returned an unusable credential: ${(error as Error).message}`,
      );
    }
    if (credential.kind === "opaque")
      throw this.#unavailable(
        "The custom sandbox adapter returned an opaque credential; a sandbox credential is an api_key or a bearer token",
      );
    if (credential.expiresAt && credential.expiresAt.getTime() <= this.#now())
      throw this.#unavailable(
        "The custom sandbox adapter returned an expired credential",
      );
    this.#current = credential;
    this.#emit(
      reason === "acquire" ? "credential.acquire" : "credential.refresh",
      {
        kind: credential.kind,
        expiresAt: credential.expiresAt?.toISOString() ?? null,
        ...(reason === "acquire" ? {} : { reason }),
      },
    );
    return credential;
  }

  /** One acquisition or renewal at a time; concurrent callers share it. */
  #renew(
    reason: "acquire" | "expiring" | "rejected",
  ): Promise<RuntimeCredential> {
    if (!this.#pending) {
      const started = this.#obtain(reason);
      this.#pending = started;
      void started
        .finally(() => {
          if (this.#pending === started) this.#pending = null;
        })
        .catch(() => {});
    }
    return this.#pending;
  }

  #expiring(credential: RuntimeCredential): boolean {
    return (
      !!credential.expiresAt &&
      credential.expiresAt.getTime() - this.#now() < ADAPTER_RENEW_BEFORE_MS
    );
  }

  /** Acquire for the session and return the accessor backends use. */
  async access(): Promise<SandboxCredentialAccess> {
    const first = await this.#renew("acquire");
    return {
      source: "adapter",
      kind: sandboxKind(first.kind),
      origins: [...this.#options.origins],
      secret: async () => {
        if (this.#revoked)
          throw this.#unavailable("The sandbox credential was revoked");
        const current = this.#current;
        if (current && !this.#expiring(current)) {
          // A principal change is refused even for a credential in hand.
          await this.#identity();
          return current.secret;
        }
        return (await this.#renew(current ? "expiring" : "acquire")).secret;
      },
      rejected: async () => {
        if (this.#revoked) return;
        await this.#renew("rejected");
      },
    };
  }

  /** Revoke the held credential where the provider can; best effort. */
  async revoke(): Promise<void> {
    if (this.#revoked) return;
    this.#revoked = true;
    const current = this.#current;
    this.#current = null;
    if (!current) return;
    let revocation: "revoked" | "failed" | "unsupported" = "unsupported";
    if (this.#provider.revoke)
      try {
        await this.#provider.revoke(current, {
          distributionId: this.#options.distributionId,
        });
        revocation = "revoked";
      } catch {
        revocation = "failed";
      }
    this.#emit("credential.revoke", {
      kind: current.kind,
      reason: "logout",
      revocation,
    });
  }
}
