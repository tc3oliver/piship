import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { basename, dirname } from "node:path";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  type IdentitySession,
  PiShipError,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  type SecretStore,
  SecretValue,
} from "@piship/contracts";
import { heldLocks } from "./lock-heartbeat.js";

export const CREDENTIAL_METADATA_SCHEMA = "piship-credential-metadata/v1";

/** Non-secret credential state. The secret itself lives only in the SecretStore. */
export interface CredentialMetadata {
  readonly schema: typeof CREDENTIAL_METADATA_SCHEMA;
  readonly mode: CredentialProvider["mode"];
  readonly credential_ref: string;
  readonly generation: number;
  readonly kind: RuntimeCredentialKind;
  readonly credential_id?: string;
  readonly expires_at?: string;
  readonly acquired_at: string;
  readonly models?: readonly string[];
  readonly base_url?: string;
  /** References whose deletion failed and must be retried. */
  readonly orphans?: readonly string[];
  /** Set when the gateway rejected this credential; forces renewal on next use. */
  readonly rejected_at?: string;
}

export type CredentialState =
  | "absent"
  | "valid"
  | "expiring"
  | "expired"
  | "rejected"
  | "delegated";

export interface CredentialStatus {
  readonly state: CredentialState;
  readonly metadata: CredentialMetadata | null;
  readonly remainingSeconds?: number;
  readonly notice?: string;
}

export interface ActiveCredential {
  readonly ref: CredentialRef | null;
  /** Request-time accessor; the secret is never exposed as plain data. */
  readonly secret: SecretValue | null;
  readonly notices: readonly string[];
}

/** Why a credential was revoked. */
export type CredentialRevokeReason = "logout" | "replace" | "lifecycle";

/**
 * Outcome of a remote revocation attempt: `revoked` when the provider
 * accepted it, `failed` when it raised, `unsupported` when the provider has
 * no remote revocation, and `skipped` when the stored secret was unreadable.
 */
export type RevocationOutcome =
  | "revoked"
  | "failed"
  | "unsupported"
  | "skipped";

/**
 * Metadata-only lifecycle event. Details never contain secret material; they
 * are suitable for the audit log as they are.
 */
export interface CredentialEvent {
  readonly event:
    | "credential.acquire"
    | "credential.refresh"
    | "credential.revoke";
  readonly detail: Readonly<Record<string, string | number | boolean | null>>;
}

export interface CredentialManagerOptions {
  readonly distributionId: string;
  readonly provider: CredentialProvider;
  readonly store: SecretStore | null;
  readonly metadataPath: string;
  readonly beforeExpirySeconds: number;
  readonly now?: () => number;
  /** Fault injection for crash-safety tests. */
  readonly onPhase?: (phase: "secret-written" | "metadata-written") => void;
  /** Receives acquire, refresh, and revoke events; failures are ignored. */
  readonly onEvent?: (event: CredentialEvent) => void;
}

function writeAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temporary, content, { mode: 0o600, flag: "wx" });
  renameSync(temporary, path);
}

/**
 * Every secret-store reference that credential or identity metadata of one
 * distribution may own: the current generation, recorded orphans, the next
 * generation (written before a crash that never reached metadata), and for
 * identity also the previous generation (a replacement whose delete failed).
 * References of other distributions are never returned.
 */
export function metadataSecretRefs(
  raw: unknown,
  distributionId: string,
): string[] {
  const value =
    raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const refs = new Set<string>();
  const inference = `piship:${distributionId}:inference#`;
  for (const item of [
    value.credential_ref,
    ...(Array.isArray(value.orphans) ? value.orphans : []),
  ])
    if (typeof item === "string" && item.startsWith(inference)) refs.add(item);
  const generation = Number(value.generation);
  if (
    value.generation !== undefined &&
    Number.isInteger(generation) &&
    generation >= 0
  ) {
    refs.add(`${inference}${generation}`);
    refs.add(`${inference}${generation + 1}`);
  }
  const identity = `piship:${distributionId}:identity#`;
  if (
    typeof value.secretRef === "string" &&
    value.secretRef.startsWith(identity)
  ) {
    refs.add(value.secretRef);
    const current = Number(value.secretRef.slice(identity.length));
    if (Number.isInteger(current) && current >= 0) {
      refs.add(`${identity}${current + 1}`);
      if (current > 1) refs.add(`${identity}${current - 1}`);
    }
  }
  return [...refs].sort();
}

const CREDENTIAL_KINDS: readonly RuntimeCredentialKind[] = [
  "api_key",
  "bearer",
  "opaque",
];

/**
 * Normalize a provider-returned secret to a SecretValue. Adapters may return
 * a plain string or a SecretValue from another copy of the contracts package;
 * redaction relies on `instanceof`, so every secret is re-wrapped here.
 */
export function toSecretValue(value: unknown): SecretValue {
  if (value instanceof SecretValue) return value;
  let text: unknown = value;
  if (
    value &&
    typeof value === "object" &&
    typeof (value as { reveal?: unknown }).reveal === "function"
  )
    try {
      text = (value as { reveal: () => unknown }).reveal();
    } catch {
      text = undefined;
    }
  if (typeof text !== "string" || text.length === 0)
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned a credential without a usable secret",
      { component: "credential" },
    );
  return new SecretValue(text);
}

/** Validate a provider-returned credential and normalize its secret and expiry. */
export function normalizeCredential(value: unknown): RuntimeCredential {
  const credential = (value ?? {}) as Partial<
    Omit<RuntimeCredential, "expiresAt">
  > & { readonly expiresAt?: unknown };
  if (!CREDENTIAL_KINDS.includes(credential.kind as RuntimeCredentialKind))
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned an unknown credential kind",
      { component: "credential" },
    );
  const expiresAt =
    credential.expiresAt === undefined
      ? undefined
      : new Date(
          credential.expiresAt instanceof Date
            ? credential.expiresAt.getTime()
            : typeof credential.expiresAt === "string"
              ? Date.parse(credential.expiresAt)
              : Number.NaN,
        );
  if (expiresAt && Number.isNaN(expiresAt.getTime()))
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned an invalid expiry",
      { component: "credential" },
    );
  if (
    credential.credentialId !== undefined &&
    typeof credential.credentialId !== "string"
  )
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned a non-string credential ID",
      { component: "credential" },
    );
  return {
    kind: credential.kind as RuntimeCredentialKind,
    secret: toSecretValue(credential.secret),
    ...(expiresAt ? { expiresAt } : {}),
    ...(credential.credentialId
      ? { credentialId: credential.credentialId }
      : {}),
    ...(credential.metadata && typeof credential.metadata === "object"
      ? { metadata: credential.metadata }
      : {}),
  };
}

/** A held lock is refreshed this often, so only an abandoned one goes stale. */
const LOCK_HEARTBEAT_MS = 5_000;
/**
 * Longer than the worst gap between refreshes: one blocking secret-store
 * command (30 s timeout; locks are touched before each one) plus a missed
 * heartbeat, with margin. Still below the wait, so an abandoned lock is
 * broken before a waiter gives up.
 */
const LOCK_STALE_MS = 75_000;
const LOCK_WAIT_MS = 90_000;
const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
/** In-process queue per metadata file, so concurrent callers never race. */
const queues = new Map<string, Promise<unknown>>();

export interface FileLockTiming {
  readonly heartbeatMs?: number;
  readonly staleMs?: number;
  readonly waitMs?: number;
}

function lockAge(lock: string): number | undefined {
  try {
    return Date.now() - statSync(lock).mtimeMs;
  } catch {
    return undefined;
  }
}

function readToken(lock: string): string | undefined {
  try {
    return readFileSync(lock, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Break a stale lock without racing another waiter: move it aside under a
 * unique name (atomic), re-check that what was moved is still stale, and only
 * then delete it. A lock that turned out fresh is put back unless a new lock
 * already took its place.
 */
function breakStaleLock(lock: string, staleMs: number): void {
  const aside = `${lock}.${process.pid}-${randomBytes(6).toString("hex")}.stale`;
  try {
    renameSync(lock, aside);
  } catch {
    return;
  }
  const age = lockAge(aside);
  if (age !== undefined && age <= staleMs)
    try {
      linkSync(aside, lock);
    } catch {
      // A new holder already created the lock.
    }
  rmSync(aside, { force: true });
}

/**
 * Cross-process lock beside the metadata file. The holder refreshes the
 * lock's mtime while its task runs (on an interval, and before each blocking
 * secret-store command), so a lock is broken only when it is stale: its
 * holder stopped refreshing it, such as a crashed process. A fresh lock is
 * never broken: after the wait, the caller fails with a retryable error.
 */
export async function withFileLock<T>(
  path: string,
  task: () => Promise<T>,
  timing: FileLockTiming = {},
): Promise<T> {
  const heartbeatMs = timing.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const staleMs = timing.staleMs ?? LOCK_STALE_MS;
  const waitMs = timing.waitMs ?? LOCK_WAIT_MS;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lock = `${path}.lock`;
  const token = `${process.pid}-${randomBytes(8).toString("hex")}`;
  const deadline = Date.now() + waitMs;
  for (;;) {
    try {
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeSync(fd, token);
      } finally {
        closeSync(fd);
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const age = lockAge(lock);
      if (age === undefined) continue;
      if (age > staleMs) {
        breakStaleLock(lock, staleMs);
        continue;
      }
      if (Date.now() > deadline)
        throw new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          `Another process is still updating ${basename(path)}; gave up after ${Math.round(waitMs / 1000)} s`,
          {
            component: "credential",
            retryable: true,
            userAction:
              "Try again when the other session finishes signing in or refreshing",
          },
        );
      await sleep(50);
    }
  }
  heldLocks.add(lock);
  const heartbeat = setInterval(() => {
    try {
      const now = new Date();
      utimesSync(lock, now, now);
    } catch {
      // The lock was removed from outside; the task still finishes.
    }
  }, heartbeatMs);
  heartbeat.unref?.();
  try {
    return await task();
  } finally {
    clearInterval(heartbeat);
    heldLocks.delete(lock);
    // Release only this holder's lock, never one another process took over.
    if (readToken(lock) === token) rmSync(lock, { force: true });
  }
}

/**
 * Implements acquire → expiry → refresh → atomic replace → revoke/logout for
 * one runtime credential. Secrets are written to a new generation reference
 * before metadata switches to it, so a crash at any point leaves metadata that
 * points either to the previous complete credential or to the new one.
 */
export class CredentialManager {
  readonly #now: () => number;
  constructor(readonly options: CredentialManagerOptions) {
    this.#now = options.now ?? Date.now;
  }

  get mode(): CredentialProvider["mode"] {
    return this.options.provider.mode;
  }

  get storesSecrets(): boolean {
    return this.mode !== "pi-native" && this.mode !== "none";
  }

  /**
   * Whether the provider can revoke remotely. A provider may declare
   * `revocable: false`, as a broker without a revoke endpoint does.
   */
  get revocable(): boolean {
    const provider = this.options.provider as CredentialProvider & {
      readonly revocable?: unknown;
    };
    return (
      typeof provider.revoke === "function" && provider.revocable !== false
    );
  }

  #emit(
    event: CredentialEvent["event"],
    detail: Record<string, string | number | boolean | null>,
  ): void {
    try {
      this.options.onEvent?.({ event, detail: { mode: this.mode, ...detail } });
    } catch {
      // Event consumers never break the credential lifecycle.
    }
  }

  readMetadata(): CredentialMetadata | null {
    if (!existsSync(this.options.metadataPath)) return null;
    let value: Partial<CredentialMetadata>;
    try {
      value = JSON.parse(
        readFileSync(this.options.metadataPath, "utf8"),
      ) as Partial<CredentialMetadata>;
    } catch {
      value = {};
    }
    if (
      value.schema !== CREDENTIAL_METADATA_SCHEMA ||
      value.mode !== this.mode ||
      typeof value.credential_ref !== "string" ||
      typeof value.generation !== "number"
    )
      return null;
    return value as CredentialMetadata;
  }

  #incompatibleMetadataPresent(): boolean {
    return (
      existsSync(this.options.metadataPath) && this.readMetadata() === null
    );
  }

  status(): CredentialStatus {
    if (!this.storesSecrets) return { state: "delegated", metadata: null };
    if (this.#incompatibleMetadataPresent())
      return {
        state: "absent",
        metadata: null,
        notice:
          "Credential metadata is from an incompatible version; login is required",
      };
    const metadata = this.readMetadata();
    if (!metadata) return { state: "absent", metadata: null };
    if (metadata.rejected_at)
      return {
        state: "rejected",
        metadata,
        notice: "The gateway rejected this credential; it will be renewed",
      };
    if (!metadata.expires_at) return { state: "valid", metadata };
    const remaining = Math.floor(
      (Date.parse(metadata.expires_at) - this.#now()) / 1000,
    );
    return {
      state:
        remaining <= 0
          ? "expired"
          : remaining <= this.options.beforeExpirySeconds
            ? "expiring"
            : "valid",
      metadata,
      remainingSeconds: Math.max(0, remaining),
    };
  }

  #ref(generation: number): string {
    return `piship:${this.options.distributionId}:inference#${generation}`;
  }

  #toRef(metadata: CredentialMetadata): CredentialRef {
    return {
      ref: metadata.credential_ref,
      mode: metadata.mode,
      kind: metadata.kind,
      ...(metadata.credential_id
        ? { credentialId: metadata.credential_id }
        : {}),
      ...(metadata.expires_at
        ? { expiresAt: new Date(metadata.expires_at) }
        : {}),
      ...(metadata.models ? { models: metadata.models } : {}),
    };
  }

  #eventDetail(
    metadata: CredentialMetadata,
  ): Record<string, string | number | boolean | null> {
    return {
      kind: metadata.kind,
      generation: metadata.generation,
      credentialId: metadata.credential_id ?? null,
      expiresAt: metadata.expires_at ?? null,
    };
  }

  #store(): SecretStore {
    if (!this.options.store)
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "No secret store is configured",
        { component: "credential" },
      );
    return this.options.store;
  }

  /** Persist a newly acquired credential and switch metadata to it atomically. */
  async #commit(credential: RuntimeCredential): Promise<CredentialMetadata> {
    credential = normalizeCredential(credential);
    const store = this.#store();
    const previous = this.readMetadata();
    const generation = (previous?.generation ?? 0) + 1;
    const ref = this.#ref(generation);
    await store.put(ref, credential.secret);
    this.options.onPhase?.("secret-written");
    const orphans = new Set(previous?.orphans ?? []);
    if (previous) orphans.add(previous.credential_ref);
    const metadata: CredentialMetadata = {
      schema: CREDENTIAL_METADATA_SCHEMA,
      mode: this.mode,
      credential_ref: ref,
      generation,
      kind: credential.kind,
      ...(credential.credentialId
        ? { credential_id: credential.credentialId }
        : {}),
      ...(credential.expiresAt
        ? { expires_at: credential.expiresAt.toISOString() }
        : {}),
      acquired_at: new Date(this.#now()).toISOString(),
      ...(credential.metadata?.models
        ? { models: [...credential.metadata.models] }
        : {}),
      ...(typeof credential.metadata?.baseUrl === "string"
        ? { base_url: credential.metadata.baseUrl }
        : {}),
      ...(orphans.size ? { orphans: [...orphans].sort() } : {}),
    };
    writeAtomic(
      this.options.metadataPath,
      `${JSON.stringify(metadata, null, 2)}\n`,
    );
    this.options.onPhase?.("metadata-written");
    return this.#collectOrphans(metadata);
  }

  async #collectOrphans(
    metadata: CredentialMetadata,
  ): Promise<CredentialMetadata> {
    if (!metadata.orphans?.length) return metadata;
    const remaining: string[] = [];
    for (const orphan of metadata.orphans)
      if (orphan !== metadata.credential_ref)
        try {
          await this.#store().delete(orphan);
        } catch {
          remaining.push(orphan);
        }
    const next: CredentialMetadata = { ...metadata };
    delete (next as { orphans?: readonly string[] }).orphans;
    if (remaining.length)
      (next as { orphans?: readonly string[] }).orphans = remaining;
    writeAtomic(
      this.options.metadataPath,
      `${JSON.stringify(next, null, 2)}\n`,
    );
    return next;
  }

  /**
   * Remove metadata we cannot use, deleting every secret it may reference so
   * nothing is left behind. Never resurrect or reuse such a secret.
   */
  async #clearMetadata(): Promise<void> {
    let raw: unknown = {};
    try {
      raw = JSON.parse(readFileSync(this.options.metadataPath, "utf8"));
    } catch {
      raw = {};
    }
    for (const ref of metadataSecretRefs(raw, this.options.distributionId))
      await this.options.store?.delete(ref).catch(() => {});
    rmSync(this.options.metadataPath, { force: true });
  }

  /**
   * Return a usable credential, acquiring or refreshing as needed.
   * `allowAcquire` is false for launches that must not prompt or contact the
   * broker without a prior login.
   */
  async ensure(
    identity: IdentitySession | null,
    ctx: CredentialContext,
    options: { allowAcquire: boolean; forceRefresh?: boolean },
  ): Promise<ActiveCredential> {
    if (!this.storesSecrets) {
      await this.options.provider.acquire(identity, ctx);
      return {
        ref: { ref: `delegated:${this.mode}`, mode: this.mode },
        secret: null,
        notices: [],
      };
    }
    // A forced renewal is satisfied by any renewal that lands after the
    // caller observed the rejected generation, including one by another caller.
    const observed = this.readMetadata()?.credential_ref;
    return this.#exclusive(() =>
      this.#ensure(identity, ctx, {
        ...options,
        forceRefresh:
          options.forceRefresh === true &&
          this.readMetadata()?.credential_ref === observed,
      }),
    );
  }

  /**
   * Serialize credential changes within this process and across processes, so
   * concurrent refreshes neither leak unrevoked credentials nor pair metadata
   * with another generation's secret.
   */
  #exclusive<T>(task: () => Promise<T>): Promise<T> {
    const path = this.options.metadataPath;
    const previous = queues.get(path) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(() => withFileLock(path, task));
    const tail = run.catch(() => {});
    queues.set(path, tail);
    void tail.then(() => {
      if (queues.get(path) === tail) queues.delete(path);
    });
    return run;
  }

  async #ensure(
    identity: IdentitySession | null,
    ctx: CredentialContext,
    options: { allowAcquire: boolean; forceRefresh?: boolean },
  ): Promise<ActiveCredential> {
    if (!this.storesSecrets) {
      await this.options.provider.acquire(identity, ctx);
      return {
        ref: { ref: `delegated:${this.mode}`, mode: this.mode },
        secret: null,
        notices: [],
      };
    }
    const notices: string[] = [];
    if (this.#incompatibleMetadataPresent()) {
      await this.#clearMetadata();
      notices.push(
        "Incompatible credential metadata was cleared; a new credential is required",
      );
    }
    let metadata = this.readMetadata();
    const secret = metadata
      ? await this.#store().get(metadata.credential_ref)
      : null;
    if (metadata && !secret) {
      await this.#clearMetadata();
      notices.push(
        "Stored credential metadata had no matching secret and was cleared",
      );
      metadata = null;
    }
    if (!metadata || !secret) {
      if (!options.allowAcquire)
        throw new PiShipError(
          "CREDENTIAL_REQUIRED",
          "No runtime credential is available",
          {
            component: "credential",
            userAction: "Run the branded login command",
          },
        );
      const returned = await this.options.provider.acquire(identity, ctx);
      if (!returned)
        throw new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          "The credential provider returned no credential",
          {
            component: "credential",
          },
        );
      const acquired = normalizeCredential(returned);
      metadata = await this.#commit(acquired);
      this.#emit("credential.acquire", this.#eventDetail(metadata));
      return { ref: this.#toRef(metadata), secret: acquired.secret, notices };
    }
    const status = this.status();
    const force = options.forceRefresh || status.state === "rejected";
    if (force || status.state === "expiring" || status.state === "expired") {
      const current: RuntimeCredential = {
        kind: metadata.kind,
        secret,
        ...(metadata.credential_id
          ? { credentialId: metadata.credential_id }
          : {}),
        ...(metadata.expires_at
          ? { expiresAt: new Date(metadata.expires_at) }
          : {}),
      };
      try {
        const provider = this.options.provider;
        const returned = provider.refresh
          ? await provider.refresh(identity, current, ctx)
          : await provider.acquire(identity, ctx);
        if (!returned)
          throw new PiShipError(
            "CREDENTIAL_ACQUIRE_FAILED",
            "Credential refresh returned nothing",
          );
        const next = normalizeCredential(returned);
        metadata = await this.#commit(next);
        this.#emit("credential.refresh", {
          ...this.#eventDetail(metadata),
          reason: force ? "rejected" : status.state,
        });
        return { ref: this.#toRef(metadata), secret: next.secret, notices };
      } catch (error) {
        if (status.state === "expired" || force) {
          if (
            error instanceof PiShipError &&
            error.code !== "CREDENTIAL_ACQUIRE_FAILED"
          )
            throw error;
          // Keep the retry contract of the failed renewal: a broker outage
          // or rate limit stays retryable, with the server's wait.
          const failure = error instanceof PiShipError ? error : undefined;
          throw new PiShipError(
            force ? "CREDENTIAL_REVOKED" : "CREDENTIAL_EXPIRED",
            `The runtime credential ${force ? "was rejected" : "expired"} and could not be renewed${error instanceof Error ? `: ${error.message}` : ""}`,
            {
              component: "credential",
              userAction: failure?.retryable
                ? "Try again later; if it keeps failing, run the branded login command"
                : "Run the branded login command",
              retryable: failure?.retryable ?? false,
              ...(failure?.retryAfterMs === undefined
                ? {}
                : { retryAfterMs: failure.retryAfterMs }),
              ...(failure?.sanitizedDetail
                ? { sanitizedDetail: failure.sanitizedDetail }
                : {}),
            },
          );
        }
        notices.push(
          `Credential refresh failed; continuing with the current credential (${status.remainingSeconds ?? 0}s remaining)`,
        );
      }
    }
    return { ref: this.#toRef(metadata), secret, notices };
  }

  /**
   * Whether a rejected credential can be replaced without the user, which
   * holds for organization-issued credentials but not user-owned secrets.
   */
  get renewable(): boolean {
    return this.mode === "http-broker" || this.mode === "adapter";
  }

  /**
   * Record a gateway rejection so this and later processes renew before reuse.
   * Only the generation that was rejected is marked, never a newer one.
   */
  async markRejected(): Promise<void> {
    if (!this.renewable) return;
    const observed = this.readMetadata()?.credential_ref;
    await this.#exclusive(async () => {
      const metadata = this.readMetadata();
      if (
        !metadata ||
        metadata.rejected_at ||
        metadata.credential_ref !== observed
      )
        return;
      writeAtomic(
        this.options.metadataPath,
        `${JSON.stringify({ ...metadata, rejected_at: new Date(this.#now()).toISOString() }, null, 2)}\n`,
      );
    });
  }

  /** Revoke when supported, then clear local secrets and metadata. */
  async logout(
    ctx: CredentialContext,
    options: { readonly reason?: CredentialRevokeReason } = {},
  ): Promise<string[]> {
    if (!this.storesSecrets) return [];
    return this.#exclusive(() => this.#logout(ctx, options.reason ?? "logout"));
  }

  /**
   * Revoke the current credential remotely without clearing it, for callers
   * that clear local state themselves (update, rollback, migration). Emits
   * `credential.revoke` when there was a credential this release can read.
   */
  async revoke(
    ctx: CredentialContext,
    reason: CredentialRevokeReason,
  ): Promise<{
    readonly outcome: RevocationOutcome | "absent";
    readonly problem?: string;
  }> {
    if (!this.storesSecrets) return { outcome: "absent" };
    return this.#exclusive(async () => {
      const metadata = this.readMetadata();
      if (!metadata) return { outcome: "absent" as const };
      return this.#revoke(metadata, ctx, reason);
    });
  }

  async #revoke(
    metadata: CredentialMetadata,
    ctx: CredentialContext,
    reason: CredentialRevokeReason,
  ): Promise<{ outcome: RevocationOutcome; problem?: string }> {
    let outcome: RevocationOutcome;
    let problem: string | undefined;
    const secret =
      this.revocable && this.options.store
        ? await this.options.store
            .get(metadata.credential_ref)
            .catch(() => null)
        : null;
    if (!this.revocable) outcome = "unsupported";
    else if (!secret) outcome = "skipped";
    else
      try {
        await this.options.provider.revoke?.(
          {
            kind: metadata.kind,
            secret,
            ...(metadata.credential_id
              ? { credentialId: metadata.credential_id }
              : {}),
          },
          ctx,
        );
        outcome = "revoked";
      } catch (error) {
        outcome = "failed";
        problem = `revocation: ${error instanceof Error ? error.message : String(error)}`;
      }
    this.#emit("credential.revoke", {
      generation: metadata.generation,
      credentialId: metadata.credential_id ?? null,
      reason,
      revocation: outcome,
    });
    return { outcome, ...(problem ? { problem } : {}) };
  }

  async #logout(
    ctx: CredentialContext,
    reason: CredentialRevokeReason,
  ): Promise<string[]> {
    const problems: string[] = [];
    const store = this.options.store;
    let raw: unknown = null;
    try {
      raw = JSON.parse(readFileSync(this.options.metadataPath, "utf8"));
    } catch {
      raw = null;
    }
    const metadata = this.readMetadata();
    if (metadata) {
      const revoked = await this.#revoke(metadata, ctx, reason);
      if (revoked.problem) problems.push(revoked.problem);
    }
    // Metadata this release cannot use may still reference secrets, and the
    // next generation may hold a secret written before a crash that never
    // reached metadata; clear all of them so logout leaves nothing behind.
    if (store && raw)
      for (const ref of metadataSecretRefs(raw, this.options.distributionId))
        try {
          await store.delete(ref);
        } catch (error) {
          problems.push(
            `delete ${ref}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
    rmSync(this.options.metadataPath, { force: true });
    return problems;
  }
}
