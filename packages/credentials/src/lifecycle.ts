import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomUUID } from "node:crypto";
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
import { basename, dirname, join } from "node:path";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  type IdentitySession,
  PiShipError,
  type PrincipalKey,
  principalKey,
  redact,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  type SecretStore,
  SecretValue,
  samePrincipal,
} from "@piship/contracts";
import { heldLocks } from "./lock-heartbeat.js";

export const CREDENTIAL_METADATA_SCHEMA = "piship-credential-metadata/v1";
/**
 * Metadata left in place of a credential whose secrets could not all be
 * deleted: it lists only the references still to delete. No release reads it
 * as a credential (older ones see an incompatible schema and clear it), so a
 * discarded credential is never used, and every command retries the deletion
 * before it does anything else with the credential.
 */
export const CREDENTIAL_DISCARDED_SCHEMA = "piship-credential-discarded/v1";
export const REVOCATION_RETRY_SCHEMA = "piship-revocation-retry/v1";
/** Default file name of pending revocations, beside the credential metadata. */
export const REVOCATION_RETRY_FILE = "revocation-retry.json";
/**
 * Most pending revocations kept. An entry without an expiry never resolves on
 * its own, so every failed switch would add one; beyond this the oldest are
 * dropped and only their number is kept.
 */
export const REVOCATION_RETRY_LIMIT = 20;

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
  /**
   * The principal `(iss, sub)` the credential and its entitlement (`models`)
   * were issued to; absent when no identity is configured. A credential is
   * used only while the signed-in principal is the same.
   */
  readonly principal?: PrincipalKey;
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
  /**
   * When this credential was acquired: with `ref` it names one issuance,
   * since generations restart from 1 after a logout.
   */
  readonly acquiredAt?: string;
}

/** The credential a failed request used, and who it was issued to. */
export interface RejectedCredential {
  readonly ref: string;
  readonly acquiredAt?: string | undefined;
  readonly principal: PrincipalKey | null;
}

/**
 * Why a credential was revoked: `principal-change` is a stored credential
 * found bound to another principal than the signed-in one; `unbound` is one
 * from an earlier release that recorded no principal, replaced once an
 * identity is signed in.
 */
export type CredentialRevokeReason =
  | "logout"
  | "replace"
  | "lifecycle"
  | "principal-change"
  | "unbound";

/**
 * Outcome of a remote revocation attempt: `revoked` when the provider
 * accepted it, `failed` when it raised or the secret store could not be read,
 * `unsupported` when the provider has no remote revocation, and `skipped`
 * when the secret store holds no secret for the credential.
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

/**
 * Points of a credential operation a crash-safety test can stop at:
 * `revoked` after a remote revocation attempt and before any local deletion,
 * `secret-deleted` after each confirmed deletion of a stored secret.
 */
export type CredentialPhase =
  | "secret-written"
  | "metadata-written"
  | "revoked"
  | "secret-deleted";

export interface CredentialManagerOptions {
  readonly distributionId: string;
  readonly provider: CredentialProvider;
  readonly store: SecretStore | null;
  readonly metadataPath: string;
  readonly beforeExpirySeconds: number;
  readonly now?: () => number;
  /**
   * Where failed remote revocations are recorded (non-secret). Defaults to
   * `revocation-retry.json` beside the metadata.
   */
  readonly revocationRetryPath?: string;
  /**
   * Fault injection for crash-safety tests: a hook that throws stops the
   * operation at that point, as a crash would.
   */
  readonly onPhase?: (phase: CredentialPhase) => void | Promise<void>;
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
 * One remote revocation that failed after the local secret was deleted, or
 * was about to be. Non-secret: it names the credential, never holds it.
 */
export interface RevocationRetryEntry {
  readonly credential_id?: string;
  readonly mode: CredentialProvider["mode"];
  readonly generation: number;
  readonly reason: CredentialRevokeReason;
  readonly failed_at: string;
  readonly expires_at?: string;
  /** How many later logins found it still pending. */
  readonly checks: number;
  readonly checked_at?: string;
}

interface RevocationRetryFile {
  readonly schema: typeof REVOCATION_RETRY_SCHEMA;
  readonly entries: readonly RevocationRetryEntry[];
  /** How many older entries were dropped to keep the file bounded. */
  readonly dropped?: number;
}

/** Pending revocations for diagnostics: counts and ages only, no secrets. */
export interface PendingRevocations {
  /** False when the file exists but cannot be read. */
  readonly readable: boolean;
  readonly count: number;
  /** Older entries dropped beyond the limit; they may still be live. */
  readonly dropped: number;
  readonly oldestAgeSeconds: number | null;
  readonly entries: readonly {
    readonly credentialId?: string;
    readonly reason: CredentialRevokeReason;
    readonly failedAt: string;
    readonly ageSeconds: number;
    readonly expiresAt?: string;
  }[];
}

function readRetryFile(path: string): RevocationRetryFile | null {
  if (!existsSync(path))
    return { schema: REVOCATION_RETRY_SCHEMA, entries: [] };
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as RevocationRetryFile;
    if (
      value?.schema !== REVOCATION_RETRY_SCHEMA ||
      !Array.isArray(value.entries)
    )
      return null;
    return {
      schema: REVOCATION_RETRY_SCHEMA,
      entries: value.entries.filter(
        (entry) =>
          !!entry &&
          typeof entry.failed_at === "string" &&
          typeof entry.generation === "number",
      ),
      ...(Number.isInteger(value.dropped) && (value.dropped ?? 0) > 0
        ? { dropped: value.dropped }
        : {}),
    };
  } catch {
    return null;
  }
}

/**
 * Summarize the pending revocations recorded at `path` (the credential
 * metadata directory's `revocation-retry.json`), for `doctor`.
 */
export function readPendingRevocations(
  path: string,
  now: number = Date.now(),
): PendingRevocations {
  const file = readRetryFile(path);
  if (!file)
    return {
      readable: false,
      count: 0,
      dropped: 0,
      oldestAgeSeconds: null,
      entries: [],
    };
  const entries = file.entries.map((entry) => ({
    ...(entry.credential_id ? { credentialId: entry.credential_id } : {}),
    reason: entry.reason,
    failedAt: entry.failed_at,
    ageSeconds: Math.max(
      0,
      Math.floor((now - Date.parse(entry.failed_at)) / 1000) || 0,
    ),
    ...(entry.expires_at ? { expiresAt: entry.expires_at } : {}),
  }));
  return {
    readable: true,
    count: entries.length,
    dropped: file.dropped ?? 0,
    oldestAgeSeconds: entries.length
      ? Math.max(...entries.map((entry) => entry.ageSeconds))
      : null,
    entries,
  };
}

/**
 * Every secret-store reference that credential or identity metadata (or a
 * discarded marker of either) of one distribution may own: the current
 * generation, recorded orphans, the next
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
  const identity = `piship:${distributionId}:identity#`;
  for (const item of [
    value.credential_ref,
    ...(Array.isArray(value.orphans) ? value.orphans : []),
  ])
    if (
      typeof item === "string" &&
      (item.startsWith(inference) || item.startsWith(identity))
    )
      refs.add(item);
  const generation = Number(value.generation);
  if (
    value.generation !== undefined &&
    Number.isInteger(generation) &&
    generation >= 0
  ) {
    refs.add(`${inference}${generation}`);
    refs.add(`${inference}${generation + 1}`);
  }
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
  const own = value instanceof SecretValue;
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
  // The secret is sent in a request header: anything but visible ASCII (a
  // space, a control character, CR or LF) would fail every request, as a
  // transport error that could even echo it. Refused here, before it is
  // stored, the same way the broker's credentials are.
  if (/[^\x21-\x7e]/.test(text))
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned a secret a request header cannot carry: only visible ASCII characters are allowed, without spaces",
      { component: "credential" },
    );
  return own ? (value as SecretValue) : new SecretValue(text);
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
  // The ID reaches notices, audit events, the retry record, and doctor: keep
  // it to the characters an identifier needs, whichever provider issued it.
  if (
    credential.credentialId !== undefined &&
    (typeof credential.credentialId !== "string" ||
      !/^[A-Za-z0-9._:-]{1,256}$/.test(credential.credentialId))
  )
    throw new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "The credential provider returned an invalid credential ID",
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

/**
 * Delete each reference and confirm it is gone. A delete that throws, or a
 * secret still readable (or unreadable) afterwards, is a failure: an
 * unconfirmed deletion never counts as absent. Returns the failures, with
 * redacted problems.
 */
export async function deleteSecretsVerified(
  store: SecretStore,
  refs: readonly string[],
  /** Called after each confirmed deletion (crash-safety tests). */
  afterDelete?: (ref: string) => void | Promise<void>,
): Promise<{ ref: string; problem: string }[]> {
  const failed: { ref: string; problem: string }[] = [];
  for (const ref of refs) {
    let deleted = false;
    try {
      await store.delete(ref);
      if ((await store.get(ref)) !== null)
        failed.push({ ref, problem: "still present after deletion" });
      else deleted = true;
    } catch (error) {
      failed.push({
        ref,
        problem:
          error instanceof PiShipError
            ? `${error.code}: ${redact(error.message)}`
            : redact(error instanceof Error ? error.message : String(error)),
      });
    }
    // Outside the try: a hook that throws stops here, as a crash would.
    if (deleted) await afterDelete?.(ref);
  }
  return failed;
}

/** A local secret that could not be deleted: fail closed. */
export function deletionFailure(
  failed: readonly { ref: string; problem: string }[],
): PiShipError {
  return new PiShipError(
    "SECRET_STORE_UNAVAILABLE",
    `A stored credential could not be deleted from the secret store (${failed.map((item) => `${item.ref}: ${item.problem}`).join("; ")}); it is not used, and the deletion is retried by the next login, launch, or logout`,
    {
      component: "credential",
      userAction:
        "Unlock or repair the secret store, then run the command again",
      sanitizedDetail: { refs: failed.map((item) => item.ref) },
    },
  );
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
/**
 * The lock files the current asynchronous call chain holds. A task that
 * already holds a lock and asks for it again (a login that clears and
 * acquires the credential under one lock) runs at once instead of waiting
 * for itself. Other call chains, in this process or another, still wait.
 * Work a task starts belongs to its chain, so a task must not start work
 * that outlives it (it would still count as holding the lock).
 */
const heldByChain = new AsyncLocalStorage<ReadonlySet<string>>();

/** Whether the current call chain holds the lock beside `path`. */
export function holdsFileLock(path: string): boolean {
  return heldByChain.getStore()?.has(`${path}.lock`) ?? false;
}

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

const LOCK_TIMEOUT = "lock-timeout";

/** Whether `error` is a wait for a cross-process lock that ran out. */
export function isLockTimeout(error: unknown): boolean {
  return (
    error instanceof PiShipError &&
    error.sanitizedDetail?.reason === LOCK_TIMEOUT
  );
}

/**
 * Cross-process lock beside the metadata file. The holder refreshes the
 * lock's mtime while its task runs (on an interval, and before each blocking
 * secret-store command), so a lock is broken only when it is stale: its
 * holder stopped refreshing it, such as a crashed process. A fresh lock is
 * never broken: after the wait, the caller fails with a retryable error.
 * The lock is reentrant within one call chain (see `holdsFileLock`).
 */
export async function withFileLock<T>(
  path: string,
  task: () => Promise<T>,
  timing: FileLockTiming = {},
): Promise<T> {
  const heartbeatMs = timing.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const staleMs = timing.staleMs ?? LOCK_STALE_MS;
  const waitMs = timing.waitMs ?? LOCK_WAIT_MS;
  const lock = `${path}.lock`;
  const held = heldByChain.getStore();
  if (held?.has(lock)) return task();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
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
            sanitizedDetail: { reason: LOCK_TIMEOUT },
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
    return await heldByChain.run(new Set([...(held ?? []), lock]), task);
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

  /**
   * Whether any credential metadata is left, including metadata of a
   * credential whose secrets could not all be deleted. A caller that must
   * know the previous credential is gone checks this after `logout`.
   */
  hasStoredCredential(): boolean {
    return existsSync(this.options.metadataPath);
  }

  #discardedPending(): boolean {
    try {
      return (
        (
          JSON.parse(readFileSync(this.options.metadataPath, "utf8")) as {
            schema?: unknown;
          }
        ).schema === CREDENTIAL_DISCARDED_SCHEMA
      );
    } catch {
      return false;
    }
  }

  status(): CredentialStatus {
    if (!this.storesSecrets) return { state: "delegated", metadata: null };
    if (this.#discardedPending())
      return {
        state: "absent",
        metadata: null,
        notice:
          "A discarded credential is still being deleted from the secret store; it is never used",
      };
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
  async #commit(
    credential: RuntimeCredential,
    principal: PrincipalKey | null,
    notices: string[],
  ): Promise<CredentialMetadata> {
    credential = normalizeCredential(credential);
    const store = this.#store();
    const previous = this.readMetadata();
    const generation = (previous?.generation ?? 0) + 1;
    const ref = this.#ref(generation);
    await store.put(ref, credential.secret);
    await this.options.onPhase?.("secret-written");
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
      ...(principal
        ? {
            principal: {
              issuer: principal.issuer,
              subject: principal.subject,
            },
          }
        : {}),
      ...(orphans.size ? { orphans: [...orphans].sort() } : {}),
    };
    writeAtomic(
      this.options.metadataPath,
      `${JSON.stringify(metadata, null, 2)}\n`,
    );
    await this.options.onPhase?.("metadata-written");
    return this.#collectOrphans(metadata, notices);
  }

  /**
   * Delete replaced generations, confirming each deletion. One that fails
   * stays listed in `orphans`, so the next commit, logout, or discard retries
   * it, and is reported as a notice.
   */
  async #collectOrphans(
    metadata: CredentialMetadata,
    notices: string[],
  ): Promise<CredentialMetadata> {
    if (!metadata.orphans?.length) return metadata;
    const failed = await deleteSecretsVerified(
      this.#store(),
      metadata.orphans.filter((orphan) => orphan !== metadata.credential_ref),
    );
    const remaining = failed.map((item) => item.ref);
    for (const item of failed)
      notices.push(
        `A replaced credential could not be deleted from the secret store (${item.ref}: ${item.problem}); it is not used, and the deletion is retried`,
      );
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

  #readRaw(): unknown {
    try {
      return JSON.parse(readFileSync(this.options.metadataPath, "utf8"));
    } catch {
      return {};
    }
  }

  /**
   * Delete every secret the metadata may reference, then the metadata. When a
   * deletion fails, the metadata is replaced by a discarded marker listing
   * the references still to delete, so the secret stays tracked and is never
   * used, and the failures are returned.
   */
  async #discardMetadata(
    raw: unknown = this.#readRaw(),
  ): Promise<{ ref: string; problem: string }[]> {
    const failed = await deleteSecretsVerified(
      this.#store(),
      metadataSecretRefs(raw, this.options.distributionId),
      () => this.options.onPhase?.("secret-deleted"),
    );
    if (!failed.length) {
      rmSync(this.options.metadataPath, { force: true });
      return failed;
    }
    writeAtomic(
      this.options.metadataPath,
      `${JSON.stringify(
        {
          schema: CREDENTIAL_DISCARDED_SCHEMA,
          orphans: failed.map((item) => item.ref).sort(),
          discarded_at: new Date(this.#now()).toISOString(),
        },
        null,
        2,
      )}\n`,
    );
    return failed;
  }

  /**
   * Discard metadata that must not be used, failing closed when a secret it
   * references could not be deleted.
   */
  async #clearMetadata(raw?: unknown): Promise<void> {
    const failed = await this.#discardMetadata(raw);
    if (failed.length) throw deletionFailure(failed);
  }

  /**
   * Return a usable credential, acquiring or refreshing as needed.
   * `allowAcquire` is false for launches that must not prompt or contact the
   * broker without a prior login.
   */
  async ensure(
    identity: IdentitySession | null,
    ctx: CredentialContext,
    options: {
      allowAcquire: boolean;
      /**
       * Renew even a valid credential: `true` after the gateway rejected it,
       * `"entitlement"` to re-read its entitlement after a model denial. A
       * failed entitlement re-read keeps the current credential and throws
       * the renewal's own error; the credential was not rejected.
       */
      forceRefresh?: boolean | "entitlement";
      /**
       * The generation (`credential_ref`) the forced renewal is about; read
       * now when omitted. Only that generation is renewed: one that another
       * caller already replaced satisfies the request, so one denial never
       * makes two processes each re-issue.
       */
      observed?: string;
      /**
       * Runs under the credential lock before anything is read, used, or
       * acquired: the caller re-checks there that `identity` is still the
       * signed-in principal, and throws to stop.
       */
      guard?: () => void | Promise<void>;
    },
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
    const observed = options.observed ?? this.readMetadata()?.credential_ref;
    const { guard, observed: _observed, ...rest } = options;
    return this.#exclusive(async () => {
      await guard?.();
      const current = this.readMetadata()?.credential_ref === observed;
      return this.#ensure(identity, ctx, {
        ...rest,
        forceRefresh: current ? (options.forceRefresh ?? false) : false,
      });
    });
  }

  /**
   * Run `task` under the credential lock, so a caller can make several
   * changes (clear, sign in, acquire) that no other process or call
   * interleaves with. Credential operations inside `task` reuse the lock.
   */
  exclusive<T>(task: () => Promise<T>): Promise<T> {
    return this.#exclusive(task);
  }

  /**
   * Serialize credential changes within this process and across processes, so
   * concurrent refreshes neither leak unrevoked credentials nor pair metadata
   * with another generation's secret.
   */
  #exclusive<T>(task: () => Promise<T>): Promise<T> {
    const path = this.options.metadataPath;
    // Already held by this call chain: queueing behind itself would deadlock.
    if (holdsFileLock(path)) return task();
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
    options: { allowAcquire: boolean; forceRefresh?: boolean | "entitlement" },
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
    // One idempotency key per logical acquire or renewal: the one request
    // this call may send. Nothing here re-sends it; a caller that retries
    // the same acquire passes the key back.
    const attempt: CredentialContext = ctx.idempotencyKey
      ? ctx
      : { ...ctx, idempotencyKey: randomUUID() };
    const principal = identity ? principalKey(identity) : null;
    if (this.#incompatibleMetadataPresent()) {
      const discarded = this.#discardedPending();
      await this.#clearMetadata();
      notices.push(
        discarded
          ? "The secrets of a discarded credential were deleted"
          : "Incompatible credential metadata was cleared; a new credential is required",
      );
    }
    let metadata = this.readMetadata();
    // A credential is used only by the principal it was issued to. Anything
    // else, including metadata written before credentials were bound to a
    // principal, is revoked where supported and deleted, never used.
    if (metadata && !samePrincipal(metadata.principal ?? null, principal)) {
      // An earlier release recorded no principal: most likely the same
      // user, but nothing proves it, so it is replaced all the same.
      const unbound = !metadata.principal && !!principal;
      const revoked = await this.#revoke(
        metadata,
        attempt,
        unbound ? "unbound" : "principal-change",
      );
      await this.#clearMetadata(metadata);
      notices.push(
        unbound
          ? "A credential from an earlier release was replaced"
          : "A stored credential that was not issued to the signed-in identity was discarded",
      );
      if (revoked.problem)
        notices.push(
          `The discarded credential could not be revoked; it is recorded for follow-up: ${revoked.problem}`,
        );
      metadata = null;
    }
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
      const returned = await this.options.provider.acquire(identity, attempt);
      if (!returned)
        throw new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          "The credential provider returned no credential",
          {
            component: "credential",
          },
        );
      const acquired = normalizeCredential(returned);
      metadata = await this.#commit(acquired, principal, notices);
      this.#emit("credential.acquire", this.#eventDetail(metadata));
      return {
        ref: this.#toRef(metadata),
        secret: acquired.secret,
        notices,
        acquiredAt: metadata.acquired_at,
      };
    }
    const status = this.status();
    const rejected =
      options.forceRefresh === true || status.state === "rejected";
    // Only an entitlement re-read of a credential nothing else is wrong with.
    const entitlement =
      options.forceRefresh === "entitlement" &&
      !rejected &&
      status.state !== "expired";
    const force = rejected || entitlement;
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
          ? await provider.refresh(identity, current, attempt)
          : await provider.acquire(identity, attempt);
        if (!returned)
          throw new PiShipError(
            "CREDENTIAL_ACQUIRE_FAILED",
            "Credential refresh returned nothing",
          );
        const next = normalizeCredential(returned);
        metadata = await this.#commit(next, principal, notices);
        this.#emit("credential.refresh", {
          ...this.#eventDetail(metadata),
          reason: entitlement
            ? "entitlement"
            : rejected
              ? "rejected"
              : status.state,
        });
        return {
          ref: this.#toRef(metadata),
          secret: next.secret,
          notices,
          acquiredAt: metadata.acquired_at,
        };
      } catch (error) {
        // A denial is the organization's answer, not an outage: an early
        // renewal it refuses does not leave the user on the credential that
        // is still valid.
        if (error instanceof PiShipError && error.code === "CREDENTIAL_DENIED")
          throw error;
        // The credential is fine and stays in use; the re-read failed with
        // its own error (a broker outage stays retryable, with its wait).
        if (entitlement)
          throw error instanceof PiShipError
            ? error
            : new PiShipError(
                "CREDENTIAL_ACQUIRE_FAILED",
                `The entitlement could not be re-read: ${redact(error instanceof Error ? error.message : String(error))}`,
                { component: "credential", retryable: true },
              );
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
            `The runtime credential ${force ? "was rejected" : "expired"} and could not be renewed${error instanceof Error ? `: ${redact(error.message)}` : ""}`,
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
    return {
      ref: this.#toRef(metadata),
      secret,
      notices,
      acquiredAt: metadata.acquired_at,
    };
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
   * `used` names the credential the failed request carried and the principal
   * it was issued to: only that issuance is marked, never a newer one, and
   * never one issued to someone else, whatever is stored by now. Without
   * `used`, the credential stored when the call is made is the one marked.
   */
  async markRejected(used?: RejectedCredential): Promise<void> {
    if (!this.renewable) return;
    const observed = used?.ref ?? this.readMetadata()?.credential_ref;
    await this.#exclusive(async () => {
      const metadata = this.readMetadata();
      if (
        !metadata ||
        metadata.rejected_at ||
        metadata.credential_ref !== observed ||
        (used &&
          ((used.acquiredAt !== undefined &&
            metadata.acquired_at !== used.acquiredAt) ||
            !samePrincipal(metadata.principal ?? null, used.principal)))
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
    let secret: SecretValue | null = null;
    let unreadable: unknown;
    if (this.revocable && this.options.store)
      try {
        secret = await this.options.store.get(metadata.credential_ref);
      } catch (error) {
        unreadable = error;
      }
    if (!this.revocable) outcome = "unsupported";
    else if (unreadable !== undefined) {
      // The credential may still be live at the broker: say so, never skip it.
      outcome = "failed";
      problem = `revocation: the stored credential could not be read (${unreadable instanceof PiShipError ? unreadable.code : "secret store error"})`;
    } else if (!secret) outcome = "skipped";
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
        problem = `revocation: ${redact(error instanceof Error ? error.message : String(error))}`;
      }
    // A failed revocation leaves a credential that may be live remotely while
    // its local secret is deleted: record it (without the secret) so login
    // and doctor keep reporting it.
    let retryPending = false;
    if (outcome === "failed")
      try {
        this.#recordRetry(metadata, reason);
        retryPending = true;
      } catch (error) {
        problem = `${problem}; the pending revocation could not be recorded (${redact(error instanceof Error ? error.message : String(error))})`;
      }
    this.#emit("credential.revoke", {
      generation: metadata.generation,
      credentialId: metadata.credential_id ?? null,
      reason,
      revocation: outcome,
      ...(retryPending ? { retryPending: true } : {}),
    });
    return { outcome, ...(problem ? { problem } : {}) };
  }

  get #retryPath(): string {
    return (
      this.options.revocationRetryPath ??
      join(dirname(this.options.metadataPath), REVOCATION_RETRY_FILE)
    );
  }

  #writeRetries(
    entries: readonly RevocationRetryEntry[],
    dropped: number,
  ): void {
    if (!entries.length && !dropped) {
      rmSync(this.#retryPath, { force: true });
      return;
    }
    writeAtomic(
      this.#retryPath,
      `${JSON.stringify(
        {
          schema: REVOCATION_RETRY_SCHEMA,
          entries,
          ...(dropped ? { dropped } : {}),
        },
        null,
        2,
      )}\n`,
    );
  }

  #recordRetry(
    metadata: CredentialMetadata,
    reason: CredentialRevokeReason,
  ): void {
    // An unreadable file is replaced: it holds nothing secret, and losing the
    // record of an older failure is better than never recording this one.
    const file = readRetryFile(this.#retryPath);
    const entries = (file?.entries ?? []).filter(
      (entry) =>
        !(
          entry.generation === metadata.generation &&
          entry.credential_id === metadata.credential_id
        ),
    );
    entries.push({
      ...(metadata.credential_id
        ? { credential_id: metadata.credential_id }
        : {}),
      mode: this.mode,
      generation: metadata.generation,
      reason,
      failed_at: new Date(this.#now()).toISOString(),
      ...(metadata.expires_at ? { expires_at: metadata.expires_at } : {}),
      checks: 0,
    });
    // Oldest first: the file stays bounded, and the count of what was
    // dropped keeps the failure visible.
    const over = Math.max(0, entries.length - REVOCATION_RETRY_LIMIT);
    this.#writeRetries(entries.slice(over), (file?.dropped ?? 0) + over);
  }

  /** Pending revocations recorded by this manager, for diagnostics. */
  pendingRevocations(): PendingRevocations {
    return readPendingRevocations(this.#retryPath, this.#now());
  }

  /**
   * Re-check recorded revocation failures, as every login does. The
   * revocation itself cannot be re-sent: the provider authenticates it with
   * the credential, whose secret was deleted. An entry is resolved once its
   * credential has expired, and the rest are returned as notices so the
   * failure stays visible until an administrator revokes the credential.
   */
  checkPendingRevocations(): string[] {
    const file = readRetryFile(this.#retryPath);
    if (!file) return ["The pending revocation record is unreadable"];
    const now = this.#now();
    const remaining = file.entries
      .filter(
        (entry) => !entry.expires_at || Date.parse(entry.expires_at) > now,
      )
      .map((entry) => ({
        ...entry,
        checks: (entry.checks ?? 0) + 1,
        checked_at: new Date(now).toISOString(),
      }));
    const dropped = file.dropped ?? 0;
    if (remaining.length !== file.entries.length || remaining.length)
      this.#writeRetries(remaining, dropped);
    return [
      ...remaining.map(
        (entry) =>
          `Credential ${entry.credential_id ?? `generation ${entry.generation}`} could not be revoked on ${entry.failed_at}; it may be valid at the provider ${entry.expires_at ? `until ${entry.expires_at}` : "until an administrator revokes it"}`,
      ),
      ...(dropped
        ? [
            `${dropped} older credential(s) could not be revoked and are no longer listed; they may be valid at the provider until an administrator revokes them`,
          ]
        : []),
    ];
  }

  async #logout(
    ctx: CredentialContext,
    reason: CredentialRevokeReason,
  ): Promise<string[]> {
    const problems: string[] = [];
    if (!this.hasStoredCredential()) return problems;
    const metadata = this.readMetadata();
    if (metadata) {
      const revoked = await this.#revoke(metadata, ctx, reason);
      if (revoked.problem) problems.push(revoked.problem);
      await this.options.onPhase?.("revoked");
    }
    // Metadata this release cannot use may still reference secrets, and the
    // next generation may hold a secret written before a crash that never
    // reached metadata; delete all of them so logout leaves nothing behind.
    // What cannot be deleted stays tracked by a discarded marker.
    for (const failed of await this.#discardMetadata())
      problems.push(`delete ${failed.ref}: ${failed.problem}`);
    return problems;
  }
}
