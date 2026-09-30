import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
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
import { writeFileAtomic } from "./atomic.js";
import {
  type FileLockTiming,
  holdsFileLock,
  withFileLock,
} from "./file-lock.js";
import { metadataFileSecretRefs, secretRefsFromText } from "./ownership.js";
import { HttpBrokerCredentialProvider } from "./providers.js";
import {
  metadataFileSecretStore,
  type SecretStoreProvider,
  type SecretStoreResolver,
  secretStoreProvider,
  storeForRecorded,
} from "./store-owner.js";

export const CREDENTIAL_METADATA_SCHEMA = "piship-credential-metadata/v1";
/**
 * Metadata of the stored sandbox credential. A schema of its own, so every
 * release before it (which lists only the runtime credential's schema) sees a
 * class it cannot read and clears it with its secrets, instead of keeping a
 * file its logout and purge would not know.
 */
export const SANDBOX_CREDENTIAL_METADATA_SCHEMA =
  "piship-sandbox-credential-metadata/v1";
/**
 * Which credential a manager keeps: the runtime (`inference`) credential, or
 * the one sandbox credential a person stores for a remote sandbox backend.
 * The slot selects the secret-store reference prefix and the metadata schema.
 */
export type CredentialSlot = "inference" | "sandbox";
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
/**
 * The runtime credential's pending issuance: the idempotency key of the one
 * acquire or renewal that was sent and not yet resolved. Non-secret.
 */
export const CREDENTIAL_ISSUANCE_SCHEMA = "piship-credential-issuance/v1";
/** Default file name of the pending issuance, beside the credential metadata. */
export const CREDENTIAL_ISSUANCE_FILE = "pending-issuance.json";
/**
 * How long a pending issuance key is reused: the idempotency retention the
 * broker contract requires at least. Past it, the broker may have forgotten
 * the key, so reusing it no longer recovers an issued credential; the next
 * acquire starts a new key instead.
 */
export const ISSUANCE_RETENTION_MS = 24 * 60 * 60 * 1000;
/** A pending issuance dated further ahead of the clock than this fails closed like an expired one. */
const ISSUANCE_CLOCK_TOLERANCE_MS = 60 * 1000;

/** Non-secret credential state. The secret itself lives only in the SecretStore. */
export interface CredentialMetadata {
  readonly schema:
    | typeof CREDENTIAL_METADATA_SCHEMA
    | typeof SANDBOX_CREDENTIAL_METADATA_SCHEMA;
  readonly mode: CredentialProvider["mode"];
  /** Sandbox slot only: where the secret came from (`stored`). */
  readonly source?: "stored";
  /**
   * Sandbox slot only: the origins (scheme://host:port) the secret may be
   * sent to, recorded when it was stored.
   */
  readonly origins?: readonly string[];
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
  /**
   * The secret store holding every reference above. Metadata of another
   * store than the configured one is never read as a credential: its
   * references are deleted from the store it records. Absent in metadata
   * written before the store was recorded.
   */
  readonly secret_store?: SecretStoreProvider;
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
  /** The non-secret ID of one stored secret, where the credential has one. */
  readonly credentialId?: string | undefined;
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
  /** Timing of the cross-process credential lock (tests shorten it). */
  readonly lockTiming?: FileLockTiming;
  /**
   * The configured `credential.storage.provider`, recorded in metadata;
   * derived from `store` when omitted.
   */
  readonly storeProvider?: SecretStoreProvider;
  /**
   * The store of another provider, for deleting references that metadata
   * recorded for it (the storage provider changed). Without it, such
   * references stay tracked and fail closed.
   */
  readonly storeFor?: SecretStoreResolver;
  /** Default `inference`. Selects the reference prefix and metadata schema. */
  readonly slot?: CredentialSlot;
  /** Sandbox slot: the origins recorded with a newly stored secret. */
  readonly origins?: readonly string[];
  /**
   * Where the pending issuance (the idempotency key of an unresolved
   * acquire or renewal) is kept. Defaults to `pending-issuance.json` beside
   * the metadata. Only an organization-issued (`http-broker` or `adapter`)
   * runtime credential has one.
   */
  readonly issuancePath?: string;
  /** How long a pending issuance key is reused. Default `ISSUANCE_RETENTION_MS`. */
  readonly issuanceRetentionMs?: number;
  /**
   * What decides where an acquire goes, such as an adapter's module and its
   * endpoints; recorded as a hash with a pending issuance, which is dropped
   * when it changes. Defaults to the endpoint of an `HttpBrokerCredentialProvider`.
   */
  readonly issuanceTarget?: string;
}

/**
 * The credential a renewal replaces, as a pending issuance records it:
 * generations restart after a logout, so the acquisition time goes with the
 * reference.
 */
export interface IssuanceBase {
  readonly credential_ref: string;
  readonly acquired_at: string;
}

/**
 * One acquire or renewal that was sent (or was about to be) and has not been
 * resolved: its idempotency key, recorded before the request leaves, so a
 * retry after a lost answer or a crash sends the same key and a broker that
 * honors it returns the credential it already issued. Never a secret.
 */
export interface PendingIssuance {
  readonly schema: typeof CREDENTIAL_ISSUANCE_SCHEMA;
  readonly idempotency_key: string;
  readonly mode: CredentialProvider["mode"];
  /** The principal the request was sent for; absent without an identity. */
  readonly principal?: PrincipalKey;
  /** The credential the renewal replaces; absent for a first acquire. */
  readonly renews?: IssuanceBase;
  /** Which kind of request it was (see `IssuanceRequest`). */
  readonly request?: IssuanceRequest;
  /**
   * SHA-256 (hex) of where the request went: the broker endpoint, or what
   * the manager was told decides an adapter's destination. A key is never
   * sent to another service than the one it was recorded for.
   */
  readonly target?: string;
  readonly created_at: string;
}

/**
 * The logical request a pending issuance belongs to: a first `acquire`, a
 * `renewal` before or after expiry, a renewal after a gateway `rejected` the
 * credential, or an `entitlement` re-read. A rejection renewal and an
 * entitlement re-read are requests of their own: they never repeat the key
 * of another kind, whose credential the broker would replay.
 */
export type IssuanceRequest =
  | "acquire"
  | "renewal"
  | "rejected"
  | "entitlement";
const ISSUANCE_REQUESTS: readonly IssuanceRequest[] = [
  "acquire",
  "renewal",
  "rejected",
  "entitlement",
];

function sameBase(
  metadata: CredentialMetadata,
  base: IssuanceBase | undefined,
): boolean {
  return (
    !!base &&
    metadata.credential_ref === base.credential_ref &&
    metadata.acquired_at === base.acquired_at
  );
}

/**
 * Whether a failed acquire or renewal is the broker's (or adapter's) final
 * answer to its key, so the next attempt is a new logical request with a new
 * key. A failure that may have happened after the request took effect (no
 * answer, `outcome`), one that invites a retry (`retryable`: 5xx, 429, a
 * request still in progress, a timeout), one that says nothing about the
 * request (identity, network or TLS policy), and anything that is not a
 * PiShip error keep the key. A 403, a 409 or 422 conflict, another 4xx, and
 * a contract violation settle it.
 */
function settlesIssuance(error: unknown): boolean {
  if (!(error instanceof PiShipError)) return false;
  const outcome = error.sanitizedDetail?.outcome;
  if (outcome === "unknown" || outcome === "not-sent") return false;
  if (error.retryable) return false;
  return !(
    error.code.startsWith("IDENTITY_") ||
    error.code === "NETWORK_DENIED" ||
    error.code === "TLS_POLICY_VIOLATION"
  );
}

/** Credential metadata, its discarded marker, and the pending revocations. */
function writeAtomic(path: string, content: string): void {
  writeFileAtomic(path, content, { directoryMode: 0o700 });
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
 * Every secret-store reference that credential, sandbox credential, or
 * identity metadata (or a discarded marker of any) of one distribution may
 * own: the current generation, recorded orphans, the next generation
 * (written before a crash that never reached metadata), and for identity also
 * the previous generation (a replacement whose delete failed). The
 * generations of sandbox credential metadata are sandbox references, never
 * runtime credential ones. References of other distributions are never
 * returned.
 */
export function metadataSecretRefs(
  raw: unknown,
  distributionId: string,
): string[] {
  const value =
    raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const refs = new Set<string>();
  const inference = `piship:${distributionId}:inference#`;
  const sandbox = `piship:${distributionId}:sandbox#`;
  const identity = `piship:${distributionId}:identity#`;
  for (const item of [
    value.credential_ref,
    ...(Array.isArray(value.orphans) ? value.orphans : []),
  ])
    if (
      typeof item === "string" &&
      (item.startsWith(inference) ||
        item.startsWith(sandbox) ||
        item.startsWith(identity))
    )
      refs.add(item);
  const generation = Number(value.generation);
  if (
    value.generation !== undefined &&
    Number.isInteger(generation) &&
    generation >= 0
  ) {
    // The slot is named by the file's own schema or reference. A file that
    // names neither (damaged, or from a future release) adds no generation
    // references: guessing the runtime slot would delete a live credential.
    const ref =
      typeof value.credential_ref === "string" ? value.credential_ref : "";
    const prefix =
      value.schema === SANDBOX_CREDENTIAL_METADATA_SCHEMA ||
      ref.startsWith(sandbox)
        ? sandbox
        : value.schema === CREDENTIAL_METADATA_SCHEMA ||
            ref.startsWith(inference)
          ? inference
          : undefined;
    if (prefix) {
      refs.add(`${prefix}${generation}`);
      refs.add(`${prefix}${generation + 1}`);
    }
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

/** In-process queue per metadata file, so concurrent callers never race. */
const queues = new Map<string, Promise<unknown>>();

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

  get slot(): CredentialSlot {
    return this.options.slot ?? "inference";
  }

  get #schema(): CredentialMetadata["schema"] {
    return this.slot === "sandbox"
      ? SANDBOX_CREDENTIAL_METADATA_SCHEMA
      : CREDENTIAL_METADATA_SCHEMA;
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
      this.options.onEvent?.({
        event,
        // A sandbox credential is a stored secret for the sandbox service,
        // not the runtime credential: events say so instead of its mode.
        detail:
          this.slot === "sandbox"
            ? { purpose: "sandbox", source: "stored", ...detail }
            : { mode: this.mode, ...detail },
      });
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
      value.schema !== this.#schema ||
      value.mode !== this.mode ||
      typeof value.credential_ref !== "string" ||
      typeof value.generation !== "number" ||
      (value.secret_store !== undefined &&
        value.secret_store !== this.#storeProvider)
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

  /**
   * Whether the metadata file is no longer JSON (`damaged`), and then whether
   * its text still names a reference (`unrecoverable` when it names none).
   */
  #damaged(): "damaged" | "unrecoverable" | null {
    let text: string;
    try {
      text = readFileSync(this.options.metadataPath, "utf8");
      JSON.parse(text);
      return null;
    } catch {
      text ??= "";
    }
    return secretRefsFromText(text, this.options.distributionId, this.slot)
      .length
      ? "damaged"
      : "unrecoverable";
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
    const foreign = this.#foreignStore();
    if (foreign && this.#incompatibleMetadataPresent())
      return {
        state: "absent",
        metadata: null,
        notice: `The stored credential is in the ${foreign} secret store, not the configured ${this.#storeProvider} store; it is never used, and the next launch or login deletes it`,
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
    return `piship:${this.options.distributionId}:${this.slot}#${generation}`;
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

  /** The configured `credential.storage.provider`. */
  get #storeProvider(): SecretStoreProvider {
    return (
      this.options.storeProvider ??
      (this.options.store ? secretStoreProvider(this.options.store) : "system")
    );
  }

  /**
   * The provider another store than the configured one recorded in the
   * metadata file (the storage provider changed), or undefined.
   */
  #foreignStore(): SecretStoreProvider | undefined {
    let recorded: SecretStoreProvider | undefined;
    try {
      recorded = metadataFileSecretStore(this.options.metadataPath);
    } catch {
      return undefined;
    }
    return recorded && recorded !== this.#storeProvider ? recorded : undefined;
  }

  /**
   * Credential metadata that is complete but recorded for another store
   * than the configured one, with that store (null when it is not available
   * here): revoked from there, never used.
   */
  #foreignMetadata(): {
    metadata: CredentialMetadata;
    store: SecretStore | null;
  } | null {
    const recorded = this.#foreignStore();
    if (!recorded) return null;
    const value = this.#readRaw() as Partial<CredentialMetadata>;
    if (
      value.schema !== CREDENTIAL_METADATA_SCHEMA ||
      value.mode !== this.mode ||
      typeof value.credential_ref !== "string" ||
      typeof value.generation !== "number"
    )
      return null;
    return {
      metadata: value as CredentialMetadata,
      store: storeForRecorded(
        this.options.store,
        this.#storeProvider,
        recorded,
        this.options.storeFor,
      ),
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

  /**
   * Whether this manager records pending issuances: only an
   * organization-issued runtime credential is requested from a remote
   * service that may issue it and lose the answer.
   */
  get #tracksIssuance(): boolean {
    return this.slot === "inference" && this.renewable;
  }

  get #issuancePath(): string {
    return (
      this.options.issuancePath ??
      join(dirname(this.options.metadataPath), CREDENTIAL_ISSUANCE_FILE)
    );
  }

  /** The recorded pending issuance; `invalid` for a file that is not one. */
  #readIssuance(): PendingIssuance | "invalid" | null {
    if (!existsSync(this.#issuancePath)) return null;
    let value: Partial<PendingIssuance>;
    try {
      value = JSON.parse(
        readFileSync(this.#issuancePath, "utf8"),
      ) as Partial<PendingIssuance>;
    } catch {
      return "invalid";
    }
    const principal = value?.principal as Partial<PrincipalKey> | undefined;
    const renews = value?.renews as Partial<IssuanceBase> | undefined;
    if (
      value?.schema !== CREDENTIAL_ISSUANCE_SCHEMA ||
      typeof value.idempotency_key !== "string" ||
      !/^[\x21-\x7e]{1,255}$/.test(value.idempotency_key) ||
      typeof value.mode !== "string" ||
      typeof value.created_at !== "string" ||
      Number.isNaN(Date.parse(value.created_at)) ||
      (principal !== undefined &&
        (typeof principal?.issuer !== "string" ||
          typeof principal.subject !== "string")) ||
      (renews !== undefined &&
        (typeof renews?.credential_ref !== "string" ||
          typeof renews.acquired_at !== "string")) ||
      (value.request !== undefined &&
        !ISSUANCE_REQUESTS.includes(value.request)) ||
      (value.target !== undefined && typeof value.target !== "string")
    )
      return "invalid";
    return value as PendingIssuance;
  }

  /** The hash of where this manager's requests go; undefined when unknown. */
  get #issuanceTarget(): string | undefined {
    const provider = this.options.provider;
    const target =
      this.options.issuanceTarget ??
      (provider instanceof HttpBrokerCredentialProvider
        ? `http-broker ${provider.options.endpoint}`
        : undefined);
    return target === undefined
      ? undefined
      : createHash("sha256").update(target).digest("hex");
  }

  /**
   * The pending issuance of the runtime credential, if one is recorded: the
   * idempotency key an acquire or renewal sent without a resolution yet.
   * Non-secret; for diagnostics. Whether the next acquire reuses it is
   * decided under the credential lock.
   */
  pendingIssuance(): {
    readonly idempotencyKey: string;
    readonly createdAt: string;
    readonly renewal: boolean;
  } | null {
    if (!this.#tracksIssuance) return null;
    const pending = this.#readIssuance();
    if (!pending || pending === "invalid") return null;
    return {
      idempotencyKey: pending.idempotency_key,
      createdAt: pending.created_at,
      renewal: !!pending.renews,
    };
  }

  #dropIssuance(): void {
    rmSync(this.#issuancePath, { force: true });
  }

  /**
   * Keep the recorded pending issuance only while it still names an
   * unresolved request that the next acquire may repeat: recorded for this
   * provider mode, within the retention, for `principal` (when given), and
   * with no credential committed since it was recorded (the stored
   * credential is absent or still the one it renews). Anything else is
   * dropped: a credential committed since means the request was resolved,
   * including by a process that stopped after committing and before it
   * removed the record. Runs under the credential lock, before anything
   * changes the metadata.
   */
  #settleIssuance(principal?: PrincipalKey | null): PendingIssuance | null {
    const pending = this.#readIssuance();
    if (!pending) return null;
    const current = this.readMetadata();
    if (
      pending === "invalid" ||
      pending.mode !== this.mode ||
      pending.target !== this.#issuanceTarget ||
      (principal !== undefined &&
        !samePrincipal(pending.principal ?? null, principal)) ||
      (current !== null && !sameBase(current, pending.renews))
    ) {
      this.#dropIssuance();
      return null;
    }
    // Wall time cannot prove broker retention across clock steps, sleep or a
    // process restart. Never turn an unresolved remote side effect into a new
    // key. Once the recorded age exceeds the broker's promised window, or the
    // record is dated ahead of the clock by more than the tolerance (its age
    // cannot be known), stop automatic issuance and require reconciliation
    // instead of guessing. Only logout removes the record.
    const age = this.#now() - Date.parse(pending.created_at);
    if (
      !(age >= -ISSUANCE_CLOCK_TOLERANCE_MS) ||
      age >= (this.options.issuanceRetentionMs ?? ISSUANCE_RETENTION_MS)
    )
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        "An unresolved credential request may be older than broker idempotency retention; reconcile it before acquiring again",
        {
          component: "credential",
          userAction:
            "Check the broker for the pending issuance key and revoke a credential it issued, then run the branded logout command and the branded login command",
        },
      );
    return pending;
  }

  /**
   * The idempotency key for the request about to be sent, recorded before
   * it is sent: the pending issuance's when one is left (a retry of the
   * same logical request), else the caller's when it passes one, or a new
   * random UUID. A caller key never replaces a pending one: the pending key
   * may already have issued a credential, which only it can recover. A
   * rejection renewal or an entitlement re-read replaces a pending key of
   * another kind of request instead of repeating it. Nothing is sent when
   * the key cannot be recorded.
   */
  #beginIssuance(
    principal: PrincipalKey | null,
    base: CredentialMetadata | null,
    requested: string | undefined,
    kind: IssuanceRequest,
  ): { readonly key: string; readonly resumed: boolean } {
    const pending = this.#readIssuance();
    if (
      pending &&
      pending !== "invalid" &&
      ((kind !== "rejected" && kind !== "entitlement") ||
        pending.request === kind)
    )
      return { key: pending.idempotency_key, resumed: true };
    const key = requested ?? randomUUID();
    const target = this.#issuanceTarget;
    const record: PendingIssuance = {
      schema: CREDENTIAL_ISSUANCE_SCHEMA,
      idempotency_key: key,
      mode: this.mode,
      request: kind,
      ...(target ? { target } : {}),
      ...(principal
        ? {
            principal: {
              issuer: principal.issuer,
              subject: principal.subject,
            },
          }
        : {}),
      ...(base
        ? {
            renews: {
              credential_ref: base.credential_ref,
              acquired_at: base.acquired_at,
            },
          }
        : {}),
      created_at: new Date(this.#now()).toISOString(),
    };
    try {
      writeAtomic(this.#issuancePath, `${JSON.stringify(record, null, 2)}\n`);
    } catch (error) {
      throw new PiShipError(
        "CREDENTIAL_ACQUIRE_FAILED",
        `The credential request could not be recorded before sending, so nothing was sent: ${redact(error instanceof Error ? error.message : String(error))}`,
        {
          component: "credential",
          userAction:
            "Make the distribution's state directory writable, then run the command again",
          sanitizedDetail: { operation: "acquire", outcome: "not-sent" },
        },
      );
    }
    return { key, resumed: false };
  }

  /** Remove the pending issuance of `key`: it is resolved. */
  #endIssuance(key: string): void {
    const pending = this.#readIssuance();
    if (pending === "invalid" || pending?.idempotency_key === key)
      this.#dropIssuance();
  }

  /**
   * Send one acquire or renewal (`call`) under a recorded idempotency key and
   * normalize its credential. A failure that settles the request (see
   * `settlesIssuance`), or an answer that cannot be used, ends the pending
   * issuance, so the next attempt uses a new key; any other failure leaves
   * it for the next attempt to repeat. A manager that does not record
   * issuances sends the caller's key or a new one.
   */
  async #issue(
    principal: PrincipalKey | null,
    base: CredentialMetadata | null,
    ctx: CredentialContext,
    call: (ctx: CredentialContext) => Promise<RuntimeCredential | null>,
    nothing: string,
    kind: IssuanceRequest,
  ): Promise<{
    readonly credential: RuntimeCredential;
    readonly key?: string;
    readonly resumed: boolean;
  }> {
    const empty = () =>
      new PiShipError("CREDENTIAL_ACQUIRE_FAILED", nothing, {
        component: "credential",
      });
    if (!this.#tracksIssuance) {
      const returned = await call(
        ctx.idempotencyKey ? ctx : { ...ctx, idempotencyKey: randomUUID() },
      );
      if (!returned) throw empty();
      return { credential: normalizeCredential(returned), resumed: false };
    }
    const { key, resumed } = this.#beginIssuance(
      principal,
      base,
      ctx.idempotencyKey,
      kind,
    );
    const end = () => {
      try {
        this.#endIssuance(key);
      } catch {
        // The next acquire drops it: a key that cannot be used again.
      }
    };
    let returned: RuntimeCredential | null;
    try {
      returned = await call({ ...ctx, idempotencyKey: key });
    } catch (error) {
      if (settlesIssuance(error)) end();
      throw error;
    }
    // Repeating the key would return the same unusable answer.
    try {
      if (!returned) throw empty();
      return { credential: normalizeCredential(returned), key, resumed };
    } catch (error) {
      end();
      throw error;
    }
  }

  /**
   * End the pending issuance that `metadata` was committed from. A failure
   * is a notice, never a failed commit: the record names a request whose
   * credential is now stored, which the next acquire recognizes and drops.
   */
  #resolveIssuance(key: string | undefined, notices: string[]): void {
    if (key === undefined) return;
    try {
      this.#endIssuance(key);
    } catch (error) {
      notices.push(
        `The record of the completed credential request could not be removed (${redact(error instanceof Error ? error.message : String(error))}); it is never reused, and the next command removes it`,
      );
    }
  }

  /** Non-secret issuance fields of an acquire or refresh event. */
  #issuanceDetail(issued: {
    readonly key?: string;
    readonly resumed: boolean;
  }): Record<string, string | boolean> {
    return issued.key === undefined
      ? {}
      : {
          idempotencyKey: issued.key,
          ...(issued.resumed ? { resumed: true } : {}),
        };
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
    // Without metadata nothing would name the new secret if the process
    // stopped between writing it and committing metadata: a discarded
    // marker names it first, so the next command deletes it, never uses it.
    if (!previous)
      this.#writeDiscarded([
        ...metadataFileSecretRefs(
          this.options.metadataPath,
          this.options.distributionId,
          this.slot,
        ),
        ref,
      ]);
    await store.put(ref, credential.secret);
    await this.options.onPhase?.("secret-written");
    const orphans = new Set(previous?.orphans ?? []);
    if (previous) orphans.add(previous.credential_ref);
    const metadata: CredentialMetadata = {
      schema: this.#schema,
      mode: this.mode,
      ...(this.slot === "sandbox"
        ? {
            source: "stored" as const,
            origins: [...new Set(this.options.origins ?? [])].sort(),
          }
        : {}),
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
      secret_store: this.#storeProvider,
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

  #writeDiscarded(
    refs: readonly string[],
    store: SecretStoreProvider = this.#storeProvider,
  ): void {
    writeAtomic(
      this.options.metadataPath,
      `${JSON.stringify(
        {
          schema: CREDENTIAL_DISCARDED_SCHEMA,
          orphans: [...new Set(refs)].sort(),
          secret_store: store,
          discarded_at: new Date(this.#now()).toISOString(),
        },
        null,
        2,
      )}\n`,
    );
  }

  /**
   * Delete every secret the metadata may reference, then the metadata. The
   * references are those of `raw` and every one the file names, read from
   * its text, so a damaged file that is no longer JSON still gets the
   * secrets it names deleted before it is removed. When a deletion fails,
   * the metadata is replaced by a discarded marker listing the references
   * still to delete, so the secret stays tracked and is never used, and the
   * failures are returned.
   */
  async #discardMetadata(
    raw: unknown = this.#readRaw(),
  ): Promise<{ ref: string; problem: string }[]> {
    const refs = [
      ...new Set([
        ...metadataSecretRefs(raw, this.options.distributionId),
        ...metadataFileSecretRefs(
          this.options.metadataPath,
          this.options.distributionId,
          this.slot,
        ),
      ]),
    ].sort();
    // References are deleted from the store that holds them, never looked
    // up in another one: after a storage provider change, that is the store
    // the file records.
    const recorded =
      metadataFileSecretStore(this.options.metadataPath) ?? this.#storeProvider;
    const store = storeForRecorded(
      this.#store(),
      this.#storeProvider,
      recorded,
      this.options.storeFor,
    );
    const failed = store
      ? await deleteSecretsVerified(store, refs, () =>
          this.options.onPhase?.("secret-deleted"),
        )
      : refs.map((ref) => ({
          ref,
          problem: `the ${recorded} secret store that holds it is not available`,
        }));
    if (!failed.length) {
      rmSync(this.options.metadataPath, { force: true });
      return failed;
    }
    this.#writeDiscarded(
      failed.map((item) => item.ref),
      recorded,
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
    const run = previous
      .catch(() => {})
      .then(() => withFileLock(path, task, this.options.lockTiming));
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
    const principal = identity ? principalKey(identity) : null;
    // Before anything changes the metadata: a pending issuance is judged
    // against the credential stored now, so one whose credential was
    // committed (by a process that stopped before removing the record) is
    // recognized while that credential is still there.
    if (this.#tracksIssuance) this.#settleIssuance(principal);
    if (this.#incompatibleMetadataPresent()) {
      const discarded = this.#discardedPending();
      const damaged = this.#damaged();
      const foreign = this.#foreignStore();
      // A credential the other store holds is revoked where supported before
      // it is deleted from that store, as any credential that is replaced.
      const held = foreign ? this.#foreignMetadata() : null;
      if (held) {
        const revoked = await this.#revoke(
          held.metadata,
          ctx,
          "lifecycle",
          held.store,
        );
        if (revoked.problem)
          notices.push(
            `The credential in the ${foreign} secret store could not be revoked; it is recorded for follow-up: ${revoked.problem}`,
          );
      }
      await this.#clearMetadata();
      notices.push(
        discarded
          ? "The secrets of a discarded credential were deleted"
          : foreign
            ? `The credential stored in the ${foreign} secret store was deleted from it: this distribution now stores credentials in the ${this.#storeProvider} store. A new credential is required`
            : damaged === "unrecoverable"
              ? "Damaged credential metadata named no secret reference that could be recovered and was cleared; a secret it referenced may remain in the secret store. A new credential is required"
              : damaged === "damaged"
                ? "Damaged credential metadata was cleared after the secrets it names were deleted; a new credential is required"
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
        ctx,
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
      const issued = await this.#issue(
        principal,
        null,
        ctx,
        (keyed) => this.options.provider.acquire(identity, keyed),
        "The credential provider returned no credential",
        "acquire",
      );
      metadata = await this.#commit(issued.credential, principal, notices);
      this.#resolveIssuance(issued.key, notices);
      this.#emit("credential.acquire", {
        ...this.#eventDetail(metadata),
        ...this.#issuanceDetail(issued),
      });
      return {
        ref: this.#toRef(metadata),
        secret: issued.credential.secret,
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
        const issued = await this.#issue(
          principal,
          metadata,
          ctx,
          (keyed) =>
            provider.refresh
              ? provider.refresh(identity, current, keyed)
              : provider.acquire(identity, keyed),
          "Credential refresh returned nothing",
          entitlement ? "entitlement" : rejected ? "rejected" : "renewal",
        );
        const next = issued.credential;
        metadata = await this.#commit(next, principal, notices);
        this.#resolveIssuance(issued.key, notices);
        this.#emit("credential.refresh", {
          ...this.#eventDetail(metadata),
          ...this.#issuanceDetail(issued),
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
   * never one issued to someone else, whatever is stored by now. A bare
   * reference marks that generation only. Without `used`, the credential
   * stored when the call is made is the one marked. A user-owned runtime
   * secret is left unmarked (the rejection may be transient); a sandbox
   * credential is marked, so doctor shows it and the next launch asks for a
   * new one instead of sending it again.
   */
  async markRejected(used?: RejectedCredential | string): Promise<void> {
    if (!this.renewable && this.slot !== "sandbox") return;
    const target = typeof used === "string" ? { ref: used } : used;
    const observed = target?.ref ?? this.readMetadata()?.credential_ref;
    await this.#exclusive(async () => {
      const metadata = this.readMetadata();
      if (
        !metadata ||
        metadata.rejected_at ||
        metadata.credential_ref !== observed ||
        (target &&
          "principal" in target &&
          ((target.acquiredAt !== undefined &&
            metadata.acquired_at !== target.acquiredAt) ||
            (target.credentialId !== undefined &&
              metadata.credential_id !== target.credentialId) ||
            !samePrincipal(metadata.principal ?? null, target.principal)))
      )
        return;
      writeAtomic(
        this.options.metadataPath,
        `${JSON.stringify({ ...metadata, rejected_at: new Date(this.#now()).toISOString() }, null, 2)}\n`,
      );
    });
  }

  /**
   * Revoke when supported, then clear local secrets and metadata, and the
   * pending issuance. A sign-in that replaces the credential for `principal`
   * passes `keepIssuanceFor`: a pending issuance of that principal that no
   * commit resolved is kept, so the acquire that follows repeats its key and
   * recovers a credential whose answer was lost, instead of issuing another.
   */
  async logout(
    ctx: CredentialContext,
    options: {
      readonly reason?: CredentialRevokeReason;
      readonly keepIssuanceFor?: PrincipalKey | null;
    } = {},
  ): Promise<string[]> {
    if (!this.storesSecrets) return [];
    return this.#exclusive(() =>
      this.#logout(ctx, options.reason ?? "logout", options.keepIssuanceFor),
    );
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
    /**
     * The store holding the secret when it is not the configured one; null
     * when that store is not available here.
     */
    holder?: SecretStore | null,
  ): Promise<{ outcome: RevocationOutcome; problem?: string }> {
    let outcome: RevocationOutcome;
    let problem: string | undefined;
    let secret: SecretValue | null = null;
    let unreadable: unknown;
    const from = holder === undefined ? this.options.store : holder;
    if (this.revocable && holder === null)
      unreadable = new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "The secret store that holds the credential is not available",
      );
    else if (this.revocable && from)
      try {
        secret = await from.get(metadata.credential_ref);
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
    keepIssuanceFor?: PrincipalKey | null,
  ): Promise<string[]> {
    const problems: string[] = [];
    // First, while the credential a commit may have resolved it with is
    // still stored.
    if (this.#tracksIssuance)
      try {
        if (keepIssuanceFor === undefined) this.#dropIssuance();
        else this.#settleIssuance(keepIssuanceFor);
      } catch (error) {
        problems.push(
          `the pending credential request record could not be removed (${redact(error instanceof Error ? error.message : String(error))})`,
        );
      }
    if (!this.hasStoredCredential()) return problems;
    const metadata = this.readMetadata();
    const foreign = metadata ? null : this.#foreignMetadata();
    if (metadata || foreign) {
      const revoked = foreign
        ? await this.#revoke(foreign.metadata, ctx, reason, foreign.store)
        : await this.#revoke(metadata as CredentialMetadata, ctx, reason);
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
