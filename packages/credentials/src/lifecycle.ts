import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  type CredentialContext,
  type CredentialProvider,
  type CredentialRef,
  type IdentitySession,
  PiShipError,
  type RuntimeCredential,
  type RuntimeCredentialKind,
  type SecretStore,
  type SecretValue,
} from "@piship/contracts";

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

export interface CredentialManagerOptions {
  readonly distributionId: string;
  readonly provider: CredentialProvider;
  readonly store: SecretStore | null;
  readonly metadataPath: string;
  readonly beforeExpirySeconds: number;
  readonly now?: () => number;
  /** Fault injection for crash-safety tests. */
  readonly onPhase?: (phase: "secret-written" | "metadata-written") => void;
}

function writeAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temporary, content, { mode: 0o600, flag: "wx" });
  renameSync(temporary, path);
}

const LOCK_STALE_MS = 120_000;
const LOCK_WAIT_MS = 90_000;
const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
/** In-process queue per metadata file, so concurrent callers never race. */
const queues = new Map<string, Promise<unknown>>();

/**
 * Cross-process lock beside the metadata file. A lock older than the longest
 * broker exchange is treated as abandoned by a crashed process.
 */
async function withFileLock<T>(
  path: string,
  task: () => Promise<T>,
): Promise<T> {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lock = `${path}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      closeSync(openSync(lock, "wx", 0o600));
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let age = 0;
      try {
        age = Date.now() - statSync(lock).mtimeMs;
      } catch {
        continue;
      }
      if (age > LOCK_STALE_MS || Date.now() > deadline)
        rmSync(lock, { force: true });
      else await sleep(50);
    }
  }
  try {
    return await task();
  } finally {
    rmSync(lock, { force: true });
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
    let raw: Record<string, unknown> = {};
    try {
      raw = JSON.parse(readFileSync(this.options.metadataPath, "utf8"));
    } catch {
      raw = {};
    }
    const refs = new Set<string>();
    const own = `piship:${this.options.distributionId}:inference#`;
    for (const value of [
      raw.credential_ref,
      ...(Array.isArray(raw.orphans) ? raw.orphans : []),
    ])
      if (typeof value === "string" && value.startsWith(own)) refs.add(value);
    const generation = Number(raw.generation);
    if (Number.isInteger(generation) && generation >= 0) {
      refs.add(this.#ref(generation));
      refs.add(this.#ref(generation + 1));
    }
    for (const ref of refs)
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
      const acquired = await this.options.provider.acquire(identity, ctx);
      if (!acquired)
        throw new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          "The credential provider returned no credential",
          {
            component: "credential",
          },
        );
      metadata = await this.#commit(acquired);
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
        const next = provider.refresh
          ? await provider.refresh(identity, current, ctx)
          : await provider.acquire(identity, ctx);
        if (!next)
          throw new PiShipError(
            "CREDENTIAL_ACQUIRE_FAILED",
            "Credential refresh returned nothing",
          );
        metadata = await this.#commit(next);
        return { ref: this.#toRef(metadata), secret: next.secret, notices };
      } catch (error) {
        if (status.state === "expired" || force) {
          if (
            error instanceof PiShipError &&
            error.code !== "CREDENTIAL_ACQUIRE_FAILED"
          )
            throw error;
          throw new PiShipError(
            force ? "CREDENTIAL_REVOKED" : "CREDENTIAL_EXPIRED",
            `The runtime credential ${force ? "was rejected" : "expired"} and could not be renewed${error instanceof Error ? `: ${error.message}` : ""}`,
            {
              component: "credential",
              userAction: "Run the branded login command",
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
  async logout(ctx: CredentialContext): Promise<string[]> {
    if (!this.storesSecrets) return [];
    return this.#exclusive(() => this.#logout(ctx));
  }

  async #logout(ctx: CredentialContext): Promise<string[]> {
    const problems: string[] = [];
    const metadata = this.readMetadata();
    const store = this.options.store;
    if (metadata && store) {
      const secret = await store.get(metadata.credential_ref).catch(() => null);
      if (secret && this.options.provider.revoke)
        try {
          await this.options.provider.revoke(
            {
              kind: metadata.kind,
              secret,
              ...(metadata.credential_id
                ? { credentialId: metadata.credential_id }
                : {}),
            },
            ctx,
          );
        } catch (error) {
          problems.push(
            `revocation: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      // The next generation may hold a secret written before a crash that never
      // reached metadata; clear it too so logout leaves nothing behind.
      for (const ref of [
        metadata.credential_ref,
        ...(metadata.orphans ?? []),
        this.#ref(metadata.generation + 1),
      ])
        try {
          await store.delete(ref);
        } catch (error) {
          problems.push(
            `delete ${ref}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
    }
    rmSync(this.options.metadataPath, { force: true });
    return problems;
  }
}
