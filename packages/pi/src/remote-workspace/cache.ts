// The setup cache of a remote workspace: after `sandbox.remote.setup` succeeds
// and before the agent acts, the sandbox's filesystem is saved as a snapshot,
// and later sessions of the same project start from it. The host remembers
// only the snapshot id it was given back; nothing is ever looked up by name,
// metadata or listing, so another holder of the API key cannot plant one.
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { userInfo } from "node:os";
import { join, relative, sep } from "node:path";
import { remoteWorkspacePaths } from "@piship/core";
import {
  type SandboxBackend,
  type SandboxPrepareRequest,
  SNAPSHOT_ID,
} from "@piship/sandbox";
import type { SandboxConfig } from "@piship/schema";
import type { GovernanceOptions } from "../governance/options.js";
import { remoteWorkdir } from "../governance/sandbox.js";
import { printable } from "./printable.js";

export const CACHE_FORMAT = 1;
/** A snapshot older than this is not used. */
export const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** How long a backend that has no snapshots is left alone. */
export const CACHE_UNSUPPORTED_MS = 24 * 60 * 60 * 1000;
const KEY_FILE_CAP = 16 * 1024 * 1024;
const CACHE_FILE_CAP = 4096;

/** The lock files that key the cache when `sandbox.remote.cacheKeyFiles` is not set. */
export const DEFAULT_CACHE_KEY_FILES: readonly string[] = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "uv.lock",
  "poetry.lock",
  "requirements.txt",
  "Pipfile.lock",
  "Cargo.lock",
  "go.sum",
  "Gemfile.lock",
  "composer.lock",
];

export const CACHE_NOTICE_GONE =
  "The cached sandbox setup was no longer available; setting up again.";
export const CACHE_NOTICE_SAVED =
  "Saved the sandbox setup; the next session starts from it.";
export const CACHE_NOTICE_OVERLAY =
  "The cached sandbox setup could not be applied; setting up again.";

/** `snapshot` or `off`: the setting, or its default (snapshot with a setup command on an e2b-compatible backend). */
export function cacheMode(sandbox: SandboxConfig): "snapshot" | "off" {
  if (sandbox.workspace !== "remote" || !sandbox.remote?.setup) return "off";
  return (
    sandbox.remote.cache ??
    (sandbox.provider === "e2b-compatible" ? "snapshot" : "off")
  );
}

export interface StoredCache {
  /** The snapshot this host saved, when it holds a valid one. */
  readonly snapshot?: {
    readonly key: string;
    readonly snapshotId: string;
    readonly createdAt: string;
  };
  /** Epoch ms until which the backend is known to have no snapshots. */
  readonly unsupportedUntil?: number;
}

export function cacheFile(stateDir: string, root: string): string {
  return join(remoteWorkspacePaths(stateDir, root).dir, "cache.json");
}

/** What `cache.json` holds; anything malformed reads as nothing. */
export function readCacheFile(path: string): StoredCache {
  try {
    if (lstatSync(path).size > CACHE_FILE_CAP) return {};
    const value = JSON.parse(readFileSync(path, "utf8")) as Record<
      string,
      unknown
    > | null;
    if (!value || typeof value !== "object" || value.version !== CACHE_FORMAT)
      return {};
    const until =
      typeof value.unsupportedUntil === "string"
        ? Date.parse(value.unsupportedUntil)
        : Number.NaN;
    const valid =
      typeof value.key === "string" &&
      /^[0-9a-f]{64}$/.test(value.key) &&
      typeof value.snapshotId === "string" &&
      SNAPSHOT_ID.test(value.snapshotId) &&
      typeof value.createdAt === "string" &&
      !Number.isNaN(Date.parse(value.createdAt));
    return {
      ...(valid
        ? {
            snapshot: {
              key: value.key as string,
              snapshotId: value.snapshotId as string,
              createdAt: value.createdAt as string,
            },
          }
        : {}),
      ...(Number.isNaN(until) ? {} : { unsupportedUntil: until }),
    };
  } catch {
    return {};
  }
}

function writeCacheFile(path: string, content: Record<string, unknown>): void {
  mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    writeFileSync(
      temporary,
      `${JSON.stringify({ version: CACHE_FORMAT, ...content })}\n`,
      { mode: 0o600 },
    );
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

/** A cache key file that cannot be hashed the way the seed reads files. */
export class CacheKeyRefused extends Error {}

function hashFile(root: string, path: string): string {
  const absolute = join(root, ...path.split("/"));
  let info: ReturnType<typeof lstatSync>;
  try {
    info = lstatSync(absolute);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    throw new CacheKeyRefused(`${path} cannot be read`);
  }
  // Regular files inside the project only, as the seed reads them.
  if (info.isSymbolicLink() || !info.isFile() || info.size > KEY_FILE_CAP)
    throw new CacheKeyRefused(
      `${path} is not a regular file inside the project, or is over 16 MiB`,
    );
  if (relative(root, realpathSync(absolute)).split(sep).join("/") !== path)
    throw new CacheKeyRefused(`${path} is reached through a symlink`);
  return createHash("sha256").update(readFileSync(absolute)).digest("hex");
}

export interface CacheKeyInput {
  readonly root: string;
  readonly endpoint: string;
  readonly template: string;
  readonly user: string;
  readonly workdir: string;
  readonly network: string;
  readonly setup: string;
  /** The signed-in principal, or the OS user name. */
  readonly identity: string;
  /** Digest of the rules that decide what the seed uploads. */
  readonly policy: string;
  readonly keyFiles: readonly string[];
}

/**
 * The key a snapshot is valid for. Key files are only hashed here: hashing
 * sends nothing anywhere, whatever the policy would upload.
 */
export function cacheKey(input: CacheKeyInput): string {
  const root = realpathSync(input.root);
  return createHash("sha256")
    .update(
      JSON.stringify([
        "piship-sandbox-cache",
        CACHE_FORMAT,
        input.endpoint,
        input.template,
        input.user,
        input.workdir,
        input.network,
        input.setup,
        input.identity,
        input.policy,
        input.keyFiles.map((path) => [path, hashFile(root, path)]),
      ]),
    )
    .digest("hex");
}

/** The key files of a project: the configured list, or those of the defaults that exist. */
export function keyFilesOf(sandbox: SandboxConfig): readonly string[] {
  return sandbox.remote?.cacheKeyFiles ?? DEFAULT_CACHE_KEY_FILES;
}

/** The identity part of a key: the signed-in principal, else the OS user. */
export function cacheIdentity(user: string | null | undefined): string {
  if (user) return user;
  try {
    return userInfo().username;
  } catch {
    return "";
  }
}

/** The host state of one session's setup cache. */
export class SetupCache {
  readonly #file: string;
  readonly #key: string | undefined;
  readonly #now: () => number;
  #stored: StoredCache;
  /** Set by `cachedBackend`: deletes a snapshot, best effort. */
  deleteRemote: ((id: string) => Promise<void>) | undefined;
  /** The sandbox was created from this host's snapshot. */
  restored = false;
  /** A one-time line for the session to show. */
  pendingNotice: string | undefined;

  constructor(options: {
    stateDir: string;
    root: string;
    /** Undefined: the cache is off for this session. */
    key: string | undefined;
    now?: () => number;
  }) {
    this.#file = cacheFile(options.stateDir, options.root);
    this.#key = options.key;
    this.#now = options.now ?? Date.now;
    this.#stored = readCacheFile(this.#file);
  }

  /** False when this session has no key to save a snapshot under. */
  get active(): boolean {
    return this.#key !== undefined;
  }

  /** The snapshot to start from: this key, fresh, and not on a backend without snapshots. */
  usable(): string | undefined {
    const { snapshot } = this.#stored;
    if (
      !this.#key ||
      !snapshot ||
      snapshot.key !== this.#key ||
      this.unsupported()
    )
      return undefined;
    return this.#now() - Date.parse(snapshot.createdAt) > CACHE_MAX_AGE_MS
      ? undefined
      : snapshot.snapshotId;
  }

  /** True while the backend is known to have no snapshots. */
  unsupported(): boolean {
    return (this.#stored.unsupportedUntil ?? 0) > this.#now();
  }

  /** Forget the stored snapshot: it is gone from the backend. */
  clear(): void {
    this.#stored = {};
    rmSync(this.#file, { force: true });
  }

  /** Forget the stored snapshot and delete it from the backend, best effort. */
  async discard(): Promise<void> {
    const id = this.#stored.snapshot?.snapshotId;
    this.clear();
    if (id) await this.deleteRemote?.(id).catch(() => undefined);
  }

  /**
   * Save a snapshot of the sandbox as it is now, and delete the one it
   * replaces. Never throws; a failure is one warning, an unsupported backend
   * is remembered for a day and silent.
   */
  async save(
    snapshot: () => Promise<{ id: string }>,
    say: { notify(message: string): void; warn(message: string): void },
  ): Promise<void> {
    const previous = this.#stored.snapshot?.snapshotId;
    const key = this.#key;
    try {
      if (!key) throw new Error("no cache key");
      const { id } = await snapshot();
      if (!SNAPSHOT_ID.test(id)) throw new Error("the snapshot id is invalid");
      const createdAt = new Date(this.#now()).toISOString();
      // Another session of this project may have saved since this one read
      // the file: its snapshot is replaced too, or nothing would delete it.
      const onDisk = readCacheFile(this.#file).snapshot?.snapshotId;
      try {
        writeCacheFile(this.#file, { key, snapshotId: id, createdAt });
      } catch (error) {
        await this.deleteRemote?.(id).catch(() => undefined);
        throw error;
      }
      this.#stored = { snapshot: { key, snapshotId: id, createdAt } };
      say.notify(CACHE_NOTICE_SAVED);
      for (const old of new Set([previous, onDisk]))
        if (old && old !== id)
          await this.deleteRemote?.(old).catch(() => undefined);
    } catch (error) {
      if ((error as { code?: unknown })?.code === "SNAPSHOT_UNSUPPORTED") {
        const until = this.#now() + CACHE_UNSUPPORTED_MS;
        const stale = new Set([
          previous,
          readCacheFile(this.#file).snapshot?.snapshotId,
        ]);
        this.#stored = { unsupportedUntil: until };
        try {
          writeCacheFile(this.#file, {
            unsupportedUntil: new Date(until).toISOString(),
          });
        } catch {
          // remembered for this session only
        }
        for (const old of stale)
          if (old) await this.deleteRemote?.(old).catch(() => undefined);
        return;
      }
      say.warn(
        `The sandbox setup could not be saved (${printable(String((error as Error)?.message ?? error).slice(0, 200))}); the next session sets up again.`,
      );
    }
  }
}

/**
 * The backend, creating the sandbox from the host's own snapshot when the
 * cache holds a usable one. A snapshot the backend no longer has clears the
 * cache and prepares once more from the configured template.
 */
export function cachedBackend(
  backend: SandboxBackend,
  cache: SetupCache,
): SandboxBackend {
  const deleteSnapshot = backend.deleteSnapshot?.bind(backend);
  cache.deleteRemote = deleteSnapshot
    ? (id) => deleteSnapshot(id, { signal: AbortSignal.timeout(30_000) })
    : undefined;
  return {
    id: backend.id,
    provider: backend.provider,
    available: (options) => backend.available(options),
    capabilities: () => backend.capabilities(),
    ...(deleteSnapshot ? { deleteSnapshot } : {}),
    prepare: async (request: SandboxPrepareRequest) => {
      const id = request.purpose === "contrast" ? undefined : cache.usable();
      if (!id) return backend.prepare(request);
      try {
        const instance = await backend.prepare({ ...request, template: id });
        cache.restored = true;
        return instance;
      } catch (error) {
        if ((error as { code?: unknown })?.code !== "SNAPSHOT_GONE")
          throw error;
        // A 400 can mean the id is merely refused: delete it, best effort.
        await cache.discard();
        cache.pendingNotice = CACHE_NOTICE_GONE;
        return backend.prepare(request);
      }
    },
  };
}

/**
 * The setup cache of a session, or undefined when it is off for it: not a
 * remote workspace with a setup command, switched off, a subagent child
 * (whose sandbox is its own), or an inspection such as doctor. A key file the
 * seed would not read turns it off for the session, with one notice.
 */
export function openSetupCache(
  options: {
    readonly lock: GovernanceOptions["lock"];
    readonly stateDir: string;
    readonly user?: string | null;
    readonly subagent?: unknown;
    readonly sandboxCache?: false;
    readonly resolveTemplate: (key: string, template: string) => string;
  },
  root: string,
  policy: string,
): SetupCache | undefined {
  const sandbox = options.lock.governance.manifest.sandbox;
  if (
    cacheMode(sandbox) !== "snapshot" ||
    options.subagent !== undefined ||
    options.sandboxCache === false
  )
    return undefined;
  let endpoint = "";
  try {
    endpoint = new URL(
      options.resolveTemplate("sandbox.endpoint", sandbox.endpoint ?? ""),
    ).origin;
  } catch {
    // a custom adapter may declare none
  }
  const user = sandbox.user ?? "user";
  const input = {
    root,
    endpoint,
    template: `${sandbox.provider}:${sandbox.template ?? sandbox.adapter ?? ""}`,
    user,
    workdir: sandbox.workdir ?? remoteWorkdir(user),
    network: sandbox.network.mode,
    setup: sandbox.remote?.setup ?? "",
    identity: cacheIdentity(options.user),
    policy,
    keyFiles: keyFilesOf(sandbox),
  };
  let key: string | undefined;
  let notice: string | undefined;
  try {
    key = cacheKey(input);
  } catch (error) {
    if (!(error instanceof CacheKeyRefused)) throw error;
    notice = `The sandbox setup cache is off for this session: ${error.message}.`;
  }
  const cache = new SetupCache({ stateDir: options.stateDir, root, key });
  cache.pendingNotice = notice;
  return cache;
}

/** The doctor row: this project's cache state, from the host's own file only. */
export function describeCache(
  sandbox: SandboxConfig,
  stateDir: string,
  root: string | undefined,
  now = Date.now(),
): string {
  if (cacheMode(sandbox) === "off")
    return sandbox.remote?.cache === "off"
      ? "off (sandbox.remote.cache: off)"
      : "off";
  if (!root) return "not checked: the project is not known";
  const stored = readCacheFile(cacheFile(stateDir, root));
  if ((stored.unsupportedUntil ?? 0) > now)
    return "the backend has no snapshots (not asked again for a day)";
  if (!stored.snapshot)
    return "no snapshot yet; the first session saves one after the setup command";
  const age = now - Date.parse(stored.snapshot.createdAt);
  return `snapshot ${stored.snapshot.snapshotId} from ${stored.snapshot.createdAt.slice(0, 16).replace("T", " ")} UTC${
    age > CACHE_MAX_AGE_MS
      ? " (older than 7 days: the next session sets up again)"
      : ""
  }`;
}
