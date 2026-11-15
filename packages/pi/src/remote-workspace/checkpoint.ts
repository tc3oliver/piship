// The session side of a remote workspace: the lazy seed, and the checkpoints
// of the sandbox's work that `sandbox pull` later reviews.
import {
  REMOTE_PATCH_MAX_BYTES,
  readRemoteWorkspaceCheckpoint,
  writeRemoteWorkspaceCheckpoint,
} from "@piship/core";
import {
  type SeedResult,
  type SeedSandbox,
  seedRemoteWorkspace,
} from "./seed.js";

const CHECKPOINT_TIMEOUT_SECONDS = 120;

/** The diff of everything the sandbox changed since the baseline commit. */
export async function readSandboxPatch(
  sandbox: SeedSandbox,
  root: string,
  baseline: string,
): Promise<Buffer> {
  if (!/^[0-9a-f]{40,64}$/.test(baseline)) throw new Error("no baseline");
  const abort = new AbortController();
  const chunks: Buffer[] = [];
  let size = 0;
  let tooLarge = false;
  const result = await sandbox
    .exec(
      // stderr stays out of the patch; `--no-ext-diff` and `--no-textconv` keep
      // the diff to git's own format.
      `git add -A 2>/dev/null && git diff --cached --binary --no-color --no-ext-diff --no-textconv --no-renames ${baseline} 2>/dev/null`,
      root,
      {
        onData: (chunk) => {
          size += chunk.length;
          if (size > REMOTE_PATCH_MAX_BYTES) {
            tooLarge = true;
            abort.abort();
            return;
          }
          chunks.push(chunk);
        },
        signal: abort.signal,
        timeout: CHECKPOINT_TIMEOUT_SECONDS,
      },
    )
    .catch((error: unknown) => {
      if (tooLarge) return undefined;
      throw error;
    });
  if (tooLarge)
    throw new Error(
      `the sandbox's changes are over the ${REMOTE_PATCH_MAX_BYTES / 1024 / 1024} MiB checkpoint cap`,
    );
  if (result?.exitCode !== 0)
    throw new Error(
      `the sandbox could not list its changes (exit ${result?.exitCode})`,
    );
  return Buffer.concat(chunks);
}

export interface RemoteWorkspaceOptions {
  readonly sandbox: SeedSandbox;
  /** The project root: the sandbox's workspace. */
  readonly root: string;
  readonly stateDir: string;
  readonly session: string;
  /** A non-prompting `filesystem.read` decision for the seed. */
  readonly decide: (absolutePath: string) => Promise<"allow" | "skip">;
  /** Workspace-relative protected paths `sandbox pull` must refuse. */
  readonly protectedPaths: () => readonly string[];
  /** Called once per successful seed. */
  readonly seeded: (result: SeedResult) => void;
  readonly warn: (message: string) => void;
}

export class RemoteWorkspace {
  readonly #options: RemoteWorkspaceOptions;
  #seed: Promise<SeedResult> | undefined;
  #seeded: SeedResult | undefined;
  #queue: Promise<unknown> = Promise.resolve();
  #changed = 0;

  constructor(options: RemoteWorkspaceOptions) {
    this.#options = options;
  }

  /** Seed once, before the first file tool or command; a failure retries on the next call. */
  async ensureSeeded(): Promise<void> {
    this.#seed ??= seedRemoteWorkspace(
      this.#options.sandbox,
      this.#options.root,
      this.#options.decide,
    ).then(
      (result) => {
        this.#seeded = result;
        this.#options.seeded(result);
        return result;
      },
      (error: unknown) => {
        this.#seed = undefined;
        throw error;
      },
    );
    await this.#seed;
  }

  /** Store the sandbox's patch. Never throws: a failed checkpoint keeps the earlier one. */
  checkpoint(): Promise<void> {
    const next = this.#queue.then(() => this.#take());
    this.#queue = next;
    return next;
  }

  /** The final checkpoint; returns how many files the stored patch changes. */
  async finish(): Promise<number> {
    await this.checkpoint();
    return this.#changed;
  }

  async #take(): Promise<void> {
    const seeded = this.#seeded;
    if (!seeded) return; // the sandbox was never used: nothing to bring back
    const { sandbox, root, stateDir, session } = this.#options;
    try {
      const patch = await readSandboxPatch(
        sandbox,
        root,
        seeded.baselineCommit,
      );
      const files = (patch.toString("latin1").match(/^diff --git /gm) ?? [])
        .length;
      // An empty result must not replace another session's unapplied patch.
      const kept = readRemoteWorkspaceCheckpoint(stateDir, root);
      if (patch.length === 0 && kept && kept.meta.session !== session) return;
      writeRemoteWorkspaceCheckpoint(stateDir, root, patch, {
        session,
        baseHead: seeded.baseHead,
        files,
        protectedPaths: this.#options.protectedPaths(),
      });
      this.#changed = files;
    } catch (error) {
      this.#options.warn(
        `The sandbox's changes could not be saved this time: ${String((error as Error)?.message ?? error).slice(0, 200)}`,
      );
    }
  }
}
