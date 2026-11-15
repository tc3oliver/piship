// The session side of a remote workspace: the lazy seed, and the checkpoints
// of the sandbox's work that `sandbox pull` later reviews.
import { rmSync } from "node:fs";
import { join } from "node:path";
import {
  REMOTE_PATCH_MAX_BYTES,
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
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
  /** The distribution's command, named in the end-of-session line. */
  readonly command: string;
  /** A non-prompting `filesystem.read` decision for the seed. */
  readonly decide: (absolutePath: string) => Promise<"allow" | "skip">;
  /** Workspace-relative protected paths `sandbox pull` must refuse. */
  readonly protectedPaths: () => readonly string[];
  /** Called once per successful seed. */
  readonly seeded: (result: SeedResult) => void;
  readonly warn: (message: string) => void;
  /**
   * False for a subagent child: its sandbox is its own, and its checkpoint
   * would replace the parent session's `latest.patch`.
   */
  readonly checkpoints: boolean;
}

export class RemoteWorkspace {
  readonly #options: RemoteWorkspaceOptions;
  #seed: Promise<SeedResult> | undefined;
  #seeded: SeedResult | undefined;
  #queue: Promise<unknown> = Promise.resolve();
  #changed = 0;
  /** Where this session's patch went instead of the shared slot. */
  #parked: string | undefined;

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

  /**
   * The final checkpoint. Returns the line to show when the sandbox changed
   * files, naming where they were saved.
   */
  async finish(): Promise<string | undefined> {
    await this.checkpoint();
    const changed = this.#changed;
    if (changed === 0) return undefined;
    const files = `${changed} ${changed === 1 ? "file" : "files"}`;
    const { command, root, stateDir } = this.#options;
    if (this.#parked)
      return `The sandbox changed ${files}, but an earlier session's changes are still waiting to be applied, so these were saved in ${this.#parked} instead. Run ${command} sandbox pull (or sandbox pull --discard) for the earlier changes first, then move latest.patch and latest.json from that directory into ${remoteWorkspacePaths(stateDir, root).dir}.`;
    return `The sandbox changed ${files}. Review and apply them with: ${command} sandbox pull`;
  }

  async #take(): Promise<void> {
    const seeded = this.#seeded;
    if (!seeded || !this.#options.checkpoints) return; // the sandbox was never used: nothing to bring back
    const { sandbox, root, stateDir, session } = this.#options;
    try {
      const patch = await readSandboxPatch(
        sandbox,
        root,
        seeded.baselineCommit,
      );
      const files = (patch.toString("latin1").match(/^diff --git /gm) ?? [])
        .length;
      // Another session's unapplied patch is never replaced: its sandbox is
      // gone, so it could not be made again. This session's patch is parked
      // beside it, in the same layout, until that one is pulled or discarded.
      const kept = readRemoteWorkspaceCheckpoint(stateDir, root);
      const blocked =
        kept !== undefined &&
        kept.meta.session !== session &&
        kept.patch.length > 0;
      if (blocked && patch.length === 0) return;
      const parkedState = join(stateDir, "sandbox-workspace-parked", session);
      const info = {
        session,
        baseHead: seeded.baseHead,
        files,
        protectedPaths: this.#options.protectedPaths(),
      };
      if (blocked) {
        this.#parked = remoteWorkspacePaths(parkedState, root).dir;
        writeRemoteWorkspaceCheckpoint(parkedState, root, patch, info);
      } else {
        writeRemoteWorkspaceCheckpoint(stateDir, root, patch, info);
        if (this.#parked) {
          rmSync(this.#parked, { recursive: true, force: true });
          this.#parked = undefined;
        }
      }
      this.#changed = files;
    } catch (error) {
      this.#options.warn(
        `The sandbox's changes could not be saved this time: ${String((error as Error)?.message ?? error).slice(0, 200)}`,
      );
    }
  }
}
