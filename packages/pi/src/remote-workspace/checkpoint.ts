// The session side of a remote workspace: the lazy seed, and the checkpoints
// of the sandbox's work that `sandbox pull` later reviews.
import {
  closeSync,
  mkdirSync,
  openSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  REMOTE_PATCH_MAX_BYTES,
  type RemoteWorkspaceMeta,
  readRemoteWorkspaceCheckpoint,
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "@piship/core";
import {
  SEED_FILE_CAP,
  SEED_TOTAL_CAP,
  SeedRefused,
  type SeedResult,
  type SeedSandbox,
  seedRemoteWorkspace,
} from "./seed.js";

const CHECKPOINT_TIMEOUT_SECONDS = 120;
const MIB = 1024 * 1024;

/** The diff of everything the sandbox changed since the baseline commit. */
export async function readSandboxPatch(
  sandbox: SeedSandbox,
  root: string,
  baseline: string,
  maxBytes = REMOTE_PATCH_MAX_BYTES,
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
          if (size > maxBytes) {
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
      `the sandbox's changes are over the ${maxBytes / 1024 / 1024} MiB checkpoint cap; delete large generated files in the sandbox or list them in its .gitignore`,
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
  /** An informational line, such as the seed's progress. */
  readonly notify: (message: string) => void;
  /** `sandbox.remote.seed`: limits in MiB; the defaults apply to what is absent. */
  readonly seedLimits?: { maxTotalMiB?: number; maxFileMiB?: number };
  /** `sandbox.remote.pull`, recorded verbatim in the checkpoint for `sandbox pull`. */
  readonly pull?: RemoteWorkspaceMeta["pull"];
  /** Tests only: a smaller checkpoint cap. */
  readonly maxPatchBytes?: number;
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
  /** Set when something ran that may have changed the sandbox since the last checkpoint. */
  #dirty = false;
  #warned = false;
  #told = false;
  /** Where this session's patch went instead of the shared slot. */
  #parked: string | undefined;

  constructor(options: RemoteWorkspaceOptions) {
    this.#options = options;
  }

  /** Run something that may change the sandbox; a checkpoint follows it. Marked again at its end, as a task may outlive the turn. */
  track<T>(work: Promise<T>): Promise<T> {
    this.#dirty = true;
    return work.finally(() => {
      this.#dirty = true;
    });
  }

  /**
   * Seed once, before the first file tool or command. A transient failure
   * retries on the next call; one a retry cannot cure (a cap, a missing tool)
   * is remembered and fails the same way at once.
   */
  async ensureSeeded(): Promise<void> {
    this.#seed ??= seedRemoteWorkspace(
      this.#options.sandbox,
      this.#options.root,
      this.#options.decide,
      {
        progress: this.#options.notify,
        caps: {
          totalCap:
            (this.#options.seedLimits?.maxTotalMiB ?? SEED_TOTAL_CAP / MIB) *
            MIB,
          fileCap:
            (this.#options.seedLimits?.maxFileMiB ?? SEED_FILE_CAP / MIB) * MIB,
        },
      },
    ).then(
      (result) => {
        this.#seeded = result;
        this.#options.seeded(result);
        this.#dirty = false;
        const left = new Map<string, number>();
        for (const { reason } of result.skipped)
          if (reason === "policy" || reason === "too-large")
            left.set(reason, (left.get(reason) ?? 0) + 1);
        if (left.size)
          this.#options.notify(
            `Left out of the sandbox: ${[...left]
              .map(([reason, n]) =>
                reason === "policy"
                  ? `${n} by policy`
                  : `${n} over the per-file size cap`,
              )
              .join(", ")}.`,
          );
        return result;
      },
      (error: unknown) => {
        if (!(error instanceof SeedRefused)) this.#seed = undefined;
        throw error;
      },
    );
    await this.#seed;
  }

  /**
   * Store the sandbox's patch. Never throws: a failed checkpoint keeps the
   * earlier one. Unless `always`, nothing is taken when nothing ran since the
   * last one.
   */
  checkpoint(always = false): Promise<void> {
    const next = this.#queue.then(() =>
      always || this.#dirty ? this.#take() : undefined,
    );
    this.#queue = next;
    return next;
  }

  /**
   * The final checkpoint. Returns the line to show when the sandbox changed
   * files, naming where they were saved.
   */
  async finish(): Promise<string | undefined> {
    await this.checkpoint(true);
    const changed = this.#changed;
    if (changed === 0) return undefined;
    const files = `${changed} ${changed === 1 ? "file" : "files"}`;
    const { command } = this.#options;
    if (this.#parked)
      return `${files} changed in the sandbox. An earlier session's changes are waiting too; run ${command} sandbox pull once for each.`;
    return `${files} changed in the sandbox; run ${command} sandbox pull to bring them to this machine`;
  }

  /**
   * Once per session: a notice when an earlier session left changes
   * unapplied for this project (the shared slot or a parked copy). This
   * session starts from the host files, so they are not in the sandbox.
   */
  waitingNotice(): string | undefined {
    if (this.#told || !this.#options.checkpoints) return undefined;
    this.#told = true;
    const { stateDir, root, command } = this.#options;
    const parkedDir = join(stateDir, "sandbox-workspace-parked");
    const states = [stateDir];
    try {
      for (const name of readdirSync(parkedDir))
        states.push(join(parkedDir, name));
    } catch {
      // none parked
    }
    let files = 0;
    let latest = "";
    for (const state of states) {
      const kept = readRemoteWorkspaceCheckpoint(state, root);
      if (!kept || kept.patch.length === 0) continue;
      files += kept.meta.files;
      if (kept.meta.createdAt > latest) latest = kept.meta.createdAt;
    }
    if (files === 0) return undefined;
    const when = latest.slice(0, 16).replace("T", " ");
    return `Earlier sandbox changes to ${files} ${files === 1 ? "file" : "files"} (saved ${when} UTC) are still waiting. Run ${command} sandbox pull first; this session starts from your host files.`;
  }

  async #take(): Promise<void> {
    const seeded = this.#seeded;
    if (!seeded || !this.#options.checkpoints) return; // the sandbox was never used: nothing to bring back
    const { sandbox, root, stateDir, session } = this.#options;
    this.#dirty = false;
    let release: (() => void) | undefined;
    try {
      const patch = await readSandboxPatch(
        sandbox,
        root,
        seeded.baselineCommit,
        this.#options.maxPatchBytes,
      );
      const files = (patch.toString("latin1").match(/^diff --git /gm) ?? [])
        .length;
      // Another session's unapplied patch is never replaced: its sandbox is
      // gone, so it could not be made again. This session's patch is parked
      // beside it, in the same layout, until that one is pulled or discarded.
      // The slot is claimed first: a session that cannot claim it parks.
      release = claimSlot(remoteWorkspacePaths(stateDir, root).dir);
      const kept = readRemoteWorkspaceCheckpoint(stateDir, root);
      const blocked =
        !release ||
        (kept !== undefined &&
          kept.meta.session !== session &&
          kept.patch.length > 0);
      const parkedState = join(stateDir, "sandbox-workspace-parked", session);
      if (blocked && patch.length === 0) {
        // The agent undid its changes: a parked patch would apply what is gone.
        rmSync(remoteWorkspacePaths(parkedState, root).dir, {
          recursive: true,
          force: true,
        });
        this.#parked = undefined;
        this.#changed = 0;
        return;
      }
      const info = {
        session,
        baseHead: seeded.baseHead,
        files,
        protectedPaths: this.#options.protectedPaths(),
        ...(this.#options.pull ? { pull: this.#options.pull } : {}),
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
      this.#warned = false;
    } catch (error) {
      this.#dirty = true; // the next turn tries again
      // Once: the earlier checkpoint is kept, and a failure that persists would repeat every turn.
      if (!this.#warned)
        this.#options.warn(
          `The sandbox's changes could not be saved this time (${String((error as Error)?.message ?? error).slice(0, 200)}). The last saved copy is kept and the next turn tries again.`,
        );
      this.#warned = true;
    } finally {
      release?.();
    }
  }
}

/**
 * Claim the shared checkpoint slot across processes with an exclusive-create
 * file beside it; a lock older than a minute is a crashed holder's.
 */
function claimSlot(dir: string): (() => void) | undefined {
  const lock = `${dir}.lock`;
  mkdirSync(dirname(lock), { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      closeSync(openSync(lock, "wx", 0o600));
      return () => rmSync(lock, { force: true });
    } catch {
      try {
        if (Date.now() - statSync(lock).mtimeMs < 60_000) return undefined;
        unlinkSync(lock);
      } catch {
        // gone meanwhile: claim it on the next attempt
      }
    }
  }
  return undefined;
}
