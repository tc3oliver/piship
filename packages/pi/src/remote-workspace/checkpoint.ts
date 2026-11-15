// The session side of a remote workspace: the lazy seed, and the checkpoints
// of the sandbox's work that `sandbox pull` later reviews.
import { randomBytes } from "node:crypto";
import {
  closeSync,
  linkSync,
  mkdirSync,
  openSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  clearRemoteWorkspacePulled,
  REMOTE_PATCH_MAX_BYTES,
  type RemoteWorkspaceMeta,
  readRemoteWorkspaceCheckpoint,
  readRemoteWorkspacePulled,
  remoteWorkspacePaths,
  writeRemoteWorkspaceCheckpoint,
} from "@piship/core";
import { CACHE_NOTICE_OVERLAY, type SetupCache } from "./cache.js";
import { printable } from "./printable.js";
import { HostRefresh, foldBaseline, run } from "./refresh.js";
import {
  SEED_FILE_CAP,
  SEED_TOTAL_CAP,
  type SeedLookup,
  SeedRefused,
  type SeedResult,
  type SeedSandbox,
  seedRemoteWorkspace,
} from "./seed.js";

const CHECKPOINT_TIMEOUT_SECONDS = 120;
const SETUP_HEARTBEAT_MS = 60_000;
const MIB = 1024 * 1024;

/**
 * The diff of everything the sandbox changed since the baseline commit, and
 * a commit holding exactly the state it was taken from (a later baseline).
 */
export async function readSandboxPatch(
  sandbox: SeedSandbox,
  root: string,
  baseline: string,
  maxBytes = REMOTE_PATCH_MAX_BYTES,
  /** Workspace-relative paths left out of the patch (an adopt's unbaselined host copy). */
  exclude: readonly string[] = [],
): Promise<{ patch: Buffer; commit: string }> {
  if (!/^[0-9a-f]{40,64}$/.test(baseline)) throw new Error("no baseline");
  const abort = new AbortController();
  const chunks: Buffer[] = [];
  let size = 0;
  let tooLarge = false;
  const result = await sandbox
    .exec(
      // stderr stays out of the patch; `--no-ext-diff` and `--no-textconv` keep
      // the diff to git's own format.
      `git add -A 2>/dev/null && c=$(git -c user.name=piship -c user.email=piship@invalid -c commit.gpgsign=false commit-tree "$(git write-tree)" -p ${baseline} -m piship-checkpoint) && echo "$c" && git diff --binary --no-color --no-ext-diff --no-textconv --no-renames ${baseline} "$c"${
        exclude.length
          ? ` -- . ${exclude.map((path) => `'${`:(exclude,literal)${path}`.replaceAll("'", `'"'"'`)}'`).join(" ")}`
          : ""
      } 2>/dev/null`,
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
  // The first line is the checkpoint commit; the patch follows it.
  const output = Buffer.concat(chunks);
  const end = output.indexOf(10);
  const commit = output.subarray(0, Math.max(end, 0)).toString("latin1");
  if (!/^[0-9a-f]{40,64}$/.test(commit))
    throw new Error("the sandbox could not record its state");
  return { patch: output.subarray(end + 1), commit };
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
  /** `sandbox.remote.refresh`: false (`off`) keeps the seed-time copy of host files. */
  readonly refresh?: boolean;
  /** `sandbox.remote.setup`: run once in the sandbox after the seed. */
  readonly setup?: { command: string; timeoutSeconds: number };
  /**
   * The setup cache, with `snapshot` the sandbox offers: a restored sandbox
   * is overlaid instead of seeded and runs no setup; after a successful
   * setup and before anything else runs, the sandbox is saved.
   */
  readonly cache?: SetupCache;
  readonly snapshot?: (options?: {
    signal?: AbortSignal;
  }) => Promise<{ id: string }>;
  /** Tests only: how often a running setup says so. */
  readonly setupHeartbeatMs?: number;
  /** Tests only: a smaller checkpoint cap. */
  readonly maxPatchBytes?: number;
  /**
   * False for a subagent child: its sandbox is its own, and its checkpoint
   * would replace the parent session's `latest.patch`.
   */
  readonly checkpoints: boolean;
}

/** What the seed upload produced, before the setup command and the snapshot. */
interface SeedStage {
  readonly result: SeedResult;
  readonly host: HostRefresh | undefined;
  /** The sandbox started from the cache and the overlay held. */
  readonly restored: boolean;
}

export class RemoteWorkspace {
  readonly #options: RemoteWorkspaceOptions;
  #seed: Promise<SeedStage> | undefined;
  /** The seed's setup and snapshot step, memoized until it succeeds or fails for good. */
  #ready: Promise<void> | undefined;
  #seeded: SeedResult | undefined;
  #queue: Promise<unknown> = Promise.resolve();
  #changed = 0;
  /** Set when something ran that may have changed the sandbox since the last checkpoint. */
  #dirty = false;
  #warned = false;
  #refreshWarned = false;
  #told = false;
  #host: HostRefresh | undefined;
  #setupFailure: string | undefined;
  /** The setup ran in an earlier session and its output came back with the snapshot. */
  #setupRestored = false;
  #touched = false;
  /** Where this session's patch went instead of the shared slot. */
  #parked: string | undefined;
  /** Checkpoint commits this session made: the only ids a pull marker may move the baseline to. */
  readonly #recorded = new Set<string>();

  constructor(options: RemoteWorkspaceOptions) {
    this.#options = options;
  }

  /** What the finished seed left out and how to add one such file; undefined before the seed. */
  lookup(): SeedLookup | undefined {
    return this.#seeded?.lookup;
  }

  /** Why the setup command failed, for the model; undefined when it ran well or was not set. */
  get setupFailure(): string | undefined {
    return this.#setupFailure;
  }

  /** True when this session's setup output came from the cache, so the setup did not run. */
  get setupRestored(): boolean {
    return this.#setupRestored;
  }

  /** True once a file or command ran that may have changed the sandbox. */
  get touched(): boolean {
    return this.#touched;
  }

  /** Run something that may change the sandbox; a checkpoint follows it. Marked again at its end, as a task may outlive the turn. */
  track<T>(work: Promise<T>): Promise<T> {
    this.#dirty = true;
    this.#touched = true;
    return work.finally(() => {
      this.#dirty = true;
    });
  }

  /**
   * Seed once, before the first file tool or command. A transient failure
   * retries on the next call; one a retry cannot cure (a cap, a missing tool)
   * is remembered and fails the same way at once.
   */
  async ensureSeeded(signal?: AbortSignal): Promise<void> {
    const startedAt = Date.now();
    const { cache } = this.#options;
    if (cache?.pendingNotice) {
      this.#options.notify(cache.pendingNotice);
      cache.pendingNotice = undefined;
    }
    const seed = (mode: "fresh" | "overlay" | "reset") =>
      seedRemoteWorkspace(
        this.#options.sandbox,
        this.#options.root,
        this.#options.decide,
        {
          mode,
          progress: this.#options.notify,
          ...(signal ? { signal } : {}),
          caps: {
            totalCap:
              (this.#options.seedLimits?.maxTotalMiB ?? SEED_TOTAL_CAP / MIB) *
              MIB,
            fileCap:
              (this.#options.seedLimits?.maxFileMiB ?? SEED_FILE_CAP / MIB) *
              MIB,
          },
        },
      );
    // A snapshot of this host's own earlier seed holds the project already:
    // lay the current files over it. Should that fail, the sandbox is cleaned
    // and seeded as usual, and the setup runs again.
    let restored = cache?.restored === true;
    this.#seed ??= (
      restored
        ? seed("overlay").catch(async (error: unknown) => {
            // Cancelled: the snapshot is still good, and the next call overlays it again.
            if (error instanceof SeedRefused || signal?.aborted) throw error;
            restored = false;
            await cache?.discard();
            this.#options.notify(CACHE_NOTICE_OVERLAY);
            return seed("reset");
          })
        : seed("fresh")
    ).then(
      async (result) => {
        this.#options.seeded(result);
        const fileCap =
          (this.#options.seedLimits?.maxFileMiB ?? SEED_FILE_CAP / MIB) * MIB;
        const host =
          this.#options.refresh !== false
            ? await HostRefresh.snapshot(
                this.#options.sandbox,
                this.#options.root,
                this.#options.decide,
                fileCap,
                result,
                startedAt,
              ).catch(() => undefined)
            : undefined;
        return { result, host, restored };
      },
      (error: unknown) => {
        if (!(error instanceof SeedRefused)) this.#seed = undefined;
        if (signal?.aborted)
          throw new Error(
            "The upload to the sandbox was cancelled before it finished; it runs again on the next tool call.",
          );
        throw error;
      },
    );
    const uploaded = await this.#seed;
    // The setup and the snapshot are part of the seed: until they are done the
    // workspace is not `seeded`, so no checkpoint or refresh sees it half made.
    // A cancelled setup is forgotten, and the next call runs it again.
    this.#ready ??= this.#finishSeed(uploaded, signal).catch(
      (error: unknown) => {
        this.#ready = undefined;
        throw error;
      },
    );
    await this.#ready;
  }

  async #finishSeed(
    { result, host, restored }: SeedStage,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    const { cache } = this.#options;
    if (restored) this.#setupRestored = true;
    else {
      await this.#setup(result, signal);
      // Before anything the agent does reaches the sandbox: the snapshot
      // holds only the uploaded files and the setup command's output. A
      // sandbox that fell back from a snapshot is not saved again.
      const { setup, snapshot } = this.#options;
      if (
        cache?.active &&
        cache.restored !== true &&
        setup &&
        snapshot &&
        !this.#setupFailure &&
        !this.#touched &&
        !cache.unsupported()
      )
        await cache.save(
          snapshot,
          { notify: this.#options.notify, warn: this.#options.warn },
          signal,
        );
    }
    this.#dirty = false;
    this.#host = host;
    this.#seeded = result;
    const policy = result.skipped.filter(
      (item) => item.reason === "policy",
    ).length;
    const large = result.skipped.filter(
      (item) => item.reason === "too-large",
    ).length;
    const left = [
      ...(policy ? [`${policy} by policy`] : []),
      ...(large ? [`${large} over the per-file size cap`] : []),
    ];
    if (left.length) {
      const total = policy + result.uploaded.length;
      this.#options.notify(
        `Left out of the sandbox: ${left.join(", ")}.${
          policy * 2 > total
            ? ` Policy withheld ${policy} of ${total} project files, so the agent will not see most of the project.`
            : ""
        }`,
      );
    }
  }

  /**
   * The setup command, once, right after the seed. Its changes to tracked
   * files are folded into the baseline, so the patch holds only the agent's
   * work. A failure is a notice and a line for the model, never a failed session.
   */
  async #setup(
    result: SeedResult,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    const setup = this.#options.setup;
    if (!setup) return;
    const { sandbox, root, notify, warn } = this.#options;
    notify(`Running setup in the sandbox: ${setup.command}`);
    let tail = "";
    let problem: string | undefined;
    const startedAt = Date.now();
    const every = this.#options.setupHeartbeatMs ?? SETUP_HEARTBEAT_MS;
    // A long setup would otherwise look like a hang.
    const heartbeat = setInterval(() => {
      const minutes = Math.round((Date.now() - startedAt) / 60_000);
      notify(
        `Still running setup in the sandbox (${minutes} min): ${printable(setup.command)}`,
      );
    }, every);
    heartbeat.unref();
    try {
      const done = await run(
        sandbox,
        root,
        setup.command,
        setup.timeoutSeconds,
        signal,
      );
      tail = printable(done.output.trim().split("\n").slice(-10).join("\n"));
      if (done.exitCode === null)
        problem = `timed out after ${setup.timeoutSeconds} seconds; raise sandbox.remote.setupTimeoutSeconds`;
      else if (done.exitCode !== 0) problem = `exit ${done.exitCode}`;
    } catch (error) {
      problem = printable(
        String((error as Error)?.message ?? error).slice(0, 200),
      );
    } finally {
      clearInterval(heartbeat);
    }
    if (signal?.aborted)
      throw new Error(
        "The sandbox setup was cancelled before it finished; it is not saved and runs again on the next tool call.",
      );
    if (problem) {
      this.#setupFailure = `${setup.command} (${problem})`;
      warn(
        `Setup failed in the sandbox: ${setup.command} (${problem}).${tail ? `\n${tail}\n` : " "}The session continues without it; ask the agent to run \`${setup.command}\` and read its output, or fix sandbox.remote.setup.`,
      );
    }
    try {
      const status = await run(sandbox, root, "git status --porcelain");
      const changed = status.output.split("\n").filter(Boolean);
      if (status.exitCode !== 0 || changed.length === 0) return;
      result.baselineCommit = await foldBaseline(
        sandbox,
        root,
        result.baselineCommit,
        undefined,
      );
      notify(
        `Setup changed ${changed.length} ${changed.length === 1 ? "file" : "files"} tracked by git in the sandbox (${printable(changed[0]?.slice(3) ?? "")}${changed.length > 1 ? ", ..." : ""}); they count as the starting project and will not appear in sandbox pull.`,
      );
    } catch {
      // The patch then also lists setup's file changes; sandbox pull shows them for review.
    }
  }

  /**
   * At the start of a turn: send what changed on this machine to the sandbox.
   * Returns a line for the model when it did. Never throws.
   */
  refresh(): Promise<string | undefined> {
    const next = this.#queue.then(async () => {
      // Not while the seed's setup is still running: it moves the baseline too.
      const host = this.#seeded ? this.#host : undefined;
      if (!host) return undefined;
      try {
        const { sent, conflicts } = await host.run();
        this.#refreshWarned = false;
        const { command, notify } = this.#options;
        if (sent.length)
          notify(
            `Sent ${sent.length} ${sent.length === 1 ? "file" : "files"} you changed on this machine to the sandbox`,
          );
        if (conflicts.length <= 3)
          for (const path of conflicts)
            notify(
              `${printable(path)} changed on this machine and in the sandbox; the sandbox copy is kept. \`${command} sandbox pull\` will merge or flag it.`,
            );
        else
          notify(
            `${conflicts.length} files changed on this machine and in the sandbox (${printable(conflicts.slice(0, 3).join(", "))}, ...); the sandbox copies are kept. \`${command} sandbox pull\` will merge or flag them.`,
          );
        const lines = [
          ...(sent.length
            ? [
                `The user changed these files on their machine since your last turn and they were copied into the sandbox: ${printable(sent.slice(0, 20).join(", "))}${sent.length > 20 ? ", ..." : ""}. Read them again before relying on earlier output.`,
              ]
            : []),
          ...(conflicts.length
            ? [
                `The user also changed ${printable(conflicts.slice(0, 20).join(", "))} on their machine, but you changed it in the sandbox too, so your copy was kept.`,
              ]
            : []),
        ];
        return lines.length ? lines.join(" ") : undefined;
      } catch (error) {
        if (!this.#refreshWarned)
          this.#options.warn(
            `Edits you made on this machine could not be sent to the sandbox this time (${printable(String((error as Error)?.message ?? error).slice(0, 200))}); the agent may see older copies. The next turn tries again.`,
          );
        this.#refreshWarned = true;
        return undefined;
      }
    });
    this.#queue = next;
    return next;
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
    const { files, latest } = waitingChanges(stateDir, root);
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
      // A pull of this session's own patch leaves a marker naming a commit this
      // session made: from there on only later changes belong in a patch.
      const pulled = readRemoteWorkspacePulled(stateDir, root, session);
      if (pulled && this.#recorded.has(pulled)) {
        seeded.baselineCommit = pulled;
        clearRemoteWorkspacePulled(stateDir, root, session);
      }
      const { patch, commit } = await readSandboxPatch(
        sandbox,
        root,
        seeded.baselineCommit,
        this.#options.maxPatchBytes,
        seeded.lookup.pending(),
      );
      this.#recorded.add(commit);
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
        checkpointCommit: commit,
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
          `The sandbox's changes could not be saved this time (${printable(String((error as Error)?.message ?? error).slice(0, 200))}). The last saved copy is kept and the next turn tries again.`,
        );
      this.#warned = true;
    } finally {
      release?.();
    }
  }
}

/** The unapplied changes waiting for a project: the shared slot and every parked copy. */
export function waitingChanges(
  stateDir: string,
  root: string,
): { files: number; patches: number; latest: string } {
  const parkedDir = join(stateDir, "sandbox-workspace-parked");
  const states = [stateDir];
  try {
    for (const name of readdirSync(parkedDir))
      states.push(join(parkedDir, name));
  } catch {
    // none parked
  }
  let files = 0;
  let patches = 0;
  let latest = "";
  for (const state of states) {
    const kept = readRemoteWorkspaceCheckpoint(state, root);
    if (!kept || kept.patch.length === 0) continue;
    files += kept.meta.files;
    patches++;
    if (kept.meta.createdAt > latest) latest = kept.meta.createdAt;
  }
  return { files, patches, latest };
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
        // Take the stale lock over by renaming it away, never by unlinking its
        // path: another session may have replaced it with a live one meanwhile.
        const taken = `${lock}.${randomBytes(6).toString("hex")}`;
        renameSync(lock, taken);
        if (Date.now() - statSync(taken).mtimeMs < 60_000) {
          // It was a live lock after all: put it back if its path is still free.
          try {
            linkSync(taken, lock);
          } catch {
            // someone claimed the path meanwhile
          }
          rmSync(taken, { force: true });
          return undefined;
        }
        rmSync(taken, { force: true });
      } catch {
        // gone meanwhile: claim it on the next attempt
      }
    }
  }
  return undefined;
}
