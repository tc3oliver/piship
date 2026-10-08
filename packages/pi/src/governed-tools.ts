// Governed replacements for Pi's built-in tools. Pi's own tool definitions are
// reused through their public operation hooks, so rendering, truncation and
// diff behavior stay upstream; PiShip only decides each file access and each
// command before it happens. The one exception is bash's execute, which
// PiShip runs so the full output is owned by the session (governedBashTool).
// Custom tools passed to the SDK take precedence over any extension tool of
// the same name.
import { constants } from "node:fs";
import {
  access,
  type FileHandle,
  mkdir,
  open,
  readlink,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import {
  type BashOperations,
  type BashToolDetails,
  createBashToolDefinition,
  createEditToolDefinition,
  createLocalBashOperations,
  createReadToolDefinition,
  createWriteToolDefinition,
  DEFAULT_MAX_BYTES,
  type ExtensionContext,
  formatSize,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  type ApprovalAnswer,
  type ApprovalChannel,
  type ApprovalDetail,
  type PolicyAction,
  processNetworkEnvironment,
  redact,
} from "@piship/contracts";
import type { GovernedMcpTool } from "@piship/mcp";
import {
  isWithin as isWithinPosix,
  normalizePathResource,
  projectGitControlDirectories,
  projectGitControlFiles,
  toPosixPath,
} from "@piship/policy";
import {
  enforcesPathPolicy,
  isWithin,
  realpathNearest,
  withApprovedNetwork,
} from "@piship/sandbox";
import { projectProtection } from "./governance/engine.js";
import type { ToolExposureTable } from "./governance/exposure.js";
import type { GovernanceSession } from "./governance-session.js";
import { SUBAGENT_TOKEN_ENV } from "./launch/subagent-owner.js";
import { manifestChange, SandboxFailureScanner } from "./sandbox-hint.js";
import { freeBytes, ShellOutput, userBashBudget } from "./shell-output.js";

/** True when `path` is `root` or below it. */
const inside = (root: string, path: string) => isWithin(path, root);

/**
 * The only tools a Plan-mode session may run: the governed `read` and
 * `ask_user`. Everything else, including MCP and extension tools whose
 * effects PiShip cannot know, is blocked until the user switches to Build.
 */
export const PLAN_ALLOWED_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "ask_user",
]);
export const PLAN_RULE = "piship-workflow.plan";
/**
 * PiShip has no way to tell a read-only shell command from one that changes
 * things, and Pi's own `grep`, `find`, and `ls` are excluded from a governed
 * session, so Plan mode explores with `read` and leaves the shell to Build.
 */
const PLAN_SHELL_REFUSAL =
  "Plan mode does not run commands, because PiShip cannot tell a read-only command from one that changes files. Explore with the read tool, or switch to Build mode with /build to run it.";

/**
 * Record a tool refused by Plan mode and return the refusal, or undefined
 * when the session is not in Plan mode or the tool is allowed there.
 */
export function planRefusal(
  gov: GovernanceSession,
  tool: string,
): string | undefined {
  // `ask_user` is PiShip's only while its builtin is loaded; without it, a
  // tool of that name is an extension's, with effects PiShip cannot know.
  if (
    gov.workflowMode !== "plan" ||
    (PLAN_ALLOWED_TOOLS.has(tool) &&
      (tool !== "ask_user" || gov.loader.builtin.has("piship-ask-user")))
  )
    return undefined;
  gov.metrics.recordPolicyDenial("tool.execute");
  gov.emit("tool.denied", {
    resource: tool,
    decision: "denied",
    policy: gov.policyId,
    rule: PLAN_RULE,
    enforcement: "control-plane",
    detail: { action: "tool.execute" },
  });
  return tool === "bash"
    ? PLAN_SHELL_REFUSAL
    : `Plan mode does not allow ${tool}. The user can switch to Build mode with /build.`;
}

/**
 * An approval channel backed by Pi's dialog UI, or none when headless. The
 * dialog closes when the turn is aborted, so a queued approval (see
 * GovernanceSession.decide) never waits on a prompt nobody can answer.
 */
export function uiChannel(ctx: ExtensionContext): ApprovalChannel | undefined {
  if (!ctx.hasUI) return undefined;
  return async (_decision, detail) => {
    const signal = ctx.signal;
    if (signal?.aborted) return "denied";
    const options = approvalOptions(detail.scopes);
    // Only when more than yes/no is offered: Pi's `select` shows the choices,
    // its `confirm` only two.
    if (options.length > 2) {
      const choice = await ctx.ui.select(
        `${detail.title}\n${detail.message}`,
        options.map((option) => option.label),
        signal ? { signal } : undefined,
      );
      if (choice === undefined) return signal?.aborted ? "denied" : "cancelled";
      return (
        options.find((option) => option.label === choice)?.answer ?? "denied"
      );
    }
    const approved = signal
      ? await ctx.ui.confirm(detail.title, detail.message, { signal })
      : await ctx.ui.confirm(detail.title, detail.message);
    return approved ? "approved" : "denied";
  };
}

/**
 * The answers a prompt shows, in order, for the scopes it offers. A scope
 * that stores its answer (a persistent "always") is one more entry here and a
 * matching `ApprovalAnswer`; the prompt itself does not change.
 */
function approvalOptions(
  scopes: ApprovalDetail["scopes"],
): { label: string; answer: ApprovalAnswer }[] {
  return [
    { label: "Allow once", answer: "approved" },
    ...(scopes?.includes("session")
      ? [
          {
            label: "Allow for this session",
            answer: "approved-session" as const,
          },
        ]
      : []),
    { label: "Deny", answer: "denied" },
  ];
}

class BlockedError extends Error {}

function blocked(message: string): BlockedError {
  return new BlockedError(redact(message));
}

/** Workspace, home, temp, or other: audit records a path class, not the path. */
export function pathClass(gov: GovernanceSession, path: string): string {
  // The engine context is normalized to POSIX separators; compare alike.
  const { workspaceRoot, homeDir, tmpDir } = gov.engine.context;
  const posix = toPosixPath(path);
  if (isWithinPosix(workspaceRoot, posix)) return "workspace";
  if (isWithinPosix(tmpDir, posix)) return "tmp";
  if (isWithinPosix(homeDir, posix)) return "home";
  return "other";
}

export const STATE_RULE = "piship.state";
export const CLAUDE_CONFIG_RULE = "piship.project.executable-config";
export const GIT_CONFIG_RULE = "piship.project.git-config";
export const CHANGED_RULE = "piship.path-changed";

/**
 * Built-in denials that no policy or sandbox level relaxes: the distribution
 * state (credentials metadata and the user policy file) is never read or
 * written, and the git files that classify the project and the git hooks
 * and info trees are never written. The user's own git config outside the
 * project (`~/.gitconfig`) is not among them: only sandboxed processes are
 * kept from it (`gitProtection`), so the edit tool still changes it.
 */
function builtinDenial(
  gov: GovernanceSession,
  action: "filesystem.read" | "filesystem.write",
  paths: readonly string[],
  existingDirectory: boolean,
): string | undefined {
  const posix = paths.map((path) => toPosixPath(path));
  const state = normalizePathResource(gov.options.stateDir, {
    workspaceRoot: gov.project.root,
  });
  if (posix.some((path) => isWithinPosix(state, path))) return STATE_RULE;
  if (action !== "filesystem.write") return undefined;
  if (isProtectedGitPath(gov.project.root, posix)) return GIT_CONFIG_RULE;
  if (gov.options.lock.deployment.mode === "managed") {
    const protection = projectProtection(
      gov.options,
      gov.project,
      gov.sandbox.profile.homeDir,
    );
    if (
      posix.some((path) =>
        protection.directories.some(
          (dir) =>
            isWithinPosix(toPosixPath(dir), path) ||
            (!existingDirectory && isWithinPosix(path, toPosixPath(dir))),
        ),
      )
    )
      return CLAUDE_CONFIG_RULE;
  }
  return undefined;
}

/**
 * Whether one of `paths` (POSIX separators) is a protected git file of the
 * project at `root`, or inside a protected git tree. macOS and Windows
 * filesystems ignore case by default, where `.GIT/hooks` is `.git/hooks`,
 * so there the comparison ignores case too.
 */
export function isProtectedGitPath(
  root: string,
  paths: readonly string[],
  platform: NodeJS.Platform = process.platform,
): boolean {
  const fold =
    platform === "darwin" || platform === "win32"
      ? (path: string) => path.toLowerCase()
      : (path: string) => path;
  const git = projectGitControlFiles(root).map(fold);
  const trees = projectGitControlDirectories(root).map(fold);
  return paths
    .map(fold)
    .some(
      (path) =>
        git.includes(path) || trees.some((dir) => isWithinPosix(dir, path)),
    );
}

/**
 * Decide one file access on both the path as given and its symlink-resolved
 * target; the stricter decision wins. Plan mode and the active sandbox
 * profile are applied to the same in-process tools.
 */
export async function gatePath(
  gov: GovernanceSession,
  action: Extract<PolicyAction, "filesystem.read" | "filesystem.write">,
  path: string,
  tool: string,
  existingDirectory = false,
): Promise<string> {
  const lexical = resolve(path);
  const real = realpathNearest(lexical);
  const classOf = pathClass(gov, real);
  if (action === "filesystem.write" && gov.workflowMode === "plan") {
    gov.metrics.recordPolicyDenial(action);
    gov.emit("tool.denied", {
      resource: tool,
      decision: "denied",
      policy: gov.policyId,
      rule: PLAN_RULE,
      enforcement: "control-plane",
      detail: { action, path: classOf },
    });
    throw blocked(
      `Plan mode does not change files. Switch to Build mode (/build) to write ${path}.`,
    );
  }
  const builtin = builtinDenial(
    gov,
    action,
    [lexical, real],
    existingDirectory,
  );
  if (builtin) {
    gov.metrics.recordPolicyDenial(action);
    gov.emit("tool.denied", {
      resource: tool,
      decision: "denied",
      policy: gov.policyId,
      rule: builtin,
      enforcement: "control-plane",
      detail: { action, path: classOf },
    });
    throw blocked(
      builtin === STATE_RULE
        ? `${path} is in the distribution state directory, which tools never read or write.`
        : builtin === CLAUDE_CONFIG_RULE
          ? `${path} controls executable project configuration; managed tools may not change it or its ancestors.`
          : `${path} is a git file that decides this project's origin or what git runs; tools may not change it.`,
    );
  }
  if (gov.sandbox.report.level === "enforced") {
    const profile = gov.sandbox.profile;
    const hidden = profile.readDeny.some(
      (denied) => inside(denied, real) || inside(denied, lexical),
    );
    const writable =
      action !== "filesystem.write" ||
      profile.writeAllow.some((allowed) => inside(allowed, real));
    if (hidden || !writable) {
      gov.metrics.recordPolicyDenial(action);
      gov.emit("tool.denied", {
        resource: tool,
        decision: "denied",
        policy: gov.policyId,
        rule: hidden
          ? "sandbox.filesystem.read.deny"
          : "sandbox.filesystem.write.allow",
        // Only a backend that enforces the path policy itself contains the
        // file; otherwise this refusal is PiShip's alone.
        enforcement: enforcesPathPolicy(gov.sandbox.report.planes)
          ? "sandbox"
          : "control-plane",
        detail: { action, path: classOf },
      });
      throw blocked(
        hidden
          ? `${path} is outside what this distribution lets tools read. ${manifestChange(gov.options.lock.deployment.mode, "sandbox.filesystem.read.deny")}`
          : `${path} is outside the directories this distribution lets tools write. ${manifestChange(gov.options.lock.deployment.mode, "sandbox.filesystem.write.allow")}`,
      );
    }
  }
  const decision = await gov.decide(
    action,
    [lexical, real],
    gov.currentChannel(),
    {
      denied: "tool.denied",
      resource: tool,
      prompt: `${tool}: ${path}`,
      detail: { path: classOf },
    },
  );
  if (decision.outcome !== "allow")
    throw blocked(
      `${action} ${path} is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? " (approval needs an interactive session)" : ""}.`,
    );
  return real;
}

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
// Opening a FIFO without it waits for a peer on a thread no abort can release,
// and a few such opens stop all async file I/O of the process. With it the
// open returns at once, and a FIFO is then refused by its type.
const NONBLOCK = constants.O_NONBLOCK ?? 0;

/**
 * The largest file the governed read and edit tools load. Pi's read tool
 * takes the whole file as one buffer, then a string and an array of its
 * lines, before it truncates the output to about 50 KB; without a bound an
 * authorized read of a huge log or sparse file exhausts memory. 16 MiB is
 * more than 300 pages of Pi's output; past it, bash reads parts of a file.
 */
export const GOVERNED_READ_LIMIT_BYTES = 16 * 1024 * 1024;

/**
 * The most output one governed shell command may produce. Only a bounded
 * tail is kept in memory, but the complete output is copied to a temp file
 * (the session's for the agent's tool, Pi's for a `!` command), so a runaway
 * command would write until the disk is full. Past this budget the command
 * is stopped and its process tree killed.
 */
export const SHELL_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024;
const OUTPUT_LIMIT_NOTICE = `\n[output exceeded the ${SHELL_OUTPUT_LIMIT_BYTES / 1024 / 1024} MiB shell output limit; PiShip stopped the command. Redirect large output to a file and inspect it with head, tail, or grep.]\n`;
const lowDiskNotice = (budget: number) =>
  `\n[output reached ${formatSize(budget)}, all the temporary disk can spare; PiShip stopped the command. Free temporary disk space or redirect large output to a file.]\n`;

/** The path the kernel reports for an open file, where the platform has one. */
async function openedPath(handle: FileHandle): Promise<string | undefined> {
  if (process.platform !== "linux") return undefined;
  try {
    return await readlink(`/proc/self/fd/${handle.fd}`);
  } catch {
    return undefined;
  }
}

/**
 * Open the decided path and confirm the handle is the file that was decided.
 * A symlink or directory swapped in between the decision and the open is
 * caught here: on Linux the opened file's own path is decided again; where
 * the platform cannot name an open file, the handle must be the same file
 * (device and inode) as the decided path, which must still resolve to itself.
 * Reads and writes then go through this handle only.
 */
async function openDecided(
  gov: GovernanceSession,
  action: "filesystem.read" | "filesystem.write",
  path: string,
  tool: string,
  flags: number,
): Promise<FileHandle> {
  const lexical = resolve(path);
  const decided = await gatePath(gov, action, lexical, tool);
  const handle = await openFile(decided, flags);
  try {
    const opened = await openedPath(handle);
    if (opened !== undefined) {
      if (opened !== decided) await gatePath(gov, action, opened, tool);
      return handle;
    }
    const [held, current] = await Promise.all([
      handle.stat({ bigint: true }),
      stat(decided, { bigint: true }).catch(() => undefined),
    ]);
    const same =
      current !== undefined &&
      held.ino !== 0n &&
      held.dev === current.dev &&
      held.ino === current.ino &&
      realpathNearest(lexical) === decided;
    if (!same) {
      gov.metrics.recordPolicyDenial(action);
      gov.emit("tool.denied", {
        resource: tool,
        decision: "denied",
        policy: gov.policyId,
        rule: CHANGED_RULE,
        enforcement: "control-plane",
        detail: { action, path: pathClass(gov, decided) },
      });
      throw blocked(`${path} changed while it was being opened.`);
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function tooLarge(path: string, size: string, tool: string): Error {
  return new Error(
    `${path} is ${size}, over the ${formatSize(GOVERNED_READ_LIMIT_BYTES)} limit of the governed ${tool} tool. Use bash to work on part of it, for example sed -n '1,200p', head -c 50000 or grep -n.`,
  );
}

/**
 * Read the opened file, refusing it once it exceeds the read limit. The size
 * is checked on the handle, and the read itself stops one byte past the
 * limit, so neither an earlier path lookup nor a file that grows while it is
 * read gets past the bound.
 */
async function readBounded(
  handle: FileHandle,
  path: string,
  tool: string,
): Promise<Buffer> {
  const stats = await handle.stat();
  if (stats.isFIFO())
    throw new Error(
      `${path} is a named pipe, not a file, so the governed ${tool} tool does not read it.`,
    );
  const { size } = stats;
  if (size > GOVERNED_READ_LIMIT_BYTES)
    throw tooLarge(path, formatSize(size), tool);
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const room = GOVERNED_READ_LIMIT_BYTES + 1 - total;
    const chunk = Buffer.allocUnsafe(
      Math.min(room, Math.max(size + 1 - total, 64 * 1024)),
    );
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    total += bytesRead;
    if (total > GOVERNED_READ_LIMIT_BYTES)
      throw tooLarge(
        path,
        `more than ${formatSize(GOVERNED_READ_LIMIT_BYTES)}`,
        tool,
      );
  }
  return Buffer.concat(chunks, total);
}

/** Open for writing without following a final symlink; create only when absent. */
async function openFile(path: string, flags: number): Promise<FileHandle> {
  const plain = flags | NOFOLLOW | NONBLOCK;
  if (!(flags & constants.O_WRONLY)) return open(path, plain);
  try {
    return await open(path, plain);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return open(path, plain | constants.O_CREAT | constants.O_EXCL);
  }
}

/** Decide a shell command; return a refusal message or undefined when allowed. */
async function gateCommand(
  gov: GovernanceSession,
  command: string,
  source: "bash" | "user-bash",
): Promise<string | undefined> {
  if (gov.workflowMode === "plan") {
    gov.metrics.recordPolicyDenial("shell.execute");
    gov.emit("tool.denied", {
      resource: source,
      decision: "denied",
      policy: gov.policyId,
      rule: PLAN_RULE,
      enforcement: "control-plane",
      detail: { action: "shell.execute" },
    });
    return PLAN_SHELL_REFUSAL;
  }
  const decision = await gov.decide(
    "shell.execute",
    command,
    gov.currentChannel(),
    {
      allowed: "tool.allowed",
      denied: "tool.denied",
      resource: source,
      prompt: `${source}: ${command}`,
      detail: { commandBytes: Buffer.byteLength(command) },
      content: { command },
    },
  );
  if (decision.outcome === "allow") return undefined;
  return `This command is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? " (approval needs an interactive session)" : ""}.`;
}

type ExecOptions = Parameters<BashOperations["exec"]>[2];

/**
 * Pass at most `budget` bytes of output through, then one notice, and abort
 * the returned signal so the runner kills the process tree.
 */
function boundedOutput(options: ExecOptions, budget: number, notice: string) {
  const limit = new AbortController();
  let passed = 0;
  let exceeded = false;
  const onData = (data: Buffer) => {
    if (exceeded) return;
    const room = budget - passed;
    if (data.length <= room) {
      passed += data.length;
      options.onData(data);
      return;
    }
    exceeded = true;
    if (room > 0) options.onData(data.subarray(0, room));
    options.onData(Buffer.from(notice));
    limit.abort();
  };
  const signal = options.signal
    ? AbortSignal.any([options.signal, limit.signal])
    : limit.signal;
  return { onData, signal, exceeded: () => exceeded };
}

/**
 * Shell operations: policy first, then the OS sandbox when it is enforced.
 * Without an enforced sandbox the command runs as Pi would run it, and the
 * decision was control-plane only. Either way the command's output is
 * bounded by SHELL_OUTPUT_LIMIT_BYTES. A user's `!` command runs through Pi,
 * which copies its full output to a temp file PiShip cannot configure, so
 * its budget is also lowered to the free temp space minus a reserve.
 */
export function governedBashOperations(
  gov: GovernanceSession,
  source: "bash" | "user-bash",
): BashOperations {
  const local = createLocalBashOperations();
  const run = (
    command: string,
    cwd: string,
    options: ExecOptions,
  ): Promise<{ exitCode: number | null }> => {
    if (gov.sandbox.report.level === "enforced")
      return gov.sandbox.exec(command, cwd, {
        onData: options.onData,
        ...(options.signal ? { signal: options.signal } : {}),
        ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
        ...(options.env ? { env: options.env } : {}),
      });
    // In a managed distribution an uncontained command still gets only the
    // approved network settings. Pi passes the agent's commands an
    // environment; if a Pi version stops doing so, the process environment
    // is the base, so the agent's command is never left unrestricted. A
    // personal distribution has no approved settings, and a user's `!`
    // command carries no environment from Pi: both keep the process
    // environment.
    const network = processNetworkEnvironment();
    // The session's subagent token is for its children, not for a command.
    const { [SUBAGENT_TOKEN_ENV]: _token, ...inherited } =
      options.env ?? process.env;
    // Always an explicit copy: a command given no environment would inherit
    // the whole process environment, token included. Only an agent's command
    // is narrowed to the approved network settings (see above).
    const narrowed = network && (options.env || source === "bash");
    return local.exec(command, cwd, {
      ...options,
      env: narrowed ? withApprovedNetwork(inherited, network) : inherited,
    });
  };
  return {
    exec: async (command, cwd, options) => {
      const refusal = await gateCommand(gov, command, source);
      if (refusal) {
        if (source === "bash") throw blocked(refusal);
        options.onData(Buffer.from(`${refusal}\n`));
        return { exitCode: 126 };
      }
      const budget =
        source === "user-bash"
          ? userBashBudget(SHELL_OUTPUT_LIMIT_BYTES, freeBytes(tmpdir()))
          : SHELL_OUTPUT_LIMIT_BYTES;
      const output = boundedOutput(
        options,
        budget,
        budget < SHELL_OUTPUT_LIMIT_BYTES
          ? lowDiskNotice(budget)
          : OUTPUT_LIMIT_NOTICE,
      );
      // A command the sandbox contained that fails on a denied path or host
      // gets one line saying which setting decides it, after its own output.
      const scanner =
        gov.sandbox.report.level === "enforced"
          ? new SandboxFailureScanner({
              profile: gov.sandbox.profile,
              mode: gov.options.lock.deployment.mode,
            })
          : undefined;
      try {
        const result = await run(command, cwd, {
          ...options,
          onData: scanner
            ? (data) => {
                scanner.feed(data);
                output.onData(data);
              }
            : output.onData,
          signal: output.signal,
        });
        if (output.exceeded()) return { exitCode: null };
        if (scanner && result.exitCode) {
          const hint = scanner.hint();
          if (hint) options.onData(Buffer.from(`\n${hint}\n`));
        }
        return result;
      } catch (error) {
        // Stopped at the limit: the notice is in the output, and no exit
        // code is reported. A caller's own abort stays an abort.
        if (output.exceeded() && !options.signal?.aborted)
          return { exitCode: null };
        throw error;
      }
    },
  };
}

/** Pi's live-update throttle for the shell tool (renderers/bash.js). */
const BASH_UPDATE_THROTTLE_MS = 100;

/** Pi's limit for `structuredContent.output` (tools/bash.js). */
const STRUCTURED_OUTPUT_MAX_BYTES = 1024 * 1024;

/**
 * The governed `bash` tool: Pi's definition (name, schema, prompt text,
 * renderers) with PiShip's execute. Pi's execute persists the full output to
 * an unbounded, unowned `pi-bash-*.log` whose write stream has no error
 * handler; this one keeps the same display tail, live updates, footer, and
 * error semantics, and persists through the session's output store.
 */
function governedBashTool(gov: GovernanceSession, cwd: string) {
  const definition = createBashToolDefinition(cwd);
  const operations = governedBashOperations(gov, "bash");
  const tool: typeof definition = {
    ...definition,
    async execute(id, params, signal, onUpdate, ctx) {
      // Pi builds the command, cwd, and environment (PATH and the PI_*
      // session variables) in execute. Its own execute is run once with
      // operations that only capture them: nothing is spawned, and with no
      // output it opens no file.
      let spawn: { command: string; cwd: string; env?: NodeJS.ProcessEnv } = {
        command: params.command,
        cwd: ctx?.cwd || cwd,
      };
      await createBashToolDefinition(cwd, {
        operations: {
          exec: async (command, dir, options) => {
            spawn = {
              command,
              cwd: dir,
              ...(options.env ? { env: options.env } : {}),
            };
            return { exitCode: 0 };
          },
        },
      }).execute(id, params, undefined, undefined, ctx);
      const output = new ShellOutput(gov.outputStore);
      let acceptingOutput = true;
      let updateTimer: NodeJS.Timeout | undefined;
      let updateDirty = false;
      let lastUpdateAt = 0;
      const emitOutputUpdate = () => {
        if (!onUpdate || !updateDirty) return;
        updateDirty = false;
        lastUpdateAt = Date.now();
        const snapshot = output.snapshot();
        onUpdate({
          content: [{ type: "text", text: snapshot.content || "" }],
          details: {
            truncation: snapshot.truncation.truncated
              ? snapshot.truncation
              : undefined,
            fullOutputPath: snapshot.fullOutputPath,
          } as BashToolDetails,
        });
      };
      const clearUpdateTimer = () => {
        if (updateTimer) {
          clearTimeout(updateTimer);
          updateTimer = undefined;
        }
      };
      const scheduleOutputUpdate = () => {
        if (!onUpdate) return;
        updateDirty = true;
        const delay = BASH_UPDATE_THROTTLE_MS - (Date.now() - lastUpdateAt);
        if (delay <= 0) {
          clearUpdateTimer();
          emitOutputUpdate();
          return;
        }
        updateTimer ??= setTimeout(() => {
          updateTimer = undefined;
          emitOutputUpdate();
        }, delay);
      };
      onUpdate?.({ content: [], details: undefined });
      const finishOutput = async () => {
        acceptingOutput = false;
        output.finish();
        clearUpdateTimer();
        emitOutputUpdate();
        const snapshot = output.snapshot();
        await output.close();
        return snapshot;
      };
      // Pi's footer, byte for byte when the output is saved: its renderer
      // drops the footer by finding fullOutputPath in it.
      const formatOutput = (
        snapshot: ReturnType<ShellOutput["snapshot"]>,
        emptyText = "(no output)",
      ) => {
        const truncation = snapshot.truncation;
        let text = snapshot.content || emptyText;
        let details: BashToolDetails | undefined;
        if (truncation.truncated) {
          // Pi's shape: fullOutputPath is present, undefined when not saved.
          details = {
            truncation,
            fullOutputPath: snapshot.fullOutputPath,
          } as BashToolDetails;
          const file = output.file;
          const saved = snapshot.fullOutputPath
            ? file?.capped
              ? `Full output (first ${formatSize(file.limit)}): ${snapshot.fullOutputPath}`
              : `Full output: ${snapshot.fullOutputPath}`
            : `Full output not saved: ${file?.failure ?? "unavailable"}`;
          const startLine = truncation.totalLines - truncation.outputLines + 1;
          const endLine = truncation.totalLines;
          if (truncation.lastLinePartial) {
            const lastLineSize = formatSize(output.lastLineBytes);
            text += `\n\n[Showing last ${formatSize(truncation.outputBytes)} of line ${endLine} (line is ${lastLineSize}). ${saved}]`;
          } else if (truncation.truncatedBy === "lines") {
            text += `\n\n[Showing lines ${startLine}-${endLine} of ${truncation.totalLines}. ${saved}]`;
          } else {
            text += `\n\n[Showing lines ${startLine}-${endLine} of ${truncation.totalLines} (${formatSize(DEFAULT_MAX_BYTES)} limit). ${saved}]`;
          }
        }
        return { text, details };
      };
      const appendStatus = (text: string, status: string) =>
        `${text ? `${text}\n\n` : ""}${status}`;
      const startedAt = performance.now();
      try {
        let exitCode: number | null;
        try {
          const result = await operations.exec(spawn.command, spawn.cwd, {
            onData: (data) => {
              if (!acceptingOutput) return;
              output.append(data);
              scheduleOutputUpdate();
            },
            ...(signal ? { signal } : {}),
            ...(params.timeout !== undefined
              ? { timeout: params.timeout }
              : {}),
            ...(spawn.env ? { env: spawn.env } : {}),
          });
          exitCode = result.exitCode;
        } catch (err) {
          const snapshot = await finishOutput();
          const { text } = formatOutput(snapshot, "");
          if (err instanceof Error && err.message === "aborted")
            throw new Error(appendStatus(text, "Command aborted"));
          if (err instanceof Error && err.message.startsWith("timeout:")) {
            const timeoutSecs = err.message.split(":")[1];
            throw new Error(
              appendStatus(
                text,
                `Command timed out after ${timeoutSecs} seconds`,
              ),
            );
          }
          throw err;
        }
        const snapshot = await finishOutput();
        const { text: outputText, details } = formatOutput(snapshot);
        if (exitCode === null)
          throw new Error(
            appendStatus(outputText, "Command terminated without an exit code"),
          );
        const wallTimeSeconds =
          Math.round((performance.now() - startedAt) / 100) / 10;
        // Pi's structured result, which codemode scripts receive.
        const fullOutput = await output.readFullOutput(
          STRUCTURED_OUTPUT_MAX_BYTES,
        );
        const structuredContent = {
          output: fullOutput.content,
          truncated: fullOutput.truncated,
          ...(fullOutput.truncated && snapshot.fullOutputPath
            ? { full_output_path: snapshot.fullOutputPath }
            : {}),
          exit_code: exitCode,
          wall_time_seconds: wallTimeSeconds,
        };
        if (exitCode !== 0)
          return {
            content: [
              {
                type: "text",
                text: appendStatus(
                  outputText,
                  `Command exited with code ${exitCode}`,
                ),
              },
            ],
            details,
            structuredContent,
            isError: true,
          };
        return {
          content: [{ type: "text", text: outputText }],
          details,
          structuredContent,
        };
      } finally {
        clearUpdateTimer();
      }
    },
  };
  return tool;
}

function withChannel<T extends ToolDefinition>(
  gov: GovernanceSession,
  tool: T,
): T {
  const execute = tool.execute.bind(tool);
  return {
    ...tool,
    execute: (id, params, signal, onUpdate, ctx) =>
      gov.withChannel(uiChannel(ctx), () =>
        execute(id, params, signal, onUpdate, ctx),
      ),
  } as T;
}

function mcpTool(
  gov: GovernanceSession,
  tool: GovernedMcpTool,
): ToolDefinition {
  return {
    name: tool.name,
    // Groups the server's tools in Codemode's searchTools/describeNamespace.
    namespace: {
      name: `mcp__${tool.server}`,
      description: `Tools from the ${tool.server} MCP server`,
    },
    label: `${tool.server}: ${tool.tool}`,
    description:
      tool.description || `${tool.tool} from the ${tool.server} MCP server`,
    promptSnippet: `${tool.name}: ${(tool.description || tool.tool).split("\n")[0]}`,
    parameters: tool.inputSchema as never,
    executionMode: "sequential",
    async execute(_id, params, signal) {
      // The tool_call hook refuses first; this holds for direct calls too.
      const refusal = planRefusal(gov, tool.name);
      if (refusal) throw blocked(refusal);
      const result = await tool.call(params as Record<string, unknown>, signal);
      if (result.isError) throw new Error(result.text || "MCP tool failed");
      return {
        content: [{ type: "text", text: result.text }],
        details: {
          server: tool.server,
          tool: tool.tool,
          truncated: result.truncated,
        },
      };
    },
  };
}

/**
 * The governed tool set for a v1alpha3 session, each with the exposure the
 * session's table resolved. A hidden tool is left out here as well as
 * excluded from the session.
 */
export function governedTools(
  gov: GovernanceSession,
  cwd: string,
  table: ToolExposureTable | null = gov.exposure,
): ToolDefinition[] {
  const absolute = (path: string) =>
    isAbsolute(path) ? path : resolve(cwd, path);
  const read = async (path: string, tool: string) => {
    const handle = await openDecided(
      gov,
      "filesystem.read",
      absolute(path),
      tool,
      constants.O_RDONLY,
    );
    try {
      return await readBounded(handle, path, tool);
    } finally {
      await handle.close();
    }
  };
  const write = async (path: string, content: string, tool: string) => {
    const handle = await openDecided(
      gov,
      "filesystem.write",
      absolute(path),
      tool,
      constants.O_WRONLY,
    );
    try {
      await handle.truncate(0);
      await handle.writeFile(content, "utf8");
    } finally {
      await handle.close();
    }
  };
  const exists = async (path: string, tool: string) => {
    await gatePath(gov, "filesystem.read", absolute(path), tool);
    await access(path, constants.R_OK);
  };
  const tools: ToolDefinition[] = [
    createReadToolDefinition(cwd, {
      operations: {
        readFile: (path) => read(path, "read"),
        access: (path) => exists(path, "read"),
      },
    }) as ToolDefinition,
    createWriteToolDefinition(cwd, {
      operations: {
        writeFile: (path, content) => write(path, content, "write"),
        mkdir: async (dir) => {
          // Keep the parent policy decision even when mkdir needs no change:
          // it is an independent opportunity to notice a redirected path.
          const existingDirectory = await stat(absolute(dir)).then(
            (info) => info.isDirectory(),
            () => false,
          );
          await gatePath(
            gov,
            "filesystem.write",
            absolute(dir),
            "write",
            existingDirectory,
          );
          if (!existingDirectory) await mkdir(dir, { recursive: true });
        },
      },
    }) as ToolDefinition,
    createEditToolDefinition(cwd, {
      operations: {
        readFile: (path) => read(path, "edit"),
        access: async (path) => {
          await gatePath(gov, "filesystem.write", absolute(path), "edit");
          await access(path, constants.R_OK | constants.W_OK);
        },
        writeFile: (path, content) => write(path, content, "edit"),
      },
    }) as ToolDefinition,
    governedBashTool(gov, cwd) as ToolDefinition,
    ...(gov.mcp?.tools() ?? []).map((item) => mcpTool(gov, item)),
  ];
  return tools.flatMap((tool) => {
    const exposure = table?.get(tool.name) ?? "direct";
    return exposure === "hidden"
      ? []
      : [withChannel(gov, { ...tool, exposure } as ToolDefinition)];
  });
}
