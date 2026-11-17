// Governed replacements for Pi's built-in tools. Pi's own tool definitions are
// reused through their public operation hooks, so rendering, truncation and
// diff behavior stay upstream; PiShip only decides each file access and each
// command before it happens. The one exception is bash's execute, which
// PiShip runs so the full output is owned by the session (governedBashTool).
// Custom tools passed to the SDK take precedence over any extension tool of
// the same name.
import { constants, existsSync } from "node:fs";
import {
  access,
  type FileHandle,
  mkdir,
  open,
  readdir,
  readlink,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, posix, resolve, win32 } from "node:path";
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
  type ExtensionToolContext,
  formatSize,
  getShellConfig,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import {
  type ApprovalAnswer,
  type ApprovalChannel,
  type ApprovalDetail,
  type PolicyAction,
  processNetworkEnvironment,
  type ResolvedDecision,
  redact,
} from "@piship/contracts";
import type { GovernedMcpTool } from "@piship/mcp";
import {
  BUILTIN_DEFAULT_RULE,
  gitPushResources,
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
import { remoteWorkdir } from "./governance/sandbox.js";
import type { ToolExposureTable } from "./governance/exposure.js";
import type { GovernanceSession } from "./governance-session.js";
import { SUBAGENT_TOKEN_ENV } from "./launch/subagent-owner.js";
import { sniffImage } from "./image-sniff.js";
import { skipExplanation } from "./remote-workspace/seed.js";
import {
  manifestChange,
  SANDBOX_NO_RETRY,
  SandboxFailureScanner,
} from "./sandbox-hint.js";
import { freeBytes, ShellOutput, userBashBudget } from "./shell-output.js";
import { taskTools } from "./task-tools.js";

/** True when `path` is `root` or below it. */
const inside = (root: string, path: string) => isWithin(path, root);

/**
 * The only tools a Plan-mode session may run: the governed `read` and
 * `ask_user`, and reading or stopping a background task (stopping only
 * removes effects; starting one stays refused). Everything else, including
 * MCP and extension tools whose effects PiShip cannot know, is blocked
 * until the user switches to Build.
 */
export const PLAN_ALLOWED_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "ask_user",
  "task_output",
  "task_stop",
]);
export const PLAN_RULE = "piship-workflow.plan";
/**
 * PiShip has no way to tell a read-only shell command from one that changes
 * things, and Pi's own `grep`, `find`, and `ls` are excluded from a governed
 * session, so Plan mode explores with `read` and leaves the shell to Build.
 */
const PLAN_SHELL_REFUSAL =
  "Plan mode does not run commands, because PiShip cannot tell a read-only command from one that changes files. Explore with the read tool (it also lists a directory); the user can switch to Build mode with /build to run it.";
/** The same refusal for the user's own `!` command: they are the one to switch. */
const USER_PLAN_SHELL_REFUSAL =
  "Plan mode does not run commands, your own ! commands included, because PiShip cannot tell a read-only command from one that changes files. Switch to Build mode with /build to run it.";
/** Told to the model after a Plan-mode refusal, so it does not loop on it. */
const PLAN_NO_RETRY =
  "Do not retry it or work around Plan mode with another tool; finish the plan and tell the user it needs Build mode.";

/**
 * Record a tool refused by Plan mode and return the refusal, or undefined
 * when the session is not in Plan mode or the tool is allowed there.
 */
export function planRefusal(
  gov: GovernanceSession,
  tool: string,
): string | undefined {
  // `ask_user` is PiShip's only while its builtin is loaded, and the task
  // tools only where PiShip offers them (not in a subagent child, not
  // hidden); otherwise a tool of that name is an extension's, with effects
  // PiShip cannot know.
  const ours =
    tool === "ask_user"
      ? gov.loader.builtin.has("piship-ask-user")
      : tool === "task_output" || tool === "task_stop"
        ? gov.backgroundTasks !== undefined &&
          gov.exposure?.get(tool) !== "hidden"
        : true;
  if (gov.workflowMode !== "plan" || (PLAN_ALLOWED_TOOLS.has(tool) && ours))
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
  return `${
    tool === "bash"
      ? PLAN_SHELL_REFUSAL
      : `Plan mode does not allow ${tool}. The user can switch to Build mode with /build.`
  } ${PLAN_NO_RETRY}`;
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
        [detail.title, detail.message, detail.sessionCovers]
          .filter((line) => line !== undefined)
          .join("\n"),
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

/** Told to the model after a policy refusal, so it does not loop on it. */
const NO_RETRY =
  "Do not retry it or work around the rule; tell the user what was blocked.";
const ASK_USER_NEXT =
  "Do not retry it unless the user asks; ask how they want to proceed.";

/**
 * The text of a refusal as the user reads it: the instructions to the model
 * are left out, and "the user can" becomes what the user does. The model
 * still receives the full text.
 */
export function userText(text: string): string {
  let shown = text;
  for (const directive of [
    NO_RETRY,
    PLAN_NO_RETRY,
    SANDBOX_NO_RETRY,
    ASK_USER_NEXT,
  ])
    shown = shown.split(` ${directive}`).join("").split(directive).join("");
  return shown
    .split("The user can switch to Build mode with /build.")
    .join("Switch to Build mode with /build.")
    .split(
      "Explore with the read tool (it also lists a directory); the user can switch to Build mode with /build to run it.",
    )
    .join("Switch to Build mode with /build to run it.")
    .split(
      "The user can run this command in their own terminal, outside the sandbox; do not retry it here.",
    )
    .join("Run this command in your own terminal, outside the sandbox.")
    .split(" declined by the user (")
    .join(" declined (");
}

/** A tool whose result shows the user `userText`, not the model's text. */
function withUserText<T extends ToolDefinition>(tool: T): T {
  const render = tool.renderResult;
  if (!render) return tool;
  return {
    ...tool,
    renderResult: (result, options, theme, context) =>
      render(
        {
          ...result,
          content: result.content.map((part) =>
            part.type === "text"
              ? { ...part, text: userText(part.text) }
              : part,
          ),
        },
        options,
        theme,
        context,
      ),
  } as T;
}

/**
 * Why `subject` (`This command`, `filesystem.write <path>`, a tool name) did
 * not run: the user's own answer to a prompt, or the policy and rule that
 * refused it with who can change that rule. Unless the user ran it (a `!`
 * command), it also tells the model not to try again.
 */
export function policyRefusal(
  gov: GovernanceSession,
  decision: ResolvedDecision,
  subject: string,
  model = true,
): string {
  const asked = `${decision.policyId} rule ${decision.ruleId} asks for approval`;
  // The user's own answer: no rule to change, so only "ask them" is left.
  const askUser = model ? ` ${ASK_USER_NEXT}` : "";
  if (decision.approval === "denied")
    return model
      ? `${subject} was declined by the user (${asked}).${askUser}`
      : `${subject} was declined (${asked}).`;
  if (decision.approval === "cancelled")
    return `${subject} did not run: the approval prompt was dismissed (${asked}).${askUser}`;
  return `${subject} is not allowed by ${decision.policyId} rule ${decision.ruleId}${decision.reason ? `: ${decision.reason}` : ""}${decision.approval === "unavailable" ? (gov.options.subagent ? " (a subagent cannot ask for approval, and approvals given in its parent session do not carry over)" : " (approval needs an interactive session)") : ""}.${gov.denialHint(decision)}${model ? ` ${NO_RETRY}` : ""}`;
}

export function blocked(message: string): BlockedError {
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
      isProtectedDirectoryPath(protection.directories, posix, existingDirectory)
    )
      return CLAUDE_CONFIG_RULE;
  }
  return undefined;
}

/**
 * Whether one of `paths` (POSIX separators) lies in a protected directory, or
 * is an ancestor that could be replaced by one while the directory does not
 * exist yet. Case-insensitive where the filesystem is, like
 * `isProtectedGitPath`.
 */
export function isProtectedDirectoryPath(
  directories: readonly string[],
  paths: readonly string[],
  existingDirectory: boolean,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const fold =
    platform === "darwin" || platform === "win32"
      ? (path: string) => path.toLowerCase()
      : (path: string) => path;
  const dirs = directories.map((dir) => fold(toPosixPath(dir)));
  return paths
    .map(fold)
    .some((path) =>
      dirs.some(
        (dir) =>
          isWithinPosix(dir, path) ||
          (!existingDirectory && isWithinPosix(path, dir)),
      ),
    );
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
      `${
        builtin === STATE_RULE
          ? `${path} is in the distribution state directory, which tools never read or write.`
          : builtin === CLAUDE_CONFIG_RULE
            ? `${path} controls executable project configuration; managed tools may not change it or its ancestors.`
            : `${path} is a git file that decides this project's origin or what git runs; tools may not change it.`
      } ${NO_RETRY}`,
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
          ? `${path} is outside what this distribution lets tools read. ${manifestChange(gov.options.lock.deployment.mode, "sandbox.filesystem.read.deny")} ${NO_RETRY}`
          : `${path} is outside the directories this distribution lets tools write. ${manifestChange(gov.options.lock.deployment.mode, "sandbox.filesystem.write.allow")} ${NO_RETRY}`,
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
      policyRefusal(
        gov,
        decision,
        `${action === "filesystem.read" ? "Reading" : "Writing"} ${path}`,
      ),
    );
  return real;
}

/**
 * The seed's decision for one file: `filesystem.read` without ever asking.
 * Only an `allow` uploads; `deny`, `ask`, the state directory, and what the
 * sandbox profile hides are skipped.
 */
export function seedDecision(
  gov: GovernanceSession,
): (path: string) => Promise<"allow" | "skip"> {
  return async (path) => {
    const lexical = resolve(path);
    const real = realpathNearest(lexical);
    if (builtinDenial(gov, "filesystem.read", [lexical, real], false))
      return "skip";
    if (
      gov.sandbox.profile.readDeny.some(
        (denied) => inside(denied, real) || inside(denied, lexical),
      )
    )
      return "skip";
    return [lexical, real].every(
      (resource) =>
        gov.engine.evaluate({ action: "filesystem.read", resource }).effect ===
        "allow",
    )
      ? "allow"
      : "skip";
  };
}

export function sandboxGoneMessage(command: string): string {
  return `The sandbox expired or was lost. Changes up to the last checkpoint are saved; changes made after it are gone. Exit, run ${command} sandbox pull to review them, then start a new session.`;
}

function sandboxGone<T>(gov: GovernanceSession, work: Promise<T>): Promise<T> {
  return work.catch((error: unknown) => {
    throw (error as { code?: string })?.code === "SANDBOX_GONE"
      ? new Error(sandboxGoneMessage(gov.options.lock.app.command))
      : error;
  });
}

/** The project directory inside a remote workspace's sandbox, when PiShip knows it. */
function remoteWorkdirOf(config: {
  workdir?: string | undefined;
  provider?: string | undefined;
  user?: string | undefined;
}): string | undefined {
  return (
    config.workdir ??
    (config.provider === "e2b-compatible"
      ? remoteWorkdir(config.user ?? "user")
      : undefined)
  );
}

/**
 * A path the sandbox printed (`pwd`, a stack trace) as the host path of the
 * same file, so policy judges the host-equivalent path. Only an exact
 * path-segment prefix of the sandbox workdir maps, and nothing that leaves it
 * after normalising. On Windows, Pi has already resolved `/home/u/ws/x`
 * against the current drive, so a drive prefix is dropped first.
 */
export function mapSandboxPath(
  path: string,
  workdir: string,
  root: string,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  const host = platform === "win32" ? win32 : posix;
  const rooted =
    platform === "win32"
      ? path.replace(/^[A-Za-z]:/, "").replaceAll("\\", "/")
      : path;
  if (!rooted.startsWith("/") || path.includes("\0")) return undefined;
  // A host path already inside the project is the host's own.
  if (platform !== "win32" || /^[A-Za-z]:/.test(path)) {
    const own = host.relative(root, path);
    if (
      own !== ".." &&
      !own.startsWith(`..${host.sep}`) &&
      !host.isAbsolute(own)
    )
      return undefined;
  }
  // normalize() leaves at most one trailing slash.
  const normal = posix.normalize(workdir);
  const base = normal.endsWith("/") ? normal.slice(0, -1) : normal;
  const full = posix.normalize(rooted);
  if (full !== base && !full.startsWith(`${base}/`)) return undefined;
  const rest = full
    .slice(base.length + 1)
    .split("/")
    .filter(Boolean);
  if (rest.some((segment) => segment === ".." || segment.includes("\\")))
    return undefined;
  return host.join(root, ...rest);
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

function tooLarge(
  path: string,
  size: string,
  tool: string,
  plan: boolean,
): Error {
  const part = plan
    ? "Plan mode runs no commands; the user can switch to Build mode with /build to work on part of it"
    : "Use bash to work on part of it, for example sed -n '1,200p', head -c 50000 or grep -n";
  return new Error(
    `${path} is ${size}, over the ${formatSize(GOVERNED_READ_LIMIT_BYTES)} limit of the governed ${tool} tool. ${part}.`,
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
  plan: boolean,
): Promise<Buffer> {
  const stats = await handle.stat();
  if (stats.isFIFO())
    throw new Error(
      `${path} is a named pipe, not a file, so the governed ${tool} tool does not read it.`,
    );
  const { size } = stats;
  if (size > GOVERNED_READ_LIMIT_BYTES)
    throw tooLarge(path, formatSize(size), tool, plan);
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
        plan,
      );
  }
  return Buffer.concat(chunks, total);
}

/** Most entries a directory read lists. */
export const DIRECTORY_LIST_LIMIT = 2000;

/**
 * A directory given to the read tool, listed: its entry names sorted, a
 * folder marked with a trailing slash. It is the opened directory that was
 * decided as `filesystem.read`, or the listing is refused. Plan mode has no
 * shell, so this is how it finds files.
 */
export async function listDirectory(
  handle: FileHandle,
  path: string,
): Promise<Buffer> {
  const held = await handle.stat({ bigint: true });
  const same = async () => {
    const current = await stat(path, { bigint: true }).catch(() => undefined);
    return current?.dev === held.dev && current.ino === held.ino;
  };
  const changed = () => blocked(`${path} changed while it was being listed.`);
  // Linux lists the opened directory itself. Node cannot list a directory
  // by descriptor elsewhere (macOS /dev/fd/N is not one), so there the path
  // must name the opened directory before and after it is read.
  const byHandle = `/proc/self/fd/${handle.fd}`;
  const fd = process.platform === "linux" && existsSync(byHandle);
  if (!fd && !(await same())) throw changed();
  const entries = await readdir(fd ? byHandle : path, { withFileTypes: true });
  if (!(await same())) throw changed();
  const names = entries
    .map((entry) => (entry.isDirectory() ? `${entry.name}/` : entry.name))
    .sort();
  const lines = names.slice(0, DIRECTORY_LIST_LIMIT);
  if (names.length > DIRECTORY_LIST_LIMIT)
    lines.push(
      `[${names.length - DIRECTORY_LIST_LIMIT} more entries not shown; read a subfolder]`,
    );
  if (!names.length) lines.push("(empty directory)");
  return Buffer.from(`${lines.join("\n")}\n`, "utf8");
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
export async function gateCommand(
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
    return source === "bash" ? PLAN_SHELL_REFUSAL : USER_PLAN_SHELL_REFUSAL;
  }
  const events = {
    allowed: "tool.allowed",
    denied: "tool.denied",
    resource: source,
    // The user typed a `!` command themselves; the prompt says so.
    prompt: `${source === "bash" ? "bash" : "your own ! command"}: ${command}`,
    detail: { commandBytes: Buffer.byteLength(command) },
    content: { command },
  } as const;
  // `git.push` only narrows: a push no rule covers is left to
  // `shell.execute` without an event. A command `shell.execute` denies is
  // refused there, before any push prompt.
  const pushes = gitPushResources(command).filter(
    (resource) =>
      gov.engine.evaluate({ action: "git.push", resource }).ruleId !==
      BUILTIN_DEFAULT_RULE,
  );
  if (
    pushes.length &&
    gov.engine.evaluate({ action: "shell.execute", resource: command })
      .effect !== "deny"
  ) {
    const push = await gov.decide(
      "git.push",
      pushes,
      gov.currentChannel(),
      events,
    );
    if (push.outcome !== "allow")
      return policyRefusal(gov, push, "This command", source === "bash");
  }
  const decision = await gov.decide(
    "shell.execute",
    command,
    gov.currentChannel(),
    events,
  );
  if (decision.outcome === "allow") return undefined;
  return policyRefusal(gov, decision, "This command", source === "bash");
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
 * The environment of a command no sandbox contains. In a managed
 * distribution it still gets only the approved network settings. Pi passes
 * the agent's commands an environment; if a Pi version stops doing so, the
 * process environment is the base, so the agent's command is never left
 * unrestricted. A personal distribution has no approved settings, and a
 * user's `!` command carries no environment from Pi: both keep the process
 * environment.
 */
export function uncontainedEnvironment(
  env: NodeJS.ProcessEnv | undefined,
  source: "bash" | "user-bash",
): NodeJS.ProcessEnv {
  const network = processNetworkEnvironment();
  // The session's subagent token is for its children, not for a command.
  const { [SUBAGENT_TOKEN_ENV]: _token, ...inherited } = env ?? process.env;
  // Always an explicit copy: a command given no environment would inherit
  // the whole process environment, token included. Only an agent's command
  // is narrowed to the approved network settings (see above).
  const narrowed = network && (env || source === "bash");
  return narrowed ? withApprovedNetwork(inherited, network) : inherited;
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
      return (
        gov.remote?.ensureSeeded(options.signal) ?? Promise.resolve()
      ).then(() => {
        const running = gov.sandbox.exec(command, cwd, {
          onData: options.onData,
          ...(options.signal ? { signal: options.signal } : {}),
          ...(options.timeout !== undefined
            ? { timeout: options.timeout }
            : {}),
          ...(options.env ? { env: options.env } : {}),
        });
        return gov.remote?.track(sandboxGone(gov, running)) ?? running;
      });
    const env = uncontainedEnvironment(options.env, source);
    // The local Pi runner has no Windows Job Object. Use the same
    // kill-on-close supervisor as background tasks for unsandboxed bash.
    if (process.platform === "win32")
      return gov.sandbox.exec(command, cwd, {
        onData: options.onData,
        ...(options.signal ? { signal: options.signal } : {}),
        ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
        env,
        // Match Pi's Git Bash/WSL shell, not the native backend's cmd.exe.
        shell: getShellConfig(),
      });
    return local.exec(command, cwd, { ...options, env });
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
              command,
              cwd,
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
          if (hint)
            options.onData(
              Buffer.from(`\n${source === "bash" ? hint : userText(hint)}\n`),
            );
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
 * The command, cwd, and environment Pi's bash tool would spawn. Pi builds
 * them (PATH and the PI_* session variables) in execute; its own execute is
 * run once with operations that only capture them: nothing is spawned, and
 * with no output it opens no file.
 */
export async function piBashSpawn(
  cwd: string,
  id: string,
  params: { command: string; timeout?: number },
  ctx: ExtensionToolContext,
): Promise<{ command: string; cwd: string; env?: NodeJS.ProcessEnv }> {
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
  return spawn;
}

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
      const spawn = await piBashSpawn(cwd, id, params, ctx);
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
        // Flush first: a write error can arrive only now, and the result must
        // not name a file that the error then removes.
        await output.close();
        return output.snapshot();
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
        gov.withToolCall(
          id,
          tool.name,
          () => execute(id, params, signal, onUpdate, ctx),
          signal,
        ),
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
    // Sequential unless the server opted in; approvals still queue one at a time.
    executionMode: tool.parallel ? "parallel" : "sequential",
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
  // A remote workspace: the same decision, then the sandbox's file API.
  // The host-only guards (no-follow open, hard-link check) do not apply to
  // a path the host cannot reach.
  const remote = gov.remote ? gov.sandbox.files : undefined;
  const workdir = remote ? remoteWorkdirOf(gov.manifest.sandbox) : undefined;
  // A path the sandbox printed names the same file as under the project root.
  const absolute = (path: string) =>
    (workdir && mapSandboxPath(path, workdir, gov.project.root)) ||
    (isAbsolute(path) ? path : resolve(cwd, path));
  const missing = (path: string, decided?: string) => {
    const reason =
      remote && decided ? gov.remote?.lookup()?.skipped(decided) : undefined;
    return Object.assign(
      new Error(
        reason && reason !== "policy"
          ? `ENOENT: ${path} is not in the sandbox: it is ${skipExplanation(reason)}`
          : `ENOENT: no such file, ${path}`,
      ),
      { code: "ENOENT" },
    );
  };
  const gone = <T>(work: Promise<T>) => sandboxGone(gov, work);
  const decideRemote = async (
    action: "filesystem.read" | "filesystem.write",
    path: string,
    tool: string,
  ) => {
    const decided = await gatePath(gov, action, absolute(path), tool);
    await gov.remote?.ensureSeeded(gov.toolSignal());
    return decided;
  };
  // A file the seed withheld by policy, read after the user approved it: it
  // goes into the sandbox now, as part of the baseline. `gated` is false when
  // only a write was decided so far, so the read is decided here too.
  const adoptWithheld = async (
    decided: string,
    tool: string,
    gated: boolean,
  ) => {
    const seed = remote && gov.remote?.lookup();
    if (!seed || seed.skipped(decided) !== "policy") return;
    if (!gated) await gatePath(gov, "filesystem.read", decided, tool);
    await gone(seed.adopt(decided, gov.toolSignal()));
  };
  const read = async (path: string, tool: string) => {
    if (remote) {
      const decided = await decideRemote("filesystem.read", path, tool);
      await adoptWithheld(decided, tool, true);
      const data = await gone(remote.read(decided)).catch((error: unknown) => {
        throw (error as { code?: string })?.code === "ENOENT"
          ? missing(path, decided)
          : error;
      });
      if (data.length > GOVERNED_READ_LIMIT_BYTES)
        throw tooLarge(
          path,
          formatSize(data.length),
          tool,
          gov.workflowMode === "plan",
        );
      return data;
    }
    const handle = await openDecided(
      gov,
      "filesystem.read",
      absolute(path),
      tool,
      constants.O_RDONLY,
    );
    try {
      if ((await handle.stat()).isDirectory())
        return await listDirectory(handle, absolute(path));
      return await readBounded(handle, path, tool, gov.workflowMode === "plan");
    } finally {
      await handle.close();
    }
  };
  const write = async (path: string, content: string, tool: string) => {
    if (remote)
      return gov.remote!.track(
        gone(
          remote.write(
            await decideRemote("filesystem.write", path, tool),
            Buffer.from(content, "utf8"),
          ),
        ),
      );
    const handle = await openDecided(
      gov,
      "filesystem.write",
      absolute(path),
      tool,
      constants.O_WRONLY,
    );
    try {
      // Writing in place would change the other name of a hard-linked file,
      // which may lie outside the workspace.
      if ((await handle.stat()).nlink > 1)
        throw blocked(
          `${path} has more than one hard link; tools may not write it.`,
        );
      await handle.truncate(0);
      await handle.writeFile(content, "utf8");
    } finally {
      await handle.close();
    }
  };
  const exists = async (path: string, tool: string) => {
    if (remote) {
      const decided = await decideRemote("filesystem.read", path, tool);
      await adoptWithheld(decided, tool, true);
      if (!(await gone(remote.stat(decided)))) throw missing(path, decided);
      return;
    }
    await gatePath(gov, "filesystem.read", absolute(path), tool);
    await access(path, constants.R_OK);
  };
  const sniffed = new Map<string, Buffer>();
  const tools: ToolDefinition[] = [
    createReadToolDefinition(cwd, {
      operations: {
        readFile: (path) => {
          const held = sniffed.get(path);
          sniffed.delete(path);
          return held ? Promise.resolve(held) : read(path, "read");
        },
        access: (path) => exists(path, "read"),
        // Pi detects from a host path, which a sandbox file lacks, and
        // opening a host path again would skip the governed open (a FIFO
        // would block): sniff the bytes read here and hand them to readFile.
        detectImageMimeType: async (path) => {
          const data = await read(path, "read");
          sniffed.set(path, data);
          return sniffImage(data);
        },
      },
    }) as ToolDefinition,
    createWriteToolDefinition(cwd, {
      operations: {
        writeFile: (path, content) => write(path, content, "write"),
        mkdir: async (dir) => {
          if (remote) {
            // The sandbox creates parents when it writes the file.
            await gatePath(gov, "filesystem.write", absolute(dir), "write");
            return;
          }
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
          if (remote) {
            const decided = await decideRemote(
              "filesystem.write",
              path,
              "edit",
            );
            await adoptWithheld(decided, "edit", false);
            if (!(await gone(remote.stat(decided))))
              throw missing(path, decided);
            return;
          }
          await gatePath(gov, "filesystem.write", absolute(path), "edit");
          await access(path, constants.R_OK | constants.W_OK);
        },
        writeFile: (path, content) => write(path, content, "edit"),
      },
    }) as ToolDefinition,
    governedBashTool(gov, cwd) as ToolDefinition,
    // A subagent child has no way to stop what it would leave running
    // (TASK_TOOLS are left out of its exposure table too).
    ...(gov.options.subagent ? [] : taskTools(gov, cwd)),
    ...(gov.mcp?.tools() ?? []).map((item) => mcpTool(gov, item)),
  ];
  const session = tools.flatMap((tool) => {
    const exposure = table?.get(tool.name) ?? "direct";
    return exposure === "hidden"
      ? []
      : [
          withUserText(
            withChannel(gov, { ...tool, exposure } as ToolDefinition),
          ),
        ];
  });
  // MCP tools have no file or command decision to defer their ask to.
  gov.resourceTools = new Set(
    session.map((tool) => tool.name).filter((name) => RESOURCE_TOOLS.has(name)),
  );
  return session;
}

/** The governed tools that decide every file or command they touch. */
const RESOURCE_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "write",
  "edit",
  "bash",
  "task_start",
]);
