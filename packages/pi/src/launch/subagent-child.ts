// The launch pi-code's `subagent` tool uses for its child processes. The tool
// spawns `process.argv[1] --mode json -p --no-session [...] <prompt>`; in a
// PiShip distribution that is this branded command, so the child must run
// through the same governed launch (identity, credential, policy, exposure,
// project trust, sandbox, audit) and then Pi's print mode.
//
// The environment marker is not a security boundary: anyone can run the
// command and set it. What keeps it safe is that the child options can only
// narrow the session (a model the distribution allows, fewer tools, a
// replacement system prompt) and that nothing here can switch a governance
// control off: there is no `--yolo`, no login, no approval channel (so an ask
// is denied), and unknown options are refused by name.
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname } from "node:path";
import { PiShipError } from "@piship/contracts";

export const SUBAGENT_ENV = "PI_CODE_SUBAGENT";
const THINKING = [
  "off",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;
export type ChildThinking = (typeof THINKING)[number];
// pi-code temp names under os.tmpdir(): pi-subagent-XXXX and pi-code-bg-session-XXXX.
const PROMPT_DIR = /^pi-subagent-[A-Za-z0-9]+$/;
const SESSION_DIR = /^pi-code-bg-session-[A-Za-z0-9]+$/;
const SESSION_ID = /^pi-code-bg-[0-9a-f]{8}-[0-9a-f]{8}$/;
const BOOLEAN_FLAGS = ["--no-session", "--no-context-files"];
const VALUE_FLAGS = [
  "--model",
  "--thinking",
  "--tools",
  "--exclude-tools",
  "--system-prompt",
  "--session-id",
  "--session-dir",
];
const MAX_PROMPT_FILE_BYTES = 1024 * 1024;

export interface SubagentChild {
  readonly prompt: string;
  readonly model?: string;
  readonly thinking?: ChildThinking;
  /** Allowlist: the child's tools are these, further bounded by exposure. */
  readonly tools?: readonly string[];
  /** Denylist, added to the tools exposure already excludes. */
  readonly excludeTools?: readonly string[];
  /** The text of the replacement system prompt. */
  readonly systemPrompt?: string;
  /** A persisted background session, else the session is in memory. */
  readonly session?: { readonly id: string; readonly dir: string };
}

const refuse = (message: string, userAction?: string): PiShipError =>
  new PiShipError("CONFIG_INVALID", message, userAction ? { userAction } : {});

/** Whether these arguments are the subagent child's, under the parent's marker. */
export function isSubagentChild(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): boolean {
  return (
    env[SUBAGENT_ENV] === "1" &&
    args[0] === "--mode" &&
    args[1] === "json" &&
    args[2] === "-p"
  );
}

/** Whether `real` (a real path) is `<tmpdir>/<name matching pattern>`. */
function inTemp(real: string, pattern: RegExp): boolean {
  return (
    pattern.test(basename(real)) && dirname(real) === realpathSync(tmpdir())
  );
}

// The text of pi-code's prompt-NAME.md in its pi-subagent-XXXX directory, a regular file.
function promptFile(path: string): string {
  const fail = () => refuse("The subagent system prompt file cannot be used");
  try {
    const real = realpathSync(path);
    if (!inTemp(dirname(real), PROMPT_DIR)) throw fail();
    const stat = lstatSync(real);
    if (!stat.isFile() || stat.size > MAX_PROMPT_FILE_BYTES) throw fail();
    return readFileSync(real, "utf8");
  } catch (error) {
    throw error instanceof PiShipError ? error : fail();
  }
}

/**
 * The child's options, by allowlist. Anything else is refused by its name,
 * never by echoing the command line: the last argument is the task prompt.
 */
export function parseSubagentChild(
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): SubagentChild {
  if (!isSubagentChild(args, env)) throw refuse("Not a subagent child launch");
  const last = args.length - 1;
  let model: string | undefined;
  let thinking: ChildThinking | undefined;
  let tools: string[] | undefined;
  let excludeTools: string[] | undefined;
  let systemPrompt: string | undefined;
  let sessionId: string | undefined;
  let sessionDir: string | undefined;
  const seen = new Set<string>();
  for (let i = 3; i < last; i += 1) {
    const flag = args[i] as string;
    if (BOOLEAN_FLAGS.includes(flag)) {
      // Governed sessions load no project context files, only the
      // distribution's own instructions, which stay.
      seen.add(flag);
      continue;
    }
    if (!VALUE_FLAGS.includes(flag))
      throw refuse(
        `Option ${flag.startsWith("-") ? flag.slice(0, 40) : "(not an option)"} is not available to a subagent child`,
        "Subagent children accept only the options pi-code passes",
      );
    if (seen.has(flag)) throw refuse(`${flag} is given twice`);
    seen.add(flag);
    const value = args[i + 1];
    if (i + 1 >= last || value === undefined || value === "")
      throw refuse(`${flag} needs a value`);
    i += 1;
    if (flag === "--model") model = value;
    else if (flag === "--thinking") {
      if (!THINKING.includes(value as ChildThinking))
        throw refuse("--thinking is not a known level");
      thinking = value as ChildThinking;
    } else if (flag === "--tools") tools = value.split(",").filter(Boolean);
    else if (flag === "--exclude-tools")
      excludeTools = value.split(",").filter(Boolean);
    else if (flag === "--system-prompt") systemPrompt = promptFile(value);
    else if (flag === "--session-id") sessionId = value;
    else sessionDir = value;
  }
  const prompt = args[last];
  if (
    last < 3 ||
    !prompt ||
    BOOLEAN_FLAGS.includes(prompt) ||
    VALUE_FLAGS.includes(prompt)
  )
    throw refuse("The subagent child needs a task prompt");
  if (!!sessionId !== !!sessionDir)
    throw refuse("--session-id and --session-dir go together");
  if (sessionId && seen.has("--no-session"))
    throw refuse("--no-session and --session-id cannot both be given");
  let session: SubagentChild["session"];
  if (sessionId && sessionDir) {
    if (!SESSION_ID.test(sessionId))
      throw refuse("--session-id is not a pi-code background session id");
    let real: string | undefined;
    try {
      real = realpathSync(sessionDir);
    } catch {
      // refused below
    }
    if (!real || !inTemp(real, SESSION_DIR))
      throw refuse("The subagent session directory cannot be used");
    session = { id: sessionId, dir: real };
  }
  // pi reads a thinking level from a `:level` suffix on the model pattern.
  let modelId = model;
  if (model) {
    const cut = model.lastIndexOf(":");
    const suffix = cut > 0 ? model.slice(cut + 1) : "";
    if (THINKING.includes(suffix as ChildThinking)) {
      modelId = model.slice(0, cut);
      thinking ??= suffix as ChildThinking;
    }
  }
  return {
    prompt,
    ...(modelId ? { model: modelId } : {}),
    ...(thinking ? { thinking } : {}),
    ...(tools ? { tools } : {}),
    ...(excludeTools ? { excludeTools } : {}),
    ...(systemPrompt !== undefined ? { systemPrompt } : {}),
    ...(session ? { session } : {}),
  };
}
