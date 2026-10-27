// `/grant`: the user's own task grants for this session. Only this typed
// command creates one; tool output and project files cannot.
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { formatError } from "@piship/contracts";
import type { TaskGrant } from "@piship/policy";
import { realpathNearest } from "@piship/sandbox";
import type { GovernanceSession } from "./governance-session.js";

const DEFAULT_TTL_MINUTES = 120;
/**
 * The programs a grant covers unless `--run` names others: build and test
 * tools, no interpreter, `npx`, or wrapper.
 */
export const DEFAULT_GRANT_COMMANDS = [
  "git",
  "npm",
  "pnpm",
  "yarn",
  "pytest",
  "cargo",
  "go",
  "make",
] as const;
const USAGE =
  'Usage: /grant [add] [path] [--for 2h] [--run npm,pytest | --no-run] [--task "label"] | /grant list | /grant revoke <id|all>';

/** Words of the arguments; `"..."` or `'...'` keeps spaces in one. */
function words(args: string): string[] {
  return [...args.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map(
    (match) => match[1] ?? match[2] ?? match[3] ?? "",
  );
}

/** Minutes in `2h`, `90m`, or `1h30m`; undefined when it is none of them. */
export function grantMinutes(text: string): number | undefined {
  const match = /^(?:(\d+)h)?(?:(\d+)m)?$/.exec(text);
  if (!match || (match[1] === undefined && match[2] === undefined))
    return undefined;
  const minutes = Number(match[1] ?? 0) * 60 + Number(match[2] ?? 0);
  return minutes > 0 ? minutes : undefined;
}

function duration(minutes: number): string {
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return [hours ? `${hours}h` : "", rest ? `${rest}m` : ""].join("");
}

function describe(grant: TaskGrant): string {
  const scope = [
    ...(grant.scope.paths ?? []).map((path) => `files under ${path}`),
    ...(grant.scope.commands?.length
      ? [`commands starting with ${grant.scope.commands.join(", ")}`]
      : []),
  ].join("; ");
  return `${scope || "nothing"}, until ${new Date(grant.expiresAt).toLocaleString()}`;
}

async function add(
  gov: GovernanceSession,
  rest: readonly string[],
  ctx: ExtensionContext,
): Promise<string> {
  let target: string | undefined;
  let minutes: number | undefined;
  let task = "";
  let commands: readonly string[] = DEFAULT_GRANT_COMMANDS;
  for (let index = 0; index < rest.length; index++) {
    const word = rest[index] as string;
    if (word === "--no-run") commands = [];
    else if (word === "--run") {
      const list = rest[++index] ?? "";
      commands =
        list === "none" ? [] : list.split(",").filter((item) => item !== "");
      if (!commands.length && list !== "none")
        throw new Error(
          `${USAGE} (--run takes a comma-separated list, or none)`,
        );
    } else if (word === "--for") {
      minutes = grantMinutes(rest[++index] ?? "");
      if (minutes === undefined)
        throw new Error(`${USAGE} (--for takes 2h, 90m, or 1h30m)`);
    } else if (word === "--task") task = rest[++index] ?? "";
    else if (word.startsWith("--") || target !== undefined)
      throw new Error(USAGE);
    else target = word;
  }
  const maxMinutes = Math.floor(gov.grantMaxTtlMs / 60_000);
  minutes ??= Math.min(DEFAULT_TTL_MINUTES, maxMinutes);
  if (minutes > maxMinutes)
    throw new Error(`A task grant lasts at most ${duration(maxMinutes)} here`);
  if (target && /^~(?:$|[/\\])/.test(target))
    throw new Error("/grant does not expand ~; use an absolute path");
  // `.` and no path are the project, not the current directory.
  const root =
    target === undefined || target === "."
      ? gov.project.root
      : resolve(gov.options.cwd, target);
  if (!ctx.hasUI) throw new Error("/grant needs an interactive session");
  // Shell coverage needs shell.execute among the actions the manifest lets a grant cover.
  const actions = gov.manifest.policy.taskGrants?.actions;
  const shellRefused =
    commands.length > 0 &&
    actions !== undefined &&
    !actions.includes("shell.execute");
  if (shellRefused) commands = [];
  const expiresAt = new Date(Date.now() + minutes * 60_000).toISOString();
  const shown = realpathNearest(root);
  const approved = await gov.serializeDialog(() =>
    ctx.ui.confirm(
      `${gov.options.lock.app.name} task grant`,
      [
        ...(task ? [`Task: ${task}`] : []),
        `Approve without a prompt, for ${duration(minutes)} (until ${new Date(expiresAt).toLocaleString()}):`,
        `  reading and writing files under ${shown}`,
        ...(commands.length
          ? [
              `  shell commands starting with ${commands.join(", ")}, one at a time: a chained, redirected, or substituted command, and a git push written out in the command, still prompt`,
              "A covered program runs whatever code it is given (an npm script, a Makefile target), so the agent can run any code through it until the grant ends.",
            ]
          : []),
        "Deny rules, rules that always ask, and everything outside this still prompt. A grant never approves a write to project configuration (.pi, .piship, .claude, .mcp.json); what the policy decides for those stays in force.",
      ].join("\n"),
    ),
  );
  if (!approved) return "No task grant was added.";
  const grant = await gov.addGrant({
    id: randomBytes(4).toString("hex"),
    task,
    createdBy: "user-command",
    expiresAt,
    // No tools: a governed tool's own ask is covered only together with the
    // file or command ask of the same prompt (GrantAsk.companion).
    scope: {
      paths: [root],
      ...(commands.length ? { commands } : {}),
    },
    inheritToSubagents: false,
  });
  // The folder confirmed is the one stored; it resolved elsewhere meanwhile.
  if (grant.scope.paths?.[0] !== shown) {
    gov.revokeGrant(grant.id);
    throw new Error(
      `${root} changed while the grant was confirmed; run /grant again`,
    );
  }
  return `Task grant ${grant.id}: ${describe(grant)}. /grant revoke ${grant.id} ends it.${shellRefused ? " Shell commands are not covered: this distribution's policy.taskGrants.actions does not list shell.execute." : ""}${actions !== undefined && !actions.includes("tool.execute") ? " A file or command ask that comes with a tool prompt is not covered: policy.taskGrants.actions does not list tool.execute." : ""}`;
}

/** `/grant`: add (the default), list, or revoke this session's task grants. */
export async function grantCommand(
  gov: GovernanceSession,
  args: string,
  ctx: ExtensionContext,
): Promise<void> {
  const [first, ...rest] = words(args);
  let message: string;
  let level: "info" | "warning" | "error" = "info";
  try {
    if (first === "list") {
      const grants = gov.listGrants();
      message = grants.length
        ? grants
            .map(
              ({ grant, uses }) =>
                `${grant.id}: ${describe(grant)}; used ${uses} time${uses === 1 ? "" : "s"}${grant.task ? ` (${grant.task})` : ""}`,
            )
            .join("\n")
        : "No task grants in this session.";
    } else if (first === "revoke") {
      const [id] = rest;
      if (!id || rest.length > 1) throw new Error(USAGE);
      const ids =
        id === "all" ? gov.listGrants().map(({ grant }) => grant.id) : [id];
      const revoked = ids.filter((item) => gov.revokeGrant(item));
      message =
        id === "all"
          ? `Revoked ${revoked.length} task grant${revoked.length === 1 ? "" : "s"}.`
          : revoked.length
            ? `Task grant ${id} revoked.`
            : `No task grant ${id} in this session.`;
      if (id !== "all" && !revoked.length) level = "warning";
    } else message = await add(gov, first === "add" ? rest : words(args), ctx);
  } catch (error) {
    message = formatError(error);
    level = "error";
  }
  if (ctx.hasUI) ctx.ui.notify(message, level);
}
