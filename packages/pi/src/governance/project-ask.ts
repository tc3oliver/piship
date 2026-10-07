// One question per project, and one line for what the answer left out. A
// project's configuration is admitted by a unit of items some of which policy
// asks about; the person is asked once for all of them, and in a personal
// distribution may keep the answer (until the files change) in the user's own
// state. A kept answer only replaces the question of a policy `ask`: a deny,
// a rule, or a managed distribution never takes it.
import { createHash } from "node:crypto";
import { type ApprovalChannel, resolveDecision } from "@piship/contracts";
import {
  digestProjectFiles,
  markProjectNotice,
  projectNoticeSeen,
  recallProjectTrust,
  rememberProjectTrust,
} from "@piship/core";
import type { GovernanceSession } from "../governance-session.js";

export interface AskItem {
  /** The path as shown: relative to the project root. */
  readonly path: string;
  readonly resolvedPath: string;
}

export interface ProjectAnswer {
  readonly outcome: "allow" | "deny";
  /** How it was decided, for reasons and audit. */
  readonly how:
    | "approved"
    | "remembered-allow"
    | "remembered-deny"
    | "denied"
    | "cancelled"
    | "unavailable";
}

/** The ways an unanswered or declined question ends, in words. */
export function answerReason(answer: ProjectAnswer, command: string): string {
  return answer.how === "remembered-deny"
    ? `project trust: remembered as not trusted (undo with ${command} config trust forget)`
    : `project trust: ${answer.how}`;
}

function safe(value: string): string {
  return Array.from(value, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || (code >= 127 && code <= 159) ? "?" : character;
  }).join("");
}

const SHOWN_ITEMS = 12;

/** The question for one project, asked at most once per launch. */
export class ProjectAsk {
  #answer: Promise<ProjectAnswer> | undefined;

  constructor(
    private readonly session: GovernanceSession,
    private readonly channel: ApprovalChannel | undefined,
    readonly items: readonly AskItem[],
    private readonly claudeOnly: boolean,
  ) {}

  /** Remembering is for personal distributions; managed policy always asks. */
  get #mayRemember(): boolean {
    return this.session.options.lock.deployment.mode === "personal";
  }

  answer(): Promise<ProjectAnswer> {
    this.#answer ??= this.#ask();
    return this.#answer;
  }

  async #ask(): Promise<ProjectAnswer> {
    const { session } = this;
    const stateDir = session.options.stateDir;
    const digest = this.#mayRemember
      ? digestProjectFiles(
          this.items.map((item) => ({
            path: item.path,
            resolvedPath: item.resolvedPath,
          })),
        )
      : undefined;
    if (digest) {
      let remembered: "allow" | "deny" | undefined;
      try {
        remembered = recallProjectTrust(stateDir, session.project.root, digest);
      } catch {
        remembered = undefined;
      }
      if (remembered)
        return {
          outcome: remembered,
          how: remembered === "allow" ? "remembered-allow" : "remembered-deny",
        };
    }
    const shown = this.items
      .slice(0, SHOWN_ITEMS)
      .map((item) => safe(item.path));
    if (this.items.length > SHOWN_ITEMS)
      shown.push(`... and ${this.items.length - SHOWN_ITEMS} more`);
    const resolved = await resolveDecision(
      {
        effect: "ask",
        policyId: session.engine.id,
        ruleId: "project-trust",
        enforcement: "control-plane",
        action: "resource.load",
        resource: "project:.claude",
        layer: "distribution-enforced",
      },
      this.channel,
      {
        title: this.claudeOnly
          ? "Project Claude Code configuration"
          : "Project configuration",
        message: `Load ${this.claudeOnly ? "the Claude Code configuration" : "the configuration"} of ${session.project.origin} project ${safe(session.project.root)}?\n${shown.join("\n")}`,
        offerRemember: digest !== undefined && this.channel !== undefined,
      },
    );
    if (
      (resolved.remember === "allow" || resolved.remember === "deny") &&
      digest
    ) {
      try {
        rememberProjectTrust(
          stateDir,
          session.project.root,
          resolved.remember,
          digest,
          this.items.map((item) => item.path),
        );
      } catch {
        // Not kept: the question is asked again next time.
      }
    }
    return {
      outcome: resolved.outcome,
      how:
        resolved.approval === "approved" ||
        resolved.approval === "denied" ||
        resolved.approval === "cancelled" ||
        resolved.approval === "unavailable"
          ? resolved.approval
          : "denied",
    };
  }
}

interface LeftOutEntry {
  readonly path: string;
  readonly resolvedPath: string;
  /** Why it is left out and how to trust it, in one clause. */
  readonly hint: string;
}

/**
 * What a launch left out of the project, said in one line, once per project
 * until the project's files or the reasons change.
 */
export class LeftOut {
  readonly #entries = new Map<string, LeftOutEntry>();

  constructor(private readonly session: GovernanceSession) {}

  add(path: string, resolvedPath: string, hint: string): void {
    if (!this.#entries.has(path))
      this.#entries.set(path, { path, resolvedPath, hint });
  }

  /** The manifest key that decides an item, and what to do with it. */
  manifestHint(key: string): string {
    return this.session.options.lock.deployment.mode === "personal"
      ? `set ${key} to allow in piship.yaml and rebuild to trust it`
      : `the distribution policy decides it (${key})`;
  }

  /** The hint for a question that was not answered with yes. */
  askedHint(answer: ProjectAnswer): string {
    const command = this.session.options.lock.app.command;
    const personal = this.session.options.lock.deployment.mode === "personal";
    if (answer.how === "remembered-deny")
      return `you chose never to trust it; undo with ${command} config trust forget`;
    if (!personal)
      return "the distribution policy asks and it was not approved";
    return answer.how === "unavailable"
      ? `nobody was there to ask; start ${command} in a terminal and answer a to trust it`
      : `you declined; start ${command} again and answer a to trust it`;
  }

  /** Show the line unless this project already saw it. */
  flush(): void {
    if (this.#entries.size === 0) return;
    const { session } = this;
    const entries = [...this.#entries.values()].sort((a, b) =>
      a.path.localeCompare(b.path),
    );
    const groups = new Map<string, string[]>();
    for (const entry of entries)
      groups.set(entry.hint, [...(groups.get(entry.hint) ?? []), entry.path]);
    const clauses = [...groups].map(([hint, paths]) => {
      const named = paths.slice(0, 4).map(safe).join(", ");
      return `${named}${paths.length > 4 ? ", ..." : ""} (${hint})`;
    });
    const content = digestProjectFiles(entries);
    const key = createHash("sha256")
      .update(JSON.stringify(entries.map((entry) => [entry.path, entry.hint])))
      .update(content ?? "")
      .digest("hex");
    const stateDir = session.options.stateDir;
    try {
      if (projectNoticeSeen(stateDir, session.project.root, key)) return;
    } catch {
      // Unreadable state: say it.
    }
    session.notice(`Not loaded from this project: ${clauses.join("; ")}.`);
    try {
      markProjectNotice(stateDir, session.project.root, key);
    } catch {
      // Said again next launch.
    }
  }
}
