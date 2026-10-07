// A contained command that fails on the sandbox prints a raw OS error
// (EROFS, EPERM, ENOTFOUND) that names neither the sandbox nor the setting
// behind it. This reads the command's output as it streams and, when the
// command failed, names the denied path or host and the manifest key that
// decides it.
import { accessSync, constants, existsSync } from "node:fs";
import {
  isWithin,
  realpathNearest,
  type SandboxProfile,
} from "@piship/sandbox";

const FILESYSTEM_ERROR =
  /\b(EROFS|EPERM|EACCES)\b|Read-only file system|Permission denied|Operation not permitted/i;
const NETWORK_ERROR =
  /\b(ENOTFOUND|EAI_AGAIN)\b|Could not resolve host|Temporary failure in name resolution|Name or service not known|nodename nor servname/i;
const HOST = /(?:ENOTFOUND|EAI_AGAIN|resolve host:?)\s+([A-Za-z0-9.-]+)/i;
// The first absolute path a failing line names, quoted or bare.
const QUOTED_PATH = /['"`](\/[^'"`\n]+)['"`]/;
const BARE_PATH = /(?:^|[\s:(])(\/[^\s:'"`()]+)/;

/** The most characters of one output line the scanner looks at. */
const LINE_LIMIT = 2000;

export interface SandboxHintContext {
  readonly profile: Pick<
    SandboxProfile,
    "readDeny" | "writeAllow" | "network" | "workspace"
  >;
  /** Who can change the manifest: `managed` names the distribution owner. */
  readonly mode: "managed" | "personal";
}

/** The one next action: who changes which manifest key. */
export function manifestChange(
  mode: SandboxHintContext["mode"],
  key: string,
): string {
  return mode === "managed"
    ? `Ask the distribution owner to change ${key}.`
    : `Change ${key} in your piship.yaml.`;
}

function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function pathOf(line: string): string | undefined {
  return (QUOTED_PATH.exec(line) ?? BARE_PATH.exec(line))?.[1];
}

/**
 * Collects the first sandbox-looking failure of one command's output. Only a
 * line that matches an error pattern is kept, so a long output costs nothing.
 */
export class SandboxFailureScanner {
  #pending = "";
  #filesystem: string[] = [];
  #network: string | undefined;
  #networkSeen = false;

  constructor(private readonly context: SandboxHintContext) {}

  feed(chunk: Buffer | string): void {
    this.#pending += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    const lines = this.#pending.split("\n");
    this.#pending = (lines.pop() ?? "").slice(-LINE_LIMIT);
    for (const line of lines) this.#line(line.slice(0, LINE_LIMIT));
  }

  #line(line: string): void {
    if (NETWORK_ERROR.test(line)) {
      this.#networkSeen = true;
      this.#network ??= HOST.exec(line)?.[1];
      return;
    }
    if (!FILESYSTEM_ERROR.test(line) || this.#filesystem.length >= 3) return;
    const path = pathOf(line);
    if (path && !this.#filesystem.includes(path)) this.#filesystem.push(path);
  }

  /**
   * The one-line hint for a command that failed, or undefined when nothing in
   * its output was a sandbox denial. A path the sandbox would have allowed
   * (an ordinary permission error inside the workspace) gets no hint.
   */
  hint(): string | undefined {
    this.feed("\n");
    const { profile, mode } = this.context;
    for (const named of this.#filesystem) {
      const path = realpathNearest(named);
      if (profile.readDeny.some((denied) => isWithin(path, denied)))
        return `[PiShip sandbox: ${named} is hidden from shell commands. ${manifestChange(mode, "sandbox.filesystem.read.deny")}]`;
      // A file the launching user cannot read is an ordinary permission
      // error on a read, not a sandbox decision.
      if (existsSync(path) && !readable(path)) continue;
      if (!profile.writeAllow.some((allowed) => isWithin(path, allowed)))
        return `[PiShip sandbox: ${named} is outside the directories shell commands can write. ${manifestChange(mode, "sandbox.filesystem.write.allow")}]`;
    }
    if (this.#networkSeen && profile.network === "deny")
      return `[PiShip sandbox: ${this.#network ? `${this.#network} cannot be reached` : "the host cannot be reached"} because shell commands have no network access. ${manifestChange(mode, "sandbox.network.mode")}]`;
    return undefined;
  }
}
