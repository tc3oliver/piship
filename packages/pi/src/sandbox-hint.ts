// A contained command that fails on the sandbox prints a raw OS error
// (EROFS, EPERM, ENOTFOUND) that names neither the sandbox nor the setting
// behind it. This reads the command's output as it streams and, when the
// command failed, names the denied path or host and the manifest key that
// decides it.
import { accessSync, constants, existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  isWithin,
  realpathNearest,
  type SandboxProfile,
} from "@piship/sandbox";

// Bubblewrap binds a protected file read-only, so replacing it is EBUSY.
const FILESYSTEM_ERROR =
  /\b(EROFS|EPERM|EACCES|EBUSY)\b|Read-only file system|Permission denied|Operation not permitted|Device or resource busy/i;
// A connect refused by the sandbox: Seatbelt fails it with EPERM, a network
// namespace with no route with ENETUNREACH.
const NETWORK_ERROR =
  /\b(ENOTFOUND|EAI_AGAIN)\b|Could not resolve host|Temporary failure in name resolution|Name or service not known|nodename nor servname|\bconnect E(?:PERM|ACCES|NETUNREACH)\b|connect to host \S+ port \d+: Operation not permitted|Network is unreachable|Failed to connect to/i;
// A command that reaches the network by itself, even when it prints nothing
// (`curl -s` fails with exit code 6 and no output).
const NETWORK_COMMAND =
  /(?:^|[\s;&|(])(?:curl|wget|ssh|scp|sftp|rsync|ping|telnet|ftp|nc)\b|(?:^|[\s;&|(])git\s+(?:clone|fetch|pull|ls-remote)\b|[a-z]+:\/\//i;
const HOST =
  /(?:ENOTFOUND|EAI_AGAIN|resolve host:?|connect E[A-Z]+|connect to host|Failed to connect to)\s+([A-Za-z0-9.-]+)/i;
// A path a failing line names, quoted or bare: absolute, or relative with a
// slash in it (`.git/config`, `../x`). The last one is the denied path for a
// write; the first is often the program, as in `/bin/bash: .git/config:
// Operation not permitted`. A hidden or protected path counts wherever it is
// on the line (`mv: cannot move '.git/config' to '.git/config.bak'`).
const PATH =
  /['"`]((?:\/|[^\s'"`/]+\/)[^'"`\n]*)['"`]|(?:^|[\s:(])((?:\/(?!\/)|[\w.-]+\/)[^\s:'"`()]*)/g;

/** The most characters of one output line the scanner looks at. */
const LINE_LIMIT = 2000;

export interface SandboxHintContext {
  readonly profile: Pick<
    SandboxProfile,
    "readDeny" | "writeAllow" | "network" | "workspace"
  > &
    Partial<Pick<SandboxProfile, "writeProtect">>;
  /** Who can change the manifest: `managed` names the administrator. */
  readonly mode: "managed" | "personal";
  /** The command, to name the network denial when its output says nothing. */
  readonly command?: string;
  /** The directory the command ran in; a relative path is resolved against it. */
  readonly cwd?: string;
}

/** The one next action: who changes which manifest key. */
export function manifestChange(
  mode: SandboxHintContext["mode"],
  key: string,
): string {
  return mode === "managed"
    ? `Ask your administrator to change ${key}.`
    : `Change ${key} in your piship.yaml.`;
}

/** The shell cannot get past the sandbox, so a retry only repeats the failure. */
export const SANDBOX_NO_RETRY =
  "Do not retry it or work around the sandbox; tell the user what failed.";

function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function pathsOf(line: string): string[] {
  return [...line.matchAll(PATH)].map((match) => match[1] ?? match[2] ?? "");
}

/**
 * Collects the first sandbox-looking failure of one command's output. Only a
 * line that matches an error pattern is kept, so a long output costs nothing.
 */
export class SandboxFailureScanner {
  #pending = "";
  #filesystem: string[] = [];
  #named: string[] = [];
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
    const paths = pathsOf(line);
    const last = paths.at(-1);
    if (last && !this.#filesystem.includes(last)) this.#filesystem.push(last);
    for (const path of paths.slice(0, 4))
      if (!this.#named.includes(path)) this.#named.push(path);
  }

  /**
   * The one-line hint for a command that failed, or undefined when nothing in
   * its output was a sandbox denial. A path the sandbox would have allowed
   * (an ordinary permission error inside the workspace) gets no hint.
   */
  hint(): string | undefined {
    this.feed("\n");
    const { profile, mode, cwd = profile.workspace } = this.context;
    const real = (named: string) => realpathNearest(resolve(cwd, named));
    const { files = [], directories = [] } = profile.writeProtect ?? {};
    for (const named of this.#named) {
      const path = real(named);
      if (profile.readDeny.some((denied) => isWithin(denied, path)))
        return `[PiShip sandbox: ${named} is hidden from shell commands. ${manifestChange(mode, "sandbox.filesystem.read.deny")} ${SANDBOX_NO_RETRY}]`;
      if (
        files.includes(path) ||
        directories.some((protectedDirectory) =>
          isWithin(protectedDirectory, path),
        )
      )
        return `[PiShip sandbox: ${named} is a protected git control path (the git config, hooks, .git/modules, .git/worktrees), which git reads when it runs outside the sandbox. The user can run this command in their own terminal, outside the sandbox; do not retry it here.]`;
    }
    for (const named of this.#filesystem) {
      const path = real(named);
      // A file the launching user cannot read is an ordinary permission
      // error on a read, not a sandbox decision.
      if (existsSync(path) && !readable(path)) continue;
      if (!profile.writeAllow.some((allowed) => isWithin(allowed, path)))
        return `[PiShip sandbox: ${named} is outside the directories shell commands can write. ${manifestChange(mode, "sandbox.filesystem.write.allow")} ${SANDBOX_NO_RETRY}]`;
    }
    if (this.#networkSeen && profile.network === "deny")
      return `[PiShip sandbox: ${this.#network ? `${this.#network} cannot be reached` : "the host cannot be reached"} because shell commands have no network access. ${manifestChange(mode, "sandbox.network.mode")} ${SANDBOX_NO_RETRY}]`;
    if (
      profile.network === "deny" &&
      this.context.command !== undefined &&
      NETWORK_COMMAND.test(this.context.command)
    )
      return `[PiShip sandbox: shell commands have no network access, so a command that needs the network fails here even when it was approved. ${manifestChange(mode, "sandbox.network.mode")} ${SANDBOX_NO_RETRY}]`;
    return undefined;
  }
}
