// Bundled `fd` and `rg` at launch. Pi's tools manager looks for each tool in
// its own bin directory, `<agent dir>/bin`, before it tries PATH, and only
// downloads one when neither has it (never when offline). PiShip points the
// agent directory at the distribution's state before Pi is imported
// (`preparePiEnvironment`), then copies the payload's verified executables
// there, so Pi runs the pinned ones whatever the user's PATH holds and never
// needs the network for them.
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  type DistributionLock,
  SEARCH_TOOL_PAYLOAD_DIRECTORY,
  searchToolFileName,
} from "@piship/core";
import { SEARCH_TOOLS, type SearchTool } from "@piship/schema";

const sha256 = (content: Buffer) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

export interface InstalledSearchTool {
  readonly tool: SearchTool;
  readonly version: string;
  /** Where Pi finds it: `<agent dir>/bin/<fd|rg>[.exe]`. */
  readonly path: string;
}

/** Pi's own tool directory for an agent directory. */
export function piToolDirectory(agentDir: string): string {
  return join(agentDir, "bin");
}

function matches(path: string, digest: string): boolean {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (!stat?.isFile()) return false;
  if (process.platform !== "win32" && (stat.mode & 0o111) === 0) return false;
  return sha256(readFileSync(path)) === digest;
}

/** Replace `path` with `content`, also over a running Windows executable. */
function replace(path: string, content: Buffer): void {
  const temporary = `${path}.piship-${process.pid}.tmp`;
  try {
    writeFileSync(temporary, content, { mode: 0o755 });
    if (process.platform !== "win32") chmodSync(temporary, 0o755);
    const existing = lstatSync(path, { throwIfNoEntry: false });
    if (existing && !existing.isFile())
      rmSync(path, { recursive: true, force: true });
    try {
      renameSync(temporary, path);
    } catch (error) {
      // Windows refuses to overwrite an executable another session runs, but
      // lets it be moved aside.
      const code = (error as NodeJS.ErrnoException).code;
      if (!existing || !["EPERM", "EBUSY", "EACCES"].includes(code ?? ""))
        throw error;
      const aside = `${path}.piship-replaced-${process.pid}`;
      renameSync(path, aside);
      renameSync(temporary, path);
      rmSync(aside, { force: true, maxRetries: 0 });
    }
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * Put the payload's bundled search tools where Pi looks first. Each
 * executable is read from the payload and checked against the lock before
 * it is copied; an identical copy already in place is kept. Returns nothing
 * when the distribution bundles no search tools.
 */
export function installSearchTools(
  lock: Pick<DistributionLock, "searchTools">,
  distributionDir: string,
  agentDir: string,
  target = `${process.platform}-${process.arch}`,
): InstalledSearchTool[] {
  const installed: InstalledSearchTool[] = [];
  if (!lock.searchTools) return installed;
  const directory = piToolDirectory(agentDir);
  for (const tool of SEARCH_TOOLS) {
    const locked = lock.searchTools[tool];
    if (!locked) continue;
    const entry = locked.targets[target];
    const name = searchToolFileName(tool, target);
    if (!entry)
      throw new PiShipError(
        "LOCK_INVALID",
        `This payload's lock has no bundled ${tool} for ${target}`,
        { component: "payload" },
      );
    const path = join(directory, name);
    if (!matches(path, entry.binary)) {
      const content = readFileSync(
        join(distributionDir, SEARCH_TOOL_PAYLOAD_DIRECTORY, name),
      );
      if (sha256(content) !== entry.binary)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `The bundled ${tool} in ${distributionDir} does not match piship.lock`,
          {
            component: "payload",
            userAction: "Do not run it; reinstall the distribution",
          },
        );
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      replace(path, content);
    }
    installed.push({ tool, version: locked.version, path });
  }
  return installed;
}

/**
 * Doctor's view: each bundled tool and whether Pi's tool directory holds the
 * pinned executable.
 */
export function searchToolStatus(
  lock: Pick<DistributionLock, "searchTools">,
  agentDir: string,
  target = `${process.platform}-${process.arch}`,
): { tool: SearchTool; version: string; path: string; pinned: boolean }[] {
  return SEARCH_TOOLS.flatMap((tool) => {
    const locked = lock.searchTools?.[tool];
    if (!locked) return [];
    const path = join(
      piToolDirectory(agentDir),
      searchToolFileName(tool, target),
    );
    const entry = locked.targets[target];
    return [
      {
        tool,
        version: locked.version,
        path,
        pinned: !!entry && matches(path, entry.binary),
      },
    ];
  });
}
