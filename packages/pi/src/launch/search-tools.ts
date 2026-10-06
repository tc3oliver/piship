// Bundled `fd` and `rg` at launch. Pi's tools manager looks for each tool in
// its own bin directory, `<agent dir>/bin`, before it tries PATH, and only
// downloads one when neither has it (never when offline). PiShip points the
// agent directory at the distribution's state before Pi is imported
// (`preparePiEnvironment`), then copies the payload's verified executables
// there, so Pi runs the pinned ones whatever the user's PATH holds and never
// needs the network for them.
//
// Reading and hashing two executables of several megabytes at every start is
// work a scanner repeats on Windows, so the check at start is a receipt: when
// an executable is put in place, or found there with the pinned digest, its
// file system fingerprint is recorded beside it, and a start that finds the
// same fingerprint (size, times, file index) has nothing to read. Any change
// to the file, including one that restores its modification time, alters its
// change time and brings the full digest check back.
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readdirSync,
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

const RECEIPT_FILE = ".piship-search-tools.json";
const RECEIPT_SCHEMA = "piship-search-tools-receipt/v1";

/** What the file system says about an executable; any edit changes it. */
interface Fingerprint {
  readonly digest: string;
  readonly size: string;
  readonly mtimeNs: string;
  readonly ctimeNs: string;
  readonly ino: string;
}

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

/** The fingerprint of a regular, runnable file, or undefined. */
function fingerprint(path: string, digest: string): Fingerprint | undefined {
  const stat = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  if (!stat?.isFile()) return undefined;
  if (process.platform !== "win32" && (Number(stat.mode) & 0o111) === 0)
    return undefined;
  return {
    digest,
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs),
    ctimeNs: String(stat.ctimeNs),
    ino: String(stat.ino),
  };
}

function readReceipt(directory: string): Record<string, Fingerprint> {
  try {
    const value = JSON.parse(
      readFileSync(join(directory, RECEIPT_FILE), "utf8"),
    ) as { schema?: unknown; files?: Record<string, Fingerprint> };
    return value.schema === RECEIPT_SCHEMA && value.files ? value.files : {};
  } catch {
    return {};
  }
}

function sameFingerprint(a: Fingerprint, b: Fingerprint): boolean {
  return (
    a.digest === b.digest &&
    a.size === b.size &&
    a.mtimeNs === b.mtimeNs &&
    a.ctimeNs === b.ctimeNs &&
    a.ino === b.ino
  );
}

/** Best effort: a receipt that is not written only costs the next start a hash. */
function writeReceipt(
  directory: string,
  files: Record<string, Fingerprint>,
): void {
  try {
    writeFileSync(
      join(directory, RECEIPT_FILE),
      `${JSON.stringify({ schema: RECEIPT_SCHEMA, files })}\n`,
      { mode: 0o600 },
    );
  } catch {
    // Read-only or busy.
  }
}

/** The suffix of an executable moved aside while it was running. */
const REPLACED = ".piship-replaced-";

/**
 * Best effort: remove executables earlier launches moved aside. One that is
 * still running stays until a later launch.
 */
function removeReplaced(directory: string): void {
  let names: string[];
  try {
    names = readdirSync(directory);
  } catch {
    return;
  }
  for (const name of names)
    if (name.includes(REPLACED))
      try {
        rmSync(join(directory, name), { force: true, maxRetries: 0 });
      } catch {
        // Still running; a later launch tries again.
      }
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
      const aside = `${path}${REPLACED}${process.pid}`;
      renameSync(path, aside);
      renameSync(temporary, path);
      // The old executable is still running, so Windows may refuse to delete
      // it too; a later launch removes it (`removeReplaced`).
      try {
        rmSync(aside, { force: true, maxRetries: 0 });
      } catch {
        // Left for a later launch.
      }
    }
  } finally {
    rmSync(temporary, { force: true });
  }
}

/**
 * Put the payload's bundled search tools where Pi looks first. Each
 * executable is read from the payload and checked against the lock before
 * it is copied; an identical copy already in place is kept. A copy whose
 * fingerprint matches the receipt written when it was last verified is kept
 * without being read. Returns nothing when the distribution bundles no
 * search tools.
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
  removeReplaced(directory);
  const receipt = readReceipt(directory);
  let receiptChanged = false;
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
    const recorded = receipt[name];
    const current = recorded && fingerprint(path, entry.binary);
    if (recorded && current && sameFingerprint(recorded, current)) {
      installed.push({ tool, version: locked.version, path });
      continue;
    }
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
    const verified = fingerprint(path, entry.binary);
    if (verified) {
      receipt[name] = verified;
      receiptChanged = true;
    }
    installed.push({ tool, version: locked.version, path });
  }
  if (receiptChanged) writeReceipt(directory, receipt);
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
