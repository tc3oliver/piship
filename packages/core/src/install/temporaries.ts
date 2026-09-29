// Recovery of atomic-write temporaries a hard termination (SIGKILL, power
// loss) leaves beside a state file. A temporary is never adopted as state:
// the committed file stays authoritative, and an abandoned temporary is only
// deleted. A temporary a live writer is still filling is kept.
import { existsSync, lstatSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { withFileLock } from "@piship/credentials";
import { accessStatePaths } from "../access/state.js";
import { STATE_MARKER_FILE } from "../migration.js";

/**
 * A temporary older than this is abandoned whatever its name says: an atomic
 * write takes milliseconds, and the age also covers a writer whose process ID
 * was reused by an unrelated process.
 */
export const STALE_TEMPORARY_MS = 10 * 60_000;

/** Whether a process with this ID exists (EPERM: it exists, not ours). */
export function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Whether work of `owner` (a process ID, or null when unknown), last changed
 * at `mtimeMs`, is abandoned: older than `staleMs`, or written by another
 * process that no longer exists.
 */
export function abandoned(
  owner: number | null,
  mtimeMs: number,
  now = Date.now(),
  staleMs = STALE_TEMPORARY_MS,
): boolean {
  if (now - mtimeMs > staleMs) return true;
  return owner !== null && owner !== process.pid && !processAlive(owner);
}

// `<file>.p<pid>-<hex>.tmp` (this module's writers), `<file>.<hex>.tmp` (no
// owner recorded), and `<file>.<pid>.tmp` (local metrics).
const OWNED = /^p(\d+)-[0-9a-f]{12}$/;
const UNOWNED = /^[0-9a-f]{12}$/;
const PID = /^(\d+)$/;

/**
 * The writer of `name` if it is an atomic-write temporary of `base` (a
 * process ID, or null when the name records none); undefined when it is not.
 */
function temporaryOwner(name: string, base: string): number | null | undefined {
  if (!name.startsWith(`${base}.`) || !name.endsWith(".tmp")) return undefined;
  const middle = name.slice(base.length + 1, -".tmp".length);
  const owned = OWNED.exec(middle) ?? PID.exec(middle);
  if (owned) return Number(owned[1]);
  return UNOWNED.test(middle) ? null : undefined;
}

/** For directories where every file is state (the file secret store). */
const ANY_FILE = /^(.+)\.(?:p\d+-[0-9a-f]{12}|[0-9a-f]{12})\.tmp$/;

export interface TemporaryRule {
  /**
   * Remove every temporary, live or not: only for a caller that holds the
   * lock every writer of these files holds.
   */
  readonly force?: boolean;
  readonly now?: number;
}

/**
 * Remove the abandoned atomic-write temporaries of `bases` (file names) in
 * `directory`, or of any file there with `"any"`. Only regular files whose
 * names have a temporary's exact shape are considered; anything else,
 * including a file that merely shares a prefix, is left alone. Returns the
 * removed paths.
 */
export function removeStaleTemporaries(
  directory: string,
  bases: readonly string[] | "any",
  rule: TemporaryRule = {},
): string[] {
  let names: string[];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  const now = rule.now ?? Date.now();
  const removed: string[] = [];
  for (const name of names) {
    let owner: number | null | undefined;
    if (bases === "any") {
      const match = ANY_FILE.exec(name);
      owner = match ? temporaryOwner(name, match[1] as string) : undefined;
    } else
      for (const base of bases) {
        owner = temporaryOwner(name, base);
        if (owner !== undefined) break;
      }
    if (owner === undefined) continue;
    const path = join(directory, name);
    try {
      const stat = lstatSync(path);
      if (!stat.isFile()) continue;
      if (!rule.force && !abandoned(owner, stat.mtimeMs, now)) continue;
      rmSync(path, { force: true });
      removed.push(path);
    } catch {
      // Gone already, or not removable now; the next sweep retries.
    }
  }
  return removed;
}

type StateTemporaries = readonly (readonly [
  directory: string,
  bases: readonly string[] | "any",
])[];

function grouped(paths: readonly string[]): StateTemporaries {
  const byDirectory = new Map<string, string[]>();
  for (const path of paths)
    byDirectory.set(dirname(path), [
      ...(byDirectory.get(dirname(path)) ?? []),
      basename(path),
    ]);
  return [...byDirectory];
}

/** Every state file of a distribution that is replaced by an atomic write. */
function stateTemporaries(stateDir: string): StateTemporaries {
  const paths = accessStatePaths(stateDir);
  return [
    ...grouped([
      join(stateDir, STATE_MARKER_FILE),
      paths.identity,
      paths.principal,
      paths.credential,
      paths.revocationRetry,
      paths.preferences,
      join(stateDir, "config", "policy.json"),
      join(stateDir, "logs", "metrics.json"),
      join(stateDir, "logs", "audit.jsonl.generation"),
    ]),
    [paths.secrets, "any"],
  ];
}

/**
 * Remove abandoned atomic-write temporaries anywhere in a distribution's
 * state: the state marker, identity and principal records, credential
 * metadata and its revocation record (including discarded markers, which
 * replace the same files), preferences, user policy, local metrics and audit
 * bookkeeping, and the file secret store. Runs when a distribution starts;
 * best effort, never throws.
 */
export function sweepStateTemporaries(stateDir: string): string[] {
  const removed: string[] = [];
  for (const [directory, bases] of stateTemporaries(stateDir))
    removed.push(...removeStaleTemporaries(directory, bases));
  return removed;
}

/**
 * Remove the temporaries of identity and credential state at logout, so no
 * signed-out identity metadata, credential metadata, or file-store secret
 * outlives it. Runs under the credential lock and then the identity lock,
 * the order a sign-in takes them: every writer of the session, the
 * credential metadata, and their secrets holds one of them, so every such
 * temporary found is abandoned and removed. The principal binding and the
 * pending-revocation record, which logout keeps, lose only their abandoned
 * temporaries.
 */
export async function removeAccessTemporaries(
  stateDir: string,
): Promise<string[]> {
  const paths = accessStatePaths(stateDir);
  const removed: string[] = [];
  const sweep = async () => {
    removed.push(
      ...removeStaleTemporaries(
        dirname(paths.identity),
        [basename(paths.identity)],
        { force: true },
      ),
      ...removeStaleTemporaries(
        dirname(paths.credential),
        [basename(paths.credential)],
        { force: true },
      ),
      ...removeStaleTemporaries(paths.secrets, "any", { force: true }),
      ...removeStaleTemporaries(dirname(paths.principal), [
        basename(paths.principal),
      ]),
      ...removeStaleTemporaries(dirname(paths.revocationRetry), [
        basename(paths.revocationRetry),
      ]),
    );
  };
  // A lock needs its directory; where it is missing, nothing was written.
  const locked = (path: string, task: () => Promise<void>) =>
    existsSync(dirname(path)) ? withFileLock(path, task) : task();
  await locked(paths.credential, () => locked(paths.identity, sweep));
  return removed;
}
