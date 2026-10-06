// A process ID alone names a process only while it runs: after it exits the
// system can hand the same ID to an unrelated process. The start identity
// tells the two apart, so an owner record naming both is not mistaken for
// live after a crash and a reuse of the ID.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  processAlive,
  processHostToken,
  startupCount,
} from "@piship/contracts";

/**
 * The start identity of the process with this ID: the boot ID and start time
 * on Linux, the UTC start time in ticks on Windows, and the UTC start time in
 * seconds elsewhere. Undefined when the process does not exist or the
 * platform cannot tell; a caller then needs another rule, such as the age of
 * its record.
 */
export function processIdentity(pid: number): string | undefined {
  if (!Number.isSafeInteger(pid) || pid < 1) return undefined;
  // This process's own start time never changes; on Windows each lookup is a
  // PowerShell start, and a launch asks for it from more than one place. A
  // lookup that failed (PowerShell blocked by policy) is remembered too, or
  // every caller would wait out its timeout again.
  if (pid !== process.pid) return lookup(pid);
  if (!ownRead) {
    ownIdentity = lookup(pid);
    ownRead = true;
  }
  return ownIdentity;
}

let ownIdentity: string | undefined;
let ownRead = false;

/**
 * The start identity this process writes into a lease, lock, or owner
 * record. Linux reads it from /proc at no cost. Elsewhere reading it starts a
 * process (PowerShell on Windows, half a second to several; `ps` on macOS),
 * so the record carries `null` and `recordedStart` instead: the process that
 * must tell a crashed owner from a live one pays for the lookup then
 * (`recordedProcessGone`), and a launch nobody contends with pays nothing.
 */
export function recordedIdentity(): string | null {
  return process.platform === "linux"
    ? (processIdentity(process.pid) ?? null)
    : null;
}

/** This process's start time in ms since the epoch, as a record carries it. */
export function recordedStart(): number {
  return Math.round(performance.timeOrigin);
}

// `ps -o lstart=` in the C locale: "Thu Oct  1 08:05:10 2026".
const LSTART = /^\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/;
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/**
 * Whether the process with this ID is the one a record names by its start
 * identity: undefined when that cannot be told, and the caller needs another
 * rule, such as the age of the record. A record written before the start time
 * was read in UTC holds the `ps` text in the writer's time zone and locale; it
 * cannot be compared, so it is unknown rather than a mismatch, and a running
 * owner is never judged gone by the format of its record.
 */
export function processIdentityMatches(
  recorded: string | null,
  pid: number,
): boolean | undefined {
  if (!recorded) return undefined;
  const current = processIdentity(pid);
  if (!current) return undefined;
  if (recorded === current) return true;
  if (
    process.platform !== "linux" &&
    process.platform !== "win32" &&
    !/^\d+$/.test(recorded)
  )
    return undefined;
  return false;
}

/**
 * How far a recorded start time (the writer's `performance.timeOrigin`) may
 * lie from the start time the system reports for the same process: `ps`
 * reports whole seconds, and Node takes its time origin after the process
 * (or the shell a command shim replaces with `exec`) began. On Windows the
 * system stamps a process when it is created, and a first launch can spend
 * seconds loading and scanning `node.exe` before Node starts, so a live
 * owner must never be judged gone for that gap; a process that merely has
 * the same ID started minutes or hours from the owner, not within half a
 * minute of it.
 */
export const START_TOLERANCE_MS = 30_000;

/** A record that names the process holding something. */
export interface ProcessRecord {
  readonly pid: number;
  /** Its start identity (`processIdentity`); null when not recorded. */
  readonly identity: string | null;
  /** Its host (`processHostToken`); null in a record written before hosts were. */
  readonly host: string | null;
  /** Its start time in ms since the epoch (`performance.timeOrigin`); null when not recorded. */
  readonly started: number | null;
}

/**
 * Whether the process a record names is gone: true when that is proven (no
 * process has its ID on this host, or the process that has it now started at
 * another time), false when it is the same running process, and undefined
 * when that cannot be told. A record from another host is always undefined:
 * its process ID means nothing here, so the absence of a local process with
 * that ID proves nothing. So is a record with no start identity or time to
 * compare (a record of an earlier PiShip) whose ID a process has. The caller
 * then needs another rule, such as the age of the record. A record without a
 * host is judged as this host's, as it was before hosts were recorded.
 */
export function recordedProcessGone(
  record: ProcessRecord,
): boolean | undefined {
  if (record.host !== null && record.host !== processHostToken())
    return undefined;
  if (!processAlive(record.pid)) return true;
  const same = processIdentityMatches(record.identity, record.pid);
  if (same !== undefined) return !same;
  if (record.started === null) return undefined;
  const current = processIdentity(record.pid);
  const start = current === undefined ? undefined : startMs(current);
  if (start === undefined) return undefined;
  return Math.abs(start - record.started) > START_TOLERANCE_MS;
}

/**
 * The start time in ms since the epoch of a start identity read on this
 * platform; undefined on Linux, whose identity counts clock ticks from boot
 * (a Linux writer records the identity itself, which is cheap there).
 */
function startMs(identity: string): number | undefined {
  if (!/^\d+$/.test(identity) || process.platform === "linux") return undefined;
  // .NET ticks: 100 ns units since 0001-01-01.
  if (process.platform === "win32")
    return Number(BigInt(identity) / 10_000n) - 62_135_596_800_000;
  return Number(identity) * 1000;
}

function lookup(pid: number): string | undefined {
  try {
    if (process.platform === "linux") {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      const boot = readFileSync(
        "/proc/sys/kernel/random/boot_id",
        "utf8",
      ).trim();
      return fields[19] ? `${boot}:${fields[19]}` : undefined;
    }
    startupCount("identity_spawns");
    if (process.platform === "win32") {
      const value = execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks`,
        ],
        { encoding: "utf8", timeout: 5000, windowsHide: true },
      ).trim();
      return /^\d+$/.test(value) ? value : undefined;
    }
    // `ps` prints the start time in the caller's time zone and locale; a
    // fixed environment makes one process read the same for every caller.
    const value = execFileSync("ps", ["-p", String(pid), "-o", "lstart="], {
      encoding: "utf8",
      timeout: 5000,
      env: { ...process.env, TZ: "UTC0", LC_ALL: "C" },
    }).trim();
    const match = LSTART.exec(value);
    const month = match ? MONTHS.indexOf(match[1] as string) : -1;
    if (!match || month < 0) return undefined;
    const [, , day, hour, minute, second, year] = match.map(Number);
    const ms = Date.UTC(year as number, month, day, hour, minute, second);
    return Number.isFinite(ms) ? String(ms / 1000) : undefined;
  } catch {
    return undefined;
  }
}
