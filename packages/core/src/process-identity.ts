// A process ID alone names a process only while it runs: after it exits the
// system can hand the same ID to an unrelated process. The start identity
// tells the two apart, so an owner record naming both is not mistaken for
// live after a crash and a reuse of the ID.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

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
  // PowerShell start, and a launch asks for it from more than one place.
  if (pid !== process.pid) return lookup(pid);
  ownIdentity ??= lookup(pid);
  return ownIdentity;
}

let ownIdentity: string | undefined;

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
