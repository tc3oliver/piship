// A process ID alone names a process only while it runs: after it exits the
// system can hand the same ID to an unrelated process. The start identity
// tells the two apart, so an owner record naming both is not mistaken for
// live after a crash and a reuse of the ID.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

/**
 * The start identity of the process with this ID: the boot ID and start time
 * on Linux, the start time elsewhere. Undefined when the process does not
 * exist or the platform cannot tell; a caller then needs another rule, such
 * as the age of its record.
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
    const value = execFileSync("ps", ["-p", String(pid), "-o", "lstart="], {
      encoding: "utf8",
      timeout: 5000,
    }).trim();
    return value || undefined;
  } catch {
    return undefined;
  }
}
