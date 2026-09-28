// macOS adapter: Seatbelt through /usr/bin/sandbox-exec and a generated SBPL
// profile. SBPL evaluates the last matching rule, so the file-write allowlist
// follows the blanket write deny and read denies come after both; a deny
// nested inside a writable path therefore still wins. The profile starts
// from `(allow default)`, so launch paths that leave the sandbox through
// launchd are denied explicitly.
import { existsSync } from "node:fs";
import { PiShipError } from "@piship/contracts";
import {
  type AdapterAvailability,
  runCheck,
  type SandboxAdapter,
  type SandboxCommand,
  type WrappedCommand,
} from "./adapter.js";
import { isDirectory, pathExists, type SandboxProfile } from "./profile.js";

export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

/** Device nodes a normal shell needs to write even under a write allowlist. */
const DEVICE_WRITES = [
  '(literal "/dev/null")',
  '(literal "/dev/zero")',
  '(literal "/dev/tty")',
  '(literal "/dev/stdout")',
  '(literal "/dev/stderr")',
  '(literal "/dev/dtracehelper")',
  '(literal "/dev/ptmx")',
  '(regex #"^/dev/fd/[0-9]+$")',
  '(regex #"^/dev/ttys[0-9]+$")',
];

/**
 * Ways to start a process that launchd, not this sandbox, would parent:
 * LaunchServices (`open`, `open -a Terminal`), Apple events (`osascript`
 * telling another app to run a script), and launchd jobs (`launchctl`).
 * Only these named services are denied; generic mach-lookup stays allowed so
 * ordinary command-line tools keep working.
 */
const LAUNCH_ESCAPES = [
  "(deny lsopen)",
  "(deny appleevent-send)",
  `(deny mach-lookup
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name-regex #"^com\\.apple\\.lsd\\.")
  (global-name "com.apple.coreservices.appleevents")
  (global-name "com.apple.appleeventsd")
  (global-name "com.apple.ScriptingAdditions"))`,
  '(deny process-exec (literal "/bin/launchctl"))',
];

/** Quote a path as an SBPL string literal. Control characters are refused. */
export function sbplString(value: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (/[\u0000-\u001f\u007f]/.test(value))
    throw new PiShipError(
      "CONFIG_INVALID",
      "Sandbox paths must not contain control characters",
      { component: "sandbox" },
    );
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

interface ProfileOptions {
  readonly exists?: (path: string) => boolean;
  readonly isDir?: (path: string) => boolean;
}

function denyFilter(
  path: string,
  exists: (path: string) => boolean,
  isDir: (path: string) => boolean,
): string {
  // A missing path is denied as a subpath so it stays covered if created.
  const kind = exists(path) && !isDir(path) ? "literal" : "subpath";
  return `(${kind} ${sbplString(path)})`;
}

/** Generate the SBPL profile text for a resolved sandbox profile. */
export function seatbeltProfile(
  profile: SandboxProfile,
  options: ProfileOptions = {},
): string {
  const exists = options.exists ?? pathExists;
  const isDir = options.isDir ?? isDirectory;
  const lines = ["(version 1)", "(allow default)", "(deny file-write*)"];
  const writable = profile.writeAllow.map(
    (path) => `(subpath ${sbplString(path)})`,
  );
  lines.push(
    `(allow file-write*\n  ${[...writable, ...DEVICE_WRITES].join("\n  ")})`,
  );
  if (profile.readDeny.length)
    lines.push(
      `(deny file-read* file-write*\n  ${profile.readDeny
        .map((path) => denyFilter(path, exists, isDir))
        .join("\n  ")})`,
    );
  lines.push(...LAUNCH_ESCAPES);
  if (profile.network === "deny") lines.push("(deny network*)");
  return `${lines.join("\n")}\n`;
}

export class SeatbeltAdapter implements SandboxAdapter {
  readonly id = "macos-seatbelt" as const;
  #availability: Promise<AdapterAvailability> | undefined;

  available(): Promise<AdapterAvailability> {
    this.#availability ??= this.#detect();
    return this.#availability;
  }

  async #detect(): Promise<AdapterAvailability> {
    if (!existsSync(SANDBOX_EXEC))
      return {
        available: false,
        reason: `${SANDBOX_EXEC} is not present on this macOS installation`,
      };
    const check = await runCheck(SANDBOX_EXEC, [
      "-p",
      "(version 1)\n(allow default)\n(deny network*)\n",
      "/bin/sh",
      "-c",
      "exit 0",
    ]);
    return check.ok
      ? { available: true }
      : {
          available: false,
          reason: `sandbox-exec cannot apply a profile: ${check.detail}`,
        };
  }

  wrap(profile: SandboxProfile, command: SandboxCommand): WrappedCommand {
    return {
      file: SANDBOX_EXEC,
      args: [
        "-p",
        seatbeltProfile(profile),
        "--",
        command.file,
        ...command.args,
      ],
      cwd: command.cwd,
      env: command.env,
    };
  }
}
