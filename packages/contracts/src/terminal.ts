// Which symbols PiShip's own output may use. The legacy Windows console (cmd.exe
// or PowerShell in conhost) often has no font for check marks, and output piped
// through a legacy code page turns them into mojibake, so there the status marks
// fall back to ASCII.

type Env = Readonly<Record<string, string | undefined>>;

/**
 * Whether to print ASCII only. `PISHIP_ASCII=1` forces it and `PISHIP_ASCII=0`
 * turns it off (the same 1/0 convention as `PISHIP_PROGRESS`). Otherwise only
 * Windows is affected, and not when the terminal is known to handle Unicode:
 * Windows Terminal (`WT_SESSION`), an editor or modern terminal that names
 * itself (`TERM_PROGRAM`, such as vscode), a terminal that sets `TERM` (Git
 * Bash, mintty, ssh), or ConEmu.
 */
export function asciiOnly(
  env: Env = process.env,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (env.PISHIP_ASCII === "1") return true;
  if (env.PISHIP_ASCII === "0") return false;
  if (platform !== "win32") return false;
  return !(env.WT_SESSION || env.TERM_PROGRAM || env.TERM || env.ConEmuPID);
}

export interface StatusMarks {
  readonly ok: string;
  readonly warn: string;
  readonly fail: string;
  readonly info: string;
}

/** One column wide either way, so report columns stay aligned. */
export function statusMarks(
  env: Env = process.env,
  platform: NodeJS.Platform = process.platform,
): StatusMarks {
  return asciiOnly(env, platform)
    ? { ok: "+", warn: "!", fail: "x", info: "-" }
    : { ok: "✓", warn: "!", fail: "✗", info: "-" };
}
