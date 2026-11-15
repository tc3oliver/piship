import { basename, resolve } from "node:path";

/**
 * How to run this PiShip again, for the "Next:" and "Run ..." lines it
 * prints. PiShip is not published to npm and is usually run by path, so
 * `piship ...` is not a command on the machine; when the running script is
 * the CLI (`bin.js`) or a payload's `piship.mjs`, the line names that path.
 * Anywhere else (a test, an embedding) it falls back to `piship`.
 */
export function pishipCommand(script: string | undefined = process.argv[1]) {
  if (script === undefined) return "piship";
  const name = basename(script);
  if (name !== "bin.js" && name !== "piship.mjs") return "piship";
  const path = resolve(script);
  return `node ${shellArg(path)}`;
}

/**
 * One argument of a command PiShip prints for the user to paste, quoted only
 * when it has to be. On Windows it is double-quoted, which both cmd.exe and
 * PowerShell read as one argument; single quotes mean nothing to cmd.exe.
 * shortcut: a Windows value with `%`, `$` or a backtick may still expand in
 * cmd.exe or PowerShell (no quoting stops both); such paths are rare.
 */
export function shellArg(
  value: string,
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform === "win32")
    return /^[\w+=:./\\~-]+$/.test(value)
      ? value
      : `"${value.replaceAll('"', '""')}"`;
  return /^[\w@%+=:,./-]+$/.test(value)
    ? value
    : `'${value.replaceAll("'", "'\\''")}'`;
}
