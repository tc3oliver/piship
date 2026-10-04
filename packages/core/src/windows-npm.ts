// npm is a .cmd shim on Windows and only runs through cmd.exe. Arguments can
// carry manifest values (a registry URL, a version range), so each one is
// quoted, and one that cmd.exe would still interpret inside quotes is refused.
import { PiShipError } from "@piship/contracts";

// Inside double quotes cmd.exe still ends the quote at `"`, expands `%VAR%`
// (and `!VAR!` under delayed expansion), and ends the line at a line break.
// `&`, `|`, `<`, `>` and `^` are literal there, so a range such as ^1.2 is safe.
const CMD_INTERPRETED = /["%!\r\n\0]/;

/** The `cmd.exe /d /s /c` argument for npm; spawn it with `windowsVerbatimArguments`. */
export function windowsNpmCommandLine(args: readonly string[]): string {
  for (const arg of args)
    if (CMD_INTERPRETED.test(arg))
      throw new PiShipError(
        "POLICY_DENIED",
        `npm argument ${JSON.stringify(arg)} contains a character cmd.exe interprets inside quotes`,
        {
          component: "packages",
          userAction:
            'Remove ", %, ! and line breaks from the registry URL or version in the manifest',
        },
      );
  // node reads `\"` as a literal quote, so trailing backslashes are doubled
  // to keep the closing quote; cmd.exe treats backslashes literally.
  return `"npm ${args.map((arg) => `"${arg.replace(/(\\+)$/, "$1$1")}"`).join(" ")}"`;
}
