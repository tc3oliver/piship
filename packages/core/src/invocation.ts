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
  return `node ${/[\s"'$&|;<>()*?]/.test(path) ? `"${path}"` : path}`;
}
