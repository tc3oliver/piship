// npm is a .cmd shim on Windows. Going through cmd.exe would let a manifest
// value (a registry URL, a version range) be read as shell syntax, so PiShip
// runs the shim's own target instead: node with npm's CLI script and the
// arguments as an array, with no shell in between.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { PiShipError } from "@piship/contracts";

export interface NpmInvocation {
  readonly file: string;
  readonly args: readonly string[];
}

const npmCli = (directory: string) =>
  join(directory, "node_modules", "npm", "bin", "npm-cli.js");

/**
 * The npm that `npm` on PATH would run, as node + npm-cli.js. The shim and
 * npm itself sit side by side in Node's directory and in a global prefix
 * (`<dir>\npm.cmd`, `<dir>\node_modules\npm\bin\npm-cli.js`). Like npm.cmd,
 * it prefers the npm installed in npm's global prefix, which is where
 * `npm install -g npm` puts an upgrade.
 */
export function windowsNpmInvocation(
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  cwd?: string,
): NpmInvocation {
  const pathKey = Object.keys(env).find((key) => /^path$/i.test(key));
  const directories = (pathKey ? (env[pathKey] ?? "") : "")
    .split(delimiter)
    .map((entry) => entry.replace(/^"(.*)"$/, "$1"))
    // A relative entry would resolve against PiShip's working directory.
    .filter((entry) => entry.length > 0 && isAbsolute(entry));
  for (const directory of directories) {
    if (!existsSync(join(directory, "npm.cmd"))) continue;
    const cli = npmCli(directory);
    if (!existsSync(cli)) continue;
    // The shim prefers the node.exe beside it, as npm.cmd itself does.
    const besideNode = join(directory, "node.exe");
    const node = existsSync(besideNode) ? besideNode : process.execPath;
    return {
      file: node,
      args: [prefixCli(node, directory, env, cwd) ?? cli, ...args],
    };
  }
  throw new PiShipError("UPDATE_FAILED", "npm was not found on PATH", {
    component: "packages",
    userAction: "Install Node.js with npm and make sure npm is on PATH",
  });
}

/** npm.cmd's redirect: npm-prefix.js prints the global prefix to prefer. */
function prefixCli(
  node: string,
  directory: string,
  env: NodeJS.ProcessEnv,
  cwd: string | undefined,
): string | undefined {
  const prefixJs = join(
    directory,
    "node_modules",
    "npm",
    "bin",
    "npm-prefix.js",
  );
  if (!existsSync(prefixJs)) return undefined;
  const result = spawnSync(node, [prefixJs], {
    env,
    encoding: "utf8",
    timeout: 30_000,
    ...(cwd ? { cwd } : {}),
  });
  const prefix =
    result.status === 0 ? (result.stdout.trim().split(/\r?\n/)[0] ?? "") : "";
  if (!prefix || !isAbsolute(prefix)) return undefined;
  const redirected = npmCli(prefix);
  return existsSync(redirected) ? redirected : undefined;
}
