// `@piship/pi/environment`: what must be set before Pi is imported. This
// module imports no Pi package, so the launcher can load it first.
//
// Pi's tools manager fixes the directory it looks in for `fd` and `rg`
// (`<agent dir>/bin`, checked before PATH) when it is imported, from
// `PI_CODING_AGENT_DIR` as it is at that moment. `@piship/pi` imports Pi
// statically, so setting the variable in `launchPiDistribution` is too late:
// Pi would keep using `~/.pi/agent/bin`, the user's own directory. The
// launcher therefore calls `preparePiEnvironment` before it imports
// `@piship/pi`.
import { join } from "node:path";
import { runtimeStateDirectory } from "@piship/core";

/** Pi's agent directory for a distribution: `<state>/agent`. */
export function piAgentDirectory(appId: string): string {
  return join(runtimeStateDirectory({ value: appId }), "agent");
}

/** Point Pi's agent directory at the distribution's state before Pi loads. */
export function preparePiEnvironment(
  appId: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const agentDir = piAgentDirectory(appId);
  env.PI_CODING_AGENT_DIR = agentDir;
  return agentDir;
}
