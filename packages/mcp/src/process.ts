// Default process runtime: stdio servers run through @piship/sandbox.

import {
  filterEnvironment,
  sanitizeStderr,
  spawnManaged,
} from "@piship/sandbox";
import type { ChildHandle, ProcessRuntime, SpawnRequest } from "./types.js";

export function defaultProcessRuntime(): ProcessRuntime {
  return {
    spawn: (request: SpawnRequest): ChildHandle =>
      spawnManaged({
        file: request.file,
        args: request.args,
        cwd: request.cwd,
        env: request.env,
        graceMs: request.graceMs,
        stdin: request.stdin,
        ...(request.sandbox ? { sandbox: request.sandbox } : {}),
        ...(request.timeoutMs === undefined
          ? {}
          : { timeoutMs: request.timeoutMs }),
        ...(request.signal ? { signal: request.signal } : {}),
        ...(request.onStdout ? { onStdout: request.onStdout } : {}),
        ...(request.onStderr ? { onStderr: request.onStderr } : {}),
      }),
    filterEnvironment: (env, allow, set) => filterEnvironment(env, allow, set),
    sanitizeStderr: (text, maxBytes) => sanitizeStderr(text, maxBytes),
  };
}
