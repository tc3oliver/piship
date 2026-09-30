// Example sandbox adapter (`sandbox.provider: custom`): runs each command in
// a company's remote execution service. The backend owns isolation only;
// PiShip keeps policy, approvals, audit, the approved environment, and the
// timeout and cancellation of every command. An adapter is one file that
// imports nothing but @piship/adapter-sdk and Node built-ins.
import {
  defineSandboxAdapter,
  HOST_FILESYSTEM_ISOLATION,
} from "@piship/adapter-sdk";

// The service is `sandbox.endpoint`; `sandbox.credential: runtime` passes the
// runtime credential when the endpoint is on the inference gateway's origin.
export default defineSandboxAdapter((context) => {
  const endpoint = context.endpoint;
  async function call(method, path, body, signal) {
    const token = await context.credential?.();
    let response;
    try {
      response = await context.fetch(new URL(path, `${endpoint}/`), {
        method,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        ...(signal ? { signal } : {}),
      });
    } catch {
      // PiShip's cancellation passes through as it came. Never build a
      // message from a transport error: it can quote the Authorization
      // header, which holds the credential.
      if (signal?.aborted) throw signal.reason;
      throw new Error("the execution service is unreachable");
    }
    if (!response.ok)
      throw new Error(`the execution service answered HTTP ${response.status}`);
    return response.status === 204 ? undefined : response.json();
  }

  return {
    id: "example-remote",
    async available() {
      if (!endpoint)
        return { available: false, reason: "sandbox.endpoint is not set" };
      try {
        await call("GET", "health");
        return { available: true };
      } catch {
        // A fixed reason: an error's message can quote the credential.
        return {
          available: false,
          reason: "the execution service is unreachable or refused the check",
        };
      }
    },
    // Claim only what the service enforces. A remote service that keeps the
    // host's files out of reach claims host-filesystem-isolation, never the
    // filesystem-* planes, which mean PiShip's path rules are applied.
    capabilities() {
      return {
        isolation: "remote",
        planes: [
          HOST_FILESYSTEM_ISOLATION,
          "network-deny",
          "environment-filter",
        ],
        network: ["deny"],
        localProcesses: false,
      };
    },
    async prepare(request) {
      const session = await call(
        "POST",
        "sessions",
        { network: request.profile.network },
        request.signal,
      );
      const path = `sessions/${encodeURIComponent(session.id)}`;
      return {
        async exec(command, io) {
          if (command.workspacePath === undefined)
            throw new Error("the command runs outside the workspace");
          // io.signal is PiShip's timeout and cancellation: pass it on.
          const result = await call(
            "POST",
            `${path}/exec`,
            {
              command: command.command,
              workspacePath: command.workspacePath,
              env: command.env,
            },
            io.signal,
          );
          if (result.stdout) io.onStdout(Buffer.from(result.stdout));
          if (result.stderr) io.onStderr(Buffer.from(result.stderr));
          return { exitCode: result.exitCode };
        },
        async dispose() {
          // Called once and must not throw.
          await call("DELETE", path).catch(() => undefined);
        },
      };
    },
  };
});
