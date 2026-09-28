// The native backend: the platform OS sandbox (Linux bubblewrap, macOS
// Seatbelt) behind the backend contract. Commands run as local processes in
// their own process group; wrapping also contains MCP stdio servers.
import { existsSync } from "node:fs";
import type { AdapterAvailability, SandboxAdapter } from "./adapter.js";
import type {
  SandboxBackend,
  SandboxCapabilities,
  SandboxExecIO,
  SandboxExecRequest,
  SandboxExecResult,
  SandboxInstance,
  SandboxPrepareRequest,
} from "./backend.js";
import { CONTAINMENT_PLANES } from "./probe.js";
import { spawnManaged } from "./process.js";
import { selectAdapter } from "./select.js";

const NATIVE_CAPABILITIES: SandboxCapabilities = {
  isolation: "local",
  planes: CONTAINMENT_PLANES,
  network: ["deny", "allow"],
  localProcesses: true,
};

/** Time between SIGTERM and SIGKILL of a cancelled command's process group. */
const EXEC_GRACE_MS = 1000;

function shellFor(platform: NodeJS.Platform): { file: string; flag: string[] } {
  if (platform === "win32")
    return { file: process.env.ComSpec ?? "cmd.exe", flag: ["/d", "/s", "/c"] };
  return {
    file: existsSync("/bin/bash") ? "/bin/bash" : "/bin/sh",
    flag: ["-c"],
  };
}

export class NativeBackend implements SandboxBackend {
  readonly provider = "native" as const;
  readonly adapter: SandboxAdapter;
  readonly #platform: NodeJS.Platform;

  constructor(
    adapter: SandboxAdapter = selectAdapter(),
    platform: NodeJS.Platform = process.platform,
  ) {
    this.adapter = adapter;
    this.#platform = platform;
  }

  get id(): string {
    return this.adapter.id;
  }

  available(): Promise<AdapterAvailability> {
    return this.adapter.available();
  }

  capabilities(): SandboxCapabilities {
    return NATIVE_CAPABILITIES;
  }

  async prepare({ profile }: SandboxPrepareRequest): Promise<SandboxInstance> {
    const adapter = this.adapter;
    const shell = shellFor(this.#platform);
    const wrap: NonNullable<SandboxInstance["wrap"]> = (command) =>
      adapter.wrap(profile, command);
    return {
      wrap,
      exec: async (
        request: SandboxExecRequest,
        io: SandboxExecIO,
      ): Promise<SandboxExecResult> => {
        const exit = await spawnManaged({
          file: shell.file,
          args: [...shell.flag, request.command],
          cwd: request.cwd,
          env: request.env,
          graceMs: EXEC_GRACE_MS,
          signal: io.signal,
          onStdout: io.onStdout,
          onStderr: io.onStderr,
          sandbox: {
            wrap: (file, args, cwd, env) =>
              wrap({ file, args, cwd, env: env ?? {} }),
          },
        }).exited;
        if (exit.error) throw new Error(exit.error);
        return { exitCode: exit.code, signal: exit.signal };
      },
      // The session temp directory is owned and removed by the activation.
      dispose: async () => {},
    };
  }
}
