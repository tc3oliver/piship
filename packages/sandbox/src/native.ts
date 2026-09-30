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
/**
 * The longest `dispose()` waits for a stopped command to be gone: the grace
 * period, then the kill and the drain of its output, with some room.
 */
const DISPOSE_WAIT_MS = EXEC_GRACE_MS + 1000;

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
    // What the isolator can guard is its own property, not the platform's.
    return {
      ...NATIVE_CAPABILITIES,
      guardsMissingFiles: this.adapter.guardsMissingFiles === true,
    };
  }

  async prepare({ profile }: SandboxPrepareRequest): Promise<SandboxInstance> {
    const adapter = this.adapter;
    const shell = shellFor(this.#platform);
    const wrap: NonNullable<SandboxInstance["wrap"]> = (command) =>
      adapter.wrap(profile, command);
    // Aborted at dispose: a command still running is stopped like a
    // cancelled one, and no command runs afterwards.
    const disposed = new AbortController();
    // Commands still running, so dispose can wait until they are gone.
    const running = new Set<Promise<unknown>>();
    const run = async (
      request: SandboxExecRequest,
      io: SandboxExecIO,
    ): Promise<SandboxExecResult> => {
      const exit = await spawnManaged({
        file: shell.file,
        args: [...shell.flag, request.command],
        cwd: request.cwd,
        env: request.env,
        graceMs: EXEC_GRACE_MS,
        signal: AbortSignal.any([io.signal, disposed.signal]),
        onStdout: io.onStdout,
        onStderr: io.onStderr,
        sandbox: {
          wrap: (file, args, cwd, env) =>
            wrap({ file, args, cwd, env: env ?? {} }),
        },
      }).exited;
      if (exit.error) throw new Error(exit.error);
      return { exitCode: exit.code, signal: exit.signal };
    };
    return {
      wrap,
      exec: async (
        request: SandboxExecRequest,
        io: SandboxExecIO,
      ): Promise<SandboxExecResult> => {
        if (disposed.signal.aborted)
          throw new Error("the sandbox instance was disposed");
        // The process is spawned before `run` first yields, so a dispose
        // that follows at once already finds it here.
        const command = run(request, io);
        running.add(command);
        const finished = () => running.delete(command);
        command.then(finished, finished);
        return command;
      },
      // A command still running is stopped, and dispose returns once it is
      // gone (bounded by the grace period): the activation removes the session
      // temp directory right after, and a command in its grace period could
      // otherwise write into it or recreate it. The directory itself is owned
      // and removed by the activation.
      dispose: async () => {
        disposed.abort();
        if (running.size === 0) return;
        let timer: NodeJS.Timeout | undefined;
        try {
          await Promise.race([
            Promise.allSettled([...running]),
            new Promise<void>((done) => {
              timer = setTimeout(done, DISPOSE_WAIT_MS);
            }),
          ]);
        } finally {
          clearTimeout(timer);
        }
      },
    };
  }
}
