// stdio transport: newline-delimited JSON-RPC over a sandboxed child's
// stdin/stdout. stderr is kept only as a bounded, sanitized tail for
// diagnostics and is never forwarded.

import type { SandboxWrapper } from "@piship/sandbox";
import { accessSync, constants, statSync } from "node:fs";
import { delimiter, isAbsolute, join, relative, resolve } from "node:path";
import {
  DEFAULT_MAX_MESSAGE_BYTES,
  mcpUnhealthy,
  parseFrame,
} from "./jsonrpc.js";
import type {
  ChildHandle,
  JsonRpcMessage,
  McpServerConfig,
  McpTransport,
  ProcessRuntime,
} from "./types.js";

const STDERR_TAIL_BYTES = 8 * 1024;
const STDERR_REPORT_BYTES = 2 * 1024;

export interface StdioTransportOptions {
  readonly server: McpServerConfig;
  readonly distributionDir: string;
  readonly workspace: string;
  readonly runtime: ProcessRuntime;
  /** Source environment filtered into the child; defaults to process.env. */
  readonly env?: NodeJS.ProcessEnv;
  readonly sandbox?: SandboxWrapper;
  readonly graceMs?: number;
  readonly maxMessageBytes?: number;
}

export interface StdioCommand {
  readonly file: string;
  readonly args: readonly string[];
}

/** Resolve a module path inside the distribution, or a command on PATH. */
export function resolveStdioCommand(
  server: McpServerConfig,
  distributionDir: string,
  env: NodeJS.ProcessEnv,
): StdioCommand {
  if (server.module && server.command)
    throw mcpUnhealthy(
      `MCP server ${server.id} declares both module and command`,
    );
  if (server.module) {
    const root = resolve(distributionDir);
    const file = resolve(root, server.module);
    const inside = relative(root, file);
    if (inside.startsWith("..") || isAbsolute(inside))
      throw mcpUnhealthy(
        `MCP server ${server.id} module must stay inside the distribution`,
      );
    if (!isFile(file))
      throw mcpUnhealthy(`MCP server ${server.id} module was not found`);
    return { file: process.execPath, args: [file, ...server.args] };
  }
  if (server.command) {
    const file = findOnPath(server.command, env);
    if (!file)
      throw mcpUnhealthy(
        `MCP server ${server.id} command ${server.command} was not found on PATH`,
      );
    return { file, args: [...server.args] };
  }
  throw mcpUnhealthy(`MCP server ${server.id} declares no module or command`);
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Find an executable by bare name on PATH (and PATHEXT on Windows). */
export function findOnPath(
  name: string,
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  if (!/^[A-Za-z0-9._+-]+$/.test(name) || name === "." || name === "..")
    return undefined;
  const directories = (env.PATH ?? env.Path ?? "")
    .split(delimiter)
    .filter((entry) => entry.length > 0 && isAbsolute(entry));
  const extensions =
    platform === "win32"
      ? ["", ...(env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";")]
      : [""];
  for (const directory of directories)
    for (const extension of extensions) {
      const candidate = join(directory, `${name}${extension}`);
      if (!isFile(candidate)) continue;
      try {
        if (platform !== "win32") accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {}
    }
  return undefined;
}

export class StdioTransport implements McpTransport {
  readonly kind = "stdio" as const;
  onMessage: ((message: unknown) => void) | undefined;
  onClose: ((error: Error | undefined) => void) | undefined;
  readonly #options: StdioTransportOptions;
  readonly #maxBytes: number;
  #child: ChildHandle | undefined;
  #buffer = "";
  #stderrTail = "";
  #closing = false;
  #ended = false;

  constructor(options: StdioTransportOptions) {
    this.#options = options;
    this.#maxBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  }

  get pid(): number | undefined {
    return this.#child?.pid;
  }

  /** Sanitized, truncated stderr tail for diagnostics. */
  stderrSummary(): string {
    return this.#options.runtime.sanitizeStderr(
      this.#stderrTail,
      STDERR_REPORT_BYTES,
    );
  }

  async start(): Promise<void> {
    const { server, runtime } = this.#options;
    const source = this.#options.env ?? process.env;
    const command = resolveStdioCommand(
      server,
      this.#options.distributionDir,
      source,
    );
    const env = runtime.filterEnvironment(
      source,
      server.env.allow,
      server.env.set,
    );
    const child = runtime.spawn({
      file: command.file,
      args: command.args,
      cwd: this.#options.workspace,
      env,
      sandbox: this.#options.sandbox,
      graceMs: this.#options.graceMs ?? 2000,
      stdin: "pipe",
      onStderr: (chunk) => this.#stderr(chunk),
    });
    this.#child = child;
    if (!child.stdin || !child.stdout) {
      await this.#terminate();
      throw mcpUnhealthy(`MCP server ${server.id} has no stdio pipes`);
    }
    child.stdin.on("error", () => undefined);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.#stdout(chunk));
    child.exited.then(
      (exit) => this.#exited(exit.code, exit.signal),
      () => this.#exited(null, null),
    );
  }

  async send(message: JsonRpcMessage, signal?: AbortSignal): Promise<void> {
    const stdin = this.#child?.stdin;
    if (!stdin || this.#ended || this.#closing)
      throw mcpUnhealthy(
        `MCP server ${this.#options.server.id} is not running`,
      );
    const line = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(line, "utf8") > this.#maxBytes)
      throw mcpUnhealthy(
        `MCP request exceeds the ${this.#maxBytes}-byte message limit`,
      );
    // The line is written whole; a signal only stops waiting for the flush.
    await new Promise<void>((done, fail) => {
      const onAbort = () => fail(signal?.reason);
      signal?.addEventListener("abort", onAbort, { once: true });
      stdin.write(line, "utf8", (error) => {
        signal?.removeEventListener("abort", onAbort);
        if (!error) done();
        else
          fail(
            mcpUnhealthy(`MCP server ${this.#options.server.id} stdin closed`, {
              retryable: true,
            }),
          );
      });
    });
  }

  setProtocolVersion(): void {}

  async close(): Promise<void> {
    if (this.#closing) return;
    this.#closing = true;
    const child = this.#child;
    if (!child) return;
    try {
      child.stdin?.end();
    } catch {}
    const grace = this.#options.graceMs ?? 2000;
    const exited = await Promise.race([
      child.exited.then(() => true),
      delay(grace).then(() => false),
    ]);
    if (!exited) await this.#terminate();
  }

  async #terminate(): Promise<void> {
    const child = this.#child;
    if (!child) return;
    try {
      await child.terminate();
    } catch {}
    await Promise.race([
      child.exited.catch(() => undefined),
      delay(this.#options.graceMs ?? 2000),
    ]);
  }

  #stderr(chunk: Buffer | string): void {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    this.#stderrTail = (this.#stderrTail + text).slice(-STDERR_TAIL_BYTES);
  }

  #stdout(chunk: string): void {
    if (this.#ended) return;
    this.#buffer += chunk;
    let index = this.#buffer.indexOf("\n");
    while (index >= 0) {
      const line = this.#buffer.slice(0, index).replace(/\r$/, "");
      this.#buffer = this.#buffer.slice(index + 1);
      if (line.trim().length > 0 && !this.#deliver(line)) return;
      index = this.#buffer.indexOf("\n");
    }
    if (Buffer.byteLength(this.#buffer, "utf8") > this.#maxBytes)
      this.#fatal(
        mcpUnhealthy(`MCP message exceeds the ${this.#maxBytes}-byte limit`),
      );
  }

  #deliver(line: string): boolean {
    let value: unknown;
    try {
      value = parseFrame(line, this.#maxBytes);
    } catch (error) {
      this.#fatal(error as Error);
      return false;
    }
    this.onMessage?.(value);
    return true;
  }

  #fatal(error: Error): void {
    if (this.#ended) return;
    this.#ended = true;
    this.#buffer = "";
    this.onClose?.(
      mcpUnhealthy(
        `MCP server ${this.#options.server.id} violated the protocol: ${error.message}`,
      ),
    );
    this.close().catch(() => undefined);
  }

  #exited(code: number | null, signal: string | null): void {
    if (this.#ended) return;
    this.#ended = true;
    if (this.#closing) {
      this.onClose?.(undefined);
      return;
    }
    const stderr = this.stderrSummary();
    this.onClose?.(
      mcpUnhealthy(
        `MCP server ${this.#options.server.id} exited (${signal ?? `code ${code}`})`,
        {
          retryable: true,
          detail: {
            exitCode: code,
            signal,
            ...(stderr ? { stderr } : {}),
          },
        },
      ),
    );
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms).unref?.());
}
